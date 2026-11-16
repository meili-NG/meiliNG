package app

import (
	"context"
	"errors"
	"log"
	"reflect"
	"sync/atomic"
	"time"

	internalconfig "github.com/meili-NG/meiliNG/v2/internal/config"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	meilingErrors "github.com/meili-NG/meiliNG/v2/pkg/errors"
	"github.com/meili-NG/meiliNG/v2/pkg/telemetry"
	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// drainTimeout bounds how long a replaced app waits for its requests before
// its resources are released.
const drainTimeout = 30 * time.Second

// generation is one built app serving requests behind the listening server.
type generation struct {
	handler  fasthttp.RequestHandler
	owner    *Meiling
	inflight atomic.Int64
}

func (m *Meiling) dispatch(ctx *fasthttp.RequestCtx) {
	g := m.current.Load()
	g.inflight.Add(1)
	defer g.inflight.Add(-1)
	g.handler(ctx)
}

// Reload reads the configuration again, builds a new app from it and swaps it
// in behind the listening server. Requests already running finish on the
// previous app. If anything fails, the previous app keeps serving and the
// error is returned. server.listen and server.prefork apply only on restart.
func (m *Meiling) Reload() error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	previous := m.current.Load()
	if previous == nil {
		return errors.New("reload: the server is not running")
	}

	var cfg *config.MeilingConfig
	var err error
	if m.configPath != "" {
		cfg, err = internalconfig.LoadConfigWithPath(m.configPath)
	} else {
		cfg, err = internalconfig.LoadConfig()
	}
	if err != nil {
		return err
	}

	m.mu.RLock()
	old, oldTokens, oldReporter := m.config, m.tokenServices, m.reporter
	m.mu.RUnlock()

	if old.ServerConfig.Prefork || cfg.ServerConfig.Prefork {
		return errors.New("reload: not supported with server.prefork; restart instead")
	}
	if cfg.ServerConfig.Listen != old.ServerConfig.Listen {
		log.Printf("reload: server.listen changed to %q; it takes effect on restart", cfg.ServerConfig.Listen)
	}

	next := &Meiling{
		config:        cfg,
		configPath:    m.configPath,
		geoIPResolver: m.getGeoIPResolver(),
		tokenServices: tokens.NewServicesFrom(cfg, oldTokens),
	}

	var oldDB *gorm.DB
	databaseChanged := !reflect.DeepEqual(old.DatabaseConfig, cfg.DatabaseConfig)
	if databaseChanged {
		oldDB = database.ReplaceInstance(nil)
	}

	app, err := next.GetServer()
	if err != nil {
		m.restoreGlobals(old, oldDB, databaseChanged)
		shutdownReporter(next.reporter)
		return err
	}

	m.current.Store(&generation{handler: app.Handler(), owner: next})
	m.mu.Lock()
	m.config, m.tokenServices, m.reporter, m.router = cfg, next.tokenServices, next.reporter, next.router
	m.mu.Unlock()

	go release(previous, oldReporter, oldDB)
	return nil
}

// restoreGlobals points the process-wide state back at the previous
// configuration after a failed reload.
func (m *Meiling) restoreGlobals(old *config.MeilingConfig, oldDB *gorm.DB, databaseChanged bool) {
	if databaseChanged {
		if failed := database.ReplaceInstance(oldDB); failed != nil {
			closeDB(failed)
		}
	}
	meilingErrors.SetConfig(&meilingErrors.Config{
		Debug:             old.DebugConfig.Enabled,
		RespondStackTrace: old.DebugConfig.RespondStackTrace,
	})
	if err := m.setupDatabaseDependencies(); err != nil {
		log.Printf("reload: restoring the previous configuration: %v", err)
	}
}

// release waits for the replaced app's requests, then frees what only it used.
func release(g *generation, reporter *telemetry.Reporter, oldDB *gorm.DB) {
	deadline := time.Now().Add(drainTimeout)
	for g.inflight.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if oldDB != nil {
		closeDB(oldDB)
	}
	shutdownReporter(reporter)
}

func shutdownReporter(reporter *telemetry.Reporter) {
	if reporter == nil || reporter.Shutdown == nil {
		return
	}
	// Bounded, so an unreachable collector cannot hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := reporter.Shutdown(ctx); err != nil {
		log.Printf("reload: shutting down the previous telemetry: %v", err)
	}
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
