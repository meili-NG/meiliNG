package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DatabaseConfig struct {
	Type  string `json:"type" default:"sqlite"`
	DSN   string `json:"dsn"`
	Debug bool   `json:"debug" default:"false"`
}

// ServerConfig is how the server listens and how it is reached.
type ServerConfig struct {
	Listen string `json:"listen" default:":8080"`
	// PublicURL is the external URL of this server. The JWT issuer and other
	// unset settings are derived from it.
	PublicURL string `json:"publicUrl" default:"http://localhost:8080"`
	// FrontendOrigins are the browser origins allowed to call the API.
	FrontendOrigins []string `json:"frontendOrigins"`
	ProxyAddresses  []string `json:"proxyAddresses"`
	ProxyHeader     string   `json:"proxyHeader"`
	Prefork         bool     `json:"prefork" default:"false"`
}

func (c *ServerConfig) PostProcess() error {
	if len(c.ProxyAddresses) > 0 {
		if c.ProxyHeader == "" {
			c.ProxyHeader = fiber.HeaderXForwardedFor
		}
	}

	if c.Listen == "" {
		c.Listen = ":8080"
	}

	return nil
}

type ValkeyConfig struct {
	InitAddress   []string      `json:"initAddress"`
	Username      string        `json:"username"`
	Password      string        `json:"password"`
	TimeoutString string        `json:"timeout" default:"5s"`
	Timeout       time.Duration `json:"-"`
}

func (c *ValkeyConfig) PostProcess() error {
	if c.TimeoutString != "" {
		d, err := time.ParseDuration(c.TimeoutString)
		if err != nil {
			return errors.New("invalid valkey timeout: " + err.Error())
		}
		c.Timeout = d
	}
	return nil
}

func (c *DatabaseConfig) PostProcess() error {
	// An empty type is left for GetInstance to reject, as configs built in
	// code may not set one.
	if c.Type == "" {
		return nil
	}
	d, ok := LookupDialect(c.Type)
	if !ok {
		return fmt.Errorf("unsupported database type %q (registered: %s)", c.Type, strings.Join(Dialects(), ", "))
	}
	if d.Prepare != nil {
		dsn, err := d.Prepare(c.DSN)
		if err != nil {
			return err
		}
		c.DSN = dsn
	}
	return nil
}

// GetDialector returns the dialector for database.type, or nil when the type
// is not registered.
func (c *DatabaseConfig) GetDialector() gorm.Dialector {
	d, ok := LookupDialect(c.Type)
	if !ok {
		return nil
	}
	return d.Open(c.DSN)
}

// prepareMySQLDSN enables parseTime, which Meiling's time columns need.
func prepareMySQLDSN(dsn string) (string, error) {
	results := strings.Split(dsn, "?")
	if len(results) >= 1 {
		queryString := strings.Join(results[1:], "?")

		params, err := url.ParseQuery(queryString)
		if err != nil {
			return "", errors.New("invalid Query Params in DSN")
		}

		if !params.Has("parseTime") {
			params.Set("parseTime", "True")
		}

		dsn = results[0] + "?" + params.Encode()
	}
	return dsn, nil
}

func (c *DatabaseConfig) GetInstance() (*gorm.DB, error) {
	dialector := c.GetDialector()
	if dialector == nil {
		return nil, errors.New("unsupported database type")
	}

	dbLogger := logger.Default.LogMode(logger.Silent)
	if c.Debug {
		dbLogger = logger.Default.LogMode(logger.Info)
	}

	return gorm.Open(dialector, &gorm.Config{
		Logger: dbLogger,
	})
}
