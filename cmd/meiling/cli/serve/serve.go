package serve

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	meiling "github.com/meili-NG/meiliNG/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/spf13/cobra"
)

// Run starts the Meiling authentication server.
func Run(cmd *cobra.Command, args []string) {
	configPath, _ := cmd.Flags().GetString("config-file")
	var m *meiling.Meiling
	var err error

	if configPath != "" {
		m, err = meiling.NewFromPath(configPath)
	} else {
		m, err = meiling.New(config.MeilingConfig{})
	}
	if err != nil {
		log.Fatalf("Failed to create meiliNG instance: %v", err)
	}

	// On SIGINT/SIGTERM stop accepting requests, let in-flight ones finish,
	// then run extension shutdown hooks. A second signal exits immediately.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-signals
		log.Print("Shutting down; send the signal again to exit immediately")
		go func() {
			<-signals
			log.Print("Forced exit")
			os.Exit(1)
		}()
		if err := m.Shutdown(); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	// SIGHUP reloads the configuration, e.g. from `systemctl reload` with
	// ExecReload=/bin/kill -HUP $MAINPID. A failed reload keeps the running one.
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if err := m.Reload(); err != nil {
				log.Printf("Reload failed, keeping the running configuration: %v", err)
			} else {
				log.Print("Configuration reloaded")
			}
		}
	}()

	if err := m.StartServer(); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	// The listener returns as soon as the server stops, which is before the
	// shutdown hooks finish; wait for them so the process does not exit
	// mid-cleanup.
	<-shutdownDone
}
