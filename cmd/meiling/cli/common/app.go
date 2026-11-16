package common

import (
	"log"

	meiling "github.com/meili-NG/meiliNG/v2"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/spf13/cobra"
)

// InitApp creates and initializes a Meiling app instance for CLI commands.
func InitApp(cmd *cobra.Command) *meiling.Meiling {
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

	if err := m.Initialize(); err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}

	return m
}
