package server

import (
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	appconfig "github.com/meili-NG/meiliNG/v2/pkg/config"
)

// Run starts the Meiling authentication server using the Meiling instance
func Run() {
	// Create Meiling instance with auto-discovered config
	m, err := app.New(appconfig.MeilingConfig{})
	if err != nil {
		panic(err)
	}

	// Run the server
	if err := m.StartServer(); err != nil {
		panic(err)
	}
}
