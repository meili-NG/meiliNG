package cli

import (
	"fmt"
	"os"

	"github.com/meili-NG/meiliNG/v2/cmd/meiling/cli/serve"
	"github.com/meili-NG/meiliNG/v2/cmd/meiling/cli/users"
	"github.com/meili-NG/meiliNG/v2/pkg/app"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/spf13/cobra"
)

var configFile string

var rootCmd = &cobra.Command{
	Use:     "meiling",
	Short:   "meiliNG authentication server",
	Long:    "meiliNG is a secure authentication and authorization service.",
	Version: app.Version,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the authentication server",
	Run: func(cmd *cobra.Command, args []string) {
		serve.Run(cmd, args)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config-file", "c", "", "local configuration file or directory; it overrides the system config file")
	rootCmd.AddCommand(serveCmd)
	users.Register(rootCmd)
}

// Root returns the root command, so a distribution can rename it or change
// its help text before calling Execute.
func Root() *cobra.Command { return rootCmd }

// Execute runs the CLI
func Execute() {
	// Extension commands are attached here rather than in init(): a
	// distribution's packages may initialize after this one, and every init()
	// has run by the time main calls Execute.
	if err := addExtensionCommands(rootCmd, ext.Extensions()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// addExtensionCommands adds the commands of every ext.CommandProvider to root,
// refusing any whose name or alias is already taken.
func addExtensionCommands(root *cobra.Command, exts []ext.Extension) error {
	taken := map[string]string{}
	for _, c := range root.Commands() {
		for _, n := range append([]string{c.Name()}, c.Aliases...) {
			taken[n] = "core"
		}
	}

	for _, e := range exts {
		p, ok := e.(ext.CommandProvider)
		if !ok {
			continue
		}
		for _, c := range p.Commands() {
			for _, n := range append([]string{c.Name()}, c.Aliases...) {
				if owner, dup := taken[n]; dup {
					return fmt.Errorf("extension %q: command %q is already provided by %s", e.Name(), n, owner)
				}
				taken[n] = fmt.Sprintf("extension %q", e.Name())
			}
			root.AddCommand(c)
		}
	}
	return nil
}
