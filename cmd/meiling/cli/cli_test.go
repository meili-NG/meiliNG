package cli

import (
	"strings"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/ext"
	"github.com/spf13/cobra"
)

type cmdExt struct {
	name string
	cmds []*cobra.Command
}

func (e cmdExt) Name() string               { return e.name }
func (e cmdExt) Commands() []*cobra.Command { return e.cmds }

type plainExt struct{}

func (plainExt) Name() string { return "plain" }

func newRoot() *cobra.Command {
	root := &cobra.Command{Use: "meiling"}
	root.AddCommand(&cobra.Command{Use: "serve", Aliases: []string{"run"}})
	return root
}

func TestAddExtensionCommands(t *testing.T) {
	root := newRoot()
	exts := []ext.Extension{
		plainExt{},
		cmdExt{name: "vendor", cmds: []*cobra.Command{{Use: "sync-billing"}}},
	}
	if err := addExtensionCommands(root, exts); err != nil {
		t.Fatalf("addExtensionCommands: %v", err)
	}
	if c, _, err := root.Find([]string{"sync-billing"}); err != nil || c.Name() != "sync-billing" {
		t.Fatalf("extension command not added: %v", err)
	}
}

func TestAddExtensionCommandsRejectsCollisions(t *testing.T) {
	for _, tc := range []struct {
		name string
		exts []ext.Extension
		want string
	}{
		{"core name", []ext.Extension{cmdExt{name: "a", cmds: []*cobra.Command{{Use: "serve"}}}}, "core"},
		{"core alias", []ext.Extension{cmdExt{name: "a", cmds: []*cobra.Command{{Use: "run"}}}}, "core"},
		{"between extensions", []ext.Extension{
			cmdExt{name: "a", cmds: []*cobra.Command{{Use: "x"}}},
			cmdExt{name: "b", cmds: []*cobra.Command{{Use: "y", Aliases: []string{"x"}}}},
		}, `extension "a"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := addExtensionCommands(newRoot(), tc.exts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want collision with %s", err, tc.want)
			}
		})
	}
}
