package users

import (
	"fmt"
	"log"
	"os"

	meiling "github.com/meili-NG/meiliNG/v2"
	clicommon "github.com/meili-NG/meiliNG/v2/cmd/meiling/cli/common"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func initApp(cmd *cobra.Command) *meiling.Meiling {
	return clicommon.InitApp(cmd)
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Run: func(cmd *cobra.Command, args []string) {
		m := initApp(cmd)

		email, _ := cmd.Flags().GetString("email")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		name, _ := cmd.Flags().GetString("name")

		if email == "" {
			log.Fatal("--email is required")
		}

		// Prompt for password if not provided
		if password == "" {
			fmt.Print("Password: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Fatalf("Failed to read password: %v", err)
			}
			password = string(pw)

			fmt.Print("Confirm password: ")
			pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Fatalf("Failed to read password: %v", err)
			}
			if string(pw2) != password {
				log.Fatal("Passwords do not match")
			}
		}

		if password == "" {
			log.Fatal("Password cannot be empty")
		}

		cfg := m.Config()
		err := api.SignUp(&api.SignUpRequest{
			Config:        cfg,
			TokenServices: m.TokenServices(),
			Email:         email,
			Username:      username,
			Password:      password,
			Name:          name,
		})
		if err != nil {
			log.Fatalf("Failed to create user: %v", err)
		}

		fmt.Printf("User created successfully (email: %s)\n", email)
	},
}

// Register adds the users subcommand to the root command
func Register(rootCmd *cobra.Command) {
	usersCmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
	}

	createCmd.Flags().String("email", "", "user email address")
	createCmd.Flags().String("username", "", "username (optional)")
	createCmd.Flags().String("password", "", "password (omit to prompt interactively)")
	createCmd.Flags().String("name", "", "display name (optional)")

	usersCmd.AddCommand(createCmd)
	rootCmd.AddCommand(usersCmd)
}
