package routes

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/meili-NG/meiliNG/v2/internal/database"
	"github.com/meili-NG/meiliNG/v2/pkg/api"
)

// registerPublicKeyRoutes publishes the signing keys users marked public, in
// the forms tools already read:
//
//   - /{username}.keys: SSH keys in authorized_keys form, as GitHub serves
//     them, e.g. for sshd's AuthorizedKeysCommand.
//   - /{username}.gpg: armored OpenPGP keys.
//   - /pks/lookup?op=get&search=0x<fingerprint or key ID>: the HKP key server
//     lookup, so `gpg --keyserver <this server> --recv-keys` works.
func (r *Router) registerPublicKeyRoutes() {
	if r.app.Config().AuthConfig.DisablePublicKeys {
		return
	}

	r.fiberApp.Get("/pks/lookup", func(c *fiber.Ctx) error {
		if c.Query("op") != "get" {
			return c.Status(fiber.StatusNotImplemented).SendString("only op=get is supported\n")
		}
		key, err := api.PublicPGPKey(c.Query("search"))
		if err != nil {
			return err
		}
		if key == "" {
			return c.Status(fiber.StatusNotFound).SendString("no public key matches\n")
		}
		c.Set(fiber.HeaderContentType, "application/pgp-keys")
		return c.SendString(key + "\n")
	})

	// One path segment ending in .keys or .gpg; anything else goes on to the
	// routes after this one, which may include a web UI mounted at "/".
	r.fiberApp.Get("/:file", func(c *fiber.Ctx) error {
		file := c.Params("file")
		kinds := map[string]string{".keys": database.SSHKeyType, ".gpg": database.PGPKeyType}
		for suffix, kind := range kinds {
			username, ok := strings.CutSuffix(file, suffix)
			if !ok || username == "" {
				continue
			}
			keys, err := api.PublicSigningKeys(username, kind)
			if err != nil {
				return err
			}
			c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
			if len(keys) == 0 {
				return c.SendString("")
			}
			return c.SendString(strings.Join(keys, "\n") + "\n")
		}
		return c.Next()
	})
}
