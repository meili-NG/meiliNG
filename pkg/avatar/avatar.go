// Package avatar picks the picture of users who have not uploaded one. It is
// published as the picture and profile claims of ID tokens and userinfo.
package avatar

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/ext"
)

// User identifies whose avatar is wanted.
type User struct {
	ID string
	// Email is the primary email, or empty.
	Email string
}

// ResolveFunc returns the avatar URL of u, or "" for none.
type ResolveFunc func(u User) string

// ProviderFunc builds the resolver for an instance from its config. Returning
// a nil ResolveFunc means users without an uploaded avatar have none; an
// error fails startup.
type ProviderFunc func(cfg *config.MeilingConfig) (ResolveFunc, error)

// Provider supplies the resolver. It defaults to Template; a distribution can
// replace it:
//
//	func init() { avatar.Provider.Override(myProvider) }
var Provider = ext.NewSlot[ProviderFunc](Template)

// Template is Provider's default. It fills the instance.avatarFallbackUrl
// template, Gravatar unless configured otherwise: {email} is the URL-escaped
// email, {email_md5} and {email_sha256} are hex hashes of it, all from the trimmed,
// lowercased email. An empty template turns the fallback off.
func Template(cfg *config.MeilingConfig) (ResolveFunc, error) {
	template := cfg.InstanceConfig.AvatarFallbackURL
	if template == "" {
		return nil, nil
	}
	return func(u User) string {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		md5sum := md5.Sum([]byte(email))
		sha := sha256.Sum256([]byte(email))
		return strings.NewReplacer(
			"{email}", url.QueryEscape(email),
			"{email_md5}", hex.EncodeToString(md5sum[:]),
			"{email_sha256}", hex.EncodeToString(sha[:]),
		).Replace(template)
	}, nil
}
