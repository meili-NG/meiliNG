package config

import (
	"net/url"

	"strings"

	"github.com/meili-NG/meiliNG/v2/internal/utils"
)

type MeilingConfig struct {
	ServerConfig       ServerConfig       `json:"server,omitempty"`
	InstanceConfig     InstanceConfig     `json:"instance,omitempty"`
	DebugConfig        DebugConfig        `json:"debug,omitempty"`
	DatabaseConfig     DatabaseConfig     `json:"database,omitempty"`
	ValkeyConfig       ValkeyConfig       `json:"valkey,omitempty"`
	AuthConfig         AuthConfig         `json:"auth,omitempty"`
	TokenConfig        TokenConfig        `json:"token,omitempty"`
	OAuth2Config       OAuth2Config       `json:"oauth2,omitempty"`
	AdminConfig        AdminConfig        `json:"admin,omitempty"`
	NotificationConfig NotificationConfig `json:"notification,omitempty"`
	WebUIConfig        WebUIConfig        `json:"webui,omitempty"`

	// Sections holds the loaded values of registered config sections, keyed
	// by path. Read them with Section; see RegisterSection.
	Sections map[string]any `json:"-"`
}

func (c *MeilingConfig) PostProcess() error {
	err := c.ServerConfig.PostProcess()
	if err != nil {
		return err
	}

	err = c.TokenConfig.PostProcess()
	if err != nil {
		return err
	}

	err = c.TokenConfig.JWT.PostProcess()
	if err != nil {
		return err
	}

	err = c.DatabaseConfig.PostProcess()
	if err != nil {
		return err
	}

	err = c.ValkeyConfig.PostProcess()
	if err != nil {
		return err
	}

	err = c.WebUIConfig.PostProcess()
	if err != nil {
		return err
	}

	err = c.AdminConfig.Validate()
	if err != nil {
		return err
	}

	err = c.PopulateDerivedDefaults()
	if err != nil {
		return err
	}

	return nil
}

// AllowsOrigin reports whether a browser at origin may call the API across
// origins: it must match an entry of FrontendOrigins by scheme, host and port.
// An empty list allows none.
func (c *ServerConfig) AllowsOrigin(origin string) bool {
	want, err := url.Parse(origin)
	if err != nil || want.Host == "" {
		return false
	}
	for _, allowed := range c.FrontendOrigins {
		if u, err := url.Parse(allowed); err == nil && strings.EqualFold(u.Scheme, want.Scheme) && strings.EqualFold(u.Host, want.Host) {
			return true
		}
	}
	return false
}

// PopulateDerivedDefaults fills settings left empty from instance.name and
// server.publicUrl.
func (c *MeilingConfig) PopulateDerivedDefaults() error {
	name := c.InstanceConfig.Name
	primaryAddress := c.ServerConfig.PublicURL

	parsedURL, err := url.Parse(primaryAddress)
	if err != nil {
		return err
	}

	if c.TokenConfig.JWT.Issuer == "" {
		c.TokenConfig.JWT.Issuer = parsedURL.Scheme + "://" + parsedURL.Hostname()
	}

	if c.AuthConfig.TOTP.Issuer == "" {
		c.AuthConfig.TOTP.Issuer = name
	}

	if c.AuthConfig.WebAuthn.DisplayName == "" {
		c.AuthConfig.WebAuthn.DisplayName = name
	}

	if len(c.ServerConfig.FrontendOrigins) == 0 {
		if len(c.OAuth2Config.ConsentFrontends) > 0 {
			c.ServerConfig.FrontendOrigins = utils.Filter(
				utils.Map(c.OAuth2Config.ConsentFrontends, func(address string) string {
					parsedURL, err := url.Parse(address)
					if err != nil {
						return ""
					}

					return parsedURL.Scheme + "://" + parsedURL.Host
				}),
				func(i string) bool {
					return i != ""
				})
		}
	}

	// The built-in web UI is served from this server, so its own origin has to
	// be allowed or every request it makes would fail the frontend-origin
	// check. Deriving it from server.publicUrl keeps that automatic instead of
	// forcing operators to restate it in server.frontendOrigins.
	if c.WebUIConfig.Enable && c.WebUIConfig.APIBaseURL == "" {
		if selfOrigin := parsedURL.Scheme + "://" + parsedURL.Host; parsedURL.Host != "" {
			if !utils.Contains(c.ServerConfig.FrontendOrigins, selfOrigin) {
				c.ServerConfig.FrontendOrigins = append(c.ServerConfig.FrontendOrigins, selfOrigin)
			}
		}
	}

	if len(c.AuthConfig.WebAuthn.RelyingPartyOrigins) == 0 {
		if len(c.ServerConfig.FrontendOrigins) > 0 {
			c.AuthConfig.WebAuthn.RelyingPartyOrigins = utils.Filter(
				utils.Map(c.ServerConfig.FrontendOrigins, func(address string) string {
					parsedURL, err := url.Parse(address)
					if err != nil {
						return ""
					}

					return parsedURL.Scheme + "://" + parsedURL.Host
				}),
				func(i string) bool {
					return i != ""
				})

			if c.AuthConfig.WebAuthn.RelyingPartyID == "" {
				parsedURL, err := url.Parse(c.AuthConfig.WebAuthn.RelyingPartyOrigins[0])
				if err == nil {
					c.AuthConfig.WebAuthn.RelyingPartyID = parsedURL.Hostname()
				}
			}
		}
	}

	return nil
}
