// Package generic provides the built-in notification provider for Meiling.
//
// It delivers notifications as HTML email over SMTP (using the SMTPConfig
// section of the configuration) and renders message content itself from the
// active templates in pkg/notify/templates, which operators (with files) and
// distributions (in code) can override. It is the default provider used when no vendor
// provider is configured for a notification key.
//
// Importing this package (typically as a blank import at the composition root)
// registers the provider under the name notify.GenericProviderName.
package generic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
	"github.com/meili-NG/meiliNG/v2/pkg/notify"
	"github.com/meili-NG/meiliNG/v2/pkg/notify/templates"
	"gopkg.in/gomail.v2"
)

func init() {
	notify.Register(New())
}

// supportedKeys lists the notification keys this provider can render and send.
var supportedKeys = map[notify.NotifyKey]bool{
	notify.NotifyKeyVerificationCode: true,
}

// Provider is the built-in SMTP-backed notification provider.
type Provider struct {
	mu        sync.Mutex
	dialer    *gomail.Dialer
	dialerKey smtpKey
}

// New returns a generic provider instance.
func New() *Provider { return &Provider{} }

// Name implements notify.Provider.
func (p *Provider) Name() string { return notify.GenericProviderName }

// Supports implements notify.Provider.
func (p *Provider) Supports(key notify.NotifyKey) bool { return supportedKeys[key] }

// Notify implements notify.Provider. It renders the content for the given key
// and delivers it as an email.
func (p *Provider) Notify(ctx context.Context, cfg *config.MeilingConfig, n notify.Notification) error {
	subject, body, err := p.render(ctx, cfg, n)
	if err != nil {
		return err
	}
	return p.sendEmail(cfg, n.Recipient, subject, body)
}

// render turns a key+args into an email subject and HTML body using the
// active template for the key (see pkg/notify/templates).
func (p *Provider) render(ctx context.Context, cfg *config.MeilingConfig, n notify.Notification) (subject, body string, err error) {
	var msg templates.Message
	switch n.Key {
	case notify.NotifyKeyVerificationCode:
		code := n.Args.String("code")
		if code == "" {
			return "", "", errors.New("generic: verification_code requires a non-empty \"code\" arg")
		}
		lang := n.Args.String("lang")
		if lang == "" {
			lang = "en"
		}
		msg, err = templates.RenderVerificationCode(cfg, templates.VerificationCodeData{
			Code:     code,
			Lang:     lang,
			Branding: templates.BrandingFrom(cfg),
		})
		if err != nil {
			return "", "", err
		}
	default:
		return "", "", fmt.Errorf("generic: unsupported notification key %q", n.Key)
	}

	body, err = msg.RenderString(ctx)
	if err != nil {
		return "", "", err
	}
	return msg.Subject, body, nil
}

func (p *Provider) sendEmail(cfg *config.MeilingConfig, to, subject, body string) error {
	d, err := p.getDialer(cfg)
	if err != nil {
		return err
	}

	m := gomail.NewMessage()
	m.SetHeader("From", cfg.NotificationConfig.SMTP.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return d.DialAndSend(m)
}

// smtpKey is the subset of SMTP settings that, when changed, require rebuilding
// the dialer.
type smtpKey struct {
	host          string
	port          int
	username      string
	password      string
	useTLS        bool
	tlsServerName string
}

func keyFromConfig(c config.SMTPConfig) smtpKey {
	return smtpKey{
		host:          c.Host,
		port:          c.Port,
		username:      c.Username,
		password:      c.Password,
		useTLS:        c.UseTLS,
		tlsServerName: c.TLSServerName,
	}
}

func (p *Provider) getDialer(cfg *config.MeilingConfig) (*gomail.Dialer, error) {
	key := keyFromConfig(cfg.NotificationConfig.SMTP)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dialer != nil && p.dialerKey == key {
		return p.dialer, nil
	}

	if cfg.NotificationConfig.SMTP.Host == "" {
		return nil, errors.New("SMTP host is not set")
	}

	port := cfg.NotificationConfig.SMTP.Port
	if port == 0 {
		port = 25 // fallback
	}

	d := gomail.NewDialer(cfg.NotificationConfig.SMTP.Host, port, cfg.NotificationConfig.SMTP.Username, cfg.NotificationConfig.SMTP.Password)

	if cfg.NotificationConfig.SMTP.UseTLS {
		serverName := cfg.NotificationConfig.SMTP.Host
		if cfg.NotificationConfig.SMTP.TLSServerName != "" {
			serverName = cfg.NotificationConfig.SMTP.TLSServerName
		}
		d.TLSConfig = &tls.Config{ServerName: serverName}
	}

	p.dialer = d
	p.dialerKey = key
	return d, nil
}
