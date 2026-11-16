package templates

import (
	"context"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	texttemplate "text/template"

	"github.com/a-h/templ"
	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

// Operators replace a template without rebuilding by putting files in the
// directory set by notification.templatesPath. For a key such as
// verification_code:
//
//	verification_code.ko.html          body for lang "ko" (html/template)
//	verification_code.html             body for any other lang
//	verification_code.ko.subject.txt   subject for lang "ko" (text/template)
//	verification_code.subject.txt      subject for any other lang
//
// Templates receive the key's data struct, e.g. {{.Code}} and
// {{.Branding.Name}}. A body file overrides the built-in template and any
// Override of it; without a subject file the subject comes from the template
// it replaces.

// fromFiles renders key from cfg's template directory. ok is false when the
// directory is unset or has no body file for key, so the caller falls back.
func fromFiles(cfg *config.MeilingConfig, key, lang string, data any, fallbackSubject func() string) (msg Message, ok bool, err error) {
	if cfg == nil || cfg.NotificationConfig.TemplatesPath == "" {
		return Message{}, false, nil
	}
	dir := cfg.NotificationConfig.TemplatesPath

	bodyPath, found, err := findTemplate(dir, key, lang, ".html")
	if err != nil || !found {
		return Message{}, false, err
	}
	body, err := htmltemplate.ParseFiles(bodyPath)
	if err != nil {
		return Message{}, false, fmt.Errorf("templates: %w", err)
	}

	subjectPath, found, err := findTemplate(dir, key, lang, ".subject.txt")
	if err != nil {
		return Message{}, false, err
	}
	var subject string
	if found {
		if subject, err = executeText(subjectPath, data); err != nil {
			return Message{}, false, err
		}
	} else {
		subject = fallbackSubject()
	}

	// Execute now so a broken template fails delivery with a clear error
	// rather than midway through writing the email.
	var rendered strings.Builder
	if err := body.Execute(&rendered, data); err != nil {
		return Message{}, false, fmt.Errorf("templates: %s: %w", bodyPath, err)
	}
	html := rendered.String()

	return Message{
		Subject: subject,
		Body: templ.ComponentFunc(func(_ context.Context, w io.Writer) error {
			_, err := io.WriteString(w, html)
			return err
		}),
	}, true, nil
}

// findTemplate returns the language-specific file for key if it exists, else
// the generic one.
func findTemplate(dir, key, lang, suffix string) (string, bool, error) {
	candidates := []string{key + suffix}
	if lang != "" {
		candidates = append([]string{key + "." + lang + suffix}, candidates...)
	}
	for _, name := range candidates {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, true, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", false, fmt.Errorf("templates: %w", err)
		}
	}
	return "", false, nil
}

func executeText(path string, data any) (string, error) {
	t, err := texttemplate.ParseFiles(path)
	if err != nil {
		return "", fmt.Errorf("templates: %w", err)
	}
	var out strings.Builder
	if err := t.Execute(&out, data); err != nil {
		return "", fmt.Errorf("templates: %s: %w", path, err)
	}
	return strings.TrimSpace(out.String()), nil
}
