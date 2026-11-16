package captcha

import (
	"context"
	"errors"
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

type verifierFunc func(token string) (bool, error)

func (verifierFunc) Widget() Widget { return Widget{Provider: "test"} }

func (f verifierFunc) Verify(_ context.Context, token, _ string) (bool, error) { return f(token) }

func TestCheck(t *testing.T) {
	t.Cleanup(Provider.Reset)
	cfg := &config.MeilingConfig{}
	ctx := context.Background()

	if err := Check(ctx, cfg, "", ""); err != nil {
		t.Fatalf("Check without a provider = %v, want nil", err)
	}

	Provider.Override(func(*config.MeilingConfig) (Verifier, error) { return nil, nil })
	if err := Check(ctx, cfg, "", ""); err != nil {
		t.Fatalf("Check with a disabled provider = %v, want nil", err)
	}

	errVerify := errors.New("verify failed")
	Provider.Override(func(*config.MeilingConfig) (Verifier, error) {
		return verifierFunc(func(token string) (bool, error) {
			if token == "error" {
				return false, errVerify
			}
			return token == "ok", nil
		}), nil
	})
	for token, want := range map[string]error{"": ErrFailed, "bad": ErrFailed, "ok": nil, "error": errVerify} {
		if err := Check(ctx, cfg, token, ""); !errors.Is(err, want) {
			t.Fatalf("Check(%q) = %v, want %v", token, err, want)
		}
	}

	Provider.Override(func(*config.MeilingConfig) (Verifier, error) { return nil, errVerify })
	if _, err := For(cfg); !errors.Is(err, errVerify) {
		t.Fatalf("For with a failing provider = %v, want %v", err, errVerify)
	}
}
