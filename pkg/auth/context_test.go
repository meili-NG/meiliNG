package auth

import (
	"slices"
	"testing"
	"time"

	"github.com/meili-NG/meiliNG/v2/pkg/tokens"
)

func TestContext(t *testing.T) {
	session := &tokens.SessionPayload{SID: "s", Users: []string{"u"}}
	if Context(session, "u") != nil || Context(nil, "u") != nil {
		t.Fatal("a context without a sign-in record")
	}

	session.RecordSignIn("u", tokens.UserAuth{Time: 100, Methods: []string{MethodPassword, MethodTOTP}, TwoFactor: true})
	ctx := Context(session, "u")
	if ctx.SID != "s" || ctx.AuthTime != 100 || ctx.ACR != ACRMultiFactor || !slices.Equal(ctx.AMR, []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("password and TOTP = %+v", ctx)
	}

	session.RecordSignIn("u", tokens.UserAuth{Time: 100, Methods: []string{MethodWebAuthn}, TwoFactor: true})
	if ctx := Context(session, "u"); ctx.ACR != ACRMultiFactor || !slices.Equal(ctx.AMR, []string{"hwk"}) {
		t.Fatalf("a passkey alone = %+v, want 2fa without mfa", ctx)
	}

	session.RemoveUser("u")
	if Context(session, "u") != nil {
		t.Fatal("a signed-out user kept a sign-in record")
	}
}

func TestReauthenticationRequired(t *testing.T) {
	now := time.Unix(1000, 0)
	oneFactor := &tokens.AuthContext{AuthTime: 900, ACR: ACRSingleFactor}
	twoFactor := &tokens.AuthContext{AuthTime: 900, ACR: ACRMultiFactor}
	for name, tc := range map[string]struct {
		ctx       *tokens.AuthContext
		maxAge    int
		acrValues string
		want      bool
	}{
		"no requirement":            {nil, -1, "", false},
		"no record, max_age":        {nil, 600, "", true},
		"within max_age":            {oneFactor, 100, "", false},
		"past max_age":              {oneFactor, 99, "", true},
		"1fa for 2fa":               {oneFactor, -1, "2fa", true},
		"2fa for 1fa":               {twoFactor, -1, "1fa", false},
		"either":                    {oneFactor, -1, "2fa 1fa", false},
		"2fa for 2fa, past max_age": {twoFactor, 10, "2fa", true},
	} {
		if got := ReauthenticationRequired(tc.ctx, tc.maxAge, tc.acrValues, now); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
