package tokens

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// PrincipalKind is what authenticated a request.
type PrincipalKind string

const (
	// PrincipalSession is a session users signed into.
	PrincipalSession PrincipalKind = "session"
	// PrincipalAdminToken is an admin token: one of admin.adminTokens, or the
	// web UI's bootstrap token.
	PrincipalAdminToken PrincipalKind = "admin_token"
	// PrincipalService is an M2M access token for the admin audience.
	PrincipalService PrincipalKind = "service"
)

// Principal is who is calling. A session acts for the users signed into it.
// An admin credential acts on any user, has no session, and cannot sign in.
type Principal struct {
	Kind PrincipalKind
	// Session is set only for PrincipalSession.
	Session *SessionPayload
	// ActorID names an admin credential in logs without revealing it, e.g.
	// "admin_token:3f2a91c0" or "service:<client id>". Empty for sessions.
	ActorID string
}

// SessionPrincipal returns the principal of a session.
func SessionPrincipal(session *SessionPayload) *Principal {
	return &Principal{Kind: PrincipalSession, Session: session}
}

// IsAdmin reports whether p is an admin credential.
func (p *Principal) IsAdmin() bool {
	return p != nil && (p.Kind == PrincipalAdminToken || p.Kind == PrincipalService)
}

// HasUser reports whether p may act as the user with id: an admin always,
// a session when the user is signed into it.
func (p *Principal) HasUser(id string) bool {
	if p.IsAdmin() {
		return true
	}
	return p != nil && p.Session != nil && slices.Contains(p.Session.Users, id)
}

// Users are the users signed into p's session; none for an admin credential.
func (p *Principal) Users() []string {
	if p == nil || p.Session == nil {
		return nil
	}
	return p.Session.Users
}

// ActorID names a credential in logs as prefix and a short hash of secret, so
// the secret itself is never written down.
func ActorID(prefix, secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return prefix + ":" + hex.EncodeToString(sum[:4])
}
