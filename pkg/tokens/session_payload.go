package tokens

import (
	"errors"
	"slices"
	"time"
)

func (p *SessionPayload) HasUser(id string) bool {
	return slices.Contains(p.Users, id)
}

func (p *SessionPayload) SignIn(id string) {
	p.AddUser(id)
}

func (p *SessionPayload) AddUser(id string) bool {
	if slices.Contains(p.Users, id) {
		return false
	}

	p.Users = append(p.Users, id)
	return true
}

func (p *SessionPayload) SignOut(id string) {
	p.RemoveUser(id)
}

func (p *SessionPayload) SignOutAll() {
	p.RemoveAllUsers()
}

// RecordSignIn notes how the user with id signed in, for auth_time, amr and
// acr in the ID tokens issued from this session.
func (p *SessionPayload) RecordSignIn(id string, auth UserAuth) {
	if p.Auth == nil {
		p.Auth = map[string]UserAuth{}
	}
	p.Auth[id] = auth
}

func (p *SessionPayload) RemoveUser(id string) {
	delete(p.Auth, id)
	for i, v := range p.Users {
		if v == id {
			p.Users = append(p.Users[:i], p.Users[i+1:]...)
			return
		}
	}
}

func (p *SessionPayload) RemoveAllUsers() {
	p.Auth = nil
	p.Users = []string{}
}

func (p *SessionPayload) GetTID() string {
	return p.TID
}

func (p *SessionPayload) GetSID() string {
	return p.SID
}

func (p *SessionPayload) Update(manager *SessionManager) error {
	if manager == nil {
		return errors.New("session manager not provided")
	}

	if p.SID != "" {
		return manager.SetBySID(p.SID, *p)
	}

	return manager.SetByTID(p.TID, *p)
}

func (p *SessionPayload) IsExpired() bool {
	return p.ExpiresAt.Before(time.Now())
}

func (p *SessionPayload) IsRevoked(manager *SessionManager) bool {
	if manager == nil {
		return true
	}

	if p.SID != "" {
		return manager.IsRevokedBySID(p.SID)
	}

	return manager.IsRevokedByTID(p.TID)
}

func (p *SessionPayload) IsValid(manager *SessionManager) bool {
	return !p.IsExpired() && !p.IsRevoked(manager)
}
