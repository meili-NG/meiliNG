package tokens

// AuthContext is how the user behind an authorization signed in. It travels in
// the authorization code into the ID token as sid, auth_time, amr and acr.
type AuthContext struct {
	SID      string   `json:"sid,omitempty"`
	AuthTime int64    `json:"authTime,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	ACR      string   `json:"acr,omitempty"`
}
