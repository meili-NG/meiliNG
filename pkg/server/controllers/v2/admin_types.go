package v2

// AdminProbeInput carries the admin authorization header for the probe. The
// admin check itself is enforced by middleware; this only documents the header.
type AdminProbeInput struct {
	Authorization string `header:"Authorization" doc:"Admin authorization header" example:"Meiling-Admin-Token your-admin-token"`
}

// AdminProbeResponse is the body returned by the admin probe.
type AdminProbeResponse struct {
	Admin bool   `json:"admin" doc:"Always true; reaching this response means the caller is an admin"`
	Kind  string `json:"kind" doc:"What authenticated the caller" enum:"admin_token,service"`
	Actor string `json:"actor" doc:"Names the credential without revealing it, e.g. admin_token:3f2a91c0 or service:<client id>"`
}

// AdminProbeOutput wraps the admin probe response.
type AdminProbeOutput struct {
	Body AdminProbeResponse
}
