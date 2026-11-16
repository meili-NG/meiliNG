package v2

import "github.com/meili-NG/meiliNG/v2/pkg/captcha"

// InstanceInput is the input for the instance description (empty).
type InstanceInput struct{}

// InstanceOutput is the instance description.
type InstanceOutput struct {
	Body InstanceInfo
}

// InstanceInfo is what a user interface needs to present this instance. It
// holds only public settings.
type InstanceInfo struct {
	Name        string `json:"name" doc:"Display name (instance.name)" example:"Meiling"`
	Description string `json:"description" doc:"Service description (instance.description)"`
	LogoURL     string `json:"logoUrl,omitempty" doc:"Absolute URL of the instance logo (instance.logoUrl)" format:"uri"`
	SupportURL  string `json:"supportUrl,omitempty" doc:"Help page for users (instance.supportUrl)" format:"uri"`

	Captcha *captcha.Widget `json:"captcha,omitempty" doc:"Challenge to complete and send as captchaToken to POST /v2/auth/verify. Absent when none is required"`

	SignIn SignInInfo `json:"signIn" doc:"Identifiers a sign-in accepts (auth.signin)"`
}

// SignInInfo tells a sign-in form what to ask for.
type SignInInfo struct {
	Username bool `json:"username" doc:"A username is accepted as the identifier"`
	Email    bool `json:"email" doc:"An email address is accepted as the identifier"`
	Passkey  bool `json:"passkey" doc:"A passkey alone, without an identifier, can sign in"`
}

// KeyOwnerInput names a signing key by fingerprint.
type KeyOwnerInput struct {
	Fingerprint string `query:"fingerprint" required:"true" doc:"SSH fingerprint (SHA256:...) or 40-digit OpenPGP fingerprint" example:"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"`
}

// KeyOwnerOutput is the owner of a public signing key.
type KeyOwnerOutput struct {
	Body KeyOwner
}

// KeyOwner is the owner of a public signing key.
type KeyOwner struct {
	Type        string `json:"type" doc:"Key type" enum:"pgp,ssh"`
	Fingerprint string `json:"fingerprint"`
	Username    string `json:"username" doc:"Username of the key's owner"`
}
