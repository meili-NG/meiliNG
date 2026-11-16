package avatar

import (
	"testing"

	"github.com/meili-NG/meiliNG/v2/pkg/config"
)

func TestTemplate(t *testing.T) {
	// md5/sha256 of "user@example.com", the normalized form of the input.
	const md5 = "b58996c504c5638798eb6b511e6f49af"
	const sha = "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514"

	cases := []struct {
		name     string
		template string
		want     string
	}{
		{"gravatar", "https://www.gravatar.com/avatar/{email_md5}", "https://www.gravatar.com/avatar/" + md5},
		{"custom", "https://avatars.example.com/{email_sha256}?d=identicon", "https://avatars.example.com/" + sha + "?d=identicon"},
		{"email", "https://avatars.example.com/?u={email}", "https://avatars.example.com/?u=user%40example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.MeilingConfig{}
			cfg.InstanceConfig.AvatarFallbackURL = tc.template
			resolve, err := Template(cfg)
			if err != nil || resolve == nil {
				t.Fatalf("Template = %v, %v", resolve != nil, err)
			}
			if got := resolve(User{Email: "  User@Example.com "}); got != tc.want {
				t.Fatalf("avatar = %q, want %q", got, tc.want)
			}
		})
	}

	if resolve, err := Template(&config.MeilingConfig{}); err != nil || resolve != nil {
		t.Fatalf("Template with an empty template = %v, %v; want off", resolve != nil, err)
	}
}
