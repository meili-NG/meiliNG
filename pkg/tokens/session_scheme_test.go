package tokens

import "testing"

func TestIsSessionScheme(t *testing.T) {
	t.Cleanup(SessionSchemes.Reset)
	if !IsSessionScheme("meilingv2") || IsSessionScheme("Bearer") {
		t.Fatal("the default scheme is not MeilingV2")
	}
	SessionSchemes.Override([]string{"AcmeV1"})
	if !IsSessionScheme("AcmeV1") || IsSessionScheme("MeilingV2") {
		t.Fatal("overridden schemes were not applied")
	}
}
