package test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rawRequest writes the request target to the server as given, so the path and
// query reach the router byte for byte.
func rawRequest(t *testing.T, env *featureEnv, method string, target string, headers ...string) *http.Response {
	t.Helper()

	client, server := net.Pipe()
	go func() { _ = env.server.Server().ServeConn(server) }()
	t.Cleanup(func() { client.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	request := method + " " + target + " HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n"
	for _, header := range headers {
		request += header + "\r\n"
	}
	if _, err := io.WriteString(client, request+"\r\n"); err != nil {
		t.Fatalf("write %s %q: %v", method, target, err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response of %s %q: %v", method, target, err)
	}
	resp.Body.Close()
	return resp
}

func TestApplicationAliasesRedirect(t *testing.T) {
	env := newFeatureEnv(t)
	// The first request through the test helper prepares the router.
	mustJSONRequest(t, env.server, http.MethodGet, "/health", nil, nil).Body.Close()

	const id = "0b7c0f5e-5a1c-4f0e-9d53-6c1f6f1f2a10"
	// Percent-encoding, "+", an empty value and a slash must come back exactly as sent.
	const query = "?user_id=a%20b&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&next=//evil.example/&crlf=%0d%0aLocation:%20x&plus=a+b&empty="

	rows := []struct {
		methods []string
		alias   string
		target  string
	}{
		{[]string{"GET", "POST"}, "/v2/oauth2/clients", "/v2/apps"},
		{[]string{"GET", "PUT", "DELETE"}, "/v2/oauth2/clients/" + id, "/v2/apps/" + id},
		{[]string{"POST"}, "/v2/oauth2/clients/" + id + "/unauthorize", "/v2/apps/" + id + "/unauthorize"},
		{[]string{"GET", "PUT"}, "/v2/oauth2/clients/" + id + "/permissions", "/v2/apps/" + id + "/permissions"},
		{[]string{"GET", "POST", "DELETE"}, "/v2/oauth2/clients/" + id + "/redirectUris", "/v2/apps/" + id + "/oauth2/redirect_uris"},
		{[]string{"GET", "POST", "DELETE"}, "/v2/oauth2/clients/" + id + "/secrets", "/v2/apps/" + id + "/oauth2/secrets"},
		{[]string{"GET", "POST", "DELETE"}, "/v2/oauth2/clients/" + id + "/audiences", "/v2/apps/" + id + "/oauth2/audiences"},
		{[]string{"GET", "POST"}, "/v2/oauth2/clients/" + id + "/auth", "/v2/apps/" + id + "/oauth2/auth"},
		// Any depth, and any method but OPTIONS.
		{[]string{"GET", "HEAD", "PATCH"}, "/v2/oauth2/clients/" + id + "/secrets/deeper/still", "/v2/apps/" + id + "/oauth2/secrets/deeper/still"},
		// Only the segment after the id is rewritten.
		{[]string{"GET"}, "/v2/oauth2/clients/secrets/secrets/secrets", "/v2/apps/secrets/oauth2/secrets/secrets"},
	}
	for _, row := range rows {
		for _, method := range row.methods {
			for _, suffix := range []string{"", "/", query, "/" + query} {
				resp := rawRequest(t, env, method, row.alias+suffix)
				if resp.StatusCode != http.StatusTemporaryRedirect {
					t.Errorf("%s %s status = %d, want 307", method, row.alias+suffix, resp.StatusCode)
				}
				if got := resp.Header.Values("Location"); len(got) != 1 || got[0] != row.target+suffix {
					t.Errorf("%s %s Location = %q, want %q", method, row.alias+suffix, got, row.target+suffix)
				}
			}
		}
	}

	t.Run("the Location does not depend on request headers", func(t *testing.T) {
		resp := rawRequest(t, env, "GET", "/v2/oauth2/clients/"+id+"/",
			"X-Forwarded-Host: evil.example", "X-Forwarded-Proto: http", "X-Forwarded-Prefix: /evil", "Forwarded: host=evil.example", "Referer: https://evil.example/")
		if got := resp.Header.Get("Location"); resp.StatusCode != http.StatusTemporaryRedirect || got != "/v2/apps/"+id+"/" {
			t.Fatalf("status = %d, Location = %q, want 307 to /v2/apps/%s/", resp.StatusCode, got, id)
		}
	})

	t.Run("OPTIONS is answered like on any other path", func(t *testing.T) {
		preflight := []string{"Origin: https://accounts.example.com", "Access-Control-Request-Method: POST", "Access-Control-Request-Headers: authorization, content-type"}
		for _, headers := range [][]string{preflight, nil} {
			want := rawRequest(t, env, "OPTIONS", "/v2/apps/"+id+"/oauth2/secrets/", headers...)
			for _, alias := range []string{"/v2/oauth2/clients", "/v2/oauth2/clients/", "/v2/oauth2/clients/" + id + "/secrets/", "/v2/oauth2/clients/" + id + "/auth/" + query} {
				got := rawRequest(t, env, "OPTIONS", alias, headers...)
				if got.StatusCode != want.StatusCode || got.Header.Get("Location") != "" {
					t.Errorf("OPTIONS %s (preflight=%t) status = %d, Location = %q, want %d and no Location", alias, headers != nil, got.StatusCode, got.Header.Get("Location"), want.StatusCode)
				}
				for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
					if got.Header.Get(header) != want.Header.Get(header) {
						t.Errorf("OPTIONS %s %s = %q, want %q", alias, header, got.Header.Get(header), want.Header.Get(header))
					}
				}
			}
		}
		if got := rawRequest(t, env, "OPTIONS", "/v2/oauth2/clients/", preflight...); got.StatusCode != http.StatusNoContent || got.Header.Get("Access-Control-Allow-Origin") == "" {
			t.Fatalf("preflight status = %d, Access-Control-Allow-Origin = %q, want 204 with the header", got.StatusCode, got.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("a crafted path does not leave /v2/apps", func(t *testing.T) {
		for _, target := range []string{
			"//evil.example/v2/oauth2/clients",
			"//evil.example/v2/oauth2/clients/",
			"/v2/oauth2/clients//evil.example",
			"/v2/oauth2/clients//evil.example/",
			"/v2/oauth2/clients/" + id + "//evil.example",
			`/v2/oauth2/clients/\evil.example`,
			`/v2/oauth2/clients/\\evil.example`,
			`/v2/oauth2/clients\evil.example`,
			`/v2/oauth2/clients/` + id + `/\evil.example`,
			"/v2/oauth2/clients/%2F%2Fevil.example",
			"/v2/oauth2/clients/%2f%2fevil.example",
			"/v2/oauth2/clients/%5Cevil.example",
			"/v2/oauth2/clients/" + id + "%2Fsecrets",
			"/v2/oauth2/clients/..",
			"/v2/oauth2/clients/../",
			"/v2/oauth2/clients/../../evil",
			"/v2/oauth2/clients/" + id + "/../../../../evil.example",
			"/v2/oauth2/clients/./" + id,
			"/v2/oauth2/clients/" + id + "/.",
			"/v2/oauth2/clients/..%2F..%2Fevil.example",
			"/v2/oauth2/clients/%2E%2E/%2E%2E/evil.example",
			"/v2/oauth2/clients/.%2E/evil.example",
			"/v2/oauth2/clients/%0d%0aLocation:%20https://evil.example",
			"/v2/oauth2/clients/" + id + "%0d%0aSet-Cookie:%20a=b",
			"/v2/oauth2/clients/" + id + "\rLocation:https://evil.example",
			"/v2/oauth2/clients/https://evil.example",
			"/v2/oauth2/clients/https:%2F%2Fevil.example",
			"/v2/oauth2/clients/@evil.example",
			"/v2/oauth2/clients/user:pass@evil.example",
			"/v2/oauth2/clients/" + id + ";evil",
			"/v2/oauth2/clients/a%20b",
			"/v2/oauth2/clients/%00",
			"/v2/oauth2/clientsevil.example",
			"/v2/oauth2/clients.evil.example/",
		} {
			resp := rawRequest(t, env, "GET", target)
			if location := resp.Header.Values("Location"); len(location) != 0 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
				t.Errorf("GET %q status = %d, Location = %q, want no redirect", target, resp.StatusCode, location)
			}
		}

		// Whatever the query holds, the path of the Location is fixed.
		for _, hostile := range []string{"?//evil.example", "?/../../evil", "?\\evil.example", "?https://evil.example/%0d%0aLocation:%20x", "??"} {
			resp := rawRequest(t, env, "GET", "/v2/oauth2/clients/"+id+hostile)
			if got := resp.Header.Values("Location"); resp.StatusCode != http.StatusTemporaryRedirect || len(got) != 1 || got[0] != "/v2/apps/"+id+hostile {
				t.Errorf("GET alias with query %q status = %d, Location = %q, want 307 to %q", hostile, resp.StatusCode, got, "/v2/apps/"+id+hostile)
			}
		}
	})
}

func TestApplicationAliasesCarryTheRequestThrough(t *testing.T) {
	f := newApplicationFixture(t)

	// follow sends the request to the alias and repeats it at the Location, as a client following a 307 does.
	follow := func(t *testing.T, want int, method string, alias string, body any, headers map[string]string, target any) {
		t.Helper()

		resp := mustJSONRequest(t, f.env.server, method, alias, body, headers)
		resp.Body.Close()
		location := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusTemporaryRedirect || !strings.HasPrefix(location, "/v2/apps") {
			t.Fatalf("%s %s status = %d, Location = %q, want 307 into /v2/apps", method, alias, resp.StatusCode, location)
		}
		f.must(t, want, method, location, body, headers, target)
	}

	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	follow(t, http.StatusCreated, http.MethodPost, "/v2/oauth2/clients/?user_id="+f.ownerID, map[string]any{
		"name":         "Created Through The Alias",
		"redirectURIs": []string{"https://alias.example.com/callback"},
		"privacy":      "https://alias.example.com/privacy",
		"terms":        "https://alias.example.com/terms",
	}, f.owner, &created)
	if created.ID == "" || created.Name != "Created Through The Alias" {
		t.Fatalf("created = %#v, want the posted application", created)
	}
	alias := "/v2/oauth2/clients/" + created.ID
	base := "/v2/apps/" + created.ID

	follow(t, http.StatusOK, http.MethodPut, alias+"/", map[string]any{"name": "Renamed Through The Alias"}, f.owner, nil)
	f.must(t, http.StatusOK, http.MethodGet, base+"/", nil, f.owner, &created)
	if created.Name != "Renamed Through The Alias" {
		t.Fatalf("name = %q, want the name put through the alias", created.Name)
	}

	follow(t, http.StatusOK, http.MethodPost, alias+"/redirectUris/?user_id="+f.ownerID, map[string]any{"redirect_uri": "https://alias.example.com/second"}, f.owner, nil)
	var redirectURIs []struct {
		ID          string `json:"id"`
		RedirectURI string `json:"redirect_uri"`
	}
	follow(t, http.StatusOK, http.MethodGet, alias+"/redirectUris/?user_id="+f.ownerID, nil, f.owner, &redirectURIs)
	if len(redirectURIs) != 2 {
		t.Fatalf("redirect URIs = %#v, want the created one and the posted one", redirectURIs)
	}
	follow(t, http.StatusOK, http.MethodDelete, fmt.Sprintf("%s/redirectUris/?user_id=%s&redirectUriId=%s", alias, f.ownerID, redirectURIs[0].ID), nil, f.owner, nil)
	f.must(t, http.StatusOK, http.MethodGet, base+"/oauth2/redirect_uris/?user_id="+f.ownerID, nil, f.owner, &redirectURIs)
	if len(redirectURIs) != 1 {
		t.Fatalf("redirect URIs after the delete = %#v, want one", redirectURIs)
	}

	var secret struct {
		ID    string `json:"id"`
		Notes string `json:"notes"`
	}
	follow(t, http.StatusOK, http.MethodPost, alias+"/secrets/?user_id="+f.ownerID, map[string]any{"notes": "through the alias"}, f.owner, &secret)
	if secret.ID == "" || secret.Notes != "through the alias" {
		t.Fatalf("secret = %#v, want the posted notes", secret)
	}
	follow(t, http.StatusOK, http.MethodDelete, fmt.Sprintf("%s/secrets/?user_id=%s&secret_id=%s", alias, f.ownerID, secret.ID), nil, f.owner, nil)

	var limit struct {
		Limited bool `json:"limited"`
	}
	follow(t, http.StatusOK, http.MethodPut, alias+"/permissions/", map[string]any{"limited": false, "permissionIds": []string{}}, adminHeaders(), &limit)
	if limit.Limited {
		t.Fatal("the limit put through the alias was not applied")
	}

	// The alias itself decides nothing: the target still refuses another user.
	follow(t, http.StatusUnauthorized, http.MethodDelete, alias+"/", nil, f.other, nil)
	follow(t, http.StatusOK, http.MethodDelete, alias+"/", nil, f.owner, nil)
	f.must(t, http.StatusNotFound, http.MethodGet, base+"/", nil, f.owner, nil)
}
