package test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	meiling "github.com/meili-NG/meiliNG/v2"
	"github.com/meili-NG/meiliNG/v2/internal/database"
)

// Reload swaps in an app built from the re-read config behind the running
// listener, and a config that fails to load leaves the running app in place.
func TestReloadSwapsTheAppBehindTheListener(t *testing.T) {
	database.ResetInstance()
	t.Cleanup(database.ResetInstance)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeReloadConfig := func(name string) {
		t.Helper()
		content := fmt.Sprintf(`{
			"instance": {"name": %q},
			"server": {"publicUrl": "https://api.example.com"},
			"database": {"type": "sqlite", "dsn": %q},
			"token": {"jwt": {"privateKeyPath": %q, "publicKeyPath": %q}}
		}`, name, filepath.Join(dir, "db.sqlite"), filepath.Join(dir, "jwt.key"), filepath.Join(dir, "jwt.pub"))
		if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeReloadConfig("Before Reload")

	m, err := meiling.NewFromPath(configPath)
	if err != nil {
		t.Fatalf("NewFromPath: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.SetListener(ln)
	go func() { _ = m.StartServer() }()
	t.Cleanup(func() { _ = m.Shutdown() })

	// The API docs title is fixed when an app is built, so it shows which app
	// serves the request.
	docsTitle := func() string {
		t.Helper()
		var resp *http.Response
		for i := 0; i < 50; i++ {
			if resp, err = http.Get("http://" + ln.Addr().String() + "/openapi.json"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("GET /openapi.json: %v", err)
		}
		defer resp.Body.Close()
		var doc struct {
			Info struct {
				Title string `json:"title"`
			} `json:"info"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode /openapi.json: %v", err)
		}
		return doc.Info.Title
	}

	if got := docsTitle(); got != "Before Reload" {
		t.Fatalf("before reload, title = %q", got)
	}

	writeReloadConfig("After Reload")
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := docsTitle(); got != "After Reload" {
		t.Fatalf("after reload, title = %q, want the new app serving", got)
	}

	if err := os.WriteFile(configPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("Reload of a broken config succeeded")
	}
	if got := docsTitle(); got != "After Reload" {
		t.Fatalf("after a failed reload, title = %q, want the running app kept", got)
	}
}
