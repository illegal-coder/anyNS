package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
)

func TestPowerDNSStatusDoesNotExposeAPIKeys(t *testing.T) {
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "pdns-secret" {
			t.Fatalf("PowerDNS key not forwarded")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/zones"), strings.HasSuffix(r.URL.Path, "/statistics"), strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`[]`))
		default:
			_, _ = w.Write([]byte(`{"id":"localhost","daemon_type":"authoritative","version":"5.0.5"}`))
		}
	}))
	defer pdns.Close()

	cfg := config.Default()
	cfg.PowerDNS.AuthoritativeURL = pdns.URL
	cfg.PowerDNS.AuthoritativeAPIKey = "pdns-secret"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/powerdns/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "pdns-secret") {
		t.Fatalf("response leaked API key: %s", rec.Body.String())
	}
}

func TestConfigurationUpdatePreservesSecretsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	initial := `{
	  "request_timeout": "3s",
	  "plugins": [{"name":"hns","enabled":true,"backend_type":"runtime-json","backend_api_key":"plugin-secret","request_timeout":"3s"}],
	  "routes": [{"name":"hns","suffixes":[".hns"],"plugin":"hns","priority":100,"fallback":"nxdomain"}],
	  "honeypot": {"api_key":"honeypot-secret","hmac_secret":"hmac-secret","failed_queue_max_entries":10,"retry_interval":"30s","max_attempts":3,"request_timeout":"5s"},
	  "powerdns": {"authoritative_url":"http://pdns-auth:8081","authoritative_api_key":"pdns-secret","server_id":"localhost","request_timeout":"5s"}
	}`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	edit := cfg.Editable()
	edit.RequestTimeoutSeconds = 9
	edit.Plugins[0].Enabled = false
	edit.Security.Enabled = false
	body, _ := json.Marshal(edit)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/configuration", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	for _, secret := range []string{"plugin-secret", "honeypot-secret", "hmac-secret", "pdns-secret"} {
		if !bytes.Contains(saved, []byte(secret)) {
			t.Fatalf("saved config lost %s: %s", secret, saved)
		}
	}
	if cfg.RequestTimeout.Seconds() != 9 || cfg.Plugins[0].Enabled {
		t.Fatalf("runtime config was not reloaded: %#v", cfg)
	}
}
