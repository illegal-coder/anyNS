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
	"github.com/anyns/anyns/internal/httpapi"
)

func TestCapabilitiesDescribeAvailabilityAndWritableState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"plugins":[{"name":"hns","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.PowerDNS.AuthoritativeURL = "http://pdns.internal"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response CapabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if response.Version != 1 {
		t.Fatalf("version=%d", response.Version)
	}
	if got := response.Features["powerdns"]; !got.Available || !got.Read || !got.Write || got.Mode != "readwrite" {
		t.Fatalf("powerdns capability=%+v", got)
	}
	if got := response.Features["config"]; !got.Read || !got.Write || got.Mode != "readwrite" {
		t.Fatalf("config capability=%+v", got)
	}
	if strings.Contains(rec.Body.String(), "api_key") {
		t.Fatalf("capabilities exposed secret-shaped fields: %s", rec.Body.String())
	}
}

func TestCapabilitiesRespectScopedReadOnlyPrincipal(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{{
		ID:     "observer",
		APIKey: "observer-secret",
		Scopes: []string{httpapi.ScopeManagementRead, httpapi.ScopePowerDNSRead, httpapi.ScopeAuditRead},
	}}
	cfg.PowerDNS.RecursorURL = "http://recursor.internal"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer observer-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response CapabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if got := response.Features["powerdns"]; !got.Read || got.Write || got.Mode != "readonly" {
		t.Fatalf("powerdns capability=%+v", got)
	}
	if got := response.Features["plugins"]; got.Read || got.Mode != "hidden" {
		t.Fatalf("plugins capability=%+v", got)
	}
	if strings.Contains(rec.Body.String(), "observer-secret") {
		t.Fatalf("capabilities leaked bearer token: %s", rec.Body.String())
	}
}

func TestCapabilitiesFollowFineGrainedEndpointReadScopes(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.PowerDNS.AuthoritativeURL = "http://pdns.internal"
	cfg.Management.Keys = []config.ManagementKey{
		{ID: "powerdns-reader", APIKey: "powerdns-secret", Scopes: []string{httpapi.ScopePowerDNSRead}},
		{ID: "plugin-reader", APIKey: "plugin-secret", Scopes: []string{httpapi.ScopePluginsRead}},
		{ID: "audit-reader", APIKey: "audit-secret", Scopes: []string{httpapi.ScopeAuditRead}},
		{ID: "config-reader", APIKey: "config-secret", Scopes: []string{httpapi.ScopeConfigRead}},
		{ID: "cache-reader", APIKey: "cache-secret", Scopes: []string{httpapi.ScopeCacheRead}},
	}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	tests := []struct {
		name            string
		token           string
		visibleFeatures []string
	}{
		{name: "powerdns", token: "powerdns-secret", visibleFeatures: []string{"powerdns"}},
		{name: "plugins", token: "plugin-secret", visibleFeatures: []string{"plugins"}},
		{name: "audit", token: "audit-secret", visibleFeatures: []string{"audit"}},
		{name: "configuration", token: "config-secret", visibleFeatures: []string{"security", "config"}},
		{name: "cache", token: "cache-secret", visibleFeatures: []string{"cache"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var response CapabilitiesResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode capabilities: %v", err)
			}
			visible := make(map[string]bool, len(tt.visibleFeatures))
			for _, feature := range tt.visibleFeatures {
				visible[feature] = true
			}
			for feature, capability := range response.Features {
				if visible[feature] {
					if !capability.Read || capability.Mode == "hidden" {
						t.Errorf("%s capability=%+v", feature, capability)
					}
					continue
				}
				if capability.Read || capability.Write || capability.Mode != "hidden" {
					t.Errorf("unrelated %s capability=%+v", feature, capability)
				}
			}
		})
	}
}

func TestCapabilitiesRequireAuthentication(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardOmitsDataOutsidePrincipalScopes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"plugins":[{"name":"hns","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{{
		ID:     "overview-only",
		APIKey: "overview-secret",
		Scopes: []string{httpapi.ScopeManagementRead},
	}}
	cfg.PowerDNS.AuthoritativeURL = "http://pdns.internal"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	application.AppendManagementAudit("config.update", "operator", http.MethodPut, "/api/v1/configuration", "ok", nil)
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	req.Header.Set("Authorization", "Bearer overview-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Services map[string]json.RawMessage `json:"services"`
		Plugins  json.RawMessage            `json:"plugins"`
		Cache    json.RawMessage            `json:"cache"`
		Audit    json.RawMessage            `json:"audit_summary"`
		Events   json.RawMessage            `json:"recent_events"`
		Config   json.RawMessage            `json:"configuration"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if _, ok := response.Services["powerdns"]; ok {
		t.Fatalf("dashboard exposed PowerDNS data: %s", rec.Body.String())
	}
	for name, value := range map[string]json.RawMessage{
		"plugins":       response.Plugins,
		"cache":         response.Cache,
		"audit_summary": response.Audit,
		"recent_events": response.Events,
		"configuration": response.Config,
	} {
		if len(value) != 0 {
			t.Fatalf("dashboard exposed %s outside principal scope: %s", name, rec.Body.String())
		}
	}
}

func TestDashboardUsesRuntimePluginViewsWhenProxyEnabled(t *testing.T) {
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/plugins":
			if r.Header.Get("Authorization") != "Bearer runtime-reader" {
				t.Fatalf("authorization was not forwarded")
			}
			_, _ = w.Write([]byte(`[{"name":"hns","enabled":false,"suffixes":[".hns"],"healthy":true}]`))
		default:
			t.Fatalf("runtime path=%s", r.URL.Path)
		}
	}))
	defer runtime.Close()

	cfg := config.Default()
	cfg.ControlPlane.AdminProxyRuntime = true
	cfg.ControlPlane.RuntimeControlURL = runtime.URL
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{{
		ID:     "reader",
		APIKey: "runtime-reader",
		Scopes: []string{httpapi.ScopeManagementRead, httpapi.ScopePluginsRead},
	}}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	req.Header.Set("Authorization", "Bearer runtime-reader")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Plugins []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if len(response.Plugins) != 1 || response.Plugins[0].Name != "hns" || response.Plugins[0].Enabled {
		t.Fatalf("plugins=%+v", response.Plugins)
	}
}
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
