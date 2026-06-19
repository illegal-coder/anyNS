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
	"time"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/httpapi"
	"github.com/anyns/anyns/internal/powerdns"
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
	if got := response.Features["powerdns_authoritative"]; !got.Available || !got.Read || !got.Write || got.Mode != "readwrite" {
		t.Fatalf("authoritative capability=%+v", got)
	}
	if got := response.Features["powerdns_recursor"]; got.Available || !got.Read || got.Write || got.Mode != "unavailable" {
		t.Fatalf("recursor capability=%+v", got)
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
		{
			name:            "powerdns",
			token:           "powerdns-secret",
			visibleFeatures: []string{"powerdns", "powerdns_authoritative", "powerdns_recursor"},
		},
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

func TestCapabilitiesSeparatePowerDNSBackendAvailability(t *testing.T) {
	tests := []struct {
		name                  string
		authoritativeURL      string
		recursorURL           string
		authoritativeMode     string
		authoritativeWritable bool
		recursorMode          string
		recursorWritable      bool
	}{
		{
			name:                  "authoritative only",
			authoritativeURL:      "http://authoritative.internal",
			authoritativeMode:     "readwrite",
			authoritativeWritable: true,
			recursorMode:          "unavailable",
		},
		{
			name:              "recursor only",
			recursorURL:       "http://recursor.internal",
			authoritativeMode: "unavailable",
			recursorMode:      "readwrite",
			recursorWritable:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.PowerDNS.AuthoritativeURL = tt.authoritativeURL
			cfg.PowerDNS.RecursorURL = tt.recursorURL
			application, err := app.NewFromConfig(cfg)
			if err != nil {
				t.Fatalf("new app: %v", err)
			}
			mux := http.NewServeMux()
			Register(mux, application, &cfg)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var response CapabilitiesResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode capabilities: %v", err)
			}
			if got := response.Features["powerdns_authoritative"]; got.Mode != tt.authoritativeMode || got.Write != tt.authoritativeWritable {
				t.Fatalf("authoritative capability=%+v", got)
			}
			if got := response.Features["powerdns_recursor"]; got.Mode != tt.recursorMode || got.Write != tt.recursorWritable {
				t.Fatalf("recursor capability=%+v", got)
			}
		})
	}
}

func TestPrivateCACertificateOrderUsesLocalIssuer(t *testing.T) {
	cfg := config.Default()
	cfg.Certificates.Enabled = true
	cfg.Certificates.IssuerMode = "private-ca"
	cfg.Certificates.StorageDir = t.TempDir()
	cfg.Certificates.MaxAttempts = 1
	cfg.Certificates.RequestTimeout = 5 * time.Second
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	rec := httptest.NewRecorder()
	body := `{"domains":["example.test"],"idempotency_key":"private-ca-order"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/certificates/orders", strings.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var job struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if job.ID == "" {
		t.Fatal("empty job id")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/certificates/orders/"+job.ID, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var current struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &current); err != nil {
			t.Fatalf("decode current job: %v", err)
		}
		if current.Status == "issued" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/certificates/orders/"+job.ID+"/certificate", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("certificate endpoint returned private key material: %s", rec.Body.String())
	}
	if count := strings.Count(rec.Body.String(), "BEGIN CERTIFICATE"); count != 2 {
		t.Fatalf("certificate chain count=%d body=%s", count, rec.Body.String())
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

func TestCreateUnicodeHNSZoneThroughAdminAPI(t *testing.T) {
	var created map[string]any
	var patched powerdns.PatchZoneRequest
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatalf("decode create request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(powerdns.Zone{ID: "xn--5nx.", Name: "xn--5nx.", Kind: "Native"})
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatalf("decode patch request: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
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

	body := `{"name":"灵","kind":"Native","hns":true,"glue_ipv4":"192.0.2.53","soa":{"ttl":600}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/powerdns/authoritative/zones", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if created["name"] != "xn--5nx." || strings.Contains(rec.Body.String(), `"name":"灵."`) {
		t.Fatalf("created=%#v response=%s", created, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"unicode_name":"灵."`) || len(patched.RRSets) != 3 {
		t.Fatalf("patched=%#v response=%s", patched, rec.Body.String())
	}
}

func TestPowerDNSZoneDetailAndRRSetPatch(t *testing.T) {
	var patched powerdns.PatchZoneRequest
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "pdns-secret" {
			t.Fatalf("PowerDNS key not forwarded")
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(powerdns.Zone{
				ID:   "example.",
				Name: "example.",
				RRSets: []powerdns.RRSet{{
					Name:    "www.example.",
					Type:    "A",
					TTL:     300,
					Records: []powerdns.Record{{Content: "192.0.2.10"}},
				}},
			})
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatalf("decode patch: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/powerdns/authoritative/zones/example.", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "www.example.") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	body := `{"rrsets":[{"name":"wallet.example","type":"TXT","ttl":300,"changetype":"REPLACE","records":[{"content":"\"wallet=0x1234\"","disabled":false}]}]}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/powerdns/authoritative/zones/example./rrsets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(patched.RRSets) != 1 || patched.RRSets[0].Name != "wallet.example." {
		t.Fatalf("patched=%#v", patched)
	}
}

func TestPowerDNSSOAUpdateThroughAdminAPI(t *testing.T) {
	var patched powerdns.PatchZoneRequest
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "pdns-secret" {
			t.Fatalf("PowerDNS key not forwarded")
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(powerdns.Zone{
				ID:   "example.",
				Name: "example.",
				RRSets: []powerdns.RRSet{{
					Name: "example.",
					Type: "SOA",
					TTL:  300,
					Records: []powerdns.Record{{
						Content: "ns1.example. hostmaster.example. 9 3600 600 86400 300",
					}},
				}},
			})
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatalf("decode patch: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
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

	body := `{"refresh":7200,"retry":900}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/powerdns/authoritative/zones/example./soa", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response powerdns.SOARecord
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Serial != 10 || response.Refresh != 7200 || response.Retry != 900 {
		t.Fatalf("soa response=%#v", response)
	}
	if len(patched.RRSets) != 1 ||
		patched.RRSets[0].Type != "SOA" ||
		patched.RRSets[0].Records[0].Content != "ns1.example. hostmaster.example. 10 7200 900 86400 300" {
		t.Fatalf("patched=%#v", patched)
	}
}

func TestAuthoritativeZonesListsZones(t *testing.T) {
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/servers/localhost/zones" {
			t.Fatalf("unexpected PowerDNS request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]powerdns.Zone{{ID: "example.", Name: "example.", Kind: "Native"}})
	}))
	defer pdns.Close()

	cfg := config.Default()
	cfg.PowerDNS.AuthoritativeURL = pdns.URL
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	Register(mux, application, &cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/powerdns/authoritative/zones", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"example."`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
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
