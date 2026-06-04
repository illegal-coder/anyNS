package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/plugins"
)

func TestRuntimePluginMutationControlsLiveRegistry(t *testing.T) {
	application, mux := newTestMux(t, ScopeRuntime)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/hns/disable", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status = %d body=%s", rec.Code, rec.Body.String())
	}

	_, _, err := application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err != plugins.ErrPluginDisabled {
		t.Fatalf("resolve err = %v, want ErrPluginDisabled", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/plugins/hns/enable", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, _, err := application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	}); err != nil {
		t.Fatalf("resolve after enable: %v", err)
	}
}

func TestCacheFlushEndpointClearsLiveRegistryCache(t *testing.T) {
	application, mux := newTestMux(t, ScopeRuntime)
	req := plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	}
	if _, _, err := application.Registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	if stats := application.Registry.CacheStats(); stats["hns"] != 1 {
		t.Fatalf("cache stats before flush = %#v", stats)
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("flush status = %d body=%s", rec.Code, rec.Body.String())
	}
	if stats := application.Registry.CacheStats(); stats["hns"] != 0 {
		t.Fatalf("cache stats after flush = %#v", stats)
	}
}

func TestBoundaryDocumentsRuntimeLiveControls(t *testing.T) {
	_, mux := newTestMux(t, ScopeRuntime)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/boundary", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("boundary status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Scope        string   `json:"scope"`
		Mode         string   `json:"mode"`
		LiveControls []string `json:"live_controls"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode boundary: %v", err)
	}
	if body.Scope != string(ScopeRuntime) || body.Mode != "runtime-local-control-plane" {
		t.Fatalf("unexpected boundary: %#v", body)
	}
	if len(body.LiveControls) == 0 {
		t.Fatalf("runtime boundary should list live controls: %#v", body)
	}
}

func TestAdminControlCanProxyToRuntime(t *testing.T) {
	cfg := config.Default()
	cfg.ControlPlane.AdminProxyRuntime = true
	cfg.ControlPlane.RuntimeControlURL = "http://runtime.internal"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	oldClient := runtimeProxyClient
	t.Cleanup(func() { runtimeProxyClient = oldClient })
	runtimeProxyClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://runtime.internal/api/v1/plugins/hns/disable" {
			t.Fatalf("proxied url = %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"name":"hns","enabled":false}`)),
		}, nil
	})}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeAdmin)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/hns/disable", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode proxy body: %v", err)
	}
	if body.Name != "hns" || body.Enabled {
		t.Fatalf("unexpected proxy body: %#v", body)
	}
}

func TestBoundaryDocumentsAdminRuntimeProxy(t *testing.T) {
	cfg := config.Default()
	cfg.ControlPlane.AdminProxyRuntime = true
	cfg.ControlPlane.RuntimeControlURL = "http://runtime.internal"
	body := Boundary(ScopeAdmin, cfg)
	if body["mode"] != "admin-runtime-proxy" {
		t.Fatalf("boundary mode = %#v", body)
	}
	controls, ok := body["live_controls"].([]string)
	if !ok || len(controls) == 0 {
		t.Fatalf("boundary controls = %#v", body["live_controls"])
	}
}

func TestControlPlaneRequiresBearerTokenWhenConfigured(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.APIKey = "admin-secret"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeRuntime)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestControlPlaneScopesSeparateReadAndWrite(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{
		{ID: "reader", APIKey: "read-secret", Scopes: []string{"read"}},
		{ID: "writer", APIKey: "write-secret", Scopes: []string{"read", "write"}},
	}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeRuntime)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer read-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("read status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
	req.Header.Set("Authorization", "Bearer read-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read key write status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
	req.Header.Set("Authorization", "Bearer write-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write key status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestControlPlaneHonorsFineGrainedScopes(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{
		{ID: "plugin-reader", APIKey: "plugin-read-secret", Scopes: []string{"plugins:read"}},
		{ID: "plugin-writer", APIKey: "plugin-write-secret", Scopes: []string{"plugins:write"}},
		{ID: "cache-writer", APIKey: "cache-write-secret", Scopes: []string{"cache:write"}},
		{ID: "management-reader", APIKey: "management-read-secret", Scopes: []string{"management:read"}},
	}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeRuntime)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer plugin-read-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin read status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/plugins/hns/disable", nil)
	req.Header.Set("Authorization", "Bearer plugin-read-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plugin read mutation status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/plugins/hns/disable", nil)
	req.Header.Set("Authorization", "Bearer plugin-write-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin write status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
	req.Header.Set("Authorization", "Bearer plugin-write-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plugin writer cache status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", nil)
	req.Header.Set("Authorization", "Bearer cache-write-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cache write status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/management/keys", nil)
	req.Header.Set("Authorization", "Bearer management-read-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("management read status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestControlPlaneWritesManagementAuditForMutation(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{
		{ID: "writer", APIKey: "write-secret", Scopes: []string{"read", "write"}},
	}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeRuntime)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/hns/disable", nil)
	req.Header.Set("Authorization", "Bearer write-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status = %d body=%s", rec.Code, rec.Body.String())
	}

	events := application.DNSLog.List(0)
	if len(events) != 1 {
		t.Fatalf("audit events = %#v", events)
	}
	event := events[0]
	if event.SourcePlugin != "management" ||
		event.Action != "management_mutation" ||
		event.MatchedRule != "plugin.disable" ||
		event.RawRR["principal_id"] != "writer" ||
		event.RawRR["plugin"] != "hns" {
		t.Fatalf("unexpected management audit event: %#v", event)
	}
}

func TestControlPlaneProxyForwardsAuthorizationHeader(t *testing.T) {
	cfg := config.Default()
	cfg.ControlPlane.AdminProxyRuntime = true
	cfg.ControlPlane.RuntimeControlURL = "http://runtime.internal"
	cfg.Management.AuthRequired = true
	cfg.Management.APIKey = "admin-secret"
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	oldClient := runtimeProxyClient
	t.Cleanup(func() { runtimeProxyClient = oldClient })
	runtimeProxyClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer admin-secret" {
			t.Fatalf("authorization header was not proxied: %#v", req.Header)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`[]`)),
		}, nil
	})}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestManagementKeysEndpointReportsRotationStatusWithoutSecrets(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.APIKey = "legacy-secret"
	cfg.Management.Roles = []config.ManagementRole{
		{ID: "ops-reader", Scopes: []string{"plugins:read", "audit:read"}},
		{ID: "ops-writer", Scopes: []string{"plugins:write", "cache:write"}},
	}
	cfg.Management.Keys = []config.ManagementKey{
		{
			ID:        "expired",
			APIKey:    "expired-secret",
			Roles:     []string{"ops-reader"},
			ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339),
		},
		{
			ID:        "future",
			APIKey:    "future-secret",
			Roles:     []string{"ops-reader"},
			NotBefore: now.Add(time.Hour).Format(time.RFC3339),
		},
		{
			ID:        "revoked",
			APIKey:    "revoked-secret",
			Roles:     []string{"ops-reader"},
			RevokedAt: now.Add(-time.Minute).Format(time.RFC3339),
		},
		{
			ID:        "active",
			APIKey:    "active-secret",
			Scopes:    []string{"management:read"},
			Roles:     []string{"ops-reader", "ops-writer"},
			NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
			AllowedClientCIDRs: []string{
				"127.0.0.1",
				"10.0.0.0/8",
			},
		},
	}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, ScopeRuntime)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/management/keys", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set("Authorization", "Bearer active-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("management keys status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "active-secret") ||
		strings.Contains(rec.Body.String(), "future-secret") ||
		strings.Contains(rec.Body.String(), "revoked-secret") ||
		strings.Contains(rec.Body.String(), "expired-secret") ||
		strings.Contains(rec.Body.String(), "legacy-secret") ||
		strings.Contains(rec.Body.String(), "10.0.0.0/8") {
		t.Fatalf("management keys response leaked token material: %s", rec.Body.String())
	}

	var body struct {
		AuthRequired         bool                 `json:"auth_required"`
		LegacyKeyConfigured  bool                 `json:"legacy_key_configured"`
		ConfiguredRoleCount  int                  `json:"configured_role_count"`
		ConfiguredKeyCount   int                  `json:"configured_key_count"`
		ActiveKeyCount       int                  `json:"active_key_count"`
		RotationWarningHours int                  `json:"rotation_warning_hours"`
		TokenMaterialExposed bool                 `json:"token_material_exposed"`
		Roles                []ManagementRoleView `json:"roles"`
		Keys                 []ManagementKeyView  `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode management keys: %v", err)
	}
	if !body.AuthRequired || !body.LegacyKeyConfigured || body.ConfiguredRoleCount != 2 || body.ConfiguredKeyCount != 4 || body.ActiveKeyCount != 1 || body.RotationWarningHours != 168 || body.TokenMaterialExposed {
		t.Fatalf("unexpected management key summary: %#v", body)
	}
	if len(body.Roles) != 2 || body.Roles[0].ID != "ops-reader" || len(body.Roles[0].Scopes) != 2 {
		t.Fatalf("role metadata = %#v", body.Roles)
	}
	statuses := map[string]string{}
	for _, key := range body.Keys {
		statuses[key.ID] = key.Status
	}
	if statuses["expired"] != "expired" || statuses["future"] != "not_yet_active" || statuses["revoked"] != "revoked" || statuses["active"] != "active" {
		t.Fatalf("statuses = %#v", statuses)
	}
	var activeKey ManagementKeyView
	for _, key := range body.Keys {
		if key.ID == "active" {
			activeKey = key
			break
		}
	}
	if !activeKey.ClientRestrictionEnabled || activeKey.AllowedClientCIDRCount != 2 {
		t.Fatalf("active key client restriction metadata = %#v", activeKey)
	}
	if !containsString(activeKey.Roles, "ops-reader") ||
		!containsString(activeKey.Scopes, "plugins:write") ||
		!containsString(activeKey.Scopes, "management:read") {
		t.Fatalf("active key role/scope metadata = %#v", activeKey)
	}
	if activeKey.ExpiresInSeconds <= 0 || activeKey.LifecycleAction == "" {
		t.Fatalf("active key lifecycle metadata = %#v", activeKey)
	}
}

func TestManagementKeysEndpointReportsLifecycleActions(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.Management.Roles = []config.ManagementRole{
		{ID: "ops-reader", Scopes: []string{"plugins:read", "audit:read"}},
	}
	cfg.Management.Keys = []config.ManagementKey{
		{
			ID:        "expiring-with-successor",
			APIKey:    "old-secret",
			Roles:     []string{"ops-reader"},
			ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		},
		{
			ID:        "successor",
			APIKey:    "new-secret",
			Roles:     []string{"ops-reader"},
			NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		},
		{
			ID:     "never-expires",
			APIKey: "stable-secret",
			Scopes: []string{"management:read"},
		},
		{
			ID:        "expiring-without-successor",
			APIKey:    "solo-secret",
			Scopes:    []string{"cache:read"},
			ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		},
		{
			ID:        "revoked",
			APIKey:    "revoked-secret",
			Scopes:    []string{"management:read"},
			RevokedAt: now.Add(-time.Hour).Format(time.RFC3339),
		},
	}

	body := ManagementKeys(cfg, now)
	keys, ok := body["keys"].([]ManagementKeyView)
	if !ok {
		t.Fatalf("keys response type = %#v", body["keys"])
	}
	views := map[string]ManagementKeyView{}
	for _, key := range keys {
		views[key.ID] = key
	}

	if got := views["expiring-with-successor"]; !got.HasOverlappingSuccessor || got.RotationDue || got.LifecycleAction != "successor_overlap_ready" {
		t.Fatalf("expiring key with successor = %#v", got)
	}
	if got := views["successor"]; got.RotationDue || got.LifecycleAction != "active" {
		t.Fatalf("successor lifecycle = %#v", got)
	}
	if got := views["never-expires"]; !got.RotationDue || got.LifecycleAction != "set_expiration_window" {
		t.Fatalf("never-expiring key lifecycle = %#v", got)
	}
	if got := views["expiring-without-successor"]; got.HasOverlappingSuccessor || !got.RotationDue || got.LifecycleAction != "schedule_successor_before_expiry" {
		t.Fatalf("expiring key without successor = %#v", got)
	}
	if got := views["revoked"]; got.Status != "revoked" || !got.RotationDue || got.LifecycleAction != "remove_revoked_key" {
		t.Fatalf("revoked key lifecycle = %#v", got)
	}
}

func newTestMux(t *testing.T, scope Scope) (*app.App, *http.ServeMux) {
	t.Helper()
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := http.NewServeMux()
	RegisterHandlers(mux, application, &cfg, scope)
	return application, mux
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
