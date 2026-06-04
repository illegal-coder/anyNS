package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/dnslog"
)

func TestQueryIntBounded(t *testing.T) {
	tests := []struct {
		name string
		path string
		want int
	}{
		{name: "missing uses fallback", path: "/audit", want: 100},
		{name: "valid value", path: "/audit?limit=25", want: 25},
		{name: "invalid uses fallback", path: "/audit?limit=nope", want: 100},
		{name: "below min clamps", path: "/audit?limit=0", want: 1},
		{name: "above max clamps", path: "/audit?limit=5000", want: 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if got := QueryIntBounded(req, "limit", 100, 1, 1000); got != tt.want {
				t.Fatalf("QueryIntBounded() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAuditEventFilterFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit?trace_id=trace-1&client_ip=192.0.2.10&client_view=adguard&tenant=prod&qname=example.hns.&qtype=TXT&source_plugin=security&risk_level=high&action=block&matched_rule=dns-tunnel-high-entropy&rcode=SERVFAIL", nil)

	filter := AuditEventFilterFromQuery(req)
	want := dnslog.EventFilter{
		TraceID:      "trace-1",
		ClientIP:     "192.0.2.10",
		ClientView:   "adguard",
		Tenant:       "prod",
		QName:        "example.hns.",
		QType:        "TXT",
		SourcePlugin: "security",
		RiskLevel:    "high",
		Action:       "block",
		MatchedRule:  "dns-tunnel-high-entropy",
		RCode:        "SERVFAIL",
	}
	if filter != want {
		t.Fatalf("filter = %#v, want %#v", filter, want)
	}
}

func TestPrincipalFromRequestHonorsManagementKeyRotationWindow(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{
		{
			ID:        "expired",
			APIKey:    "expired-secret",
			Scopes:    []string{ScopeRead},
			ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339),
		},
		{
			ID:        "future",
			APIKey:    "future-secret",
			Scopes:    []string{ScopeRead},
			NotBefore: now.Add(time.Hour).Format(time.RFC3339),
		},
		{
			ID:        "revoked",
			APIKey:    "revoked-secret",
			Scopes:    []string{ScopeRead},
			RevokedAt: now.Add(-time.Minute).Format(time.RFC3339),
		},
		{
			ID:        "active",
			APIKey:    "active-secret",
			Scopes:    []string{ScopeRead, ScopeWrite},
			NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		},
	}

	for _, token := range []string{"expired-secret", "future-secret", "revoked-secret"} {
		req, err := http.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if principal, ok := PrincipalFromRequest(req, cfg); ok {
			t.Fatalf("principal for inactive token %q = %#v", token, principal)
		}
	}

	req, err := http.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer active-secret")
	principal, ok := PrincipalFromRequest(req, cfg)
	if !ok {
		t.Fatal("active key was not authorized")
	}
	if principal.ID != "active" || !principal.HasScope(ScopeWrite) {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestPrincipalFromRequestHonorsManagementKeyClientCIDRs(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []config.ManagementKey{
		{
			ID:                 "cidr-bound",
			APIKey:             "bound-secret",
			Scopes:             []string{ScopeRead},
			AllowedClientCIDRs: []string{"198.51.100.0/24", "2001:db8::10"},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = "198.51.100.25:49152"
	req.Header.Set("Authorization", "Bearer bound-secret")
	principal, ok := PrincipalFromRequest(req, cfg)
	if !ok {
		t.Fatal("CIDR-bound key was not authorized for allowed client")
	}
	if principal.ID != "cidr-bound" {
		t.Fatalf("principal = %#v", principal)
	}

	req, err = http.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = "203.0.113.25:49152"
	req.Header.Set("Authorization", "Bearer bound-secret")
	if principal, ok := PrincipalFromRequest(req, cfg); ok {
		t.Fatalf("principal for disallowed client = %#v", principal)
	}

	req, err = http.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = "[2001:db8::10]:49152"
	req.Header.Set("Authorization", "Bearer bound-secret")
	if _, ok := PrincipalFromRequest(req, cfg); !ok {
		t.Fatal("CIDR-bound key was not authorized for allowed IPv6 client")
	}
}

func TestPrincipalHasFineGrainedManagementScopes(t *testing.T) {
	readOnly := Principal{ID: "reader", Scopes: []string{ScopeRead}}
	if !readOnly.HasScope(ScopePluginsRead) || !readOnly.HasScope(ScopeAuditRead) {
		t.Fatalf("coarse read scope did not grant fine read permissions: %#v", readOnly)
	}
	if readOnly.HasScope(ScopePluginsWrite) || readOnly.HasScope(ScopeHoneypotWrite) {
		t.Fatalf("coarse read scope granted write permissions: %#v", readOnly)
	}

	pluginWriter := Principal{ID: "plugin-writer", Scopes: []string{ScopePluginsWrite}}
	if !pluginWriter.HasScope(ScopePluginsWrite) {
		t.Fatalf("fine plugin write scope was not honored: %#v", pluginWriter)
	}
	if pluginWriter.HasScope(ScopeCacheWrite) || pluginWriter.HasScope(ScopePolicyWrite) {
		t.Fatalf("fine plugin write scope leaked into other write permissions: %#v", pluginWriter)
	}

	admin := Principal{ID: "admin", Scopes: []string{"admin"}}
	if !admin.HasScope(ScopeManagementRead) || !admin.HasScope(ScopePolicyWrite) {
		t.Fatalf("admin scope did not grant management permissions: %#v", admin)
	}
}

func TestPrincipalFromRequestExpandsManagementRoles(t *testing.T) {
	cfg := config.Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Roles = []config.ManagementRole{
		{ID: "plugin-operator", Scopes: []string{ScopePluginsRead, ScopePluginsWrite}},
		{ID: "auditor", Scopes: []string{ScopeAuditRead}},
	}
	cfg.Management.Keys = []config.ManagementKey{
		{
			ID:     "ops",
			APIKey: "ops-secret",
			Scopes: []string{ScopeManagementRead},
			Roles:  []string{"plugin-operator", "auditor"},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer ops-secret")
	principal, ok := PrincipalFromRequest(req, cfg)
	if !ok {
		t.Fatal("role-backed key was not authorized")
	}
	for _, scope := range []string{ScopeManagementRead, ScopePluginsRead, ScopePluginsWrite, ScopeAuditRead} {
		if !principal.HasScope(scope) {
			t.Fatalf("principal %#v missing expanded scope %q", principal, scope)
		}
	}
	if principal.HasScope(ScopeHoneypotWrite) {
		t.Fatalf("principal scopes leaked unrelated write access: %#v", principal)
	}
}
