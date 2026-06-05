package main

import (
	"context"
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
	"github.com/anyns/anyns/internal/dnslog"
	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/security"
)

func TestPoliciesReloadAppliesConfigToProcessState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "anyns.json")
	if err := os.WriteFile(configPath, []byte(`{
		"routes": [{
			"name": "ens-reloaded",
			"suffixes": [".eth"],
			"client_views": ["default"],
			"tenants": ["default"],
			"plugin": "ens",
			"priority": 200,
			"fallback": "nxdomain"
		}],
		"plugins": [
			{"name": "hns", "enabled": true},
			{"name": "ens", "enabled": true}
		],
		"security": {
			"enabled": false
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := config.Default()
	cfg.ConfigFile = configPath
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reload", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Status string          `json:"status"`
		Routes []plugins.Route `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "loaded" || len(response.Routes) != 1 || response.Routes[0].Name != "ens-reloaded" {
		t.Fatalf("reload response = %#v", response)
	}

	result, route, err := application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "vitalik.eth",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err == nil {
		t.Fatalf("expected enabled ENS skeleton to fail closed without backend")
	}
	if route.Name != "ens-reloaded" || result.SourcePlugin != "ens" || result.RCode != plugins.RCodeServFail {
		t.Fatalf("resolve after reload route=%#v result=%#v err=%v", route, result, err)
	}

	finding := application.Security.AnalyzeQuery(plugins.ResolveRequest{
		QName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
		QType: "TXT",
	})
	if finding.Rule != "security-disabled" || finding.Action != security.ActionAllow {
		t.Fatalf("security policy was not reloaded: %#v", finding)
	}

	events := application.DNSLog.List(0)
	if len(events) != 1 {
		t.Fatalf("audit events = %#v", events)
	}
	event := events[0]
	if event.SourcePlugin != "management" ||
		event.Action != "management_mutation" ||
		event.MatchedRule != "policy.reload" ||
		event.RawRR["config_file"] != configPath {
		t.Fatalf("unexpected reload audit event: %#v", event)
	}
}

func TestPoliciesReloadRequiresConfigFile(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reload", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reload without config status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPoliciesReloadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "invalid-anyns.json")
	if err := os.WriteFile(configPath, []byte(`{
		"routes": [{
			"name": "broken-route",
			"suffixes": [".eth"],
			"plugin": "missing-plugin",
			"priority": 200,
			"fallback": "nxdomain"
		}],
		"plugins": [
			{"name": "hns", "enabled": true}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := config.Default()
	cfg.ConfigFile = configPath
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reload", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("reload invalid config status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing-plugin") {
		t.Fatalf("reload invalid config body = %s", rec.Body.String())
	}
	if events := application.DNSLog.List(0); len(events) != 0 {
		t.Fatalf("invalid reload should not write management audit: %#v", events)
	}
}

func TestPoliciesReloadUpdatesControlPlaneConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "anyns.json")
	if err := os.WriteFile(configPath, []byte(`{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "reader", "api_key": "read-secret", "scopes": ["read"]}
			]
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := config.Default()
	cfg.ConfigFile = configPath
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reload", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated plugins status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	req.Header.Set("Authorization", "Bearer read-secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated plugins status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuditSummaryEndpointAggregatesDNSLog(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	application.DNSLog.Append(dnslog.Event{ClientIP: "192.0.2.10", QName: "one.hns.", RiskLevel: "none", Action: "allow", MatchedRule: "hns-default", SourcePlugin: "hns"})
	application.DNSLog.Append(dnslog.Event{ClientIP: "192.0.2.10", QName: "blocked.example.", RiskLevel: "high", Action: "block", MatchedRule: "dga-high-entropy", SourcePlugin: "security"})
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/summary?top_n=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d body=%s", rec.Code, rec.Body.String())
	}
	var summary dnslog.Summary
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summary.Total != 2 || summary.ByAction["block"] != 1 || summary.ByRule["dga-high-entropy"] != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if len(summary.TopClients) != 1 || summary.TopClients[0].Value != "192.0.2.10" || summary.TopClients[0].Count != 2 {
		t.Fatalf("unexpected top clients: %#v", summary.TopClients)
	}
}

func TestAuditEventsEndpointHonorsLimit(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	application.DNSLog.Append(dnslog.Event{TraceID: "first", QName: "one.hns.", Action: "allow", SourcePlugin: "hns"})
	application.DNSLog.Append(dnslog.Event{TraceID: "second", QName: "two.hns.", Action: "allow", SourcePlugin: "hns"})
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?limit=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit events status = %d body=%s", rec.Code, rec.Body.String())
	}
	var events []dnslog.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(events) != 1 || events[0].TraceID != "second" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestAuditEventsEndpointHonorsExplicitOrder(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	application.DNSLog.Append(dnslog.Event{TraceID: "first", QName: "one.hns.", Action: "allow", SourcePlugin: "hns"})
	application.DNSLog.Append(dnslog.Event{TraceID: "second", QName: "two.hns.", Action: "allow", SourcePlugin: "hns"})
	application.DNSLog.Append(dnslog.Event{TraceID: "third", QName: "three.hns.", Action: "allow", SourcePlugin: "hns"})
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?limit=2&order=desc", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit events status = %d body=%s", rec.Code, rec.Body.String())
	}
	var events []dnslog.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(events) != 2 || events[0].TraceID != "third" || events[1].TraceID != "second" {
		t.Fatalf("descending audit events = %#v", events)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?limit=2&order=asc", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit events status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(events) != 2 || events[0].TraceID != "first" || events[1].TraceID != "second" {
		t.Fatalf("ascending audit events = %#v", events)
	}
}

func TestAuditEventsEndpointFiltersEvents(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	base := time.Date(2026, 6, 5, 1, 0, 0, 0, time.UTC)
	application.DNSLog.Append(dnslog.Event{Timestamp: base, TraceID: "hns-allow", ClientIP: "192.0.2.10", ClientView: "default", Tenant: "default", QName: "one.hns.", QType: "A", RCode: "NOERROR", Action: "allow", RiskLevel: "none", SourcePlugin: "hns"})
	application.DNSLog.Append(dnslog.Event{Timestamp: base.Add(time.Minute), TraceID: "security-block", ClientIP: "192.0.2.11", ClientView: "adguard", Tenant: "prod", QName: "two.hns.", QType: "TXT", RCode: "SERVFAIL", Action: "block", RiskLevel: "high", SourcePlugin: "security", MatchedRule: "dns-tunnel-high-entropy"})
	application.DNSLog.Append(dnslog.Event{Timestamp: base.Add(2 * time.Minute), TraceID: "security-log", ClientIP: "192.0.2.12", ClientView: "default", Tenant: "prod", QName: "three.hns.", QType: "AAAA", RCode: "NOERROR", Action: "log_only", RiskLevel: "medium", SourcePlugin: "security", MatchedRule: "dga-high-entropy"})
	mux := newAdminMux(application, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?trace_id=security-block&client_ip=192.0.2.11&client_view=adguard&tenant=prod&qname=two.hns.&qtype=TXT&source_plugin=security&risk_level=high&action=block&matched_rule=dns-tunnel-high-entropy&rcode=SERVFAIL&since="+base.Add(time.Minute).Format(time.RFC3339)+"&until="+base.Add(time.Minute).Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit events status = %d body=%s", rec.Code, rec.Body.String())
	}
	var events []dnslog.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	if len(events) != 1 || events[0].TraceID != "security-block" {
		t.Fatalf("filtered audit events = %#v", events)
	}
}
