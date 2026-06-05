package main

import (
	"bytes"
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
	"github.com/anyns/anyns/internal/honeypot"
	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/security"
)

func TestResolveEndpointPersistsDNSLogAndQueuesHoneypotFailure(t *testing.T) {
	dir := t.TempDir()
	dnslogPath := filepath.Join(dir, "dnslog.jsonl")
	queuePath := filepath.Join(dir, "honeypot-failed.jsonl")

	cfg := config.Default()
	cfg.DNSLog.Path = dnslogPath
	cfg.Honeypot.URL = "://bad-honeypot-url"
	cfg.Honeypot.FailedQueuePath = queuePath
	cfg.Honeypot.MaxAttempts = 3

	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "4xj9q2z8p1m7n5v3k0c6b4r2t8y9u1i3.hns",
		"qtype": "TXT",
		"context": {
			"trace_id": "runtime-integration-forward",
			"client_ip": "192.0.2.10",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Security security.Finding `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Security.Action != security.ActionForwardToHoneypot {
		t.Fatalf("security action = %#v", response.Security)
	}

	reloadedLog, err := dnslog.NewPersistentStore(10, dnslogPath)
	if err != nil {
		t.Fatalf("reload dnslog: %v", err)
	}
	events := reloadedLog.List(0)
	if len(events) != 1 {
		t.Fatalf("dnslog events = %#v", events)
	}
	if events[0].TraceID != "runtime-integration-forward" ||
		events[0].SourcePlugin != "hns" ||
		events[0].Action != string(security.ActionForwardToHoneypot) ||
		events[0].MatchedRule != "dns-tunnel-high-entropy" {
		t.Fatalf("unexpected dnslog event: %#v", events[0])
	}

	reloadedQueue, err := honeypot.NewFailedQueue(queuePath, 10)
	if err != nil {
		t.Fatalf("reload honeypot queue: %v", err)
	}
	deliveries := reloadedQueue.List(0)
	if len(deliveries) != 1 || len(deliveries[0].Events) != 1 {
		t.Fatalf("failed queue deliveries = %#v", deliveries)
	}
	if deliveries[0].Events[0].TraceID != "runtime-integration-forward" || deliveries[0].Attempts != 1 {
		t.Fatalf("unexpected failed delivery: %#v", deliveries[0])
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	mux.ServeHTTP(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d body=%s", metricsRec.Code, metricsRec.Body.String())
	}
	metricsBody := metricsRec.Body.String()
	for _, want := range []string{
		`anyns_process_up{service="runtime"} 1`,
		`anyns_dnslog_events_buffered{service="runtime"} 1`,
		`anyns_dnslog_events_by_risk_level{service="runtime",risk_level="high"} 1`,
		`anyns_dnslog_events_by_action{service="runtime",action="forward_to_honeypot"} 1`,
		`anyns_dnslog_rule_hits{service="runtime",rule="dns-tunnel-high-entropy"} 1`,
		`anyns_dnslog_events_by_plugin{service="runtime",source_plugin="hns"} 1`,
		`anyns_dnslog_events_by_rcode{service="runtime",rcode="NXDOMAIN"} 1`,
		`anyns_dnslog_latency_average_ms{service="runtime"}`,
		`anyns_dnslog_plugin_latency_average_ms{service="runtime",source_plugin="hns"}`,
		`anyns_dnslog_top_qname_events{service="runtime",qname="4xj9q2z8p1m7n5v3k0c6b4r2t8y9u1i3.hns."} 1`,
		`anyns_honeypot_enabled{service="runtime"} 1`,
		`anyns_honeypot_delivery_attempts_total{service="runtime"} 1`,
		`anyns_honeypot_failed_queue_length{service="runtime"} 1`,
	} {
		if !strings.Contains(metricsBody, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, metricsBody)
		}
	}

	summaryReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/summary?top_n=1", nil)
	summaryRec := httptest.NewRecorder()
	mux.ServeHTTP(summaryRec, summaryReq)
	if summaryRec.Code != http.StatusOK {
		t.Fatalf("audit summary status = %d body=%s", summaryRec.Code, summaryRec.Body.String())
	}
	var summary dnslog.Summary
	if err := json.Unmarshal(summaryRec.Body.Bytes(), &summary); err != nil {
		t.Fatalf("decode audit summary: %v", err)
	}
	if summary.Total != 1 ||
		summary.ByAction[string(security.ActionForwardToHoneypot)] != 1 ||
		summary.ByRule["dns-tunnel-high-entropy"] != 1 ||
		summary.ByRCode["NXDOMAIN"] != 1 ||
		summary.LatencyMS.Count != 1 ||
		summary.LatencyByPlugin["hns"].Count != 1 ||
		len(summary.TopClients) != 1 ||
		summary.TopClients[0].Value != "192.0.2.10" {
		t.Fatalf("unexpected audit summary: %#v", summary)
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
	mux := newRuntimeMux(application, cfg)

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
	mux := newRuntimeMux(application, cfg)

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
	mux := newRuntimeMux(application, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?trace_id=security-block&client_ip=192.0.2.11&client_view=adguard&tenant=prod&qname=two.hns.&qname_contains=two&qtype=TXT&source_plugin=security&risk_level=high&action=block&matched_rule=dns-tunnel-high-entropy&rcode=SERVFAIL&since="+base.Add(time.Minute).Format(time.RFC3339)+"&until="+base.Add(time.Minute).Format(time.RFC3339), nil)
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

func TestResolveEndpointBlocksRebindingResponse(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	application.Registry = plugins.NewRegistry([]plugins.Route{{
		Name:        "private-hns",
		Suffixes:    []string{".hns"},
		ClientViews: []string{"default"},
		Tenants:     []string{"default"},
		Plugin:      "private",
		Priority:    300,
		Fallback:    "icann-recursive",
	}}, fakePlugin{
		name:     "private",
		suffixes: []string{".hns"},
		result: plugins.ResolveResult{
			RRSet:        []plugins.RR{{Name: "rebind.hns.", Type: "A", TTL: 60, Value: "192.168.1.10"}},
			RCode:        plugins.RCodeNoError,
			TTL:          60,
			SourcePlugin: "private",
			Confidence:   "authoritative",
			SecurityTags: []string{"decentralized", "private"},
		},
	})
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "rebind.hns",
		"qtype": "A",
		"context": {
			"trace_id": "runtime-rebinding-block",
			"client_ip": "192.0.2.40",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result   plugins.ResolveResult `json:"result"`
		Security security.Finding      `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result.RCode != plugins.RCodeServFail || len(response.Result.RRSet) != 0 {
		t.Fatalf("blocked response leaked answer: %#v", response.Result)
	}
	if response.Security.Rule != "dns-rebinding-private-address" || response.Security.Action != security.ActionBlock {
		t.Fatalf("security finding = %#v", response.Security)
	}
	events := application.DNSLog.List(0)
	if len(events) != 1 ||
		events[0].TraceID != "runtime-rebinding-block" ||
		events[0].MatchedRule != "dns-rebinding-private-address" ||
		events[0].Action != string(security.ActionBlock) ||
		len(events[0].Answer) != 0 {
		t.Fatalf("unexpected blocked event: %#v", events)
	}
}

func TestResolveEndpointQueryBlockUsesResolveResultContract(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "x9q2z8p1m7n5v3k0c6b4r2t8y9u1i3.example.com",
		"qtype": "A",
		"context": {
			"trace_id": "runtime-query-block",
			"client_ip": "192.0.2.41",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result   plugins.ResolveResult `json:"result"`
		Security security.Finding      `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result.RCode != plugins.RCodeServFail || response.Result.SourcePlugin != "security" || len(response.Result.RRSet) != 0 {
		t.Fatalf("blocked query result = %#v", response.Result)
	}
	if response.Security.Rule != "dga-high-entropy" || response.Security.Action != security.ActionBlock {
		t.Fatalf("security finding = %#v", response.Security)
	}
}

func TestResolveEndpointDenylistBlockUsesResolveResultContract(t *testing.T) {
	cfg := config.Default()
	cfg.Security.DenylistDomains = []string{".blocked.example"}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "malware.blocked.example",
		"qtype": "A",
		"context": {
			"trace_id": "runtime-denylist-block",
			"client_ip": "192.0.2.42",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result   plugins.ResolveResult `json:"result"`
		Security security.Finding      `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result.RCode != plugins.RCodeServFail || response.Result.SourcePlugin != "security" || len(response.Result.RRSet) != 0 {
		t.Fatalf("blocked denylist result = %#v", response.Result)
	}
	if response.Security.Rule != "denylist-domain" || response.Security.Action != security.ActionBlock {
		t.Fatalf("security finding = %#v", response.Security)
	}
	events := application.DNSLog.List(0)
	if len(events) != 1 ||
		events[0].TraceID != "runtime-denylist-block" ||
		events[0].MatchedRule != "denylist-domain" ||
		events[0].Action != string(security.ActionBlock) {
		t.Fatalf("unexpected denylist event: %#v", events)
	}
}

func TestResolveEndpointSinkholeReturnsConfiguredAnswer(t *testing.T) {
	cfg := config.Default()
	cfg.Security.SinkholeDomains = []string{"ads.example"}
	cfg.Security.SinkholeIPv4 = "203.0.113.250"
	cfg.Security.SinkholeTTL = 45
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "ads.example",
		"qtype": "A",
		"context": {
			"trace_id": "runtime-sinkhole",
			"client_ip": "192.0.2.43",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result   plugins.ResolveResult `json:"result"`
		Security security.Finding      `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result.RCode != plugins.RCodeNoError ||
		response.Result.SourcePlugin != "security" ||
		response.Result.Confidence != "sinkhole" ||
		len(response.Result.RRSet) != 1 ||
		response.Result.RRSet[0].Value != "203.0.113.250" ||
		response.Result.RRSet[0].TTL != 45 {
		t.Fatalf("sinkhole result = %#v", response.Result)
	}
	if response.Security.Rule != "sinkhole-domain" || response.Security.Action != security.ActionSinkhole {
		t.Fatalf("security finding = %#v", response.Security)
	}
	events := application.DNSLog.List(0)
	if len(events) != 1 ||
		events[0].TraceID != "runtime-sinkhole" ||
		events[0].MatchedRule != "sinkhole-domain" ||
		events[0].Action != string(security.ActionSinkhole) ||
		len(events[0].Answer) != 1 ||
		events[0].Answer[0] != "203.0.113.250" {
		t.Fatalf("unexpected sinkhole event: %#v", events)
	}
}

func TestResolveEndpointRateLimitUsesResolveResultContract(t *testing.T) {
	cfg := config.Default()
	cfg.Security.QueryRateWindowSeconds = 60
	cfg.Security.QueryRateThreshold = 1
	cfg.Security.RandomSubdomainThreshold = 100
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "example.hns",
		"qtype": "A",
		"context": {
			"trace_id": "runtime-rate-limit",
			"client_ip": "192.0.2.44",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result   plugins.ResolveResult `json:"result"`
		Security security.Finding      `json:"security"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result.RCode != plugins.RCodeServFail ||
		response.Result.SourcePlugin != "security" ||
		response.Result.Confidence != "blocked" ||
		len(response.Result.RRSet) != 0 {
		t.Fatalf("rate-limited result = %#v", response.Result)
	}
	if response.Security.Rule != "query-rate-limit" || response.Security.Action != security.ActionRateLimit {
		t.Fatalf("security finding = %#v", response.Security)
	}
	events := application.DNSLog.List(0)
	if len(events) != 1 ||
		events[0].TraceID != "runtime-rate-limit" ||
		events[0].MatchedRule != "query-rate-limit" ||
		events[0].Action != string(security.ActionRateLimit) {
		t.Fatalf("unexpected rate-limit event: %#v", events)
	}
}

func TestResolveEndpointHonorsPolicyTagRoutes(t *testing.T) {
	cfg := config.Default()
	cfg.Routes = []plugins.Route{{
		Name:       "hns-adguard-tagged",
		Suffixes:   []string{".hns"},
		Plugin:     "hns",
		Priority:   200,
		Fallback:   "icann-recursive",
		PolicyTags: []string{"adguard"},
	}}
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "example.hns",
		"qtype": "A",
		"context": {
			"trace_id": "policy-tag-route",
			"client_ip": "192.0.2.20",
			"client_view": "default",
			"tenant": "default",
			"policy_tags": ["adguard"]
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Route plugins.Route `json:"route"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Route.Name != "hns-adguard-tagged" {
		t.Fatalf("route = %#v", response.Route)
	}
}

func TestResolveEndpointReturnsRoutedNXDomainForMissingHNS(t *testing.T) {
	cfg := config.Default()
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	mux := newRuntimeMux(application, cfg)

	body := []byte(`{
		"qname": "missing-name.hns",
		"qtype": "A",
		"context": {
			"trace_id": "runtime-hns-nxdomain",
			"client_ip": "192.0.2.21",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result plugins.ResolveResult `json:"result"`
		Route  plugins.Route         `json:"route"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Route.Name != "hns-default" || response.Result.RCode != plugins.RCodeNXDomain || response.Result.SourcePlugin != "hns" {
		t.Fatalf("unexpected routed NXDOMAIN response: route=%#v result=%#v", response.Route, response.Result)
	}
	events := application.DNSLog.List(0)
	if len(events) != 1 ||
		events[0].TraceID != "runtime-hns-nxdomain" ||
		events[0].SourcePlugin != "hns" ||
		events[0].RCode != plugins.RCodeNXDomain ||
		events[0].MatchedRule != "hns-default" {
		t.Fatalf("unexpected routed NXDOMAIN event: %#v", events)
	}
}

func TestRuntimePoliciesReloadAppliesConfigToLiveDataPlane(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(configPath, []byte(`{
		"routes": [{
			"name": "ens-runtime-reloaded",
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
	mux := newRuntimeMux(application, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reload", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload status = %d body=%s", rec.Code, rec.Body.String())
	}
	events := application.DNSLog.List(0)
	if len(events) != 1 ||
		events[0].SourcePlugin != "management" ||
		events[0].Action != "management_mutation" ||
		events[0].MatchedRule != "policy.reload" ||
		events[0].RawRR["scope"] != "plugin-runtime" {
		t.Fatalf("unexpected runtime reload audit event: %#v", events)
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
	if route.Name != "ens-runtime-reloaded" || result.SourcePlugin != "ens" || result.RCode != plugins.RCodeServFail {
		t.Fatalf("resolve after reload route=%#v result=%#v err=%v", route, result, err)
	}

	resolveBody := []byte(`{
		"qname": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
		"qtype": "TXT",
		"context": {
			"trace_id": "security-disabled-after-reload",
			"client_ip": "192.0.2.30",
			"client_view": "default",
			"tenant": "default"
		}
	}`)
	resolveReq := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", bytes.NewReader(resolveBody))
	resolveRec := httptest.NewRecorder()
	mux.ServeHTTP(resolveRec, resolveReq)
	if resolveRec.Code != http.StatusNotFound {
		t.Fatalf("resolve status = %d body=%s", resolveRec.Code, resolveRec.Body.String())
	}
	if !strings.Contains(resolveRec.Body.String(), `"rule":"security-disabled"`) {
		t.Fatalf("resolve should use reloaded disabled security policy: %s", resolveRec.Body.String())
	}
}

func TestRuntimePoliciesReloadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "invalid-runtime.json")
	if err := os.WriteFile(configPath, []byte(`{
		"routes": [{
			"name": "broken-runtime-route",
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
	mux := newRuntimeMux(application, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reload", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("reload invalid config status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing-plugin") {
		t.Fatalf("reload invalid config body = %s", rec.Body.String())
	}

	result, route, err := application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err != nil || route.Name != "hns-default" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("invalid reload should preserve existing runtime state route=%#v result=%#v err=%v", route, result, err)
	}
}

type fakePlugin struct {
	name     string
	enabled  bool
	suffixes []string
	result   plugins.ResolveResult
	err      error
}

func (p fakePlugin) Name() string {
	return p.name
}

func (p fakePlugin) Enabled() bool {
	return true
}

func (p fakePlugin) SetEnabled(enabled bool) {}

func (p fakePlugin) Suffixes() []string {
	return p.suffixes
}

func (p fakePlugin) Resolve(context.Context, plugins.ResolveRequest) (plugins.ResolveResult, error) {
	return p.result, p.err
}

func (p fakePlugin) Health(context.Context) error {
	return p.err
}
