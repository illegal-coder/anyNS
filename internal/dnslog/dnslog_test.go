package dnslog

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentStoreAppendsAndReloadsRecentEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnslog.jsonl")
	store, err := NewPersistentStore(2, path)
	if err != nil {
		t.Fatalf("new persistent store: %v", err)
	}
	store.Append(Event{Timestamp: time.Unix(1, 0).UTC(), TraceID: "one", QName: "one.hns.", QType: "A"})
	store.Append(Event{Timestamp: time.Unix(2, 0).UTC(), TraceID: "two", QName: "two.hns.", QType: "A"})
	store.Append(Event{Timestamp: time.Unix(3, 0).UTC(), TraceID: "three", QName: "three.hns.", QType: "A"})
	if err := store.LastError(); err != nil {
		t.Fatalf("append error: %v", err)
	}

	reloaded, err := NewPersistentStore(2, path)
	if err != nil {
		t.Fatalf("reload persistent store: %v", err)
	}
	events := reloaded.List(0)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	if events[0].TraceID != "two" || events[1].TraceID != "three" {
		t.Fatalf("unexpected events after reload: %#v", events)
	}
}

func TestStoreListFilteredAppliesFiltersBeforeLimit(t *testing.T) {
	store := NewStore(10)
	base := time.Date(2026, 6, 5, 1, 0, 0, 0, time.UTC)
	store.Append(Event{Timestamp: base, TraceID: "one", ClientIP: "192.0.2.10", ClientView: "default", Tenant: "default", QName: "one.hns.", QType: "A", RCode: "NOERROR", SourcePlugin: "hns", RiskLevel: "none", Action: "allow"})
	store.Append(Event{Timestamp: base.Add(time.Minute), TraceID: "two", ClientIP: "192.0.2.11", ClientView: "default", Tenant: "default", QName: "two.hns.", QType: "AAAA", RCode: "SERVFAIL", SourcePlugin: "security", RiskLevel: "high", Action: "block", MatchedRule: "dga-high-entropy"})
	store.Append(Event{Timestamp: base.Add(2 * time.Minute), TraceID: "three", ClientIP: "192.0.2.12", ClientView: "default", Tenant: "default", QName: "three.hns.", QType: "A", RCode: "NXDOMAIN", SourcePlugin: "hns", RiskLevel: "low", Action: "allow"})
	store.Append(Event{Timestamp: base.Add(3 * time.Minute), TraceID: "four", ClientIP: "192.0.2.11", ClientView: "adguard", Tenant: "prod", QName: "four.hns.", QType: "TXT", RCode: "SERVFAIL", SourcePlugin: "security", RiskLevel: "high", Action: "block", MatchedRule: "dns-tunnel-high-entropy"})

	events := store.ListFiltered(EventFilter{SourcePlugin: "security", RiskLevel: "high", Action: "block", RCode: "SERVFAIL"}, 1)
	if len(events) != 1 || events[0].TraceID != "four" {
		t.Fatalf("filtered events = %#v", events)
	}

	events = store.ListFiltered(EventFilter{
		TraceID:     "four",
		ClientIP:    "192.0.2.11",
		ClientView:  "adguard",
		Tenant:      "prod",
		QName:       "four.hns.",
		QType:       "TXT",
		MatchedRule: "dns-tunnel-high-entropy",
	}, 10)
	if len(events) != 1 || events[0].TraceID != "four" {
		t.Fatalf("expanded filtered events = %#v", events)
	}

	if events := store.ListFiltered(EventFilter{SourcePlugin: "hns", RCode: "SERVFAIL"}, 10); len(events) != 0 {
		t.Fatalf("unexpected mismatched filtered events: %#v", events)
	}
}

func TestStoreListFilteredSupportsQNameContains(t *testing.T) {
	store := NewStore(10)
	store.Append(Event{TraceID: "one", QName: "wallet.example.hns."})
	store.Append(Event{TraceID: "two", QName: "alice.crypto."})
	store.Append(Event{TraceID: "three", QName: "blocked.integration.test."})
	store.Append(Event{TraceID: "four", QName: "deep.WALLET.example.hns."})

	events := store.ListFiltered(EventFilter{QNameContains: "wallet"}, 10)
	if len(events) != 2 || events[0].TraceID != "one" || events[1].TraceID != "four" {
		t.Fatalf("qname_contains events = %#v", events)
	}

	events = store.ListFiltered(EventFilter{QNameContains: ".integration."}, 10)
	if len(events) != 1 || events[0].TraceID != "three" {
		t.Fatalf("integration qname_contains events = %#v", events)
	}

	if events := store.ListFiltered(EventFilter{QName: "alice.crypto.", QNameContains: "wallet"}, 10); len(events) != 0 {
		t.Fatalf("exact qname should still narrow qname_contains, got %#v", events)
	}
}

func TestStoreListFilteredAppliesTimeWindow(t *testing.T) {
	store := NewStore(10)
	base := time.Date(2026, 6, 5, 1, 0, 0, 0, time.UTC)
	store.Append(Event{Timestamp: base, TraceID: "before"})
	store.Append(Event{Timestamp: base.Add(time.Minute), TraceID: "start"})
	store.Append(Event{Timestamp: base.Add(2 * time.Minute), TraceID: "middle"})
	store.Append(Event{Timestamp: base.Add(3 * time.Minute), TraceID: "end"})
	store.Append(Event{Timestamp: base.Add(4 * time.Minute), TraceID: "after"})

	events := store.ListFiltered(EventFilter{
		Since: base.Add(time.Minute),
		Until: base.Add(3 * time.Minute),
	}, 10)
	if len(events) != 3 || events[0].TraceID != "start" || events[1].TraceID != "middle" || events[2].TraceID != "end" {
		t.Fatalf("time-window events = %#v", events)
	}

	events = store.ListFiltered(EventFilter{Since: base.Add(time.Minute)}, 2)
	if len(events) != 2 || events[0].TraceID != "end" || events[1].TraceID != "after" {
		t.Fatalf("time-window limited events = %#v", events)
	}
}

func TestStoreListFilteredHonorsExplicitOrder(t *testing.T) {
	store := NewStore(10)
	store.Append(Event{TraceID: "one"})
	store.Append(Event{TraceID: "two"})
	store.Append(Event{TraceID: "three"})

	events := store.ListFiltered(EventFilter{Order: "asc"}, 2)
	if len(events) != 2 || events[0].TraceID != "one" || events[1].TraceID != "two" {
		t.Fatalf("ascending events = %#v", events)
	}

	events = store.ListFiltered(EventFilter{Order: "desc"}, 2)
	if len(events) != 2 || events[0].TraceID != "three" || events[1].TraceID != "two" {
		t.Fatalf("descending events = %#v", events)
	}

	events = store.ListFiltered(EventFilter{}, 2)
	if len(events) != 2 || events[0].TraceID != "two" || events[1].TraceID != "three" {
		t.Fatalf("default latest chronological events = %#v", events)
	}
}

func TestStoreSummaryAggregatesSecurityAndTopValues(t *testing.T) {
	store := NewStore(10)
	store.Append(Event{TraceID: "one", ClientIP: "192.0.2.10", QName: "one.hns.", RCode: "NOERROR", SourcePlugin: "hns", RiskLevel: "none", Action: "allow", MatchedRule: "hns-default", LatencyMS: 9})
	store.Append(Event{TraceID: "two", ClientIP: "192.0.2.10", QName: "two.hns.", RCode: "SERVFAIL", SourcePlugin: "security", RiskLevel: "high", Action: "block", MatchedRule: "dga-high-entropy", LatencyMS: 30})
	store.Append(Event{TraceID: "three", ClientIP: "192.0.2.11", QName: "two.hns.", RCode: "SERVFAIL", SourcePlugin: "security", RiskLevel: "high", Action: "block", MatchedRule: "dga-high-entropy", LatencyMS: 60})

	summary := store.Summary(1)
	if summary.Total != 3 {
		t.Fatalf("summary total = %d, want 3", summary.Total)
	}
	if summary.ByRiskLevel["high"] != 2 || summary.ByRiskLevel["none"] != 1 {
		t.Fatalf("risk summary = %#v", summary.ByRiskLevel)
	}
	if summary.ByAction["block"] != 2 || summary.ByAction["allow"] != 1 {
		t.Fatalf("action summary = %#v", summary.ByAction)
	}
	if summary.ByRule["dga-high-entropy"] != 2 || summary.ByPlugin["security"] != 2 {
		t.Fatalf("rule/plugin summary rule=%#v plugin=%#v", summary.ByRule, summary.ByPlugin)
	}
	if summary.ByRCode["SERVFAIL"] != 2 || summary.ByRCode["NOERROR"] != 1 {
		t.Fatalf("rcode summary = %#v", summary.ByRCode)
	}
	if summary.LatencyMS.Count != 3 || summary.LatencyMS.Average != 33 || summary.LatencyMS.Max != 60 {
		t.Fatalf("latency summary = %#v", summary.LatencyMS)
	}
	if summary.LatencyByPlugin["security"].Count != 2 ||
		summary.LatencyByPlugin["security"].Average != 45 ||
		summary.LatencyByPlugin["security"].Max != 60 {
		t.Fatalf("plugin latency summary = %#v", summary.LatencyByPlugin)
	}
	if len(summary.TopClients) != 1 || summary.TopClients[0].Value != "192.0.2.10" || summary.TopClients[0].Count != 2 {
		t.Fatalf("top clients = %#v", summary.TopClients)
	}
	if len(summary.TopQNames) != 1 || summary.TopQNames[0].Value != "two.hns." || summary.TopQNames[0].Count != 2 {
		t.Fatalf("top qnames = %#v", summary.TopQNames)
	}
}
