package observability

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/dnslog"
	"github.com/anyns/anyns/internal/honeypot"
)

func TestWritePrometheusTextIncludesDNSLogAndHoneypotState(t *testing.T) {
	store := dnslog.NewStore(10)
	store.Append(dnslog.Event{
		TraceID:      "metric-event",
		ClientIP:     "192.0.2.10",
		QName:        "metric.hns.",
		RCode:        "NOERROR",
		RiskLevel:    "high",
		Action:       "forward_to_honeypot",
		MatchedRule:  "dns-tunnel-high-entropy",
		SourcePlugin: "hns",
		LatencyMS:    37,
	})
	queue, err := honeypot.NewFailedQueue("", 10)
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	queuedAt := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	if err := queue.Enqueue(honeypot.FailedDelivery{QueuedAt: queuedAt, Events: []dnslog.Event{{TraceID: "queued"}}}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	client := &honeypot.Client{URL: "https://honeypot.example/api/v1/dns-events", Queue: queue, Retained: 2, Dropped: 1}

	var buf bytes.Buffer
	WritePrometheusText(&buf, MetricsOptions{
		Service:  "runtime",
		DNSLog:   store,
		Honeypot: client,
		Now:      queuedAt.Add(90 * time.Second),
	})
	got := buf.String()
	for _, want := range []string{
		`anyns_process_up{service="runtime"} 1`,
		`anyns_dnslog_events_buffered{service="runtime"} 1`,
		`anyns_dnslog_persist_last_error{service="runtime"} 0`,
		`anyns_dnslog_events_by_risk_level{service="runtime",risk_level="high"} 1`,
		`anyns_dnslog_events_by_action{service="runtime",action="forward_to_honeypot"} 1`,
		`anyns_dnslog_rule_hits{service="runtime",rule="dns-tunnel-high-entropy"} 1`,
		`anyns_dnslog_events_by_plugin{service="runtime",source_plugin="hns"} 1`,
		`anyns_dnslog_events_by_rcode{service="runtime",rcode="NOERROR"} 1`,
		`anyns_dnslog_latency_average_ms{service="runtime"} 37`,
		`anyns_dnslog_latency_max_ms{service="runtime"} 37`,
		`anyns_dnslog_plugin_latency_average_ms{service="runtime",source_plugin="hns"} 37`,
		`anyns_dnslog_plugin_latency_max_ms{service="runtime",source_plugin="hns"} 37`,
		`anyns_dnslog_top_client_events{service="runtime",client_ip="192.0.2.10"} 1`,
		`anyns_dnslog_top_qname_events{service="runtime",qname="metric.hns."} 1`,
		`anyns_honeypot_enabled{service="runtime"} 1`,
		`anyns_honeypot_replay_retained_total{service="runtime"} 2`,
		`anyns_honeypot_replay_dropped_total{service="runtime"} 1`,
		`anyns_honeypot_failed_queue_length{service="runtime"} 1`,
		`anyns_honeypot_oldest_queued_age_seconds{service="runtime"} 90`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, got)
		}
	}
}
