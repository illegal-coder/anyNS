package observability

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/dnslog"
	"github.com/anyns/anyns/internal/honeypot"
)

type MetricsOptions struct {
	Service  string
	DNSLog   *dnslog.Store
	Honeypot *honeypot.Client
	Now      time.Time
}

func WritePrometheus(w http.ResponseWriter, opts MetricsOptions) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	WritePrometheusText(w, opts)
}

func WritePrometheusText(w io.Writer, opts MetricsOptions) {
	service := sanitizeLabel(opts.Service)
	if service == "" {
		service = "anyns"
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	fmt.Fprintf(w, "# HELP anyns_process_up Process health by service.\n")
	fmt.Fprintf(w, "# TYPE anyns_process_up gauge\n")
	fmt.Fprintf(w, "anyns_process_up{service=%q} 1\n", service)

	dnslogCount := 0
	dnslogPersistError := 0
	if opts.DNSLog != nil {
		dnslogCount = len(opts.DNSLog.List(0))
		if opts.DNSLog.LastError() != nil {
			dnslogPersistError = 1
		}
	}
	fmt.Fprintf(w, "# HELP anyns_dnslog_events_buffered DNSLog events currently retained in memory.\n")
	fmt.Fprintf(w, "# TYPE anyns_dnslog_events_buffered gauge\n")
	fmt.Fprintf(w, "anyns_dnslog_events_buffered{service=%q} %d\n", service, dnslogCount)
	fmt.Fprintf(w, "# HELP anyns_dnslog_persist_last_error DNSLog persistence last append status, 1 means the last append failed.\n")
	fmt.Fprintf(w, "# TYPE anyns_dnslog_persist_last_error gauge\n")
	fmt.Fprintf(w, "anyns_dnslog_persist_last_error{service=%q} %d\n", service, dnslogPersistError)
	if opts.DNSLog != nil {
		summary := opts.DNSLog.Summary(5)
		fmt.Fprintf(w, "# HELP anyns_dnslog_events_by_risk_level DNSLog events grouped by risk level.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_events_by_risk_level gauge\n")
		for risk, count := range summary.ByRiskLevel {
			fmt.Fprintf(w, "anyns_dnslog_events_by_risk_level{service=%q,risk_level=%q} %d\n", service, sanitizeLabel(risk), count)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_events_by_action DNSLog events grouped by action.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_events_by_action gauge\n")
		for action, count := range summary.ByAction {
			fmt.Fprintf(w, "anyns_dnslog_events_by_action{service=%q,action=%q} %d\n", service, sanitizeLabel(action), count)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_rule_hits DNSLog events grouped by matched rule.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_rule_hits gauge\n")
		for rule, count := range summary.ByRule {
			fmt.Fprintf(w, "anyns_dnslog_rule_hits{service=%q,rule=%q} %d\n", service, sanitizeLabel(rule), count)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_events_by_plugin DNSLog events grouped by source plugin.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_events_by_plugin gauge\n")
		for plugin, count := range summary.ByPlugin {
			fmt.Fprintf(w, "anyns_dnslog_events_by_plugin{service=%q,source_plugin=%q} %d\n", service, sanitizeLabel(plugin), count)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_events_by_rcode DNSLog events grouped by response code.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_events_by_rcode gauge\n")
		for rcode, count := range summary.ByRCode {
			fmt.Fprintf(w, "anyns_dnslog_events_by_rcode{service=%q,rcode=%q} %d\n", service, sanitizeLabel(rcode), count)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_latency_average_ms Average latency in milliseconds across retained DNSLog events.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_latency_average_ms gauge\n")
		fmt.Fprintf(w, "anyns_dnslog_latency_average_ms{service=%q} %d\n", service, summary.LatencyMS.Average)
		fmt.Fprintf(w, "# HELP anyns_dnslog_latency_max_ms Maximum latency in milliseconds across retained DNSLog events.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_latency_max_ms gauge\n")
		fmt.Fprintf(w, "anyns_dnslog_latency_max_ms{service=%q} %d\n", service, summary.LatencyMS.Max)
		fmt.Fprintf(w, "# HELP anyns_dnslog_plugin_latency_average_ms Average latency in milliseconds grouped by source plugin.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_plugin_latency_average_ms gauge\n")
		for plugin, stats := range summary.LatencyByPlugin {
			fmt.Fprintf(w, "anyns_dnslog_plugin_latency_average_ms{service=%q,source_plugin=%q} %d\n", service, sanitizeLabel(plugin), stats.Average)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_plugin_latency_max_ms Maximum latency in milliseconds grouped by source plugin.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_plugin_latency_max_ms gauge\n")
		for plugin, stats := range summary.LatencyByPlugin {
			fmt.Fprintf(w, "anyns_dnslog_plugin_latency_max_ms{service=%q,source_plugin=%q} %d\n", service, sanitizeLabel(plugin), stats.Max)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_top_client_events Top retained DNSLog client event counts.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_top_client_events gauge\n")
		for _, top := range summary.TopClients {
			fmt.Fprintf(w, "anyns_dnslog_top_client_events{service=%q,client_ip=%q} %d\n", service, sanitizeLabel(top.Value), top.Count)
		}
		fmt.Fprintf(w, "# HELP anyns_dnslog_top_qname_events Top retained DNSLog qname event counts.\n")
		fmt.Fprintf(w, "# TYPE anyns_dnslog_top_qname_events gauge\n")
		for _, top := range summary.TopQNames {
			fmt.Fprintf(w, "anyns_dnslog_top_qname_events{service=%q,qname=%q} %d\n", service, sanitizeLabel(top.Value), top.Count)
		}
	}

	status := honeypot.DeliveryStatus{}
	if opts.Honeypot != nil {
		status = opts.Honeypot.Status(now)
	}
	enabled := boolInt(status.Enabled)
	fmt.Fprintf(w, "# HELP anyns_honeypot_enabled Honeypot delivery is configured.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_enabled gauge\n")
	fmt.Fprintf(w, "anyns_honeypot_enabled{service=%q} %d\n", service, enabled)
	fmt.Fprintf(w, "# HELP anyns_honeypot_delivery_attempts_total Honeypot delivery attempts recorded by this process.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_delivery_attempts_total counter\n")
	fmt.Fprintf(w, "anyns_honeypot_delivery_attempts_total{service=%q} %d\n", service, status.Attempted)
	fmt.Fprintf(w, "# HELP anyns_honeypot_deliveries_total Successful honeypot deliveries recorded by this process.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_deliveries_total counter\n")
	fmt.Fprintf(w, "anyns_honeypot_deliveries_total{service=%q} %d\n", service, status.Delivered)
	fmt.Fprintf(w, "# HELP anyns_honeypot_replay_retained_total Honeypot replay batches retained after retry failures.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_replay_retained_total counter\n")
	fmt.Fprintf(w, "anyns_honeypot_replay_retained_total{service=%q} %d\n", service, status.Retained)
	fmt.Fprintf(w, "# HELP anyns_honeypot_replay_dropped_total Honeypot replay batches dropped after exhausting retry attempts.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_replay_dropped_total counter\n")
	fmt.Fprintf(w, "anyns_honeypot_replay_dropped_total{service=%q} %d\n", service, status.Dropped)
	fmt.Fprintf(w, "# HELP anyns_honeypot_failed_queue_length Failed honeypot delivery batches retained for retry.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_failed_queue_length gauge\n")
	fmt.Fprintf(w, "anyns_honeypot_failed_queue_length{service=%q} %d\n", service, status.FailedQueueLength)
	fmt.Fprintf(w, "# HELP anyns_honeypot_oldest_queued_age_seconds Age of the oldest retained honeypot delivery batch.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_oldest_queued_age_seconds gauge\n")
	fmt.Fprintf(w, "anyns_honeypot_oldest_queued_age_seconds{service=%q} %d\n", service, status.OldestQueuedAgeSeconds)
	fmt.Fprintf(w, "# HELP anyns_honeypot_last_latency_ms Last honeypot delivery latency in milliseconds.\n")
	fmt.Fprintf(w, "# TYPE anyns_honeypot_last_latency_ms gauge\n")
	fmt.Fprintf(w, "anyns_honeypot_last_latency_ms{service=%q} %d\n", service, status.LastLatencyMS)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func sanitizeLabel(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	return value
}
