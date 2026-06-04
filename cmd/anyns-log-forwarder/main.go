package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/dnslog"
	"github.com/anyns/anyns/internal/honeypot"
	"github.com/anyns/anyns/internal/httpapi"
	"github.com/anyns/anyns/internal/observability"
)

func main() {
	cfg, err := config.FromEnvWithError()
	if err != nil {
		log.Printf("load config: %v", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		log.Printf("validate config: %v", err)
		os.Exit(1)
	}
	queue, err := honeypot.NewFailedQueue(cfg.Honeypot.FailedQueuePath, cfg.Honeypot.FailedQueueMaxEntries)
	if err != nil {
		log.Printf("load honeypot failed queue: %v", err)
		os.Exit(1)
	}
	requestTimeout := cfg.Honeypot.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 5 * time.Second
	}
	client := &honeypot.Client{
		URL:           cfg.Honeypot.URL,
		APIKey:        cfg.Honeypot.APIKey,
		HMACSecret:    cfg.Honeypot.HMACSecret,
		HTTPClient:    &http.Client{Timeout: requestTimeout},
		Queue:         queue,
		MaxAttempts:   cfg.Honeypot.MaxAttempts,
		RetryInterval: cfg.Honeypot.RetryInterval,
	}
	if cfg.Honeypot.URL != "" && client.Queue != nil {
		client.StartReplayWorker(context.Background(), honeypot.ReplayWorkerOptions{Logf: log.Printf})
	}
	store, err := dnslog.NewPersistentStore(cfg.DNSLog.Limit, cfg.DNSLog.Path)
	if err != nil {
		log.Printf("load dnslog store: %v", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		observability.WritePrometheus(w, observability.MetricsOptions{
			Service:  "log-forwarder",
			DNSLog:   store,
			Honeypot: client,
		})
	})
	mux.HandleFunc("/api/v1/dns-events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var body struct {
			Events []dnslog.Event `json:"events"`
		}
		if err := httpapi.DecodeJSON(r, &body); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		for _, event := range body.Events {
			if event.Timestamp.IsZero() {
				event.Timestamp = time.Now().UTC()
			}
			store.Append(event)
		}
		if cfg.Honeypot.URL != "" && len(body.Events) > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), cfg.RequestTimeout)
			defer cancel()
			if err := client.DeliverOrQueue(ctx, body.Events); err != nil {
				log.Printf("honeypot forwarding failed: %v", err)
				httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"accepted": len(body.Events), "forwarded": false, "error": err.Error()})
				return
			}
		}
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"accepted": len(body.Events), "forwarded": cfg.Honeypot.URL != ""})
	})
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeAuditRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, store.ListFiltered(
			httpapi.AuditEventFilterFromQuery(r),
			httpapi.QueryIntBounded(r, "limit", 100, 1, 1000),
		))
	})
	mux.HandleFunc("/api/v1/audit/summary", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeAuditRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, store.Summary(queryInt(r, "top_n", 10)))
	})
	mux.HandleFunc("/api/v1/honeypot/status", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeHoneypotRead) {
			return
		}
		status := client.Status(time.Now().UTC())
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{
			"enabled":                   cfg.Honeypot.URL != "",
			"url_configured":            cfg.Honeypot.URL != "",
			"attempted":                 status.Attempted,
			"delivered":                 status.Delivered,
			"retained":                  status.Retained,
			"dropped":                   status.Dropped,
			"last_attempt_at":           status.LastAttemptAt,
			"last_error":                status.LastError,
			"last_latency_ms":           status.LastLatencyMS,
			"failed_queue_length":       status.FailedQueueLength,
			"oldest_queued_at":          status.OldestQueuedAt,
			"oldest_queued_age_seconds": status.OldestQueuedAgeSeconds,
			"failed_queue_path":         cfg.Honeypot.FailedQueuePath,
			"failed_queue_max_entries":  cfg.Honeypot.FailedQueueMaxEntries,
			"retry_interval_seconds":    int(cfg.Honeypot.RetryInterval.Seconds()),
			"max_attempts":              cfg.Honeypot.MaxAttempts,
		})
	})
	mux.HandleFunc("/api/v1/honeypot/drain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeHoneypotWrite) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		result, err := client.Drain(ctx, 0)
		if err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, result)
	})
	log.Printf("starting anyNS log forwarder addr=%s", cfg.LogForwarderAddr)
	if err := http.ListenAndServe(cfg.LogForwarderAddr, mux); err != nil {
		log.Printf("log forwarder stopped: %v", err)
		os.Exit(1)
	}
}

func queryInt(r *http.Request, name string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
