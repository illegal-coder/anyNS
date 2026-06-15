package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/adminapi"
	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/controlplane"
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
	application, err := app.NewFromConfig(cfg)
	if err != nil {
		log.Printf("load admin app: %v", err)
		os.Exit(1)
	}
	if cfg.Honeypot.URL != "" && application.Honeypot != nil && application.Honeypot.Queue != nil {
		application.Honeypot.StartReplayWorker(context.Background(), honeypot.ReplayWorkerOptions{Logf: log.Printf})
	}
	mux := newAdminMux(application, cfg)
	log.Printf("starting anyNS admin API addr=%s", cfg.AdminAddr)
	if err := http.ListenAndServe(cfg.AdminAddr, mux); err != nil {
		log.Printf("admin api stopped: %v", err)
		os.Exit(1)
	}
}

func newAdminMux(application *app.App, cfg config.Config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		observability.WritePrometheus(w, observability.MetricsOptions{
			Service:  "admin",
			DNSLog:   application.DNSLog,
			Honeypot: application.Honeypot,
		})
	})
	controlplane.RegisterHandlers(mux, application, &cfg, controlplane.ScopeAdmin)
	adminapi.Register(mux, application, &cfg)
	mux.HandleFunc("/api/v1/policies/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, cfg, httpapi.ScopePolicyWrite)
		if !ok {
			return
		}
		if cfg.ConfigFile == "" {
			httpapi.Error(w, http.StatusBadRequest, "config_file is not set")
			return
		}
		reloaded, err := config.LoadFileWithEnvOverrides(cfg.ConfigFile)
		if err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := reloaded.Validate(); err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := application.ReloadFromConfig(reloaded); err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		cfg = reloaded
		application.AppendManagementAudit("policy.reload", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"config_file": cfg.ConfigFile,
			"routes":      len(cfg.Routes),
			"plugins":     len(cfg.Plugins),
			"scope":       "admin-api",
		})
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{
			"status":      "loaded",
			"config_file": cfg.ConfigFile,
			"routes":      cfg.Routes,
			"plugins":     cfg.Plugins,
			"security":    cfg.Security,
		})
	})
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeAuditRead) {
			return
		}
		filter := httpapi.AuditEventFilterFromQuery(r)
		limit := httpapi.QueryIntBounded(r, "limit", 100, 1, 1000)
		if httpapi.AuditEventPageRequested(r) {
			httpapi.WriteJSON(w, http.StatusOK, application.DNSLog.ListFilteredPage(filter, limit, httpapi.AuditEventCursor(r)))
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, application.DNSLog.ListFiltered(filter, limit))
	})
	mux.HandleFunc("/api/v1/audit/summary", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeAuditRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, application.DNSLog.Summary(queryInt(r, "top_n", 10)))
	})
	mux.HandleFunc("/api/v1/honeypot/status", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeHoneypotRead) {
			return
		}
		status := honeypot.DeliveryStatus{}
		if application.Honeypot != nil {
			status = application.Honeypot.Status(time.Now().UTC())
		}
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
		principal, ok := httpapi.RequireScopePrincipal(w, r, cfg, httpapi.ScopeHoneypotWrite)
		if !ok {
			return
		}
		if application.Honeypot == nil {
			httpapi.Error(w, http.StatusServiceUnavailable, "honeypot client is not configured")
			return
		}
		limit := queryInt(r, "limit", 0)
		timeout := cfg.Honeypot.RequestTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		result, err := application.Honeypot.Drain(ctx, limit)
		if err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		application.AppendManagementAudit("honeypot.drain", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"limit":     limit,
			"delivered": result.Delivered,
			"retained":  result.Retained,
			"dropped":   result.Dropped,
			"scope":     "admin-api",
		})
		httpapi.WriteJSON(w, http.StatusOK, result)
	})
	registerAdminUI(mux, os.Getenv("ANYNS_ADMIN_UI_DIR"))
	return mux
}

func registerAdminUI(mux *http.ServeMux, directory string) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return
	}
	indexPath := filepath.Join(directory, "index.html")
	if info, err := os.Stat(indexPath); err != nil || info.IsDir() {
		return
	}
	files := http.FileServer(http.Dir(directory))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
		if clean != "." {
			if info, err := os.Stat(filepath.Join(directory, clean)); err == nil && !info.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, indexPath)
	})
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
