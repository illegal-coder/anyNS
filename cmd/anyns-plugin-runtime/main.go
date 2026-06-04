package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/controlplane"
	"github.com/anyns/anyns/internal/dnslog"
	"github.com/anyns/anyns/internal/honeypot"
	"github.com/anyns/anyns/internal/httpapi"
	"github.com/anyns/anyns/internal/observability"
	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/security"
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
		log.Printf("load runtime app: %v", err)
		os.Exit(1)
	}
	if cfg.Honeypot.URL != "" && application.Honeypot != nil && application.Honeypot.Queue != nil {
		application.Honeypot.StartReplayWorker(context.Background(), honeypot.ReplayWorkerOptions{Logf: log.Printf})
	}
	mux := newRuntimeMux(application, cfg)
	log.Printf("starting anyNS plugin runtime addr=%s", cfg.RuntimeAddr)
	if err := http.ListenAndServe(cfg.RuntimeAddr, mux); err != nil {
		log.Printf("runtime stopped: %v", err)
		os.Exit(1)
	}
}

func newRuntimeMux(application *app.App, cfg config.Config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		observability.WritePrometheus(w, observability.MetricsOptions{
			Service:  "runtime",
			DNSLog:   application.DNSLog,
			Honeypot: application.Honeypot,
		})
	})
	controlplane.RegisterHandlers(mux, application, &cfg, controlplane.ScopeRuntime)
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeAuditRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, application.DNSLog.ListFiltered(
			httpapi.AuditEventFilterFromQuery(r),
			httpapi.QueryIntBounded(r, "limit", 100, 1, 1000),
		))
	})
	mux.HandleFunc("/api/v1/audit/summary", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.RequireScope(w, r, cfg, httpapi.ScopeAuditRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, application.DNSLog.Summary(queryInt(r, "top_n", 10)))
	})
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
			"scope":       "plugin-runtime",
		})
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{
			"status":      "loaded",
			"config_file": cfg.ConfigFile,
			"routes":      cfg.Routes,
			"plugins":     cfg.Plugins,
			"security":    cfg.Security,
		})
	})
	mux.HandleFunc("/api/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req plugins.ResolveRequest
		if err := httpapi.DecodeJSON(r, &req); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Context.TraceID == "" {
			req.Context.TraceID = time.Now().UTC().Format("20060102T150405.000000000")
		}
		if req.Context.ClientView == "" {
			req.Context.ClientView = "default"
		}
		if req.Context.Tenant == "" {
			req.Context.Tenant = "default"
		}
		preFinding := application.Security.AnalyzeQuery(req)
		if preFinding.Action == security.ActionBlock {
			blocked := blockedResult("security", preFinding)
			event := makeEvent(req, blocked, preFinding, "")
			application.DNSLog.Append(event)
			deliverIfNeeded(r.Context(), application, event)
			httpapi.WriteJSON(w, http.StatusForbidden, map[string]any{"result": blocked, "security": preFinding})
			return
		}
		if preFinding.Action == security.ActionRateLimit {
			limited := blockedResult("security", preFinding)
			event := makeEvent(req, limited, preFinding, "")
			application.DNSLog.Append(event)
			deliverIfNeeded(r.Context(), application, event)
			httpapi.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"result": limited, "security": preFinding})
			return
		}
		if preFinding.Action == security.ActionSinkhole {
			sinkholed := sinkholeResult(req, application.Security.Policy(), preFinding)
			event := makeEvent(req, sinkholed, preFinding, "")
			application.DNSLog.Append(event)
			deliverIfNeeded(r.Context(), application, event)
			httpapi.WriteJSON(w, http.StatusOK, map[string]any{"result": sinkholed, "security": preFinding})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), cfg.RequestTimeout)
		defer cancel()
		result, route, err := application.Registry.Resolve(ctx, req)
		if err != nil && !errors.Is(err, plugins.ErrNoRoute) {
			log.Printf("resolve failed: error=%v qname=%s qtype=%s", err, req.QName, req.QType)
		}
		postFinding := application.Security.AnalyzeResponse(req, result)
		finding := strongest(preFinding, postFinding)
		if finding.Action == security.ActionBlock {
			blocked := blockedResult(result.SourcePlugin, finding)
			event := makeEvent(req, blocked, finding, route.Name)
			application.DNSLog.Append(event)
			deliverIfNeeded(r.Context(), application, event)
			httpapi.WriteJSON(w, http.StatusForbidden, map[string]any{"result": blocked, "route": route, "security": finding})
			return
		}
		if finding.Action == security.ActionRateLimit {
			limited := blockedResult(result.SourcePlugin, finding)
			event := makeEvent(req, limited, finding, route.Name)
			application.DNSLog.Append(event)
			deliverIfNeeded(r.Context(), application, event)
			httpapi.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"result": limited, "route": route, "security": finding})
			return
		}
		event := makeEvent(req, result, finding, route.Name)
		application.DNSLog.Append(event)
		deliverIfNeeded(r.Context(), application, event)
		status := http.StatusOK
		if errors.Is(err, plugins.ErrNoRoute) {
			status = http.StatusNotFound
		}
		httpapi.WriteJSON(w, status, map[string]any{"result": result, "route": route, "security": finding})
	})
	return mux
}

func makeEvent(req plugins.ResolveRequest, result plugins.ResolveResult, finding security.Finding, routeName string) dnslog.Event {
	answer := make([]string, 0, len(result.RRSet))
	for _, rr := range result.RRSet {
		answer = append(answer, rr.Value)
	}
	if finding.Rule != "" && finding.Rule != "default-allow" {
		routeName = finding.Rule
	}
	if routeName == "" {
		routeName = finding.Rule
	}
	return dnslog.Event{
		Timestamp:    time.Now().UTC(),
		TraceID:      req.Context.TraceID,
		ClientIP:     req.Context.ClientIP,
		ClientView:   req.Context.ClientView,
		Tenant:       req.Context.Tenant,
		QName:        plugins.NormalizeQName(req.QName),
		QType:        plugins.NormalizeQType(req.QType),
		RCode:        result.RCode,
		Answer:       answer,
		SourcePlugin: result.SourcePlugin,
		RiskLevel:    string(finding.RiskLevel),
		Action:       string(finding.Action),
		MatchedRule:  routeName,
		RawRR:        result.RawRecord,
		LatencyMS:    result.LatencyMS,
	}
}

func blockedResult(sourcePlugin string, finding security.Finding) plugins.ResolveResult {
	if sourcePlugin == "" {
		sourcePlugin = "security"
	}
	return plugins.ResolveResult{
		RRSet:        []plugins.RR{},
		RCode:        plugins.RCodeServFail,
		TTL:          0,
		SourcePlugin: sourcePlugin,
		Confidence:   "blocked",
		SecurityTags: []string{"security", string(finding.RiskLevel), string(finding.Action)},
		RawRecord: map[string]any{
			"blocked_rule": finding.Rule,
			"reason":       finding.Reason,
		},
	}
}

func sinkholeResult(req plugins.ResolveRequest, policy security.Policy, finding security.Finding) plugins.ResolveResult {
	qtype := plugins.NormalizeQType(req.QType)
	ttl := policy.SinkholeTTL
	if ttl <= 0 {
		ttl = 60
	}
	rrset := []plugins.RR{}
	switch qtype {
	case "A", "ANY":
		rrset = append(rrset, plugins.RR{Name: plugins.NormalizeQName(req.QName), Type: "A", TTL: ttl, Value: policy.SinkholeIPv4})
	case "AAAA":
		rrset = append(rrset, plugins.RR{Name: plugins.NormalizeQName(req.QName), Type: "AAAA", TTL: ttl, Value: policy.SinkholeIPv6})
	}
	return plugins.ResolveResult{
		RRSet:        rrset,
		RCode:        plugins.RCodeNoError,
		TTL:          ttl,
		SourcePlugin: "security",
		Confidence:   "sinkhole",
		SecurityTags: []string{"security", string(finding.RiskLevel), string(finding.Action)},
		RawRecord: map[string]any{
			"sinkhole_rule": finding.Rule,
			"reason":        finding.Reason,
		},
	}
}

func strongest(left, right security.Finding) security.Finding {
	if score(right.RiskLevel) > score(left.RiskLevel) {
		return right
	}
	return left
}

func score(level security.RiskLevel) int {
	switch level {
	case security.RiskCritical:
		return 5
	case security.RiskHigh:
		return 4
	case security.RiskMedium:
		return 3
	case security.RiskLow:
		return 2
	default:
		return 1
	}
}

func deliverIfNeeded(ctx context.Context, application *app.App, event dnslog.Event) {
	if application.Honeypot == nil || application.Honeypot.URL == "" || event.Action != string(security.ActionForwardToHoneypot) {
		return
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := application.Honeypot.DeliverOrQueue(deliveryCtx, []dnslog.Event{event}); err != nil {
		log.Printf("honeypot delivery failed: error=%v trace_id=%s", err, event.TraceID)
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
