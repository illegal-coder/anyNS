package adminapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/controlplane"
	"github.com/anyns/anyns/internal/httpapi"
	"github.com/anyns/anyns/internal/powerdns"
)

type Handler struct {
	application *app.App
	cfg         *config.Config
	httpClient  *http.Client
}

type ServiceStatus struct {
	Configured bool   `json:"configured"`
	Healthy    bool   `json:"healthy"`
	URL        string `json:"url,omitempty"`
	Error      string `json:"error,omitempty"`
}

func Register(mux *http.ServeMux, application *app.App, cfg *config.Config) {
	handler := &Handler{
		application: application,
		cfg:         cfg,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	mux.HandleFunc("/api/v1/dashboard", handler.dashboard)
	mux.HandleFunc("/api/v1/configuration", handler.configuration)
	mux.HandleFunc("/api/v1/powerdns/status", handler.powerDNSStatus)
	mux.HandleFunc("/api/v1/powerdns/zones", handler.powerDNSZones)
	mux.HandleFunc("/api/v1/powerdns/authoritative/zones", handler.authoritativeZones)
	mux.HandleFunc("/api/v1/powerdns/authoritative/zones/", handler.authoritativeZone)
	mux.HandleFunc("/api/v1/powerdns/recursor/cache/flush", handler.recursorCacheFlush)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	if !httpapi.RequireScope(w, r, current, httpapi.ScopeManagementRead) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), powerDNSTimeout(current))
	defer cancel()
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC(),
		"services": map[string]any{
			"admin":    ServiceStatus{Configured: true, Healthy: true, URL: current.AdminAddr},
			"runtime":  h.runtimeStatus(ctx, current),
			"powerdns": powerdns.New(current.PowerDNS).Snapshot(ctx),
		},
		"plugins":       pluginViews(ctx, h.application),
		"cache":         h.application.Registry.CacheStats(),
		"audit_summary": h.application.DNSLog.Summary(8),
		"recent_events": h.application.DNSLog.ListFilteredPage(
			httpapi.AuditEventFilterFromQuery(r),
			httpapi.QueryIntBounded(r, "event_limit", 20, 1, 100),
			"",
		).Events,
		"configuration": current.Editable(),
	})
}

func (h *Handler) configuration(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	switch r.Method {
	case http.MethodGet:
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeConfigRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, current.Editable())
	case http.MethodPut:
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeConfigWrite)
		if !ok {
			return
		}
		var edit config.EditableConfig
		decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&edit); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		next := config.ApplyEditable(current, edit)
		if err := next.Validate(); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := config.SaveEditableFile(current.ConfigFile, edit); err != nil {
			httpapi.Error(w, http.StatusConflict, err.Error())
			return
		}
		reloaded, err := config.LoadFileWithEnvOverrides(current.ConfigFile)
		if err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := reloaded.Validate(); err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := h.application.ReloadFromConfig(reloaded); err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		*h.cfg = reloaded
		runtimeReload := h.reloadRuntime(r, reloaded)
		h.application.AppendManagementAudit("config.update", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"config_file":    reloaded.ConfigFile,
			"runtime_reload": runtimeReload,
			"plugins":        len(reloaded.Plugins),
			"routes":         len(reloaded.Routes),
			"scope":          "admin-api",
		})
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{
			"status":         "saved",
			"runtime_reload": runtimeReload,
			"configuration":  reloaded.Editable(),
		})
	default:
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) powerDNSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), powerDNSTimeout(current))
	defer cancel()
	httpapi.WriteJSON(w, http.StatusOK, powerdns.New(current.PowerDNS).Snapshot(ctx))
}

func (h *Handler) powerDNSZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
		return
	}
	service := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("service")))
	if service == "" {
		service = "authoritative"
	}
	if service != "authoritative" && service != "recursor" {
		httpapi.Error(w, http.StatusBadRequest, "service must be authoritative or recursor")
		return
	}
	zones, err := powerdns.New(current.PowerDNS).Zones(r.Context(), service)
	if err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, zones)
}

func (h *Handler) authoritativeZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
	if !ok {
		return
	}
	var request powerdns.CreateZoneRequest
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	zone, err := powerdns.New(current.PowerDNS).CreateAuthoritativeZone(r.Context(), request)
	if err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	h.application.AppendManagementAudit("powerdns.zone.create", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"zone": zone.Name,
	})
	httpapi.WriteJSON(w, http.StatusCreated, zone)
}

func (h *Handler) authoritativeZone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
	if !ok {
		return
	}
	rawID := strings.TrimPrefix(r.URL.Path, "/api/v1/powerdns/authoritative/zones/")
	zoneID, err := url.PathUnescape(rawID)
	if err != nil || strings.TrimSpace(zoneID) == "" {
		httpapi.Error(w, http.StatusBadRequest, "zone id is required")
		return
	}
	if err := powerdns.New(current.PowerDNS).DeleteAuthoritativeZone(r.Context(), zoneID); err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	h.application.AppendManagementAudit("powerdns.zone.delete", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"zone_id": zoneID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) recursorCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
	if !ok {
		return
	}
	var request struct {
		Domain  string `json:"domain"`
		Subtree bool   `json:"subtree"`
	}
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := powerdns.New(current.PowerDNS).FlushRecursorCache(r.Context(), request.Domain, request.Subtree)
	if err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	h.application.AppendManagementAudit("powerdns.cache.flush", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"domain":  request.Domain,
		"subtree": request.Subtree,
		"count":   result.Count,
	})
	httpapi.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) runtimeStatus(ctx context.Context, cfg config.Config) ServiceStatus {
	status := ServiceStatus{
		Configured: cfg.ControlPlane.RuntimeControlURL != "",
		URL:        cfg.ControlPlane.RuntimeControlURL,
	}
	if !status.Configured {
		return status
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(status.URL, "/")+"/healthz", nil)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	response, err := h.httpClient.Do(req)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer response.Body.Close()
	status.Healthy = response.StatusCode >= 200 && response.StatusCode < 300
	if !status.Healthy {
		status.Error = response.Status
	}
	return status
}

func (h *Handler) reloadRuntime(original *http.Request, cfg config.Config) string {
	if cfg.ControlPlane.RuntimeControlURL == "" {
		return "not_configured"
	}
	target := strings.TrimRight(cfg.ControlPlane.RuntimeControlURL, "/") + "/api/v1/policies/reload"
	req, err := http.NewRequestWithContext(original.Context(), http.MethodPost, target, nil)
	if err != nil {
		return "failed: " + err.Error()
	}
	if authorization := original.Header.Get("Authorization"); authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response, err := h.httpClient.Do(req)
	if err != nil {
		return "failed: " + err.Error()
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return "failed: " + response.Status + " " + strings.TrimSpace(string(body))
	}
	return "loaded"
}

func pluginViews(ctx context.Context, application *app.App) []controlplane.PluginView {
	views := make([]controlplane.PluginView, 0)
	for _, plugin := range application.Registry.Plugins() {
		err := plugin.Health(ctx)
		view := controlplane.PluginView{
			Name:     plugin.Name(),
			Enabled:  plugin.Enabled(),
			Suffixes: plugin.Suffixes(),
			Healthy:  err == nil,
		}
		if err != nil {
			view.LastError = err.Error()
		}
		views = append(views, view)
	}
	return views
}

func powerDNSTimeout(cfg config.Config) time.Duration {
	if cfg.PowerDNS.RequestTimeout > 0 {
		return cfg.PowerDNS.RequestTimeout
	}
	return 5 * time.Second
}
