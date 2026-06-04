package controlplane

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/httpapi"
)

type Scope string

const (
	ScopeAdmin   Scope = "admin-api"
	ScopeRuntime Scope = "plugin-runtime"
)

var runtimeProxyClient = http.DefaultClient

type PluginView struct {
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Suffixes  []string `json:"suffixes"`
	Healthy   bool     `json:"healthy"`
	LastError string   `json:"last_error,omitempty"`
}

type ManagementKeyView struct {
	ID                       string   `json:"id"`
	Scopes                   []string `json:"scopes"`
	Roles                    []string `json:"roles,omitempty"`
	NotBefore                string   `json:"not_before,omitempty"`
	ExpiresAt                string   `json:"expires_at,omitempty"`
	RevokedAt                string   `json:"revoked_at,omitempty"`
	ExpiresInSeconds         int64    `json:"expires_in_seconds,omitempty"`
	AllowedClientCIDRCount   int      `json:"allowed_client_cidr_count"`
	ClientRestrictionEnabled bool     `json:"client_restriction_enabled"`
	Status                   string   `json:"status"`
	RotationDue              bool     `json:"rotation_due"`
	HasOverlappingSuccessor  bool     `json:"has_overlapping_successor"`
	LifecycleAction          string   `json:"lifecycle_action"`
}

type ManagementRoleView struct {
	ID     string   `json:"id"`
	Scopes []string `json:"scopes"`
}

const managementRotationWarning = 7 * 24 * time.Hour

func RegisterHandlers(mux *http.ServeMux, application *app.App, cfg *config.Config, scope Scope) {
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, r *http.Request) {
		current := *cfg
		if r.Method != http.MethodGet {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, current, httpapi.ScopePluginsRead) {
			return
		}
		if proxied, _ := proxyToRuntime(w, r, current, scope); proxied {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, pluginViews(r, application))
	})
	mux.HandleFunc("/api/v1/plugins/", func(w http.ResponseWriter, r *http.Request) {
		current := *cfg
		name, enabled, ok := parsePluginMutation(r.URL.Path)
		if !ok || r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusNotFound, "not found")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePluginsWrite)
		if !ok {
			return
		}
		if proxied, status := proxyToRuntime(w, r, current, scope); proxied {
			application.AppendManagementAudit(pluginOperation(enabled), principal.ID, r.Method, r.URL.Path, http.StatusText(status), map[string]any{
				"plugin":  name,
				"enabled": enabled,
				"proxied": true,
				"scope":   string(scope),
			})
			return
		}
		if setPlugin(w, application, name, enabled) {
			application.AppendManagementAudit(pluginOperation(enabled), principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
				"plugin":  name,
				"enabled": enabled,
				"scope":   string(scope),
			})
		}
	})
	mux.HandleFunc("/api/v1/cache/flush", func(w http.ResponseWriter, r *http.Request) {
		current := *cfg
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCacheWrite)
		if !ok {
			return
		}
		if proxied, status := proxyToRuntime(w, r, current, scope); proxied {
			application.AppendManagementAudit("cache.flush", principal.ID, r.Method, r.URL.Path, http.StatusText(status), map[string]any{
				"proxied": true,
				"scope":   string(scope),
			})
			return
		}
		application.Registry.FlushCache()
		application.AppendManagementAudit("cache.flush", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"scope": string(scope),
		})
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "flushed"})
	})
	mux.HandleFunc("/api/v1/cache/stats", func(w http.ResponseWriter, r *http.Request) {
		current := *cfg
		if r.Method != http.MethodGet {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeCacheRead) {
			return
		}
		if proxied, _ := proxyToRuntime(w, r, current, scope); proxied {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, application.Registry.CacheStats())
	})
	mux.HandleFunc("/api/v1/control-plane/boundary", func(w http.ResponseWriter, r *http.Request) {
		current := *cfg
		if r.Method != http.MethodGet {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeManagementRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, Boundary(scope, current))
	})
	mux.HandleFunc("/api/v1/management/keys", func(w http.ResponseWriter, r *http.Request) {
		current := *cfg
		if r.Method != http.MethodGet {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeManagementRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, ManagementKeys(current, time.Now().UTC()))
	})
}

func Boundary(scope Scope, cfg config.Config) map[string]any {
	mode := "process-local"
	note := "admin-api and plugin-runtime load the same config file but do not share live mutable state"
	liveControls := []string{}
	if scope == ScopeRuntime {
		mode = "runtime-local-control-plane"
		note = "plugin-runtime control endpoints mutate live data-plane plugin and cache state in this process"
		liveControls = []string{
			"GET /api/v1/plugins",
			"POST /api/v1/plugins/{name}/enable",
			"POST /api/v1/plugins/{name}/disable",
			"POST /api/v1/cache/flush",
			"GET /api/v1/cache/stats",
		}
	} else if cfg.ControlPlane.AdminProxyRuntime && cfg.ControlPlane.RuntimeControlURL != "" {
		mode = "admin-runtime-proxy"
		note = "admin-api proxies live plugin and cache controls to plugin-runtime"
		liveControls = []string{
			"GET /api/v1/plugins",
			"POST /api/v1/plugins/{name}/enable",
			"POST /api/v1/plugins/{name}/disable",
			"POST /api/v1/cache/flush",
			"GET /api/v1/cache/stats",
		}
	}
	return map[string]any{
		"scope":               string(scope),
		"mode":                mode,
		"note":                note,
		"config_file":         cfg.ConfigFile,
		"runtime_addr":        cfg.RuntimeAddr,
		"admin_addr":          cfg.AdminAddr,
		"runtime_control_url": cfg.ControlPlane.RuntimeControlURL,
		"live_controls":       liveControls,
	}
}

func ManagementKeys(cfg config.Config, now time.Time) map[string]any {
	keys := make([]ManagementKeyView, 0, len(cfg.Management.Keys))
	for _, key := range cfg.Management.Keys {
		keys = append(keys, managementKeyView(cfg, key, now))
	}
	roles := make([]ManagementRoleView, 0, len(cfg.Management.Roles))
	for _, role := range cfg.Management.Roles {
		roles = append(roles, ManagementRoleView{
			ID:     strings.TrimSpace(role.ID),
			Scopes: normalizedScopes(role.Scopes),
		})
	}
	return map[string]any{
		"auth_required":          cfg.Management.AuthRequired,
		"legacy_key_configured":  strings.TrimSpace(cfg.Management.APIKey) != "",
		"configured_role_count":  len(roles),
		"configured_key_count":   len(keys),
		"active_key_count":       activeManagementKeyCount(keys),
		"rotation_warning_hours": int(managementRotationWarning.Hours()),
		"roles":                  roles,
		"keys":                   keys,
		"token_material_exposed": false,
	}
}

func managementKeyView(cfg config.Config, key config.ManagementKey, now time.Time) ManagementKeyView {
	expiresAt, hasExpiresAt := parseKeyTime(key.ExpiresAt)
	view := ManagementKeyView{
		ID:                       strings.TrimSpace(key.ID),
		Scopes:                   cfg.Management.ScopesForKey(key),
		Roles:                    normalizedRoles(key.Roles),
		NotBefore:                strings.TrimSpace(key.NotBefore),
		ExpiresAt:                strings.TrimSpace(key.ExpiresAt),
		RevokedAt:                strings.TrimSpace(key.RevokedAt),
		AllowedClientCIDRCount:   len(key.AllowedClientCIDRs),
		ClientRestrictionEnabled: len(key.AllowedClientCIDRs) > 0,
		Status:                   managementKeyStatus(key, now),
	}
	if hasExpiresAt && expiresAt.After(now) {
		view.ExpiresInSeconds = int64(expiresAt.Sub(now).Seconds())
	}
	view.HasOverlappingSuccessor = hasOverlappingSuccessor(cfg, key, now)
	view.RotationDue, view.LifecycleAction = managementKeyLifecycle(view.Status, hasExpiresAt, expiresAt, now, view.HasOverlappingSuccessor)
	return view
}

func managementKeyLifecycle(status string, hasExpiresAt bool, expiresAt time.Time, now time.Time, hasSuccessor bool) (bool, string) {
	switch status {
	case "revoked":
		return true, "remove_revoked_key"
	case "expired":
		return true, "remove_expired_key"
	case "not_yet_active":
		return false, "pending_activation"
	}
	if !hasExpiresAt {
		return true, "set_expiration_window"
	}
	if expiresAt.Sub(now) <= managementRotationWarning {
		if hasSuccessor {
			return false, "successor_overlap_ready"
		}
		return true, "schedule_successor_before_expiry"
	}
	if hasSuccessor {
		return false, "rotation_scheduled"
	}
	return false, "active"
}

func hasOverlappingSuccessor(cfg config.Config, key config.ManagementKey, now time.Time) bool {
	keyExpiresAt, ok := parseKeyTime(key.ExpiresAt)
	if !ok || !keyExpiresAt.After(now) {
		return false
	}
	keyID := strings.TrimSpace(key.ID)
	keyScopes := cfg.Management.ScopesForKey(key)
	for _, candidate := range cfg.Management.Keys {
		if strings.TrimSpace(candidate.ID) == keyID || !sameScopes(keyScopes, cfg.Management.ScopesForKey(candidate)) {
			continue
		}
		if candidateExpiresAt, ok := parseKeyTime(candidate.ExpiresAt); ok && !candidateExpiresAt.After(keyExpiresAt) {
			continue
		}
		if candidateNotBefore, ok := parseKeyTime(candidate.NotBefore); ok && candidateNotBefore.After(keyExpiresAt) {
			continue
		}
		if managementKeyStatus(candidate, now) == "expired" {
			continue
		}
		return true
	}
	return false
}

func sameScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, scope := range a {
		counts[strings.TrimSpace(strings.ToLower(scope))]++
	}
	for _, scope := range b {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if counts[scope] == 0 {
			return false
		}
		counts[scope]--
	}
	return true
}

func managementKeyStatus(key config.ManagementKey, now time.Time) string {
	if revokedAt, ok := parseKeyTime(key.RevokedAt); ok && !now.Before(revokedAt) {
		return "revoked"
	}
	if notBefore, ok := parseKeyTime(key.NotBefore); ok && now.Before(notBefore) {
		return "not_yet_active"
	}
	if expiresAt, ok := parseKeyTime(key.ExpiresAt); ok && !now.Before(expiresAt) {
		return "expired"
	}
	return "active"
}

func parseKeyTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func normalizedScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{httpapi.ScopeRead}
	}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope != "" {
			out = append(out, scope)
		}
	}
	if len(out) == 0 {
		return []string{httpapi.ScopeRead}
	}
	return out
}

func normalizedRoles(roles []string) []string {
	out := make([]string, 0, len(roles))
	seen := map[string]bool{}
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		out = append(out, role)
	}
	return out
}

func activeManagementKeyCount(keys []ManagementKeyView) int {
	count := 0
	for _, key := range keys {
		if key.Status == "active" {
			count++
		}
	}
	return count
}

func proxyToRuntime(w http.ResponseWriter, r *http.Request, cfg config.Config, scope Scope) (bool, int) {
	if scope != ScopeAdmin || !cfg.ControlPlane.AdminProxyRuntime || cfg.ControlPlane.RuntimeControlURL == "" {
		return false, 0
	}
	target := strings.TrimRight(cfg.ControlPlane.RuntimeControlURL, "/") + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return true, http.StatusBadGateway
	}
	req.Header = r.Header.Clone()
	resp, err := runtimeProxyClient.Do(req)
	if err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return true, http.StatusBadGateway
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return true, resp.StatusCode
	}
	return true, resp.StatusCode
}

func pluginViews(r *http.Request, application *app.App) []PluginView {
	views := []PluginView{}
	for _, p := range application.Registry.Plugins() {
		err := p.Health(r.Context())
		view := PluginView{Name: p.Name(), Enabled: p.Enabled(), Suffixes: p.Suffixes(), Healthy: err == nil}
		if err != nil {
			view.LastError = err.Error()
		}
		views = append(views, view)
	}
	return views
}

func setPlugin(w http.ResponseWriter, application *app.App, name string, enabled bool) bool {
	name = strings.TrimSpace(name)
	if !application.Registry.SetPluginEnabled(name, enabled) {
		httpapi.Error(w, http.StatusNotFound, "plugin not found")
		return false
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"name": name, "enabled": enabled})
	return true
}

func parsePluginMutation(path string) (string, bool, bool) {
	const prefix = "/api/v1/plugins/"
	if !strings.HasPrefix(path, prefix) {
		return "", false, false
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		return "", false, false
	}
	switch parts[1] {
	case "enable":
		return parts[0], true, true
	case "disable":
		return parts[0], false, true
	default:
		return "", false, false
	}
}

func pluginOperation(enabled bool) string {
	if enabled {
		return "plugin.enable"
	}
	return "plugin.disable"
}
