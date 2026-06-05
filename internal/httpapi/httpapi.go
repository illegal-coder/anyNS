package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/dnslog"
)

const (
	ScopeRead            = "read"
	ScopeWrite           = "write"
	ScopePluginsRead     = "plugins:read"
	ScopePluginsWrite    = "plugins:write"
	ScopeCacheRead       = "cache:read"
	ScopeCacheWrite      = "cache:write"
	ScopePolicyWrite     = "policy:write"
	ScopeAuditRead       = "audit:read"
	ScopeHoneypotRead    = "honeypot:read"
	ScopeHoneypotWrite   = "honeypot:write"
	ScopeManagementRead  = "management:read"
	ScopeManagementWrite = "management:write"
)

type Principal struct {
	ID     string
	Scopes []string
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode http response: %v", err)
	}
}

func Error(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]any{"error": message})
}

func DecodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func QueryIntBounded(r *http.Request, name string, fallback, min, max int) int {
	value := fallback
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err == nil {
			value = parsed
		}
	}
	if min > 0 && value < min {
		value = min
	}
	if max > 0 && value > max {
		value = max
	}
	return value
}

func AuditEventFilterFromQuery(r *http.Request) dnslog.EventFilter {
	query := r.URL.Query()
	return dnslog.EventFilter{
		TraceID:      strings.TrimSpace(query.Get("trace_id")),
		ClientIP:     strings.TrimSpace(query.Get("client_ip")),
		ClientView:   strings.TrimSpace(query.Get("client_view")),
		Tenant:       strings.TrimSpace(query.Get("tenant")),
		QName:        strings.TrimSpace(query.Get("qname")),
		QType:        strings.TrimSpace(query.Get("qtype")),
		SourcePlugin: strings.TrimSpace(query.Get("source_plugin")),
		RiskLevel:    strings.TrimSpace(query.Get("risk_level")),
		Action:       strings.TrimSpace(query.Get("action")),
		MatchedRule:  strings.TrimSpace(query.Get("matched_rule")),
		RCode:        strings.TrimSpace(query.Get("rcode")),
		Since:        queryTime(query.Get("since")),
		Until:        queryTime(query.Get("until")),
		Order:        queryAuditOrder(query.Get("order")),
	}
}

func queryAuditOrder(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "asc", "desc":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func queryTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func Authorized(r *http.Request, cfg config.Config) bool {
	_, ok := PrincipalFromRequest(r, cfg)
	return ok
}

func PrincipalFromRequest(r *http.Request, cfg config.Config) (Principal, bool) {
	if !cfg.Management.AuthRequired {
		return Principal{ID: "anonymous", Scopes: []string{ScopeRead, ScopeWrite}}, true
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return Principal{}, false
	}
	got := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	now := time.Now()
	for _, key := range cfg.Management.Keys {
		if key.APIKey == "" || !managementKeyActive(key, now) || !managementKeyAllowsClient(key, r) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(key.APIKey)) == 1 {
			return Principal{ID: key.ID, Scopes: cfg.Management.ScopesForKey(key)}, true
		}
	}
	if cfg.Management.APIKey != "" && subtle.ConstantTimeCompare([]byte(got), []byte(cfg.Management.APIKey)) == 1 {
		return Principal{ID: "legacy-management-key", Scopes: []string{ScopeRead, ScopeWrite}}, true
	}
	return Principal{}, false
}

func managementKeyActive(key config.ManagementKey, now time.Time) bool {
	if notBefore, ok := parseKeyTime(key.NotBefore); ok && now.Before(notBefore) {
		return false
	}
	if expiresAt, ok := parseKeyTime(key.ExpiresAt); ok && !now.Before(expiresAt) {
		return false
	}
	if revokedAt, ok := parseKeyTime(key.RevokedAt); ok && !now.Before(revokedAt) {
		return false
	}
	return true
}

func managementKeyAllowsClient(key config.ManagementKey, r *http.Request) bool {
	if len(key.AllowedClientCIDRs) == 0 {
		return true
	}
	clientIP := requestClientIP(r)
	if clientIP == nil {
		return false
	}
	for _, allowed := range key.AllowedClientCIDRs {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if ip := net.ParseIP(allowed); ip != nil {
			if ip.Equal(clientIP) {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(allowed); err == nil && network.Contains(clientIP) {
			return true
		}
	}
	return false
}

func requestClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func parseKeyTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func RequireAuth(w http.ResponseWriter, r *http.Request, cfg config.Config) bool {
	if Authorized(r, cfg) {
		return true
	}
	Error(w, http.StatusUnauthorized, "unauthorized")
	return false
}

func RequireScope(w http.ResponseWriter, r *http.Request, cfg config.Config, scope string) bool {
	_, ok := RequireScopePrincipal(w, r, cfg, scope)
	return ok
}

func RequireScopePrincipal(w http.ResponseWriter, r *http.Request, cfg config.Config, scope string) (Principal, bool) {
	principal, ok := PrincipalFromRequest(r, cfg)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return Principal{}, false
	}
	if principal.HasScope(scope) {
		return principal, true
	}
	Error(w, http.StatusForbidden, "forbidden")
	return Principal{}, false
}

func (p Principal) HasScope(scope string) bool {
	scope = strings.TrimSpace(strings.ToLower(scope))
	for _, current := range p.Scopes {
		current = strings.TrimSpace(strings.ToLower(current))
		if current == scope || current == "*" || current == "admin" {
			return true
		}
		if scopeAccessKind(scope) == current {
			return true
		}
	}
	return false
}

func scopeAccessKind(scope string) string {
	if strings.HasSuffix(scope, ":read") {
		return ScopeRead
	}
	if strings.HasSuffix(scope, ":write") {
		return ScopeWrite
	}
	return ""
}
