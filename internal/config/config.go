package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/security"
)

type Config struct {
	AdminAddr          string
	RuntimeAddr        string
	LogForwarderAddr   string
	HoneypotURL        string
	HoneypotAPIKey     string
	HoneypotHMACSecret string
	RequestTimeout     time.Duration
	Routes             []plugins.Route
	Plugins            []PluginConfig
	Security           security.Policy
	DNSLog             DNSLogConfig
	Honeypot           HoneypotConfig
	ControlPlane       ControlPlaneConfig
	Management         ManagementConfig
	PowerDNS           PowerDNSConfig
	ConfigFile         string
}

type PluginConfig struct {
	Name              string            `json:"name"`
	Enabled           bool              `json:"enabled"`
	BackendType       string            `json:"backend_type,omitempty"`
	BackendURL        string            `json:"backend_url,omitempty"`
	BackendAPIKey     string            `json:"backend_api_key,omitempty"`
	BackendAPIKeyFile string            `json:"backend_api_key_file,omitempty"`
	RequestTimeout    durationOrSeconds `json:"request_timeout,omitempty"`
}

type DNSLogConfig struct {
	Limit int    `json:"limit"`
	Path  string `json:"path"`
}

type HoneypotConfig struct {
	URL                   string        `json:"url"`
	APIKey                string        `json:"api_key"`
	APIKeyFile            string        `json:"api_key_file"`
	HMACSecret            string        `json:"hmac_secret"`
	HMACSecretFile        string        `json:"hmac_secret_file"`
	FailedQueuePath       string        `json:"failed_queue_path"`
	FailedQueueMaxEntries int           `json:"failed_queue_max_entries"`
	RetryInterval         time.Duration `json:"retry_interval"`
	RetryIntervalSeconds  int           `json:"retry_interval_seconds"`
	MaxAttempts           int           `json:"max_attempts"`
	RequestTimeout        time.Duration `json:"request_timeout"`
	RequestTimeoutSeconds int           `json:"request_timeout_seconds"`
}

type ControlPlaneConfig struct {
	AdminProxyRuntime bool   `json:"admin_proxy_runtime"`
	RuntimeControlURL string `json:"runtime_control_url"`
}

type PowerDNSConfig struct {
	AuthoritativeURL        string        `json:"authoritative_url"`
	AuthoritativeAPIKey     string        `json:"authoritative_api_key"`
	AuthoritativeAPIKeyFile string        `json:"authoritative_api_key_file,omitempty"`
	RecursorURL             string        `json:"recursor_url"`
	RecursorAPIKey          string        `json:"recursor_api_key"`
	RecursorAPIKeyFile      string        `json:"recursor_api_key_file,omitempty"`
	ServerID                string        `json:"server_id"`
	RequestTimeout          time.Duration `json:"-"`
	RequestTimeoutSeconds   int           `json:"request_timeout_seconds"`
}

type ManagementConfig struct {
	APIKey       string           `json:"api_key"`
	APIKeyFile   string           `json:"api_key_file,omitempty"`
	AuthRequired bool             `json:"auth_required"`
	Roles        []ManagementRole `json:"roles"`
	Keys         []ManagementKey  `json:"keys"`
}

type ManagementRole struct {
	ID     string   `json:"id"`
	Scopes []string `json:"scopes"`
}

type ManagementKey struct {
	ID                 string   `json:"id"`
	APIKey             string   `json:"api_key"`
	APIKeyFile         string   `json:"api_key_file,omitempty"`
	Scopes             []string `json:"scopes"`
	Roles              []string `json:"roles,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	RevokedAt          string   `json:"revoked_at,omitempty"`
	AllowedClientCIDRs []string `json:"allowed_client_cidrs,omitempty"`
}

type ValidationError struct {
	Problems []string
}

func (e ValidationError) Error() string {
	return "config validation failed: " + strings.Join(e.Problems, "; ")
}

type fileConfig struct {
	AdminAddr        string                 `json:"admin_addr"`
	RuntimeAddr      string                 `json:"runtime_addr"`
	LogForwarderAddr string                 `json:"log_forwarder_addr"`
	RequestTimeout   durationOrSeconds      `json:"request_timeout"`
	Routes           []plugins.Route        `json:"routes"`
	Plugins          []PluginConfig         `json:"plugins"`
	Security         security.Policy        `json:"security"`
	DNSLog           DNSLogConfig           `json:"dnslog"`
	Honeypot         fileHoneypotConfig     `json:"honeypot"`
	ControlPlane     ControlPlaneConfig     `json:"control_plane"`
	Management       ManagementConfig       `json:"management"`
	PowerDNS         filePowerDNSConfig     `json:"powerdns"`
	Extra            map[string]interface{} `json:"-"`
}

type fileHoneypotConfig struct {
	URL                   string            `json:"url"`
	APIKey                string            `json:"api_key"`
	APIKeyFile            string            `json:"api_key_file"`
	HMACSecret            string            `json:"hmac_secret"`
	HMACSecretFile        string            `json:"hmac_secret_file"`
	FailedQueuePath       string            `json:"failed_queue_path"`
	FailedQueueMaxEntries int               `json:"failed_queue_max_entries"`
	RetryInterval         durationOrSeconds `json:"retry_interval"`
	MaxAttempts           int               `json:"max_attempts"`
	RequestTimeout        durationOrSeconds `json:"request_timeout"`
}

type filePowerDNSConfig struct {
	AuthoritativeURL        string            `json:"authoritative_url"`
	AuthoritativeAPIKey     string            `json:"authoritative_api_key"`
	AuthoritativeAPIKeyFile string            `json:"authoritative_api_key_file"`
	RecursorURL             string            `json:"recursor_url"`
	RecursorAPIKey          string            `json:"recursor_api_key"`
	RecursorAPIKeyFile      string            `json:"recursor_api_key_file"`
	ServerID                string            `json:"server_id"`
	RequestTimeout          durationOrSeconds `json:"request_timeout"`
}

type durationOrSeconds struct {
	time.Duration
}

func Default() Config {
	return Config{
		AdminAddr:          env("ANYNS_ADMIN_ADDR", ":8080"),
		RuntimeAddr:        env("ANYNS_RUNTIME_ADDR", ":8081"),
		LogForwarderAddr:   env("ANYNS_LOG_FORWARDER_ADDR", ":8082"),
		HoneypotURL:        env("ANYNS_HONEYPOT_URL", ""),
		HoneypotAPIKey:     env("ANYNS_HONEYPOT_API_KEY", ""),
		HoneypotHMACSecret: env("ANYNS_HONEYPOT_HMAC_SECRET", ""),
		RequestTimeout:     time.Duration(envInt("ANYNS_REQUEST_TIMEOUT_SECONDS", 3)) * time.Second,
		Routes:             plugins.DefaultRoutes(),
		Plugins: []PluginConfig{
			{Name: "hns", Enabled: true},
			{Name: "ens", Enabled: false},
			{Name: "namecoin-bit", Enabled: false},
			{Name: "stacks-bns", Enabled: false},
			{Name: "pns-polkadot", Enabled: false},
			{Name: "pns-pulsechain", Enabled: false},
			{Name: "unstoppable-domains", Enabled: false},
			{Name: "solana-sns", Enabled: false},
			{Name: "space-id", Enabled: false},
			{Name: "ton-dns", Enabled: false},
			{Name: "tezos-domains", Enabled: false},
			{Name: "aptos-names", Enabled: false},
			{Name: "suins", Enabled: false},
			{Name: "freename-fns", Enabled: false},
			{Name: "rif-rns", Enabled: false},
			{Name: "fio-handle", Enabled: false},
			{Name: "openalias", Enabled: false},
			{Name: "ada-handle", Enabled: false},
			{Name: "did-bit", Enabled: false},
		},
		Security: security.DefaultPolicy(),
		DNSLog: DNSLogConfig{
			Limit: envInt("ANYNS_DNSLOG_LIMIT", 1000),
			Path:  env("ANYNS_DNSLOG_PATH", ""),
		},
		Honeypot: HoneypotConfig{
			URL:                   env("ANYNS_HONEYPOT_URL", ""),
			APIKey:                env("ANYNS_HONEYPOT_API_KEY", ""),
			HMACSecret:            env("ANYNS_HONEYPOT_HMAC_SECRET", ""),
			FailedQueuePath:       env("ANYNS_HONEYPOT_FAILED_QUEUE_PATH", ""),
			FailedQueueMaxEntries: envInt("ANYNS_HONEYPOT_FAILED_QUEUE_MAX_ENTRIES", 10000),
			RetryInterval:         time.Duration(envInt("ANYNS_HONEYPOT_RETRY_INTERVAL_SECONDS", 30)) * time.Second,
			MaxAttempts:           envInt("ANYNS_HONEYPOT_MAX_ATTEMPTS", 5),
			RequestTimeout:        time.Duration(envInt("ANYNS_HONEYPOT_REQUEST_TIMEOUT_SECONDS", 5)) * time.Second,
		},
		ControlPlane: ControlPlaneConfig{
			AdminProxyRuntime: envBool("ANYNS_ADMIN_PROXY_RUNTIME_CONTROL", false),
			RuntimeControlURL: env("ANYNS_RUNTIME_CONTROL_URL", ""),
		},
		Management: ManagementConfig{
			APIKey:       env("ANYNS_MANAGEMENT_API_KEY", ""),
			AuthRequired: envBool("ANYNS_MANAGEMENT_AUTH_REQUIRED", false),
		},
		PowerDNS: PowerDNSConfig{
			AuthoritativeURL:      env("ANYNS_PDNS_AUTH_URL", ""),
			AuthoritativeAPIKey:   env("PDNS_AUTH_API_KEY", ""),
			RecursorURL:           env("ANYNS_PDNS_RECURSOR_URL", ""),
			RecursorAPIKey:        env("PDNS_RECURSOR_API_KEY", ""),
			ServerID:              env("ANYNS_PDNS_SERVER_ID", "localhost"),
			RequestTimeout:        time.Duration(envInt("ANYNS_PDNS_REQUEST_TIMEOUT_SECONDS", 5)) * time.Second,
			RequestTimeoutSeconds: envInt("ANYNS_PDNS_REQUEST_TIMEOUT_SECONDS", 5),
		},
	}
}

func FromEnv() Config {
	cfg, err := FromEnvWithError()
	if err != nil {
		return Default()
	}
	return cfg
}

func FromEnvWithError() (Config, error) {
	cfg := Default()
	path := env("ANYNS_CONFIG_FILE", "")
	if path == "" {
		return cfg, nil
	}
	loaded, err := LoadFile(path)
	if err != nil {
		return cfg, err
	}
	loaded.ConfigFile = path
	return applyEnvOverrides(loaded), nil
}

func LoadFile(path string) (Config, error) {
	cfg := Default()
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	if err := LoadWithBase(file, &cfg, filepath.Dir(path)); err != nil {
		return cfg, err
	}
	cfg.ConfigFile = path
	return cfg, nil
}

func LoadFileWithEnvOverrides(path string) (Config, error) {
	cfg, err := LoadFile(path)
	if err != nil {
		return cfg, err
	}
	return applyEnvOverrides(cfg), nil
}

func Load(r io.Reader, cfg *Config) error {
	return LoadWithBase(r, cfg, "")
}

func LoadWithBase(r io.Reader, cfg *Config, baseDir string) error {
	var raw fileConfig
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if raw.AdminAddr != "" {
		cfg.AdminAddr = raw.AdminAddr
	}
	if raw.RuntimeAddr != "" {
		cfg.RuntimeAddr = raw.RuntimeAddr
	}
	if raw.LogForwarderAddr != "" {
		cfg.LogForwarderAddr = raw.LogForwarderAddr
	}
	if raw.RequestTimeout.Duration > 0 {
		cfg.RequestTimeout = raw.RequestTimeout.Duration
	}
	if len(raw.Routes) > 0 {
		cfg.Routes = raw.Routes
	}
	if len(raw.Plugins) > 0 {
		cfg.Plugins = raw.Plugins
	}
	if raw.Security.Configured {
		cfg.Security = raw.Security.WithDefaults()
	}
	if raw.DNSLog.Limit != 0 || raw.DNSLog.Path != "" {
		if raw.DNSLog.Limit <= 0 {
			raw.DNSLog.Limit = cfg.DNSLog.Limit
		}
		cfg.DNSLog = raw.DNSLog
	}
	applyHoneypot(raw.Honeypot, cfg)
	if raw.ControlPlane.AdminProxyRuntime {
		cfg.ControlPlane.AdminProxyRuntime = true
	}
	if raw.ControlPlane.RuntimeControlURL != "" {
		cfg.ControlPlane.RuntimeControlURL = raw.ControlPlane.RuntimeControlURL
	}
	if raw.Management.APIKey != "" {
		cfg.Management.APIKey = raw.Management.APIKey
	}
	if raw.Management.APIKeyFile != "" {
		cfg.Management.APIKeyFile = raw.Management.APIKeyFile
	}
	if raw.Management.AuthRequired {
		cfg.Management.AuthRequired = true
	}
	if len(raw.Management.Roles) > 0 {
		cfg.Management.Roles = raw.Management.Roles
	}
	if len(raw.Management.Keys) > 0 {
		cfg.Management.Keys = raw.Management.Keys
	}
	applyPowerDNS(raw.PowerDNS, cfg)
	if err := resolveSecretFiles(cfg, baseDir); err != nil {
		return err
	}
	return nil
}

func (cfg Config) Validate() error {
	var problems []string
	if strings.TrimSpace(cfg.AdminAddr) == "" {
		problems = append(problems, "admin_addr is required")
	}
	if strings.TrimSpace(cfg.RuntimeAddr) == "" {
		problems = append(problems, "runtime_addr is required")
	}
	if strings.TrimSpace(cfg.LogForwarderAddr) == "" {
		problems = append(problems, "log_forwarder_addr is required")
	}
	if cfg.RequestTimeout <= 0 {
		problems = append(problems, "request_timeout must be greater than zero")
	}
	if cfg.DNSLog.Limit <= 0 {
		problems = append(problems, "dnslog.limit must be greater than zero")
	}
	if cfg.Honeypot.FailedQueueMaxEntries <= 0 {
		problems = append(problems, "honeypot.failed_queue_max_entries must be greater than zero")
	}
	if cfg.Honeypot.RetryInterval <= 0 {
		problems = append(problems, "honeypot.retry_interval must be greater than zero")
	}
	if cfg.Honeypot.MaxAttempts <= 0 {
		problems = append(problems, "honeypot.max_attempts must be greater than zero")
	}
	if cfg.Honeypot.RequestTimeout <= 0 {
		problems = append(problems, "honeypot.request_timeout must be greater than zero")
	}
	if cfg.ControlPlane.AdminProxyRuntime && strings.TrimSpace(cfg.ControlPlane.RuntimeControlURL) == "" {
		problems = append(problems, "control_plane.runtime_control_url is required when control_plane.admin_proxy_runtime is true")
	}
	if cfg.ControlPlane.RuntimeControlURL != "" && !validHTTPURL(cfg.ControlPlane.RuntimeControlURL) {
		problems = append(problems, "control_plane.runtime_control_url must be an http or https URL with a host")
	}
	if cfg.PowerDNS.AuthoritativeURL != "" && !validHTTPURL(cfg.PowerDNS.AuthoritativeURL) {
		problems = append(problems, "powerdns.authoritative_url must be an http or https URL with a host")
	}
	if cfg.PowerDNS.RecursorURL != "" && !validHTTPURL(cfg.PowerDNS.RecursorURL) {
		problems = append(problems, "powerdns.recursor_url must be an http or https URL with a host")
	}
	if strings.TrimSpace(cfg.PowerDNS.ServerID) == "" {
		problems = append(problems, "powerdns.server_id is required")
	}
	if cfg.PowerDNS.RequestTimeout <= 0 {
		problems = append(problems, "powerdns.request_timeout must be greater than zero")
	}
	if strings.TrimSpace(cfg.PowerDNS.AuthoritativeAPIKey) != "" && strings.TrimSpace(cfg.PowerDNS.AuthoritativeAPIKeyFile) != "" {
		problems = append(problems, "powerdns must not set both authoritative_api_key and authoritative_api_key_file")
	}
	if strings.TrimSpace(cfg.PowerDNS.RecursorAPIKey) != "" && strings.TrimSpace(cfg.PowerDNS.RecursorAPIKeyFile) != "" {
		problems = append(problems, "powerdns must not set both recursor_api_key and recursor_api_key_file")
	}

	pluginNames := make(map[string]bool, len(cfg.Plugins))
	for i, plugin := range cfg.Plugins {
		name := strings.TrimSpace(plugin.Name)
		if name == "" {
			problems = append(problems, fmt.Sprintf("plugins[%d].name is required", i))
			continue
		}
		if pluginNames[name] {
			problems = append(problems, fmt.Sprintf("plugins[%d].name %q is duplicated", i, name))
		}
		pluginNames[name] = true
		if plugin.RequestTimeout.Duration < 0 {
			problems = append(problems, fmt.Sprintf("plugins[%d].request_timeout must not be negative", i))
		}
		if plugin.BackendURL != "" && !validPluginBackendURL(plugin.BackendURL) {
			problems = append(problems, fmt.Sprintf("plugins[%d].backend_url must use http, https, or dns scheme", i))
		}
		if !validPluginBackendType(name, plugin.BackendType) {
			problems = append(problems, fmt.Sprintf("plugins[%d].backend_type %q is unsupported for plugin %q", i, plugin.BackendType, name))
		}
		if strings.TrimSpace(plugin.BackendAPIKey) != "" && strings.TrimSpace(plugin.BackendAPIKeyFile) != "" {
			problems = append(problems, fmt.Sprintf("plugins[%d] must not set both backend_api_key and backend_api_key_file", i))
		}
	}

	for i, route := range cfg.Routes {
		if strings.TrimSpace(route.Name) == "" {
			problems = append(problems, fmt.Sprintf("routes[%d].name is required", i))
		}
		pluginName := strings.TrimSpace(route.Plugin)
		if pluginName == "" {
			problems = append(problems, fmt.Sprintf("routes[%d].plugin is required", i))
		} else if !pluginNames[pluginName] {
			problems = append(problems, fmt.Sprintf("routes[%d].plugin %q is not configured", i, pluginName))
		}
		if len(route.Domains) == 0 && len(route.Suffixes) == 0 {
			problems = append(problems, fmt.Sprintf("routes[%d] must declare at least one domain or suffix", i))
		}
		for j, suffix := range route.Suffixes {
			trimmed := strings.TrimSpace(suffix)
			if trimmed == "" || trimmed == "." {
				problems = append(problems, fmt.Sprintf("routes[%d].suffixes[%d] is invalid", i, j))
			}
		}
		for j, domain := range route.Domains {
			if strings.TrimSpace(domain) == "" {
				problems = append(problems, fmt.Sprintf("routes[%d].domains[%d] is required", i, j))
			}
		}
	}

	if cfg.Security.SinkholeTTL < 0 {
		problems = append(problems, "security.sinkhole_ttl must not be negative")
	}
	if cfg.Security.QueryRateWindowSeconds < 0 {
		problems = append(problems, "security.query_rate_window_seconds must not be negative")
	}
	if cfg.Security.QueryRateThreshold < 0 {
		problems = append(problems, "security.query_rate_threshold must not be negative")
	}
	if cfg.Security.RandomSubdomainWindowSec < 0 {
		problems = append(problems, "security.random_subdomain_window_seconds must not be negative")
	}
	if cfg.Security.RandomSubdomainThreshold < 0 {
		problems = append(problems, "security.random_subdomain_threshold must not be negative")
	}
	if cfg.Security.NXDomainWindowSeconds < 0 {
		problems = append(problems, "security.nxdomain_window_seconds must not be negative")
	}
	if cfg.Security.NXDomainThreshold < 0 {
		problems = append(problems, "security.nxdomain_threshold must not be negative")
	}
	if cfg.Security.SinkholeIPv4 != "" && !isIPv4(cfg.Security.SinkholeIPv4) {
		problems = append(problems, "security.sinkhole_ipv4 must be a valid IPv4 address")
	}
	if cfg.Security.SinkholeIPv6 != "" && !isIPv6(cfg.Security.SinkholeIPv6) {
		problems = append(problems, "security.sinkhole_ipv6 must be a valid IPv6 address")
	}
	for i, domain := range cfg.Security.AllowlistDomains {
		if strings.TrimSpace(domain) == "" {
			problems = append(problems, fmt.Sprintf("security.allowlist_domains[%d] is required", i))
		}
	}
	for i, domain := range cfg.Security.DenylistDomains {
		if strings.TrimSpace(domain) == "" {
			problems = append(problems, fmt.Sprintf("security.denylist_domains[%d] is required", i))
		}
	}
	for i, domain := range cfg.Security.SinkholeDomains {
		if strings.TrimSpace(domain) == "" {
			problems = append(problems, fmt.Sprintf("security.sinkhole_domains[%d] is required", i))
		}
	}

	if strings.TrimSpace(cfg.Honeypot.APIKey) != "" && strings.TrimSpace(cfg.Honeypot.APIKeyFile) != "" {
		problems = append(problems, "honeypot must not set both api_key and api_key_file")
	}
	if strings.TrimSpace(cfg.Honeypot.HMACSecret) != "" && strings.TrimSpace(cfg.Honeypot.HMACSecretFile) != "" {
		problems = append(problems, "honeypot must not set both hmac_secret and hmac_secret_file")
	}

	if strings.TrimSpace(cfg.Management.APIKey) != "" && strings.TrimSpace(cfg.Management.APIKeyFile) != "" {
		problems = append(problems, "management must not set both api_key and api_key_file")
	}
	if cfg.Management.AuthRequired && cfg.Management.APIKey == "" && !hasUsableManagementKey(cfg.Management.Keys) {
		problems = append(problems, "management.auth_required requires management.api_key or at least one management.keys[].api_key")
	}
	seenRoleIDs := map[string]bool{}
	roleIDs := map[string]bool{}
	for i, role := range cfg.Management.Roles {
		id := strings.TrimSpace(role.ID)
		if id == "" {
			problems = append(problems, fmt.Sprintf("management.roles[%d].id is required", i))
		} else if seenRoleIDs[id] {
			problems = append(problems, fmt.Sprintf("management.roles[%d].id %q is duplicated", i, id))
		}
		seenRoleIDs[id] = true
		roleIDs[id] = true
		if len(role.Scopes) == 0 {
			problems = append(problems, fmt.Sprintf("management.roles[%d].scopes must not be empty", i))
		}
		for j, scope := range role.Scopes {
			if !supportedManagementScope(scope) {
				problems = append(problems, fmt.Sprintf("management.roles[%d].scopes[%d] %q is unsupported", i, j, scope))
			}
		}
	}
	seenKeyIDs := map[string]bool{}
	for i, key := range cfg.Management.Keys {
		id := strings.TrimSpace(key.ID)
		if id == "" {
			problems = append(problems, fmt.Sprintf("management.keys[%d].id is required", i))
		} else if seenKeyIDs[id] {
			problems = append(problems, fmt.Sprintf("management.keys[%d].id %q is duplicated", i, id))
		}
		seenKeyIDs[id] = true
		notBefore, hasNotBefore := parseOptionalTime(key.NotBefore)
		expiresAt, hasExpiresAt := parseOptionalTime(key.ExpiresAt)
		_, hasRevokedAt := parseOptionalTime(key.RevokedAt)
		if strings.TrimSpace(key.NotBefore) != "" && !hasNotBefore {
			problems = append(problems, fmt.Sprintf("management.keys[%d].not_before must be RFC3339", i))
		}
		if strings.TrimSpace(key.ExpiresAt) != "" && !hasExpiresAt {
			problems = append(problems, fmt.Sprintf("management.keys[%d].expires_at must be RFC3339", i))
		}
		if strings.TrimSpace(key.RevokedAt) != "" && !hasRevokedAt {
			problems = append(problems, fmt.Sprintf("management.keys[%d].revoked_at must be RFC3339", i))
		}
		if strings.TrimSpace(key.APIKey) != "" && strings.TrimSpace(key.APIKeyFile) != "" {
			problems = append(problems, fmt.Sprintf("management.keys[%d] must not set both api_key and api_key_file", i))
		}
		if hasNotBefore && hasExpiresAt && !expiresAt.After(notBefore) {
			problems = append(problems, fmt.Sprintf("management.keys[%d].expires_at must be after not_before", i))
		}
		for j, scope := range key.Scopes {
			if !supportedManagementScope(scope) {
				problems = append(problems, fmt.Sprintf("management.keys[%d].scopes[%d] %q is unsupported", i, j, scope))
			}
		}
		for j, roleID := range key.Roles {
			roleID = strings.TrimSpace(roleID)
			if roleID == "" {
				problems = append(problems, fmt.Sprintf("management.keys[%d].roles[%d] is required", i, j))
			} else if !roleIDs[roleID] {
				problems = append(problems, fmt.Sprintf("management.keys[%d].roles[%d] %q is not configured", i, j, roleID))
			}
		}
		for j, cidr := range key.AllowedClientCIDRs {
			if !validClientCIDR(cidr) {
				problems = append(problems, fmt.Sprintf("management.keys[%d].allowed_client_cidrs[%d] must be a valid IP address or CIDR", i, j))
			}
		}
	}

	if len(problems) > 0 {
		return ValidationError{Problems: problems}
	}
	return nil
}

func supportedManagementScope(scope string) bool {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "read", "write", "admin", "*",
		"plugins:read", "plugins:write",
		"cache:read", "cache:write",
		"policy:write",
		"audit:read",
		"honeypot:read", "honeypot:write",
		"management:read", "management:write",
		"powerdns:read", "powerdns:write",
		"config:read", "config:write":
		return true
	default:
		return false
	}
}

func parseOptionalTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func hasUsableManagementKey(keys []ManagementKey) bool {
	for _, key := range keys {
		if strings.TrimSpace(key.APIKey) != "" {
			return true
		}
	}
	return false
}

func (m ManagementConfig) ScopesForKey(key ManagementKey) []string {
	scopes := append([]string{}, key.Scopes...)
	if len(key.Roles) > 0 && len(m.Roles) > 0 {
		roleScopes := map[string][]string{}
		for _, role := range m.Roles {
			id := strings.TrimSpace(role.ID)
			if id != "" {
				roleScopes[id] = role.Scopes
			}
		}
		for _, roleID := range key.Roles {
			scopes = append(scopes, roleScopes[strings.TrimSpace(roleID)]...)
		}
	}
	return normalizedManagementScopes(scopes)
}

func normalizedManagementScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	if len(out) == 0 {
		return []string{"read"}
	}
	return out
}

func isIPv4(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil
}

func isIPv6(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() == nil
}

func validClientCIDR(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func validPluginBackendURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "dns":
		return parsed.Host != ""
	default:
		return false
	}
}

func validPluginBackendType(pluginName, backendType string) bool {
	backendType = strings.ToLower(strings.TrimSpace(backendType))
	if backendType == "" || backendType == "runtime-json" {
		return true
	}
	switch pluginName {
	case "ens":
		return backendType == "ens-json-rpc"
	case "namecoin-bit":
		return backendType == "namecoin-json-rpc"
	case "stacks-bns":
		return backendType == "stacks-bns-api"
	case "pns-polkadot":
		return backendType == "pns-polkadot-api"
	case "pns-pulsechain":
		return backendType == "pulsechain-pns-json-rpc"
	case "rif-rns":
		return backendType == "rif-rns-json-rpc"
	case "unstoppable-domains":
		return backendType == "unstoppable-resolution-api"
	case "solana-sns":
		return backendType == "solana-sns-quicknode"
	case "space-id":
		return backendType == "space-id-api"
	case "ton-dns":
		return backendType == "toncenter-v3-dns"
	case "tezos-domains":
		return backendType == "tezos-domains-api"
	case "aptos-names":
		return backendType == "aptos-names-api"
	case "suins":
		return backendType == "suins-json-rpc"
	case "freename-fns":
		return backendType == "freename-resolution-api"
	case "fio-handle":
		return backendType == "fio-chain-api"
	case "openalias":
		return backendType == "openalias-dns-txt"
	case "ada-handle":
		return backendType == "ada-handle-api"
	case "did-bit":
		return backendType == "did-universal-resolver"
	default:
		return false
	}
}

func validHTTPURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func (d *durationOrSeconds) UnmarshalJSON(data []byte) error {
	var seconds int
	if err := json.Unmarshal(data, &seconds); err == nil {
		d.Duration = time.Duration(seconds) * time.Second
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("duration must be seconds or Go duration string: %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func applyHoneypot(raw fileHoneypotConfig, cfg *Config) {
	if raw.URL != "" {
		cfg.Honeypot.URL = raw.URL
		cfg.HoneypotURL = raw.URL
	}
	if raw.APIKey != "" {
		cfg.Honeypot.APIKey = raw.APIKey
		cfg.HoneypotAPIKey = raw.APIKey
	}
	if raw.APIKeyFile != "" {
		cfg.Honeypot.APIKeyFile = raw.APIKeyFile
	}
	if raw.HMACSecret != "" {
		cfg.Honeypot.HMACSecret = raw.HMACSecret
		cfg.HoneypotHMACSecret = raw.HMACSecret
	}
	if raw.HMACSecretFile != "" {
		cfg.Honeypot.HMACSecretFile = raw.HMACSecretFile
	}
	if raw.FailedQueuePath != "" {
		cfg.Honeypot.FailedQueuePath = raw.FailedQueuePath
	}
	if raw.FailedQueueMaxEntries > 0 {
		cfg.Honeypot.FailedQueueMaxEntries = raw.FailedQueueMaxEntries
	}
	if raw.RetryInterval.Duration > 0 {
		cfg.Honeypot.RetryInterval = raw.RetryInterval.Duration
	}
	if raw.MaxAttempts > 0 {
		cfg.Honeypot.MaxAttempts = raw.MaxAttempts
	}
	if raw.RequestTimeout.Duration > 0 {
		cfg.Honeypot.RequestTimeout = raw.RequestTimeout.Duration
	}
}

func applyPowerDNS(raw filePowerDNSConfig, cfg *Config) {
	if raw.AuthoritativeURL != "" {
		cfg.PowerDNS.AuthoritativeURL = raw.AuthoritativeURL
	}
	if raw.AuthoritativeAPIKey != "" {
		cfg.PowerDNS.AuthoritativeAPIKey = raw.AuthoritativeAPIKey
	}
	if raw.AuthoritativeAPIKeyFile != "" {
		cfg.PowerDNS.AuthoritativeAPIKeyFile = raw.AuthoritativeAPIKeyFile
	}
	if raw.RecursorURL != "" {
		cfg.PowerDNS.RecursorURL = raw.RecursorURL
	}
	if raw.RecursorAPIKey != "" {
		cfg.PowerDNS.RecursorAPIKey = raw.RecursorAPIKey
	}
	if raw.RecursorAPIKeyFile != "" {
		cfg.PowerDNS.RecursorAPIKeyFile = raw.RecursorAPIKeyFile
	}
	if raw.ServerID != "" {
		cfg.PowerDNS.ServerID = raw.ServerID
	}
	if raw.RequestTimeout.Duration > 0 {
		cfg.PowerDNS.RequestTimeout = raw.RequestTimeout.Duration
		cfg.PowerDNS.RequestTimeoutSeconds = int(raw.RequestTimeout.Duration.Seconds())
	}
}

func resolveSecretFiles(cfg *Config, baseDir string) error {
	for i := range cfg.Plugins {
		secret, err := readSecretFile("plugins["+strconv.Itoa(i)+"].backend_api_key", cfg.Plugins[i].BackendAPIKey, cfg.Plugins[i].BackendAPIKeyFile, baseDir)
		if err != nil {
			return err
		}
		if secret != "" {
			cfg.Plugins[i].BackendAPIKey = secret
			cfg.Plugins[i].BackendAPIKeyFile = ""
		}
	}
	secret, err := readSecretFile("honeypot.api_key", cfg.Honeypot.APIKey, cfg.Honeypot.APIKeyFile, baseDir)
	if err != nil {
		return err
	}
	if secret != "" {
		cfg.Honeypot.APIKey = secret
		cfg.HoneypotAPIKey = secret
		cfg.Honeypot.APIKeyFile = ""
	}
	secret, err = readSecretFile("honeypot.hmac_secret", cfg.Honeypot.HMACSecret, cfg.Honeypot.HMACSecretFile, baseDir)
	if err != nil {
		return err
	}
	if secret != "" {
		cfg.Honeypot.HMACSecret = secret
		cfg.HoneypotHMACSecret = secret
		cfg.Honeypot.HMACSecretFile = ""
	}
	secret, err = readSecretFile("management.api_key", cfg.Management.APIKey, cfg.Management.APIKeyFile, baseDir)
	if err != nil {
		return err
	}
	if secret != "" {
		cfg.Management.APIKey = secret
		cfg.Management.APIKeyFile = ""
	}
	for i := range cfg.Management.Keys {
		secret, err := readSecretFile("management.keys["+strconv.Itoa(i)+"].api_key", cfg.Management.Keys[i].APIKey, cfg.Management.Keys[i].APIKeyFile, baseDir)
		if err != nil {
			return err
		}
		if secret != "" {
			cfg.Management.Keys[i].APIKey = secret
			cfg.Management.Keys[i].APIKeyFile = ""
		}
	}
	secret, err = readSecretFile("powerdns.authoritative_api_key", cfg.PowerDNS.AuthoritativeAPIKey, cfg.PowerDNS.AuthoritativeAPIKeyFile, baseDir)
	if err != nil {
		return err
	}
	if secret != "" {
		cfg.PowerDNS.AuthoritativeAPIKey = secret
		cfg.PowerDNS.AuthoritativeAPIKeyFile = ""
	}
	secret, err = readSecretFile("powerdns.recursor_api_key", cfg.PowerDNS.RecursorAPIKey, cfg.PowerDNS.RecursorAPIKeyFile, baseDir)
	if err != nil {
		return err
	}
	if secret != "" {
		cfg.PowerDNS.RecursorAPIKey = secret
		cfg.PowerDNS.RecursorAPIKeyFile = ""
	}
	return nil
}

func readSecretFile(field, inlineValue, filePath, baseDir string) (string, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return "", nil
	}
	if strings.TrimSpace(inlineValue) != "" {
		return "", fmt.Errorf("%s must not set both inline value and file reference", field)
	}
	path := filePath
	if baseDir != "" && !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s_file %q: %w", field, filePath, err)
	}
	secret := strings.TrimSpace(string(body))
	if secret == "" {
		return "", fmt.Errorf("%s_file %q is empty", field, filePath)
	}
	return secret, nil
}

func applyEnvOverrides(cfg Config) Config {
	cfg.AdminAddr = env("ANYNS_ADMIN_ADDR", cfg.AdminAddr)
	cfg.RuntimeAddr = env("ANYNS_RUNTIME_ADDR", cfg.RuntimeAddr)
	cfg.LogForwarderAddr = env("ANYNS_LOG_FORWARDER_ADDR", cfg.LogForwarderAddr)
	cfg.RequestTimeout = envDuration("ANYNS_REQUEST_TIMEOUT_SECONDS", cfg.RequestTimeout)
	cfg.DNSLog.Limit = envInt("ANYNS_DNSLOG_LIMIT", cfg.DNSLog.Limit)
	cfg.DNSLog.Path = env("ANYNS_DNSLOG_PATH", cfg.DNSLog.Path)
	cfg.Honeypot.URL = env("ANYNS_HONEYPOT_URL", cfg.Honeypot.URL)
	cfg.Honeypot.APIKey = env("ANYNS_HONEYPOT_API_KEY", cfg.Honeypot.APIKey)
	cfg.Honeypot.HMACSecret = env("ANYNS_HONEYPOT_HMAC_SECRET", cfg.Honeypot.HMACSecret)
	cfg.Honeypot.FailedQueuePath = env("ANYNS_HONEYPOT_FAILED_QUEUE_PATH", cfg.Honeypot.FailedQueuePath)
	cfg.Honeypot.FailedQueueMaxEntries = envInt("ANYNS_HONEYPOT_FAILED_QUEUE_MAX_ENTRIES", cfg.Honeypot.FailedQueueMaxEntries)
	cfg.Honeypot.RetryInterval = envDuration("ANYNS_HONEYPOT_RETRY_INTERVAL_SECONDS", cfg.Honeypot.RetryInterval)
	cfg.Honeypot.MaxAttempts = envInt("ANYNS_HONEYPOT_MAX_ATTEMPTS", cfg.Honeypot.MaxAttempts)
	cfg.Honeypot.RequestTimeout = envDuration("ANYNS_HONEYPOT_REQUEST_TIMEOUT_SECONDS", cfg.Honeypot.RequestTimeout)
	cfg.HoneypotURL = cfg.Honeypot.URL
	cfg.HoneypotAPIKey = cfg.Honeypot.APIKey
	cfg.HoneypotHMACSecret = cfg.Honeypot.HMACSecret
	cfg.ControlPlane.AdminProxyRuntime = envBool("ANYNS_ADMIN_PROXY_RUNTIME_CONTROL", cfg.ControlPlane.AdminProxyRuntime)
	cfg.ControlPlane.RuntimeControlURL = env("ANYNS_RUNTIME_CONTROL_URL", cfg.ControlPlane.RuntimeControlURL)
	cfg.Management.APIKey = env("ANYNS_MANAGEMENT_API_KEY", cfg.Management.APIKey)
	cfg.Management.AuthRequired = envBool("ANYNS_MANAGEMENT_AUTH_REQUIRED", cfg.Management.AuthRequired)
	cfg.PowerDNS.AuthoritativeURL = env("ANYNS_PDNS_AUTH_URL", cfg.PowerDNS.AuthoritativeURL)
	cfg.PowerDNS.AuthoritativeAPIKey = env("PDNS_AUTH_API_KEY", cfg.PowerDNS.AuthoritativeAPIKey)
	cfg.PowerDNS.RecursorURL = env("ANYNS_PDNS_RECURSOR_URL", cfg.PowerDNS.RecursorURL)
	cfg.PowerDNS.RecursorAPIKey = env("PDNS_RECURSOR_API_KEY", cfg.PowerDNS.RecursorAPIKey)
	cfg.PowerDNS.ServerID = env("ANYNS_PDNS_SERVER_ID", cfg.PowerDNS.ServerID)
	cfg.PowerDNS.RequestTimeout = envDuration("ANYNS_PDNS_REQUEST_TIMEOUT_SECONDS", cfg.PowerDNS.RequestTimeout)
	cfg.PowerDNS.RequestTimeoutSeconds = int(cfg.PowerDNS.RequestTimeout.Seconds())
	return cfg
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
