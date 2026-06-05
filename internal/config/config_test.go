package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/plugins"
)

func TestLoadAppliesFileConfigAndDefaults(t *testing.T) {
	cfg := Default()
	err := Load(strings.NewReader(`{
		"runtime_addr": ":18081",
		"request_timeout": "750ms",
		"routes": [{
			"name": "ens-default",
			"suffixes": [".eth"],
			"client_views": ["default"],
			"tenants": ["default"],
			"plugin": "ens",
			"priority": 90,
			"fallback": "nxdomain"
		}],
		"plugins": [{
			"name": "ens",
			"enabled": true,
			"backend_type": "runtime-json",
			"backend_url": "https://ens-backend.example/resolve",
			"backend_api_key": "ens-secret",
			"request_timeout": "1500ms"
		}],
			"security": {
				"enabled": true,
				"query_rate_window_seconds": 12,
				"query_rate_threshold": 34,
				"random_subdomain_window_seconds": 56,
				"random_subdomain_threshold": 78,
				"nxdomain_threshold": 7,
				"allowlist_domains": ["trusted.example"],
				"denylist_domains": [".blocked.example"],
			"sinkhole_domains": ["ads.example"],
			"sinkhole_ipv4": "203.0.113.250",
			"sinkhole_ipv6": "2001:db8::250",
			"sinkhole_ttl": 45
		},
		"dnslog": {
			"limit": 25,
			"path": "/tmp/anyns-dnslog.jsonl"
		},
		"honeypot": {
			"url": "https://honeypot.example/api/v1/dns-events",
			"failed_queue_path": "/tmp/anyns-honeypot-failed.jsonl",
			"retry_interval": 15
		},
		"control_plane": {
			"admin_proxy_runtime": true,
			"runtime_control_url": "http://127.0.0.1:8081"
		},
		"management": {
			"api_key": "admin-secret",
			"auth_required": true,
			"roles": [
				{"id": "ops-reader", "scopes": ["plugins:read", "audit:read"]},
				{"id": "ops-writer", "scopes": ["plugins:write", "cache:write"]}
			],
			"keys": [
				{"id": "ops-read", "api_key": "read-secret", "roles": ["ops-reader"], "not_before": "2026-01-01T00:00:00Z", "allowed_client_cidrs": ["127.0.0.1", "10.0.0.0/8"]},
				{"id": "ops-write", "api_key": "write-secret", "scopes": ["read"], "roles": ["ops-writer"], "expires_at": "2027-01-01T00:00:00Z"}
			]
		}
	}`), &cfg)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.RuntimeAddr != ":18081" {
		t.Fatalf("runtime addr = %q", cfg.RuntimeAddr)
	}
	if cfg.RequestTimeout != 750*time.Millisecond {
		t.Fatalf("request timeout = %s", cfg.RequestTimeout)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Plugin != "ens" {
		t.Fatalf("routes = %#v", cfg.Routes)
	}
	if len(cfg.Plugins) != 1 || !cfg.Plugins[0].Enabled {
		t.Fatalf("plugins = %#v", cfg.Plugins)
	}
	if cfg.Plugins[0].BackendURL != "https://ens-backend.example/resolve" ||
		cfg.Plugins[0].BackendType != "runtime-json" ||
		cfg.Plugins[0].BackendAPIKey != "ens-secret" ||
		cfg.Plugins[0].RequestTimeout.Duration != 1500*time.Millisecond {
		t.Fatalf("plugin backend config = %#v", cfg.Plugins[0])
	}
	if cfg.Security.NXDomainThreshold != 7 ||
		cfg.Security.QueryRateWindowSeconds != 12 ||
		cfg.Security.QueryRateThreshold != 34 ||
		cfg.Security.RandomSubdomainWindowSec != 56 ||
		cfg.Security.RandomSubdomainThreshold != 78 ||
		cfg.Security.TunnelEntropyThreshold == 0 ||
		len(cfg.Security.AllowlistDomains) != 1 ||
		len(cfg.Security.DenylistDomains) != 1 ||
		len(cfg.Security.SinkholeDomains) != 1 ||
		cfg.Security.SinkholeIPv4 != "203.0.113.250" ||
		cfg.Security.SinkholeIPv6 != "2001:db8::250" ||
		cfg.Security.SinkholeTTL != 45 {
		t.Fatalf("security defaults not applied: %#v", cfg.Security)
	}
	if cfg.DNSLog.Limit != 25 || cfg.DNSLog.Path == "" {
		t.Fatalf("dnslog = %#v", cfg.DNSLog)
	}
	if cfg.Honeypot.URL == "" || cfg.Honeypot.RetryInterval != 15*time.Second {
		t.Fatalf("honeypot = %#v", cfg.Honeypot)
	}
	if !cfg.ControlPlane.AdminProxyRuntime || cfg.ControlPlane.RuntimeControlURL == "" {
		t.Fatalf("control plane = %#v", cfg.ControlPlane)
	}
	if !cfg.Management.AuthRequired || cfg.Management.APIKey != "admin-secret" {
		t.Fatalf("management = %#v", cfg.Management)
	}
	if len(cfg.Management.Roles) != 2 || cfg.Management.Roles[0].ID != "ops-reader" {
		t.Fatalf("management roles = %#v", cfg.Management.Roles)
	}
	if len(cfg.Management.Keys) != 2 ||
		cfg.Management.Keys[0].ID != "ops-read" ||
		cfg.Management.Keys[0].Roles[0] != "ops-reader" ||
		cfg.Management.Keys[0].NotBefore != "2026-01-01T00:00:00Z" ||
		len(cfg.Management.Keys[0].AllowedClientCIDRs) != 2 ||
		cfg.Management.Keys[1].Roles[0] != "ops-writer" ||
		cfg.Management.Keys[1].ExpiresAt != "2027-01-01T00:00:00Z" {
		t.Fatalf("management keys = %#v", cfg.Management.Keys)
	}
	scopes := cfg.Management.ScopesForKey(cfg.Management.Keys[1])
	if !stringSliceContains(scopes, "read") || !stringSliceContains(scopes, "plugins:write") || !stringSliceContains(scopes, "cache:write") {
		t.Fatalf("expanded management key scopes = %#v", scopes)
	}
}

func TestFromEnvWithErrorOverridesOperationalFileConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
		"admin_addr": ":18080",
		"runtime_addr": ":18081",
		"log_forwarder_addr": ":18082",
		"request_timeout": "1s",
		"dnslog": {
			"limit": 10,
			"path": "/var/lib/anyns/file-dnslog.jsonl"
		},
		"honeypot": {
			"url": "https://file.example/api/v1/dns-events",
			"api_key": "file-key",
			"hmac_secret": "file-secret",
			"failed_queue_path": "/var/lib/anyns/file-failed.jsonl",
			"failed_queue_max_entries": 100,
			"retry_interval": "10s",
			"max_attempts": 3,
			"request_timeout": "2s"
		},
		"control_plane": {
			"runtime_control_url": "http://file-runtime:8081"
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("ANYNS_CONFIG_FILE", path)
	t.Setenv("ANYNS_REQUEST_TIMEOUT_SECONDS", "9")
	t.Setenv("ANYNS_DNSLOG_LIMIT", "99")
	t.Setenv("ANYNS_DNSLOG_PATH", "/tmp/env-dnslog.jsonl")
	t.Setenv("ANYNS_HONEYPOT_URL", "https://env.example/api/v1/dns-events")
	t.Setenv("ANYNS_HONEYPOT_API_KEY", "env-key")
	t.Setenv("ANYNS_HONEYPOT_HMAC_SECRET", "env-secret")
	t.Setenv("ANYNS_HONEYPOT_FAILED_QUEUE_PATH", "/tmp/env-failed.jsonl")
	t.Setenv("ANYNS_HONEYPOT_FAILED_QUEUE_MAX_ENTRIES", "222")
	t.Setenv("ANYNS_HONEYPOT_RETRY_INTERVAL_SECONDS", "33")
	t.Setenv("ANYNS_HONEYPOT_MAX_ATTEMPTS", "7")
	t.Setenv("ANYNS_HONEYPOT_REQUEST_TIMEOUT_SECONDS", "4")
	t.Setenv("ANYNS_ADMIN_PROXY_RUNTIME_CONTROL", "true")
	t.Setenv("ANYNS_RUNTIME_CONTROL_URL", "http://env-runtime:8081")
	t.Setenv("ANYNS_MANAGEMENT_API_KEY", "env-admin-secret")
	t.Setenv("ANYNS_MANAGEMENT_AUTH_REQUIRED", "true")

	cfg, err := FromEnvWithError()
	if err != nil {
		t.Fatalf("from env: %v", err)
	}
	if cfg.ConfigFile != path {
		t.Fatalf("config file = %q, want %q", cfg.ConfigFile, path)
	}
	if cfg.RequestTimeout != 9*time.Second {
		t.Fatalf("request timeout = %s", cfg.RequestTimeout)
	}
	if cfg.DNSLog.Limit != 99 || cfg.DNSLog.Path != "/tmp/env-dnslog.jsonl" {
		t.Fatalf("dnslog override = %#v", cfg.DNSLog)
	}
	if cfg.Honeypot.URL != "https://env.example/api/v1/dns-events" ||
		cfg.Honeypot.APIKey != "env-key" ||
		cfg.Honeypot.HMACSecret != "env-secret" ||
		cfg.Honeypot.FailedQueuePath != "/tmp/env-failed.jsonl" ||
		cfg.Honeypot.FailedQueueMaxEntries != 222 ||
		cfg.Honeypot.RetryInterval != 33*time.Second ||
		cfg.Honeypot.MaxAttempts != 7 ||
		cfg.Honeypot.RequestTimeout != 4*time.Second {
		t.Fatalf("honeypot override = %#v", cfg.Honeypot)
	}
	if cfg.HoneypotURL != cfg.Honeypot.URL || cfg.HoneypotAPIKey != cfg.Honeypot.APIKey || cfg.HoneypotHMACSecret != cfg.Honeypot.HMACSecret {
		t.Fatalf("legacy honeypot aliases not synced: %#v", cfg)
	}
	if !cfg.ControlPlane.AdminProxyRuntime || cfg.ControlPlane.RuntimeControlURL != "http://env-runtime:8081" {
		t.Fatalf("control plane override = %#v", cfg.ControlPlane)
	}
	if !cfg.Management.AuthRequired || cfg.Management.APIKey != "env-admin-secret" {
		t.Fatalf("management override = %#v", cfg.Management)
	}
}

func TestLoadFileResolvesSecretFileReferences(t *testing.T) {
	dir := t.TempDir()
	writeSecret := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o600); err != nil {
			t.Fatalf("write secret %s: %v", name, err)
		}
	}
	writeSecret("plugin.key", "plugin-secret")
	writeSecret("honeypot.key", "honeypot-secret")
	writeSecret("honeypot.hmac", "honeypot-hmac")
	writeSecret("legacy.key", "legacy-secret")
	writeSecret("ops.key", "ops-secret")

	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
		"admin_addr": ":18080",
		"runtime_addr": ":18081",
		"log_forwarder_addr": ":18082",
		"plugins": [{
			"name": "hns",
			"enabled": true,
			"backend_url": "https://hns-backend.example/resolve",
			"backend_api_key_file": "plugin.key"
		}],
		"routes": [{
			"name": "hns-default",
			"suffixes": [".hns"],
			"plugin": "hns",
			"priority": 100,
			"fallback": "icann-recursive"
		}],
		"honeypot": {
			"url": "https://honeypot.example/api/v1/dns-events",
			"api_key_file": "honeypot.key",
			"hmac_secret_file": "honeypot.hmac"
		},
		"management": {
			"api_key_file": "legacy.key",
			"auth_required": true,
			"keys": [{
				"id": "ops",
				"api_key_file": "ops.key",
				"scopes": ["management:read"]
			}]
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load config with secret files: %v", err)
	}
	if cfg.Plugins[0].BackendAPIKey != "plugin-secret" {
		t.Fatalf("plugin secret = %q", cfg.Plugins[0].BackendAPIKey)
	}
	if cfg.Honeypot.APIKey != "honeypot-secret" || cfg.Honeypot.HMACSecret != "honeypot-hmac" {
		t.Fatalf("honeypot secrets = %#v", cfg.Honeypot)
	}
	if cfg.HoneypotAPIKey != "honeypot-secret" || cfg.HoneypotHMACSecret != "honeypot-hmac" {
		t.Fatalf("legacy honeypot aliases not synced: %#v", cfg)
	}
	if cfg.Management.APIKey != "legacy-secret" || cfg.Management.Keys[0].APIKey != "ops-secret" {
		t.Fatalf("management secrets = %#v", cfg.Management)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config with resolved secret files: %v", err)
	}
}

func TestValidateAcceptsExampleConfig(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "configs", "anyns", "config.example.json"))
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate example config: %v", err)
	}
}

func TestValidateAcceptsUnstoppableResolutionBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "unstoppable-domains", Enabled: true, BackendType: "unstoppable-resolution-api", BackendURL: "https://api.unstoppabledomains.com/resolve"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "unstoppable",
		Suffixes: []string{".crypto"},
		Plugin:   "unstoppable-domains",
		Priority: 90,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate unstoppable backend type: %v", err)
	}
}

func TestValidateAcceptsENSJSONRPCBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "ens", Enabled: true, BackendType: "ens-json-rpc", BackendURL: "https://ethereum-rpc.example"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "ens",
		Suffixes: []string{".eth"},
		Plugin:   "ens",
		Priority: 90,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate ENS backend type: %v", err)
	}
}

func TestValidateAcceptsStacksBNSBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "stacks-bns", Enabled: true, BackendType: "stacks-bns-api", BackendURL: "https://api.mainnet.hiro.so/v1"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "stacks-bns",
		Suffixes: []string{".btc"},
		Plugin:   "stacks-bns",
		Priority: 90,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate stacks BNS backend type: %v", err)
	}
}

func TestValidateAcceptsPNSPolkadotBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "pns-polkadot", Enabled: true, BackendType: "pns-polkadot-api", BackendURL: "https://api.ddns.so"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "pns-polkadot",
		Suffixes: []string{".dot"},
		Plugin:   "pns-polkadot",
		Priority: 90,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate PNS Polkadot backend type: %v", err)
	}
}

func TestValidateAcceptsPulseChainPNSBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "pns-pulsechain", Enabled: true, BackendType: "pulsechain-pns-json-rpc", BackendURL: "https://rpc.pulsechain.example?registry=0x1111111111111111111111111111111111111111"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "pns-pulsechain",
		Suffixes: []string{".pls"},
		Plugin:   "pns-pulsechain",
		Priority: 90,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate PulseChain PNS backend type: %v", err)
	}
}

func TestValidateAcceptsRIFRNSBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "rif-rns", Enabled: true, BackendType: "rif-rns-json-rpc", BackendURL: "https://public-node.rsk.co?registry=0x1111111111111111111111111111111111111111"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "rif-rns",
		Suffixes: []string{".rsk"},
		Plugin:   "rif-rns",
		Priority: 70,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate RIF RNS backend type: %v", err)
	}
}

func TestValidateAcceptsWave2RuntimeJSONSkeletons(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "solana-sns", Enabled: false, BackendType: "runtime-json", BackendURL: "https://sns-backend.example/resolve"},
		{Name: "space-id", Enabled: false, BackendType: "runtime-json", BackendURL: "https://space-id-backend.example/resolve"},
		{Name: "ton-dns", Enabled: false, BackendType: "runtime-json", BackendURL: "https://ton-backend.example/resolve"},
		{Name: "tezos-domains", Enabled: false, BackendType: "runtime-json", BackendURL: "https://tezos-backend.example/resolve"},
		{Name: "aptos-names", Enabled: false, BackendType: "runtime-json", BackendURL: "https://aptos-backend.example/resolve"},
		{Name: "suins", Enabled: false, BackendType: "runtime-json", BackendURL: "https://suins-backend.example/resolve"},
	}
	cfg.Routes = plugins.DefaultWave2Routes()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Wave 2 runtime-json skeletons: %v", err)
	}
}

func TestValidateAcceptsWave3RuntimeJSONSkeletons(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "freename-fns", Enabled: false, BackendType: "runtime-json", BackendURL: "https://freename-backend.example/resolve"},
		{Name: "rif-rns", Enabled: false, BackendType: "runtime-json", BackendURL: "https://rns-backend.example/resolve"},
		{Name: "fio-handle", Enabled: false, BackendType: "runtime-json", BackendURL: "https://fio-backend.example/resolve"},
		{Name: "openalias", Enabled: false, BackendType: "runtime-json", BackendURL: "https://openalias-backend.example/resolve"},
		{Name: "ada-handle", Enabled: false, BackendType: "runtime-json", BackendURL: "https://ada-backend.example/resolve"},
		{Name: "did-bit", Enabled: false, BackendType: "runtime-json", BackendURL: "https://did-bit-backend.example/resolve"},
	}
	cfg.Routes = plugins.DefaultWave3Routes()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Wave 3 runtime-json skeletons: %v", err)
	}
}

func TestValidateAcceptsSpaceIDBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "space-id", Enabled: true, BackendType: "space-id-api", BackendURL: "https://nameapi.space.id"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "space-id",
		Suffixes: []string{".bnb", ".arb"},
		Plugin:   "space-id",
		Priority: 80,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate SPACE ID backend type: %v", err)
	}
}

func TestValidateAcceptsSolanaSNSBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "solana-sns", Enabled: true, BackendType: "solana-sns-quicknode", BackendURL: "https://solana-mainnet.quiknode.pro/token/"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "solana-sns",
		Suffixes: []string{".sol"},
		Plugin:   "solana-sns",
		Priority: 80,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Solana SNS backend type: %v", err)
	}
}

func TestValidateAcceptsTONDNSBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "ton-dns", Enabled: true, BackendType: "toncenter-v3-dns", BackendURL: "https://toncenter.com"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "ton-dns",
		Suffixes: []string{".ton"},
		Plugin:   "ton-dns",
		Priority: 80,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate TON DNS backend type: %v", err)
	}
}

func TestValidateAcceptsTezosDomainsBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "tezos-domains", Enabled: true, BackendType: "tezos-domains-api", BackendURL: "https://api.tezos.domains/graphql"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "tezos-domains",
		Suffixes: []string{".tez"},
		Plugin:   "tezos-domains",
		Priority: 80,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Tezos Domains backend type: %v", err)
	}
}

func TestValidateAcceptsAptosNamesBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "aptos-names", Enabled: true, BackendType: "aptos-names-api", BackendURL: "https://www.aptosnames.com/api/mainnet"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "aptos-names",
		Suffixes: []string{".apt"},
		Plugin:   "aptos-names",
		Priority: 80,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Aptos Names backend type: %v", err)
	}
}

func TestValidateAcceptsSuiNSBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "suins", Enabled: true, BackendType: "suins-json-rpc", BackendURL: "https://fullnode.mainnet.sui.io:443"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "suins",
		Suffixes: []string{".sui"},
		Plugin:   "suins",
		Priority: 80,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate SuiNS backend type: %v", err)
	}
}

func TestValidateAcceptsFIOChainBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "fio-handle", Enabled: true, BackendType: "fio-chain-api", BackendURL: "https://fio.blockpane.com?chain_code=ETH&token_code=ETH"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "fio-handle",
		Suffixes: []string{".fio"},
		Plugin:   "fio-handle",
		Priority: 70,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate FIO Chain backend type: %v", err)
	}
}

func TestValidateAcceptsFreenameResolutionBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "freename-fns", Enabled: true, BackendType: "freename-resolution-api", BackendURL: "https://rslvr.freename.io"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "freename-fns",
		Suffixes: []string{".fns"},
		Plugin:   "freename-fns",
		Priority: 70,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Freename Resolution backend type: %v", err)
	}
}

func TestValidateAcceptsOpenAliasDNSTXTBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "openalias", Enabled: true, BackendType: "openalias-dns-txt", BackendURL: "https://openalias-dns-adapter.example/txt"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "openalias",
		Suffixes: []string{".openalias"},
		Plugin:   "openalias",
		Priority: 70,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate OpenAlias DNS TXT backend type: %v", err)
	}
}

func TestValidateAcceptsADAHandleAPIBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "ada-handle", Enabled: true, BackendType: "ada-handle-api", BackendURL: "https://api.handle.me"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "ada-handle",
		Suffixes: []string{".ada"},
		Plugin:   "ada-handle",
		Priority: 70,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate ADA Handle API backend type: %v", err)
	}
}

func TestValidateAcceptsDIDUniversalResolverBackendType(t *testing.T) {
	cfg := Default()
	cfg.Plugins = []PluginConfig{
		{Name: "did-bit", Enabled: true, BackendType: "did-universal-resolver", BackendURL: "https://resolver.example"},
	}
	cfg.Routes = []plugins.Route{{
		Name:     "did-bit",
		Domains:  []string{"alice.did.bit"},
		Plugin:   "did-bit",
		Priority: 95,
		Fallback: "nxdomain",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate DID Universal Resolver backend type: %v", err)
	}
}

func TestValidateRejectsInvalidIntegrationConfig(t *testing.T) {
	cfg := Default()
	cfg.RequestTimeout = 0
	cfg.DNSLog.Limit = 0
	cfg.Honeypot.MaxAttempts = 0
	cfg.Plugins = []PluginConfig{
		{Name: "hns", Enabled: true},
		{Name: "hns", Enabled: false, BackendType: "namecoin-json-rpc", BackendURL: "file:///tmp/not-a-backend", BackendAPIKey: "inline", BackendAPIKeyFile: "/tmp/plugin-key"},
	}
	cfg.Routes = append(cfg.Routes, cfg.Routes[0])
	cfg.Routes[0].Name = ""
	cfg.Routes[0].Plugin = "missing-plugin"
	cfg.Routes[1].Domains = nil
	cfg.Routes[1].Suffixes = nil
	cfg.Management.AuthRequired = true
	cfg.Management.APIKey = "inline-legacy"
	cfg.Management.APIKeyFile = "/tmp/legacy-key"
	cfg.Management.Roles = []ManagementRole{
		{ID: "bad-role", Scopes: []string{"invalid-role-scope"}},
		{ID: "bad-role", Scopes: nil},
	}
	cfg.Management.Keys = []ManagementKey{
		{ID: "ops", APIKey: "inline", APIKeyFile: "/tmp/ops-key", Scopes: []string{"invalid-scope"}, Roles: []string{"missing-role"}, NotBefore: "not-a-time", RevokedAt: "not-a-time", AllowedClientCIDRs: []string{"not-a-cidr"}},
		{ID: "ops", APIKey: "", Scopes: []string{"read"}, NotBefore: "2027-01-01T00:00:00Z", ExpiresAt: "2026-01-01T00:00:00Z"},
	}
	cfg.Security.SinkholeTTL = -1
	cfg.Security.SinkholeIPv4 = "not-an-ip"
	cfg.Security.AllowlistDomains = []string{""}
	cfg.Security.QueryRateWindowSeconds = -1
	cfg.Security.RandomSubdomainThreshold = -1
	cfg.ControlPlane.AdminProxyRuntime = true
	cfg.ControlPlane.RuntimeControlURL = "dns://runtime.internal:8081"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	msg := err.Error()
	for _, want := range []string{
		"request_timeout",
		"dnslog.limit",
		"honeypot.max_attempts",
		"duplicated",
		"backend_url",
		"backend_type",
		"backend_api_key_file",
		"missing-plugin",
		"domain or suffix",
		"management must not set both",
		"management.roles",
		"unsupported",
		"not configured",
		"not_before",
		"expires_at",
		"revoked_at",
		"api_key_file",
		"allowed_client_cidrs",
		"security.sinkhole_ttl",
		"security.sinkhole_ipv4",
		"security.allowlist_domains",
		"security.query_rate_window_seconds",
		"security.random_subdomain_threshold",
		"control_plane.runtime_control_url",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("validation error %q does not contain %q", msg, want)
		}
	}
}

func TestManagementScopesForKeyExpandsRoleTemplates(t *testing.T) {
	cfg := Default()
	cfg.Management.Roles = []ManagementRole{
		{ID: "ops-reader", Scopes: []string{"plugins:read", "audit:read"}},
		{ID: "ops-writer", Scopes: []string{"plugins:write", "cache:write"}},
	}
	key := ManagementKey{
		ID:     "operator",
		Scopes: []string{"management:read", "plugins:read"},
		Roles:  []string{"ops-reader", "ops-writer", "ops-reader"},
	}

	scopes := cfg.Management.ScopesForKey(key)
	for _, want := range []string{"management:read", "plugins:read", "audit:read", "plugins:write", "cache:write"} {
		if !stringSliceContains(scopes, want) {
			t.Fatalf("expanded scopes %#v missing %q", scopes, want)
		}
	}
	if countString(scopes, "plugins:read") != 1 {
		t.Fatalf("expanded scopes should deduplicate direct and role scopes: %#v", scopes)
	}
}

func TestValidateAcceptsFineGrainedManagementScopes(t *testing.T) {
	cfg := Default()
	cfg.Management.AuthRequired = true
	cfg.Management.Keys = []ManagementKey{
		{
			ID:     "scoped-ops",
			APIKey: "scoped-secret",
			Scopes: []string{
				"plugins:read",
				"plugins:write",
				"cache:read",
				"cache:write",
				"policy:write",
				"audit:read",
				"honeypot:read",
				"honeypot:write",
				"management:read",
				"management:write",
			},
			RevokedAt: "2026-06-01T00:00:00Z",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate fine-grained scopes: %v", err)
	}
}

func TestValidateRequiresRuntimeControlURLWhenProxying(t *testing.T) {
	cfg := Default()
	cfg.ControlPlane.AdminProxyRuntime = true
	cfg.ControlPlane.RuntimeControlURL = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "control_plane.runtime_control_url") {
		t.Fatalf("validation error = %q", err.Error())
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func countString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}
