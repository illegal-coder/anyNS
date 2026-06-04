package plugins

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
	routes  []Route
	cache   map[string]map[string]cacheEntry
}

type cacheEntry struct {
	result    ResolveResult
	expiresAt time.Time
}

func NewRegistry(routes []Route, plugs ...Plugin) *Registry {
	r := &Registry{
		plugins: make(map[string]Plugin, len(plugs)),
		routes:  append([]Route(nil), routes...),
		cache:   make(map[string]map[string]cacheEntry),
	}
	for _, p := range plugs {
		r.plugins[p.Name()] = p
	}
	sort.SliceStable(r.routes, func(i, j int) bool {
		return r.routes[i].Priority > r.routes[j].Priority
	})
	return r
}

func DefaultRoutes() []Route {
	return []Route{
		{
			Name:        "hns-default",
			Suffixes:    []string{".hns", ".hsd"},
			ClientViews: []string{"default", "adguard"},
			Tenants:     []string{"default"},
			Plugin:      "hns",
			Priority:    100,
			Fallback:    "icann-recursive",
		},
	}
}

func DefaultWave1Routes() []Route {
	return []Route{
		{Name: "ens-wave1", Suffixes: []string{".eth"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "ens", Priority: 90, Fallback: "nxdomain"},
		{Name: "namecoin-bit-wave1", Suffixes: []string{".bit"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "namecoin-bit", Priority: 90, Fallback: "nxdomain"},
		{Name: "stacks-bns-wave1", Suffixes: []string{".btc", ".stx"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "stacks-bns", Priority: 90, Fallback: "nxdomain"},
		{Name: "pns-polkadot-wave1", Suffixes: []string{".dot"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "pns-polkadot", Priority: 90, Fallback: "nxdomain"},
		{Name: "pns-pulsechain-wave1", Suffixes: []string{".pls"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "pns-pulsechain", Priority: 90, Fallback: "nxdomain"},
		{Name: "unstoppable-domains-wave1", Suffixes: []string{".crypto", ".nft", ".wallet", ".x", ".dao", ".888", ".zil", ".blockchain", ".bitcoin"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "unstoppable-domains", Priority: 90, Fallback: "nxdomain"},
	}
}

func DefaultWave2Routes() []Route {
	return []Route{
		{Name: "solana-sns-wave2", Suffixes: []string{".sol"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "solana-sns", Priority: 80, Fallback: "nxdomain"},
		{Name: "space-id-wave2", Suffixes: []string{".bnb", ".arb"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "space-id", Priority: 80, Fallback: "nxdomain"},
		{Name: "ton-dns-wave2", Suffixes: []string{".ton"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "ton-dns", Priority: 80, Fallback: "nxdomain"},
		{Name: "tezos-domains-wave2", Suffixes: []string{".tez"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "tezos-domains", Priority: 80, Fallback: "nxdomain"},
		{Name: "aptos-names-wave2", Suffixes: []string{".apt"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "aptos-names", Priority: 80, Fallback: "nxdomain"},
		{Name: "suins-wave2", Suffixes: []string{".sui"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "suins", Priority: 80, Fallback: "nxdomain"},
	}
}

func DefaultWave3Routes() []Route {
	return []Route{
		{Name: "freename-fns-wave3", Suffixes: []string{".fns"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "freename-fns", Priority: 70, Fallback: "nxdomain"},
		{Name: "rif-rns-wave3", Suffixes: []string{".rsk"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "rif-rns", Priority: 70, Fallback: "nxdomain"},
		{Name: "fio-handle-wave3", Suffixes: []string{".fio"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "fio-handle", Priority: 70, Fallback: "nxdomain"},
		{Name: "openalias-wave3", Suffixes: []string{".openalias"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "openalias", Priority: 70, Fallback: "nxdomain"},
		{Name: "ada-handle-wave3", Suffixes: []string{".ada"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "ada-handle", Priority: 70, Fallback: "nxdomain"},
		{Name: "did-bit-wave3", Suffixes: []string{".bit"}, ClientViews: []string{"default"}, Tenants: []string{"default"}, Plugin: "did-bit", Priority: 70, Fallback: "nxdomain"},
	}
}

func (r *Registry) Plugins() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

func (r *Registry) Resolve(ctx context.Context, req ResolveRequest) (ResolveResult, Route, error) {
	started := time.Now()
	req.QName = NormalizeQName(req.QName)
	req.QType = NormalizeQType(req.QType)
	route, p, ok := r.match(req)
	if !ok {
		return ResolveResult{RCode: RCodeNXDomain, SourcePlugin: "router", TTL: 30, LatencyMS: time.Since(started).Milliseconds()}, Route{}, ErrNoRoute
	}
	if !p.Enabled() {
		return ResolveResult{RCode: RCodeServFail, SourcePlugin: p.Name(), TTL: 5, LatencyMS: time.Since(started).Milliseconds()}, route, ErrPluginDisabled
	}
	key := cacheKey(req)
	if cached, ok := r.getCached(p.Name(), key); ok {
		cached.AuditMetadata = cloneMap(cached.AuditMetadata)
		cached.AuditMetadata["cache_hit"] = true
		cached.LatencyMS = time.Since(started).Milliseconds()
		return cached, route, nil
	}
	res, err := p.Resolve(ctx, req)
	if err != nil {
		return ResolveResult{RCode: RCodeServFail, SourcePlugin: p.Name(), TTL: 5, LatencyMS: time.Since(started).Milliseconds()}, route, err
	}
	r.setCached(p.Name(), key, res)
	return res, route, nil
}

func (r *Registry) SetPluginEnabled(name string, enabled bool) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[name]
	if !ok {
		return false
	}
	p.SetEnabled(enabled)
	return true
}

func (r *Registry) FlushCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]map[string]cacheEntry)
}

func (r *Registry) CacheStats() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]int, len(r.cache))
	now := time.Now()
	for plugin, entries := range r.cache {
		for _, entry := range entries {
			if entry.expiresAt.After(now) {
				out[plugin]++
			}
		}
	}
	return out
}

func (r *Registry) getCached(plugin, key string) (ResolveResult, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := r.cache[plugin]
	entry, ok := entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return ResolveResult{}, false
	}
	return entry.result, true
}

func (r *Registry) setCached(plugin, key string, result ResolveResult) {
	if result.TTL <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := r.cache[plugin]
	if entries == nil {
		entries = map[string]cacheEntry{}
		r.cache[plugin] = entries
	}
	entries[key] = cacheEntry{result: result, expiresAt: time.Now().Add(time.Duration(result.TTL) * time.Second)}
}

func (r *Registry) match(req ResolveRequest) (Route, Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, route := range r.routes {
		if !containsOrEmpty(route.ClientViews, req.Context.ClientView) ||
			!containsOrEmpty(route.Tenants, req.Context.Tenant) ||
			!containsAll(route.PolicyTags, req.Context.PolicyTags) {
			continue
		}
		if routeMatchesName(route, req.QName) {
			p, ok := r.plugins[route.Plugin]
			return route, p, ok
		}
	}
	return Route{}, nil, false
}

func routeMatchesName(route Route, qname string) bool {
	normalized := NormalizeQName(qname)
	for _, domain := range route.Domains {
		if normalized == NormalizeQName(domain) {
			return true
		}
	}
	for _, suffix := range route.Suffixes {
		if MatchSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func cacheKey(req ResolveRequest) string {
	policyTags := append([]string(nil), req.Context.PolicyTags...)
	for i, tag := range policyTags {
		policyTags[i] = strings.ToLower(strings.TrimSpace(tag))
	}
	sort.Strings(policyTags)
	return strings.Join([]string{
		NormalizeQName(req.QName),
		NormalizeQType(req.QType),
		normalizeRouteValue(req.Context.Tenant),
		normalizeRouteValue(req.Context.ClientView),
		strings.Join(policyTags, ","),
	}, "|")
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func containsOrEmpty(values []string, value string) bool {
	if len(values) == 0 {
		return true
	}
	value = normalizeRouteValue(value)
	if value == "" {
		value = "default"
	}
	for _, v := range values {
		if normalizeRouteValue(v) == value {
			return true
		}
	}
	return false
}

func normalizeRouteValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func containsAll(required []string, provided []string) bool {
	if len(required) == 0 {
		return true
	}
	seen := make(map[string]bool, len(provided))
	for _, value := range provided {
		seen[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range required {
		if !seen[strings.ToLower(strings.TrimSpace(value))] {
			return false
		}
	}
	return true
}
