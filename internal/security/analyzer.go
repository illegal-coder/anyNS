package security

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/anyns/anyns/internal/dnsname"
	"github.com/anyns/anyns/internal/plugins"
)

type RiskLevel string

const (
	RiskNone     RiskLevel = "none"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Action string

const (
	ActionAllow             Action = "allow"
	ActionLogOnly           Action = "log_only"
	ActionBlock             Action = "block"
	ActionSinkhole          Action = "sinkhole"
	ActionRateLimit         Action = "rate_limit"
	ActionForwardToHoneypot Action = "forward_to_honeypot"
	ActionTagAndContinue    Action = "tag_and_continue"
)

type Finding struct {
	Rule      string    `json:"rule"`
	RiskLevel RiskLevel `json:"risk_level"`
	Action    Action    `json:"action"`
	Reason    string    `json:"reason"`
}

type Policy struct {
	Configured                 bool     `json:"-"`
	Enabled                    bool     `json:"enabled"`
	TunnelMaxQNameLength       int      `json:"tunnel_max_qname_length"`
	TunnelMaxLabelLength       int      `json:"tunnel_max_label_length"`
	TunnelEntropyThreshold     float64  `json:"tunnel_entropy_threshold"`
	DGAEntropyThreshold        float64  `json:"dga_entropy_threshold"`
	DGADigitRatioThreshold     float64  `json:"dga_digit_ratio_threshold"`
	QueryRateWindowSeconds     int      `json:"query_rate_window_seconds"`
	QueryRateThreshold         int      `json:"query_rate_threshold"`
	RandomSubdomainWindowSec   int      `json:"random_subdomain_window_seconds"`
	RandomSubdomainThreshold   int      `json:"random_subdomain_threshold"`
	NXDomainWindowSeconds      int      `json:"nxdomain_window_seconds"`
	NXDomainThreshold          int      `json:"nxdomain_threshold"`
	BlockRebinding             bool     `json:"block_rebinding"`
	AbnormalRRAction           Action   `json:"abnormal_rr_action"`
	ReflectionAmplificationAct Action   `json:"reflection_amplification_action"`
	AllowlistDomains           []string `json:"allowlist_domains,omitempty"`
	DenylistDomains            []string `json:"denylist_domains,omitempty"`
	SinkholeDomains            []string `json:"sinkhole_domains,omitempty"`
	RejectDNSLogPlatforms      bool     `json:"reject_dnslog_platforms"`
	DNSLogPlatformDomains      []string `json:"dnslog_platform_domains,omitempty"`
	SinkholeIPv4               string   `json:"sinkhole_ipv4,omitempty"`
	SinkholeIPv6               string   `json:"sinkhole_ipv6,omitempty"`
	SinkholeTTL                int      `json:"sinkhole_ttl,omitempty"`
}

type Analyzer struct {
	mu                       sync.Mutex
	clientQueries            map[string][]time.Time
	clientBaseSubdomainQuery map[string]map[string]time.Time
	clientNXDomains          map[string][]time.Time
	now                      func() time.Time
	policy                   Policy
}

func NewAnalyzer() *Analyzer {
	return NewAnalyzerWithPolicy(DefaultPolicy())
}

func NewAnalyzerWithPolicy(policy Policy) *Analyzer {
	return &Analyzer{
		clientQueries:            make(map[string][]time.Time),
		clientBaseSubdomainQuery: make(map[string]map[string]time.Time),
		clientNXDomains:          make(map[string][]time.Time),
		now:                      time.Now,
		policy:                   policy.WithDefaults(),
	}
}

func DefaultPolicy() Policy {
	return Policy{
		Configured:                 true,
		Enabled:                    true,
		TunnelMaxQNameLength:       180,
		TunnelMaxLabelLength:       63,
		TunnelEntropyThreshold:     4.0,
		DGAEntropyThreshold:        4.2,
		DGADigitRatioThreshold:     0.25,
		QueryRateWindowSeconds:     60,
		QueryRateThreshold:         120,
		RandomSubdomainWindowSec:   60,
		RandomSubdomainThreshold:   50,
		NXDomainWindowSeconds:      60,
		NXDomainThreshold:          20,
		BlockRebinding:             true,
		AbnormalRRAction:           ActionLogOnly,
		ReflectionAmplificationAct: ActionRateLimit,
		SinkholeIPv4:               "0.0.0.0",
		SinkholeIPv6:               "::",
		SinkholeTTL:                60,
	}
}

func (p Policy) WithDefaults() Policy {
	defaults := DefaultPolicy()
	if !p.Configured && !p.Enabled {
		return defaults
	}
	p.Configured = true
	if p.TunnelMaxQNameLength == 0 {
		p.TunnelMaxQNameLength = defaults.TunnelMaxQNameLength
	}
	if p.TunnelMaxLabelLength == 0 {
		p.TunnelMaxLabelLength = defaults.TunnelMaxLabelLength
	}
	if p.TunnelEntropyThreshold == 0 {
		p.TunnelEntropyThreshold = defaults.TunnelEntropyThreshold
	}
	if p.DGAEntropyThreshold == 0 {
		p.DGAEntropyThreshold = defaults.DGAEntropyThreshold
	}
	if p.DGADigitRatioThreshold == 0 {
		p.DGADigitRatioThreshold = defaults.DGADigitRatioThreshold
	}
	if p.QueryRateWindowSeconds == 0 {
		p.QueryRateWindowSeconds = defaults.QueryRateWindowSeconds
	}
	if p.QueryRateThreshold == 0 {
		p.QueryRateThreshold = defaults.QueryRateThreshold
	}
	if p.RandomSubdomainWindowSec == 0 {
		p.RandomSubdomainWindowSec = defaults.RandomSubdomainWindowSec
	}
	if p.RandomSubdomainThreshold == 0 {
		p.RandomSubdomainThreshold = defaults.RandomSubdomainThreshold
	}
	if p.NXDomainWindowSeconds == 0 {
		p.NXDomainWindowSeconds = defaults.NXDomainWindowSeconds
	}
	if p.NXDomainThreshold == 0 {
		p.NXDomainThreshold = defaults.NXDomainThreshold
	}
	if p.AbnormalRRAction == "" {
		p.AbnormalRRAction = defaults.AbnormalRRAction
	}
	if p.ReflectionAmplificationAct == "" {
		p.ReflectionAmplificationAct = defaults.ReflectionAmplificationAct
	}
	if p.SinkholeIPv4 == "" {
		p.SinkholeIPv4 = defaults.SinkholeIPv4
	}
	if p.SinkholeIPv6 == "" {
		p.SinkholeIPv6 = defaults.SinkholeIPv6
	}
	if p.SinkholeTTL == 0 {
		p.SinkholeTTL = defaults.SinkholeTTL
	}
	if normalized, err := NormalizeDNSLogPlatformDomains(p.DNSLogPlatformDomains); err == nil {
		p.DNSLogPlatformDomains = normalized
	}
	return p
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	type alias Policy
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["enabled"]; !ok {
		out.Enabled = true
	}
	out.Configured = true
	*p = Policy(out)
	return nil
}

func (a *Analyzer) AnalyzeQuery(req plugins.ResolveRequest) Finding {
	if !a.policy.Enabled {
		return Finding{"security-disabled", RiskNone, ActionAllow, "security policy disabled"}
	}
	qname := strings.TrimSuffix(plugins.NormalizeQName(req.QName), ".")
	qtype := plugins.NormalizeQType(req.QType)
	if matchesDomainPattern(qname, a.policy.AllowlistDomains) {
		return Finding{"allowlist-domain", RiskNone, ActionAllow, "domain matched security allowlist"}
	}
	if a.policy.RejectDNSLogPlatforms && matchesPlatformDomain(qname, a.policy.DNSLogPlatformDomains) {
		return Finding{"external-dnslog-platform", RiskHigh, ActionBlock, "domain matched external DNSLog/OOB callback platform list"}
	}
	if matchesDomainPattern(qname, a.policy.DenylistDomains) {
		return Finding{"denylist-domain", RiskCritical, ActionBlock, "domain matched security denylist"}
	}
	if matchesDomainPattern(qname, a.policy.SinkholeDomains) {
		return Finding{"sinkhole-domain", RiskHigh, ActionSinkhole, "domain matched sinkhole policy"}
	}
	if a.trackQueryRate(req.Context.ClientIP) {
		return Finding{"query-rate-limit", RiskMedium, ActionRateLimit, "client exceeded query rate threshold"}
	}
	if a.trackRandomSubdomain(req.Context.ClientIP, qname) {
		return Finding{"random-subdomain-rate-limit", RiskHigh, ActionRateLimit, "client queried too many unique subdomains under one base domain"}
	}
	labels := strings.Split(qname, ".")
	longest := ""
	for _, label := range labels {
		if len(label) > len(longest) {
			longest = label
		}
	}
	if qtype == "TXT" && (len(qname) > a.policy.TunnelMaxQNameLength || len(longest) > a.policy.TunnelMaxLabelLength || entropy(longest) >= a.policy.TunnelEntropyThreshold) {
		return Finding{"dns-tunnel-high-entropy", RiskHigh, ActionForwardToHoneypot, "TXT query has long or high-entropy label"}
	}
	if entropy(strings.ReplaceAll(qname, ".", "")) >= a.policy.DGAEntropyThreshold && digitRatio(qname) > a.policy.DGADigitRatioThreshold {
		return Finding{"dga-high-entropy", RiskHigh, ActionBlock, "domain resembles DGA/high-entropy sample"}
	}
	if isAbnormalQType(qtype) {
		return Finding{"abnormal-rr-query", RiskMedium, a.policy.AbnormalRRAction, "unusual RR type queried"}
	}
	if qtype == "ANY" || qtype == "DNSKEY" {
		return Finding{"reflection-amplification-rr", RiskMedium, a.policy.ReflectionAmplificationAct, "query type can amplify reflection attacks"}
	}
	return Finding{"default-allow", RiskNone, ActionAllow, "no rule matched"}
}

func (a *Analyzer) AnalyzeResponse(req plugins.ResolveRequest, result plugins.ResolveResult) Finding {
	if !a.policy.Enabled {
		return Finding{"security-disabled", RiskNone, ActionAllow, "security policy disabled"}
	}
	if result.RCode == plugins.RCodeNXDomain && a.trackNXDomain(req.Context.ClientIP) {
		return Finding{"nxdomain-flood", RiskHigh, ActionRateLimit, "client exceeded NXDOMAIN threshold"}
	}
	for _, rr := range result.RRSet {
		if a.policy.BlockRebinding && (rr.Type == "A" || rr.Type == "AAAA") && isPrivate(rr.Value) {
			return Finding{"dns-rebinding-private-address", RiskHigh, ActionBlock, "answer contains private or local address"}
		}
	}
	return Finding{"default-allow", RiskNone, ActionAllow, "no rule matched"}
}

func (a *Analyzer) trackQueryRate(clientIP string) bool {
	if clientIP == "" {
		clientIP = "unknown"
	}
	return a.trackWindowCount(clientIP, a.policy.QueryRateWindowSeconds, a.policy.QueryRateThreshold, a.clientQueries)
}

func (a *Analyzer) trackRandomSubdomain(clientIP, qname string) bool {
	if clientIP == "" {
		clientIP = "unknown"
	}
	if a.policy.RandomSubdomainThreshold <= 0 || a.policy.RandomSubdomainWindowSec <= 0 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) < 3 {
		return false
	}
	base := strings.Join(labels[len(labels)-2:], ".")
	subdomain := strings.Join(labels[:len(labels)-2], ".")
	key := clientIP + "|" + base
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	cutoff := now.Add(-time.Duration(a.policy.RandomSubdomainWindowSec) * time.Second)
	seen := a.clientBaseSubdomainQuery[key]
	if seen == nil {
		seen = map[string]time.Time{}
	}
	for name, ts := range seen {
		if !ts.After(cutoff) {
			delete(seen, name)
		}
	}
	seen[subdomain] = now
	a.clientBaseSubdomainQuery[key] = seen
	return len(seen) >= a.policy.RandomSubdomainThreshold
}

func (a *Analyzer) trackNXDomain(clientIP string) bool {
	if clientIP == "" {
		clientIP = "unknown"
	}
	return a.trackWindowCount(clientIP, a.policy.NXDomainWindowSeconds, a.policy.NXDomainThreshold, a.clientNXDomains)
}

func (a *Analyzer) trackWindowCount(key string, windowSeconds, threshold int, store map[string][]time.Time) bool {
	if threshold <= 0 || windowSeconds <= 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	cutoff := now.Add(-time.Duration(windowSeconds) * time.Second)
	values := store[key]
	kept := values[:0]
	for _, seen := range values {
		if seen.After(cutoff) {
			kept = append(kept, seen)
		}
	}
	kept = append(kept, now)
	store[key] = kept
	return len(kept) >= threshold
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	var e float64
	l := float64(len([]rune(s)))
	for _, c := range counts {
		p := c / l
		e -= p * math.Log2(p)
	}
	return e
}

func digitRatio(s string) float64 {
	if s == "" {
		return 0
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return float64(digits) / float64(len([]rune(s)))
}

func isAbnormalQType(qtype string) bool {
	switch qtype {
	case "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "URI", "HTTPS", "SVCB", "TLSA", "CAA", "WALLET", "TYPE262", "ANY", "DNSKEY":
		return false
	default:
		return true
	}
}

func isPrivate(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

func matchesDomainPattern(qname string, patterns []string) bool {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	for _, pattern := range patterns {
		p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, ".") {
			suffix := strings.TrimPrefix(p, ".")
			if q == suffix || strings.HasSuffix(q, "."+suffix) {
				return true
			}
			continue
		}
		if q == p {
			return true
		}
	}
	return false
}

func matchesPlatformDomain(qname string, domains []string) bool {
	q, ok := normalizePlatformDomain(qname)
	if !ok {
		return false
	}
	for _, domain := range domains {
		p, ok := normalizePlatformDomain(domain)
		if !ok {
			continue
		}
		if q == p || strings.HasSuffix(q, "."+p) {
			return true
		}
	}
	return false
}

func normalizePlatformDomain(value string) (string, bool) {
	ascii, err := dnsname.ToASCII(value)
	if err != nil {
		return "", false
	}
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ascii)), ".")
	if domain == "" || domain == "." || strings.HasPrefix(domain, ".") || strings.Contains(domain, "..") {
		return "", false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", false
		}
	}
	return domain, true
}

func NormalizeDNSLogPlatformDomains(domains []string) ([]string, error) {
	normalized := make([]string, 0, len(domains))
	seen := map[string]bool{}
	for i, domain := range domains {
		value, ok := normalizePlatformDomain(domain)
		if !ok {
			return nil, fmt.Errorf("dnslog platform domain %d is invalid", i)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		normalized = append(normalized, value)
	}
	return normalized, nil
}

func (a *Analyzer) Policy() Policy {
	return a.policy
}
