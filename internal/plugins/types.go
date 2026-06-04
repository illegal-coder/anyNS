package plugins

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

const (
	RCodeNoError  = "NOERROR"
	RCodeNXDomain = "NXDOMAIN"
	RCodeServFail = "SERVFAIL"
)

var (
	ErrPluginDisabled = errors.New("plugin disabled")
	ErrNoRoute        = errors.New("no plugin route matched")
)

type QueryContext struct {
	TraceID    string   `json:"trace_id"`
	ClientIP   string   `json:"client_ip"`
	ClientView string   `json:"client_view"`
	Tenant     string   `json:"tenant"`
	Transport  string   `json:"transport"`
	Protocol   string   `json:"protocol"`
	PolicyTags []string `json:"policy_tags"`
}

type ResolveRequest struct {
	QName   string       `json:"qname"`
	QType   string       `json:"qtype"`
	Context QueryContext `json:"context"`
}

type RR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

type ResolveResult struct {
	RRSet         []RR           `json:"rrset"`
	RCode         string         `json:"rcode"`
	TTL           int            `json:"ttl"`
	SourcePlugin  string         `json:"source_plugin"`
	Confidence    string         `json:"confidence"`
	SecurityTags  []string       `json:"security_tags"`
	RawRecord     map[string]any `json:"raw_record,omitempty"`
	AuditMetadata map[string]any `json:"audit_metadata,omitempty"`
	LatencyMS     int64          `json:"latency_ms"`
}

type Plugin interface {
	Name() string
	Enabled() bool
	SetEnabled(enabled bool)
	Suffixes() []string
	Resolve(ctx context.Context, req ResolveRequest) (ResolveResult, error)
	Health(ctx context.Context) error
}

type Route struct {
	Name        string   `json:"name"`
	Domains     []string `json:"domains,omitempty"`
	Suffixes    []string `json:"suffixes"`
	ClientViews []string `json:"client_views,omitempty"`
	Tenants     []string `json:"tenants,omitempty"`
	PolicyTags  []string `json:"policy_tags,omitempty"`
	Plugin      string   `json:"plugin"`
	Priority    int      `json:"priority"`
	Fallback    string   `json:"fallback"`
}

func NormalizeQName(qname string) string {
	q := strings.ToLower(strings.TrimSpace(qname))
	q = strings.TrimSuffix(q, ".")
	if q == "" {
		return "."
	}
	return q + "."
}

func NormalizeQType(qtype string) string {
	return strings.ToUpper(strings.TrimSpace(qtype))
}

func MatchSuffix(qname, suffix string) bool {
	q := NormalizeQName(qname)
	s := strings.ToLower(strings.TrimSpace(suffix))
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	return q == s+"." || strings.HasSuffix(q, "."+s+".")
}

func IsPrivateAddress(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func NewResult(plugin, rcode string, ttl int, rrset []RR, started time.Time) ResolveResult {
	return ResolveResult{
		RRSet:        rrset,
		RCode:        rcode,
		TTL:          ttl,
		SourcePlugin: plugin,
		Confidence:   "authoritative",
		SecurityTags: []string{"decentralized", plugin},
		RawRecord: map[string]any{
			"rr_count": len(rrset),
		},
		AuditMetadata: map[string]any{
			"resolved_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
		LatencyMS: time.Since(started).Milliseconds(),
	}
}
