package security

import (
	"testing"
	"time"

	"github.com/anyns/anyns/internal/plugins"
)

func TestAnalyzeQueryDetectsDNSTunnel(t *testing.T) {
	analyzer := NewAnalyzer()
	finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{
		QName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
		QType: "TXT",
	})
	if finding.Rule != "dns-tunnel-high-entropy" || finding.Action != ActionForwardToHoneypot {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestAnalyzeResponseDetectsRebinding(t *testing.T) {
	analyzer := NewAnalyzer()
	finding := analyzer.AnalyzeResponse(plugins.ResolveRequest{}, plugins.ResolveResult{
		RCode: plugins.RCodeNoError,
		RRSet: []plugins.RR{{Type: "A", Value: "192.168.1.10"}},
	})
	if finding.Rule != "dns-rebinding-private-address" || finding.Action != ActionBlock {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestAnalyzeQueryHonorsListPolicies(t *testing.T) {
	analyzer := NewAnalyzerWithPolicy(Policy{
		Enabled:          true,
		AllowlistDomains: []string{"safe.example"},
		DenylistDomains:  []string{".blocked.example"},
		SinkholeDomains:  []string{"ads.example"},
	})

	allowed := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: "safe.example", QType: "TXT"})
	if allowed.Rule != "allowlist-domain" || allowed.Action != ActionAllow {
		t.Fatalf("allowlist finding = %#v", allowed)
	}

	denied := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: "sub.blocked.example", QType: "A"})
	if denied.Rule != "denylist-domain" || denied.Action != ActionBlock || denied.RiskLevel != RiskCritical {
		t.Fatalf("denylist finding = %#v", denied)
	}

	sinkholed := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: "ads.example", QType: "A"})
	if sinkholed.Rule != "sinkhole-domain" || sinkholed.Action != ActionSinkhole {
		t.Fatalf("sinkhole finding = %#v", sinkholed)
	}
}

func TestAnalyzeQueryRejectsExternalDNSLogPlatforms(t *testing.T) {
	analyzer := NewAnalyzerWithPolicy(Policy{
		Enabled:               true,
		RejectDNSLogPlatforms: true,
		DNSLogPlatformDomains: []string{"Interactsh.COM.", "dnslog.例子"},
	})

	for _, qname := range []string{
		"interactsh.com",
		"token.INTERACTSH.com.",
		"dnslog.xn--fsqu00a",
		"a.b.dnslog.xn--fsqu00a.",
	} {
		finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: qname, QType: "A"})
		if finding.Rule != "external-dnslog-platform" || finding.Action != ActionBlock || finding.RiskLevel != RiskHigh {
			t.Fatalf("dnslog platform finding for %q = %#v", qname, finding)
		}
	}

	for _, qname := range []string{
		"notinteractsh.com",
		"interactsh.com.evil.example",
		"evilinteractsh.com",
	} {
		finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: qname, QType: "A"})
		if finding.Rule == "external-dnslog-platform" {
			t.Fatalf("boundary bypass candidate %q should not match: %#v", qname, finding)
		}
	}
}

func TestAnalyzeQueryAllowsTrustedDomainBeforeDNSLogPlatformRejection(t *testing.T) {
	analyzer := NewAnalyzerWithPolicy(Policy{
		Enabled:               true,
		AllowlistDomains:      []string{".interactsh.com"},
		RejectDNSLogPlatforms: true,
		DNSLogPlatformDomains: []string{"interactsh.com"},
		DenylistDomains:       []string{".interactsh.com"},
	})

	finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: "token.interactsh.com", QType: "TXT"})
	if finding.Rule != "allowlist-domain" || finding.Action != ActionAllow {
		t.Fatalf("allowlist should take precedence over DNSLog platform rejection: %#v", finding)
	}
}

func TestAnalyzeQueryDNSLogPlatformRejectionCanBeDisabled(t *testing.T) {
	analyzer := NewAnalyzerWithPolicy(Policy{
		Enabled:               true,
		RejectDNSLogPlatforms: false,
		DNSLogPlatformDomains: []string{"interactsh.com"},
	})

	finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{QName: "token.interactsh.com", QType: "A"})
	if finding.Rule == "external-dnslog-platform" || finding.Action != ActionAllow {
		t.Fatalf("disabled DNSLog platform rejection finding = %#v", finding)
	}
}

func TestNormalizeDNSLogPlatformDomainsRejectsUnsafeEntries(t *testing.T) {
	normalized, err := NormalizeDNSLogPlatformDomains([]string{" Interactsh.COM. ", "dnslog.例子", "interactsh.com"})
	if err != nil {
		t.Fatalf("normalize domains: %v", err)
	}
	if len(normalized) != 2 || normalized[0] != "interactsh.com" || normalized[1] != "dnslog.xn--fsqu00a" {
		t.Fatalf("normalized domains = %#v", normalized)
	}

	for _, domains := range [][]string{
		{""},
		{"*.interactsh.com"},
		{".interactsh.com"},
		{"bad..interactsh.com"},
		{"bad\ninteractsh.com"},
		{"-bad.example"},
		{"bad-.example"},
	} {
		if _, err := NormalizeDNSLogPlatformDomains(domains); err == nil {
			t.Fatalf("expected unsafe DNSLog platform entry to fail: %#v", domains)
		}
	}
}

func TestAnalyzeQueryRateLimitsClientWindow(t *testing.T) {
	analyzer := NewAnalyzerWithPolicy(Policy{
		Enabled:                true,
		QueryRateWindowSeconds: 10,
		QueryRateThreshold:     3,
	})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	analyzer.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{
			QName:   "example.hns",
			QType:   "A",
			Context: plugins.QueryContext{ClientIP: "192.0.2.50"},
		})
		if finding.Action != ActionAllow {
			t.Fatalf("finding before threshold = %#v", finding)
		}
	}
	limited := analyzer.AnalyzeQuery(plugins.ResolveRequest{
		QName:   "example.hns",
		QType:   "A",
		Context: plugins.QueryContext{ClientIP: "192.0.2.50"},
	})
	if limited.Rule != "query-rate-limit" || limited.Action != ActionRateLimit {
		t.Fatalf("rate-limit finding = %#v", limited)
	}

	now = now.Add(11 * time.Second)
	expired := analyzer.AnalyzeQuery(plugins.ResolveRequest{
		QName:   "example.hns",
		QType:   "A",
		Context: plugins.QueryContext{ClientIP: "192.0.2.50"},
	})
	if expired.Action != ActionAllow {
		t.Fatalf("window should expire, got %#v", expired)
	}
}

func TestAnalyzeQueryRateLimitsRandomSubdomains(t *testing.T) {
	analyzer := NewAnalyzerWithPolicy(Policy{
		Enabled:                  true,
		QueryRateThreshold:       100,
		RandomSubdomainWindowSec: 30,
		RandomSubdomainThreshold: 3,
	})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	analyzer.now = func() time.Time { return now }

	for _, qname := range []string{"a1.example.com", "b2.example.com"} {
		finding := analyzer.AnalyzeQuery(plugins.ResolveRequest{
			QName:   qname,
			QType:   "A",
			Context: plugins.QueryContext{ClientIP: "192.0.2.51"},
		})
		if finding.Action != ActionAllow {
			t.Fatalf("finding before random-subdomain threshold = %#v", finding)
		}
	}
	limited := analyzer.AnalyzeQuery(plugins.ResolveRequest{
		QName:   "c3.example.com",
		QType:   "A",
		Context: plugins.QueryContext{ClientIP: "192.0.2.51"},
	})
	if limited.Rule != "random-subdomain-rate-limit" || limited.Action != ActionRateLimit {
		t.Fatalf("random-subdomain finding = %#v", limited)
	}
}
