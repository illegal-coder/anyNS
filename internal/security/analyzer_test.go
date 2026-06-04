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
