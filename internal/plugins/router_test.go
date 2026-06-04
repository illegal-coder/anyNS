package plugins_test

import (
	"context"
	"testing"

	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/plugins/hns"
	"github.com/anyns/anyns/internal/plugins/wave1"
)

func TestRegistryRoutesHNSByPriorityAndSuffix(t *testing.T) {
	registry := plugins.NewRegistry(plugins.DefaultRoutes(), hns.New())
	result, route, err := registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if route.Plugin != "hns" {
		t.Fatalf("route plugin = %q, want hns", route.Plugin)
	}
	if result.RCode != plugins.RCodeNoError || result.SourcePlugin != "hns" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Value != "203.0.113.10" {
		t.Fatalf("unexpected rrset: %#v", result.RRSet)
	}
}

func TestRegistryDoesNotHijackICANN(t *testing.T) {
	registry := plugins.NewRegistry(plugins.DefaultRoutes(), hns.New())
	_, _, err := registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.com",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err != plugins.ErrNoRoute {
		t.Fatalf("err = %v, want ErrNoRoute", err)
	}
}

func TestRegistryCacheIsIsolatedByClientView(t *testing.T) {
	registry := plugins.NewRegistry(plugins.DefaultRoutes(), hns.New())
	req := plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	}
	if _, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if result, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("second resolve failed: %v", err)
	} else if result.AuditMetadata["cache_hit"] != true {
		t.Fatalf("expected cache hit metadata, got %#v", result.AuditMetadata)
	}
	req.Context.ClientView = "adguard"
	if result, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("adguard resolve failed: %v", err)
	} else if result.AuditMetadata["cache_hit"] == true {
		t.Fatalf("cache should be isolated by client view")
	}
}

func TestRegistryNormalizesClientViewAndTenantForRouteMatchingAndCache(t *testing.T) {
	registry := plugins.NewRegistry(plugins.DefaultRoutes(), hns.New())
	req := plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: " AdGuard ",
			Tenant:     " DEFAULT ",
		},
	}
	if result, route, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("mixed-case route resolve failed: route=%#v result=%#v err=%v", route, result, err)
	} else if route.Name != "hns-default" {
		t.Fatalf("route = %#v", route)
	} else if result.AuditMetadata["cache_hit"] == true {
		t.Fatalf("first normalized resolve should not be a cache hit")
	}

	req.Context.ClientView = "adguard"
	req.Context.Tenant = "default"
	if result, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("normalized cache resolve failed: %v", err)
	} else if result.AuditMetadata["cache_hit"] != true {
		t.Fatalf("expected cache hit after client_view/tenant normalization, got %#v", result.AuditMetadata)
	}
}

func TestRegistryRoutesExactDomainBeforeLowerPrioritySuffix(t *testing.T) {
	registry := plugins.NewRegistry([]plugins.Route{
		{
			Name:     "hns-suffix",
			Suffixes: []string{".hns"},
			Plugin:   "hns",
			Priority: 100,
			Fallback: "icann-recursive",
		},
		{
			Name:     "hns-exact-override",
			Domains:  []string{"example.hns"},
			Plugin:   "hns",
			Priority: 200,
			Fallback: "icann-recursive",
		},
	}, hns.New())

	_, route, err := registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns.",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if route.Name != "hns-exact-override" {
		t.Fatalf("route = %#v", route)
	}
}

func TestRegistryRequiresConfiguredPolicyTags(t *testing.T) {
	registry := plugins.NewRegistry([]plugins.Route{
		{
			Name:       "adguard-only",
			Suffixes:   []string{".hns"},
			PolicyTags: []string{"adguard"},
			Plugin:     "hns",
			Priority:   100,
			Fallback:   "icann-recursive",
		},
	}, hns.New())

	req := plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	}
	if _, _, err := registry.Resolve(context.Background(), req); err != plugins.ErrNoRoute {
		t.Fatalf("err without policy tag = %v, want ErrNoRoute", err)
	}
	req.Context.PolicyTags = []string{"adguard", "audit"}
	_, route, err := registry.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("resolve with policy tag failed: %v", err)
	}
	if route.Name != "adguard-only" {
		t.Fatalf("route = %#v", route)
	}
}

func TestDefaultWave3RoutesKeepDidBitLowerPriorityThanNamecoin(t *testing.T) {
	routes := append(plugins.DefaultWave1Routes(), plugins.DefaultWave3Routes()...)
	plugs := make([]plugins.Plugin, 0, len(wave1.NewAll()))
	for _, p := range wave1.NewAll() {
		if p.Name() == "namecoin-bit" || p.Name() == "did-bit" {
			p.SetEnabled(true)
		}
		plugs = append(plugs, p)
	}
	registry := plugins.NewRegistry(routes, plugs...)

	_, route, err := registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.bit",
		QType: "TXT",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err == nil {
		t.Fatalf("expected skeleton backend error")
	}
	if route.Plugin != "namecoin-bit" {
		t.Fatalf(".bit should prefer Namecoin route, got %#v", route)
	}
}

func TestRegistryCacheIsIsolatedByPolicyTags(t *testing.T) {
	registry := plugins.NewRegistry(plugins.DefaultRoutes(), hns.New())
	req := plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	}
	if _, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if result, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("second resolve failed: %v", err)
	} else if result.AuditMetadata["cache_hit"] != true {
		t.Fatalf("expected same-policy cache hit, got %#v", result.AuditMetadata)
	}

	req.Context.PolicyTags = []string{"adguard"}
	if result, _, err := registry.Resolve(context.Background(), req); err != nil {
		t.Fatalf("tagged resolve failed: %v", err)
	} else if result.AuditMetadata["cache_hit"] == true {
		t.Fatalf("cache should be isolated by policy tags")
	}
}
