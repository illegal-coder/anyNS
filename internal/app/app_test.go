package app

import (
	"context"
	"testing"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/plugins"
)

func TestNewFromConfigIncludesDecentralizedPluginSkeletons(t *testing.T) {
	cfg := config.Default()
	application, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	names := map[string]bool{}
	for _, p := range application.Registry.Plugins() {
		names[p.Name()] = p.Enabled()
	}
	if !names["hns"] {
		t.Fatalf("hns should be enabled by default: %#v", names)
	}
	for _, name := range []string{
		"ens",
		"namecoin-bit",
		"stacks-bns",
		"pns-polkadot",
		"pns-pulsechain",
		"unstoppable-domains",
		"solana-sns",
		"space-id",
		"ton-dns",
		"tezos-domains",
		"aptos-names",
		"suins",
		"freename-fns",
		"rif-rns",
		"fio-handle",
		"openalias",
		"ada-handle",
		"did-bit",
	} {
		if _, ok := names[name]; !ok {
			t.Fatalf("missing decentralized plugin %s in %#v", name, names)
		}
		if names[name] {
			t.Fatalf("decentralized plugin %s should be disabled until a backend is configured", name)
		}
	}
}

func TestNewFromConfigAppliesRoutesAndPluginStates(t *testing.T) {
	cfg := config.Default()
	cfg.Plugins = []config.PluginConfig{
		{Name: "hns", Enabled: true},
		{Name: "ens", Enabled: true},
	}
	cfg.Routes = []plugins.Route{
		{
			Name:        "ens-test",
			Suffixes:    []string{".eth"},
			ClientViews: []string{"default"},
			Tenants:     []string{"default"},
			Plugin:      "ens",
			Priority:    200,
			Fallback:    "nxdomain",
		},
	}
	application, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	result, route, err := application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "vitalik.eth",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err == nil {
		t.Fatalf("expected enabled wave1 skeleton backend error")
	}
	if route.Name != "ens-test" {
		t.Fatalf("route = %#v", route)
	}
	if result.SourcePlugin != "ens" || result.RCode != plugins.RCodeServFail {
		t.Fatalf("result = %#v", result)
	}

	_, _, err = application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err != plugins.ErrNoRoute {
		t.Fatalf("hns should not be routed when config replaces routes, got %v", err)
	}
}

func TestNewFromConfigAppliesWave1BackendConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Plugins = []config.PluginConfig{
		{Name: "ens", Enabled: true, BackendURL: "https://ens-backend.example/resolve"},
	}
	application, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	for _, p := range application.Registry.Plugins() {
		if p.Name() != "ens" {
			continue
		}
		if !p.Enabled() {
			t.Fatalf("ens should be enabled")
		}
		if err := p.Health(context.Background()); err != nil {
			t.Fatalf("ens backend health = %v", err)
		}
		return
	}
	t.Fatalf("ens plugin not found")
}

func TestNewFromConfigAppliesHNSBackendConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Plugins = []config.PluginConfig{
		{Name: "hns", Enabled: true, BackendURL: "://hns-backend"},
	}
	application, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	result, _, err := application.Registry.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "example.hns",
		QType: "A",
		Context: plugins.QueryContext{
			ClientView: "default",
			Tenant:     "default",
		},
	})
	if err == nil {
		t.Fatalf("expected remote backend request failure without a reachable HNS backend")
	}
	if result.SourcePlugin != "hns" || result.RCode != plugins.RCodeServFail {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] == "static-hns-fixture" {
		t.Fatalf("expected configured remote backend to replace static fixture: %#v", result.RawRecord)
	}
}
