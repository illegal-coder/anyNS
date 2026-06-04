package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/dnslog"
	"github.com/anyns/anyns/internal/honeypot"
	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/plugins/hns"
	"github.com/anyns/anyns/internal/plugins/wave1"
	"github.com/anyns/anyns/internal/security"
)

type App struct {
	Registry *plugins.Registry
	Security *security.Analyzer
	DNSLog   *dnslog.Store
	Honeypot *honeypot.Client
	Config   config.Config
}

func (a *App) AppendManagementAudit(operation, principalID, method, path, status string, details map[string]any) {
	if a == nil || a.DNSLog == nil {
		return
	}
	if principalID == "" {
		principalID = "unknown"
	}
	if details == nil {
		details = map[string]any{}
	}
	details["principal_id"] = principalID
	details["method"] = method
	details["path"] = path
	details["status"] = status
	now := time.Now().UTC()
	a.DNSLog.Append(dnslog.Event{
		Timestamp:    now,
		TraceID:      "management-" + now.Format("20060102T150405.000000000"),
		ClientView:   "management",
		Tenant:       "management",
		QName:        path,
		QType:        method,
		RCode:        status,
		SourcePlugin: "management",
		RiskLevel:    "low",
		Action:       "management_mutation",
		MatchedRule:  operation,
		RawRR:        details,
	})
}

func New(honeypotClient *honeypot.Client) *App {
	cfg := config.Default()
	cfg.Honeypot.URL = honeypotClient.URL
	cfg.Honeypot.APIKey = honeypotClient.APIKey
	cfg.Honeypot.HMACSecret = honeypotClient.HMACSecret
	app, err := NewFromConfig(cfg)
	if err != nil {
		return &App{
			Registry: plugins.NewRegistry(plugins.DefaultRoutes(), hns.New()),
			Security: security.NewAnalyzer(),
			DNSLog:   dnslog.NewStore(1000),
			Honeypot: honeypotClient,
			Config:   cfg,
		}
	}
	return app
}

func NewFromConfig(cfg config.Config) (*App, error) {
	honeypotClient, err := newHoneypotClient(cfg)
	if err != nil {
		return nil, err
	}
	logStore, err := dnslog.NewPersistentStore(cfg.DNSLog.Limit, cfg.DNSLog.Path)
	if err != nil {
		return nil, fmt.Errorf("dnslog store: %w", err)
	}
	plugs := buildPlugins(cfg.Plugins)
	return &App{
		Registry: plugins.NewRegistry(cfg.Routes, plugs...),
		Security: security.NewAnalyzerWithPolicy(cfg.Security),
		DNSLog:   logStore,
		Honeypot: honeypotClient,
		Config:   cfg,
	}, nil
}

func (a *App) ReloadFromConfig(cfg config.Config) error {
	refreshed, err := NewFromConfig(cfg)
	if err != nil {
		return err
	}
	a.Registry = refreshed.Registry
	a.Security = refreshed.Security
	a.DNSLog = refreshed.DNSLog
	a.Honeypot = refreshed.Honeypot
	a.Config = refreshed.Config
	return nil
}

func buildPlugins(pluginCfgs []config.PluginConfig) []plugins.Plugin {
	hnsPlugin := hns.New()
	plugs := []plugins.Plugin{hnsPlugin}
	wave1Plugins := wave1.NewAll()
	for _, p := range wave1Plugins {
		plugs = append(plugs, p)
	}
	configByName := map[string]config.PluginConfig{}
	for _, p := range pluginCfgs {
		configByName[p.Name] = p
	}
	for _, p := range plugs {
		if cfg, ok := configByName[p.Name()]; ok {
			p.SetEnabled(cfg.Enabled)
		}
	}
	if cfg, ok := configByName[hnsPlugin.Name()]; ok {
		hnsPlugin.ConfigureBackend(hns.BackendConfig{
			URL:            cfg.BackendURL,
			APIKey:         cfg.BackendAPIKey,
			RequestTimeout: cfg.RequestTimeout.Duration,
		})
	}
	for _, p := range wave1Plugins {
		if cfg, ok := configByName[p.Name()]; ok {
			p.ConfigureBackend(wave1.BackendConfig{
				Type:           cfg.BackendType,
				URL:            cfg.BackendURL,
				APIKey:         cfg.BackendAPIKey,
				RequestTimeout: cfg.RequestTimeout.Duration,
			})
		}
	}
	return plugs
}

func newHoneypotClient(cfg config.Config) (*honeypot.Client, error) {
	queue, err := honeypot.NewFailedQueue(cfg.Honeypot.FailedQueuePath, cfg.Honeypot.FailedQueueMaxEntries)
	if err != nil {
		return nil, fmt.Errorf("honeypot failed queue: %w", err)
	}
	timeout := cfg.Honeypot.RequestTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &honeypot.Client{
		URL:           cfg.Honeypot.URL,
		APIKey:        cfg.Honeypot.APIKey,
		HMACSecret:    cfg.Honeypot.HMACSecret,
		HTTPClient:    &http.Client{Timeout: timeout},
		Queue:         queue,
		MaxAttempts:   cfg.Honeypot.MaxAttempts,
		RetryInterval: cfg.Honeypot.RetryInterval,
	}, nil
}
