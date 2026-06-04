package hns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/anyns/anyns/internal/plugins"
)

type Plugin struct {
	mu             sync.RWMutex
	enabled        bool
	records        map[string][]plugins.RR
	timeout        time.Duration
	backendURL     string
	backendAPIKey  string
	backendTimeout time.Duration
	httpClient     *http.Client
	dnsExchange    dnsExchangeFunc
}

type BackendConfig struct {
	URL            string
	APIKey         string
	RequestTimeout time.Duration
	HTTPClient     *http.Client
	DNSExchange    dnsExchangeFunc
}

func New() *Plugin {
	return &Plugin{
		enabled:        true,
		timeout:        2 * time.Second,
		backendTimeout: 3 * time.Second,
		httpClient:     http.DefaultClient,
		dnsExchange:    exchangeDNS,
		records: map[string][]plugins.RR{
			"example.hns.": {
				{Name: "example.hns.", Type: "A", TTL: 300, Value: "203.0.113.10"},
				{Name: "example.hns.", Type: "AAAA", TTL: 300, Value: "2001:db8::10"},
				{Name: "example.hns.", Type: "TXT", TTL: 300, Value: "anyNS HNS sample record"},
				{Name: "example.hns.", Type: "NS", TTL: 300, Value: "ns1.example.hns."},
			},
			"wallet.hns.": {
				{Name: "wallet.hns.", Type: "WALLET", TTL: 300, Value: "eth 0x0000000000000000000000000000000000000000"},
				{Name: "wallet.hns.", Type: "TYPE262", TTL: 300, Value: `\# 45 036574682A3078303030303030303030303030303030303030303030303030303030303030303030303030`},
			},
		},
	}
}

func (p *Plugin) ConfigureBackend(cfg BackendConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backendURL = strings.TrimSpace(cfg.URL)
	p.backendAPIKey = strings.TrimSpace(cfg.APIKey)
	if cfg.RequestTimeout > 0 {
		p.backendTimeout = cfg.RequestTimeout
	}
	if cfg.HTTPClient != nil {
		p.httpClient = cfg.HTTPClient
	}
	if cfg.DNSExchange != nil {
		p.dnsExchange = cfg.DNSExchange
	}
}

func (p *Plugin) Name() string { return "hns" }

func (p *Plugin) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

func (p *Plugin) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

func (p *Plugin) Suffixes() []string { return []string{".hns", ".hsd"} }

func (p *Plugin) Health(ctx context.Context) error {
	if !p.Enabled() {
		return errors.New("hns plugin disabled")
	}
	return nil
}

func (p *Plugin) Resolve(ctx context.Context, req plugins.ResolveRequest) (plugins.ResolveResult, error) {
	started := time.Now()
	backendURL, apiKey, timeout, client := p.backendState()
	if backendURL != "" {
		if strings.HasPrefix(strings.ToLower(backendURL), "dns://") {
			return p.resolveDNSBackend(ctx, req, backendURL, timeout, started)
		}
		return p.resolveRemote(ctx, req, backendURL, apiKey, timeout, client, started)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	select {
	case <-timeoutCtx.Done():
		return plugins.ResolveResult{}, timeoutCtx.Err()
	default:
	}

	qname := plugins.NormalizeQName(req.QName)
	qtype := plugins.NormalizeQType(req.QType)
	p.mu.RLock()
	records := append([]plugins.RR(nil), p.records[qname]...)
	p.mu.RUnlock()
	if len(records) == 0 {
		res := plugins.NewResult(p.Name(), plugins.RCodeNXDomain, 60, nil, started)
		res.AuditMetadata["reason"] = "hns_name_not_found"
		return res, nil
	}
	filtered := filter(records, qtype)
	if len(filtered) == 0 {
		res := plugins.NewResult(p.Name(), plugins.RCodeNoError, 60, nil, started)
		res.AuditMetadata["reason"] = "hns_type_not_found"
		return res, nil
	}
	res := plugins.NewResult(p.Name(), plugins.RCodeNoError, minTTL(filtered), filtered, started)
	res.RawRecord["backend"] = "static-hns-fixture"
	res.SecurityTags = append(res.SecurityTags, "alternate-root")
	return res, nil
}

func (p *Plugin) backendState() (string, string, time.Duration, *http.Client) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	client := p.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	timeout := p.backendTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return p.backendURL, p.backendAPIKey, timeout, client
}

func (p *Plugin) resolveRemote(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	body, err := json.Marshal(map[string]any{
		"plugin":  p.Name(),
		"qname":   plugins.NormalizeQName(req.QName),
		"qtype":   plugins.NormalizeQType(req.QType),
		"context": req.Context,
	})
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, backendURL, bytes.NewReader(body))
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-hns-plugin/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure("backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("hns backend status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(resp.Body)
	result, err := decodeRemoteResult(decoder)
	if err != nil {
		return serviceFailure("backend_decode_failed", started), err
	}
	if result.SourcePlugin == "" {
		result.SourcePlugin = p.Name()
	}
	if result.RCode == "" {
		result.RCode = plugins.RCodeNoError
	}
	if result.TTL <= 0 {
		result.TTL = minPositiveTTL(result.RRSet, 60)
	}
	if result.RawRecord == nil {
		result.RawRecord = map[string]any{}
	}
	result.RawRecord["backend"] = "remote-http"
	if result.AuditMetadata == nil {
		result.AuditMetadata = map[string]any{}
	}
	result.AuditMetadata["backend_url"] = backendURL
	result.LatencyMS = time.Since(started).Milliseconds()
	return result, nil
}

func decodeRemoteResult(decoder *json.Decoder) (plugins.ResolveResult, error) {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return plugins.ResolveResult{}, err
	}
	var envelope struct {
		Result *plugins.ResolveResult `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Result != nil {
		return *envelope.Result, nil
	}
	var result plugins.ResolveResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return plugins.ResolveResult{}, err
	}
	if result.RCode == "" && len(result.RRSet) == 0 {
		return plugins.ResolveResult{}, errors.New("backend response missing result")
	}
	return result, nil
}

func serviceFailure(reason string, started time.Time) plugins.ResolveResult {
	result := plugins.NewResult("hns", plugins.RCodeServFail, 5, nil, started)
	result.Confidence = "unavailable"
	result.SecurityTags = append(result.SecurityTags, "hns-remote")
	result.AuditMetadata["reason"] = reason
	return result
}

func filter(records []plugins.RR, qtype string) []plugins.RR {
	if qtype == "ANY" {
		return records
	}
	out := make([]plugins.RR, 0, len(records))
	for _, rr := range records {
		if strings.EqualFold(rr.Type, qtype) || (qtype == "TYPE262" && rr.Type == "WALLET") || (qtype == "WALLET" && rr.Type == "TYPE262") {
			out = append(out, rr)
		}
	}
	return out
}

func minTTL(records []plugins.RR) int {
	ttl := records[0].TTL
	for _, rr := range records[1:] {
		if rr.TTL < ttl {
			ttl = rr.TTL
		}
	}
	return ttl
}

func minPositiveTTL(rrset []plugins.RR, fallback int) int {
	ttl := 0
	for _, rr := range rrset {
		if rr.TTL > 0 && (ttl == 0 || rr.TTL < ttl) {
			ttl = rr.TTL
		}
	}
	if ttl == 0 {
		return fallback
	}
	return ttl
}
