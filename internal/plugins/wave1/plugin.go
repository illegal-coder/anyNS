package wave1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/anyns/anyns/internal/plugins"
)

type Plugin struct {
	mu             sync.RWMutex
	name           string
	suffixes       []string
	enabled        bool
	backendType    string
	backendURL     string
	backendAPIKey  string
	backendTimeout time.Duration
	httpClient     *http.Client
}

func NewAll() []*Plugin {
	return []*Plugin{
		New("ens", []string{".eth"}),
		New("namecoin-bit", []string{".bit"}),
		New("stacks-bns", []string{".btc", ".stx"}),
		New("pns-polkadot", []string{".dot"}),
		New("pns-pulsechain", []string{".pls"}),
		New("unstoppable-domains", []string{".crypto", ".nft", ".wallet", ".x", ".dao", ".888", ".zil", ".blockchain", ".bitcoin"}),
		New("solana-sns", []string{".sol"}),
		New("space-id", []string{".bnb", ".arb"}),
		New("ton-dns", []string{".ton"}),
		New("tezos-domains", []string{".tez"}),
		New("aptos-names", []string{".apt"}),
		New("suins", []string{".sui"}),
		New("freename-fns", []string{".fns"}),
		New("rif-rns", []string{".rsk"}),
		New("fio-handle", []string{".fio"}),
		New("openalias", []string{".openalias"}),
		New("ada-handle", []string{".ada"}),
		New("did-bit", []string{".bit"}),
	}
}

func New(name string, suffixes []string) *Plugin {
	return &Plugin{
		name:           name,
		suffixes:       append([]string(nil), suffixes...),
		backendTimeout: 3 * time.Second,
		httpClient:     http.DefaultClient,
	}
}

type BackendConfig struct {
	Type           string
	URL            string
	APIKey         string
	RequestTimeout time.Duration
	HTTPClient     *http.Client
}

func (p *Plugin) ConfigureBackend(cfg BackendConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backendType = strings.ToLower(strings.TrimSpace(cfg.Type))
	p.backendURL = strings.TrimSpace(cfg.URL)
	p.backendAPIKey = strings.TrimSpace(cfg.APIKey)
	if cfg.RequestTimeout > 0 {
		p.backendTimeout = cfg.RequestTimeout
	}
	if cfg.HTTPClient != nil {
		p.httpClient = cfg.HTTPClient
	}
}

func (p *Plugin) Name() string { return p.name }

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

func (p *Plugin) Suffixes() []string {
	return append([]string(nil), p.suffixes...)
}

func (p *Plugin) Health(ctx context.Context) error {
	if !p.Enabled() {
		return errors.New(p.name + " plugin disabled")
	}
	if p.backendConfigured() {
		return nil
	}
	return errors.New(p.name + " backend not configured")
}

func (p *Plugin) Resolve(ctx context.Context, req plugins.ResolveRequest) (plugins.ResolveResult, error) {
	started := time.Now()
	backendType, backendURL, apiKey, timeout, client := p.backendState()
	if backendURL != "" {
		if p.name == "ens" && backendType == "ens-json-rpc" {
			return p.resolveENSJSONRPC(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "namecoin-bit" && backendType == "namecoin-json-rpc" {
			return p.resolveNamecoinJSONRPC(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "unstoppable-domains" && backendType == "unstoppable-resolution-api" {
			return p.resolveUnstoppableResolutionAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "stacks-bns" && backendType == "stacks-bns-api" {
			return p.resolveStacksBNSAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "pns-polkadot" && backendType == "pns-polkadot-api" {
			return p.resolvePNSPolkadotAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "pns-pulsechain" && backendType == "pulsechain-pns-json-rpc" {
			return p.resolveEVMENSJSONRPC(ctx, req, backendURL, apiKey, timeout, client, started, evmENSConfig{
				BackendType:      "pulsechain-pns-json-rpc",
				WalletChain:      "pls",
				InvalidReason:    "invalid_pulsechain_pns_name",
				NoResolverReason: "pulsechain_pns_resolver_not_found",
				TypeNotFound:     "pulsechain_pns_type_not_found",
				RawNameKey:       "pulsechain_pns_name",
			})
		}
		if p.name == "rif-rns" && backendType == "rif-rns-json-rpc" {
			return p.resolveEVMENSJSONRPC(ctx, req, backendURL, apiKey, timeout, client, started, evmENSConfig{
				BackendType:      "rif-rns-json-rpc",
				WalletChain:      "rbtc",
				InvalidReason:    "invalid_rif_rns_name",
				NoResolverReason: "rif_rns_resolver_not_found",
				TypeNotFound:     "rif_rns_type_not_found",
				RawNameKey:       "rif_rns_name",
			})
		}
		if p.name == "space-id" && backendType == "space-id-api" {
			return p.resolveSpaceIDAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "tezos-domains" && backendType == "tezos-domains-api" {
			return p.resolveTezosDomainsAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "aptos-names" && backendType == "aptos-names-api" {
			return p.resolveAptosNamesAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "solana-sns" && backendType == "solana-sns-quicknode" {
			return p.resolveSolanaSNSQuickNode(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "ton-dns" && backendType == "toncenter-v3-dns" {
			return p.resolveTONCenterV3DNS(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "suins" && backendType == "suins-json-rpc" {
			return p.resolveSuiNSJSONRPC(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "fio-handle" && backendType == "fio-chain-api" {
			return p.resolveFIOChainAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "freename-fns" && backendType == "freename-resolution-api" {
			return p.resolveFreenameResolutionAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "openalias" && backendType == "openalias-dns-txt" {
			return p.resolveOpenAliasDNSTXT(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "ada-handle" && backendType == "ada-handle-api" {
			return p.resolveADAHandleAPI(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		if p.name == "did-bit" && backendType == "did-universal-resolver" {
			return p.resolveDIDUniversalResolver(ctx, req, backendURL, apiKey, timeout, client, started)
		}
		return p.resolveRemote(ctx, req, backendURL, apiKey, timeout, client, started)
	}
	result := plugins.NewResult(p.name, plugins.RCodeServFail, 5, nil, started)
	result.Confidence = "unavailable"
	result.SecurityTags = append(result.SecurityTags, "wave1-skeleton")
	result.AuditMetadata["reason"] = "backend_not_configured"
	return result, errors.New(p.name + " backend not configured")
}

func (p *Plugin) backendConfigured() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.backendURL != ""
}

func (p *Plugin) backendState() (string, string, string, time.Duration, *http.Client) {
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
	return p.backendType, p.backendURL, p.backendAPIKey, timeout, client
}

func (p *Plugin) resolveRemote(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	body, err := json.Marshal(map[string]any{
		"plugin":  p.name,
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
	httpReq.Header.Set("User-Agent", "anyns-wave1-plugin/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	decoder := json.NewDecoder(resp.Body)
	result, err := decodeRemoteResult(decoder)
	if err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if result.SourcePlugin == "" {
		result.SourcePlugin = p.name
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

func serviceFailure(plugin, reason string, started time.Time) plugins.ResolveResult {
	result := plugins.NewResult(plugin, plugins.RCodeServFail, 5, nil, started)
	result.Confidence = "unavailable"
	result.SecurityTags = append(result.SecurityTags, "wave1-remote")
	result.AuditMetadata["reason"] = reason
	return result
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

const (
	ensRegistryAddress          = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
	ensResolverSelector         = "0178b8bf"
	ensAddrSelector             = "3b3b57de"
	ensTextSelector             = "59d1d43c"
	ensContenthashSelector      = "bc1c58d1"
	ensJSONRPCLatestBlock       = "latest"
	ensZeroAddressReturn        = "0000000000000000000000000000000000000000000000000000000000000000"
	ensZeroAddress              = "0x0000000000000000000000000000000000000000"
	ensTextRecordDefaultTTL     = 300
	ensUniversalResolverAddress = "0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe"
)

var ensTextKeys = []string{"email", "url", "avatar", "description", "notice", "keywords", "com.twitter", "com.github", "org.telegram"}

type evmENSConfig struct {
	BackendType      string
	WalletChain      string
	InvalidReason    string
	NoResolverReason string
	TypeNotFound     string
	RawNameKey       string
}

func (p *Plugin) resolveENSJSONRPC(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := ensDomainName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_ens_name"
		return result, nil
	}
	node, err := ensNamehash(domain)
	if err != nil {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_ens_name"
		return result, nil
	}
	resolver, err := ethCall(ctx, client, backendURL, apiKey, timeout, ensRegistryAddress, "0x"+ensResolverSelector+node)
	if err != nil {
		return serviceFailure(p.name, "backend_rpc_call_failed", started), err
	}
	resolverAddress := abiAddressResult(resolver)
	if resolverAddress == "" || resolverAddress == ensZeroAddress {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "ens-json-rpc"
		result.RawRecord["ens_name"] = domain
		result.RawRecord["ens_node"] = "0x" + node
		result.AuditMetadata["reason"] = "ens_resolver_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}

	records := ensRecordsForQType(ctx, client, backendURL, apiKey, timeout, resolverAddress, node, plugins.NormalizeQName(req.QName), plugins.NormalizeQType(req.QType), "eth")
	filtered := filterRecords(records, plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(filtered, ensTextRecordDefaultTTL), filtered, started)
	result.RawRecord["backend"] = "ens-json-rpc"
	result.RawRecord["ens_name"] = domain
	result.RawRecord["ens_node"] = "0x" + node
	result.RawRecord["ens_resolver"] = resolverAddress
	result.RawRecord["ens_universal_resolver"] = ensUniversalResolverAddress
	result.AuditMetadata["backend_url"] = backendURL
	if len(filtered) == 0 {
		result.AuditMetadata["reason"] = "ens_type_not_found"
	}
	return result, nil
}

func (p *Plugin) resolveEVMENSJSONRPC(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time, cfg evmENSConfig) (plugins.ResolveResult, error) {
	rpcURL, registryAddress, err := evmENSBackendEndpoint(backendURL)
	if err != nil {
		result := serviceFailure(p.name, "backend_registry_required", started)
		return result, err
	}
	domain, ok := ensDomainName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = cfg.InvalidReason
		return result, nil
	}
	node, err := ensNamehash(domain)
	if err != nil {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = cfg.InvalidReason
		return result, nil
	}
	resolver, err := ethCall(ctx, client, rpcURL, apiKey, timeout, registryAddress, "0x"+ensResolverSelector+node)
	if err != nil {
		return serviceFailure(p.name, "backend_rpc_call_failed", started), err
	}
	resolverAddress := abiAddressResult(resolver)
	if resolverAddress == "" || resolverAddress == ensZeroAddress {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = cfg.BackendType
		result.RawRecord[cfg.RawNameKey] = domain
		result.RawRecord["evm_ens_node"] = "0x" + node
		result.RawRecord["evm_ens_registry"] = registryAddress
		result.AuditMetadata["reason"] = cfg.NoResolverReason
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	records := ensRecordsForQType(ctx, client, rpcURL, apiKey, timeout, resolverAddress, node, plugins.NormalizeQName(req.QName), plugins.NormalizeQType(req.QType), cfg.WalletChain)
	filtered := filterRecords(records, plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(filtered, ensTextRecordDefaultTTL), filtered, started)
	result.RawRecord["backend"] = cfg.BackendType
	result.RawRecord[cfg.RawNameKey] = domain
	result.RawRecord["evm_ens_node"] = "0x" + node
	result.RawRecord["evm_ens_registry"] = registryAddress
	result.RawRecord["evm_ens_resolver"] = resolverAddress
	result.AuditMetadata["backend_url"] = backendURL
	if len(filtered) == 0 {
		result.AuditMetadata["reason"] = cfg.TypeNotFound
	}
	return result, nil
}

func evmENSBackendEndpoint(rawURL string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", err
	}
	query := parsed.Query()
	registry := strings.TrimSpace(query.Get("registry"))
	if registry == "" {
		registry = strings.TrimSpace(query.Get("anyns_registry"))
	}
	registryHex := strings.TrimPrefix(strings.ToLower(registry), "0x")
	if len(registryHex) != 40 {
		return "", "", errors.New("evm ENS-compatible backend url requires registry query parameter")
	}
	if _, err := hex.DecodeString(registryHex); err != nil || strings.Trim(registryHex, "0") == "" {
		return "", "", errors.New("evm ENS-compatible backend url requires registry query parameter")
	}
	query.Del("registry")
	query.Del("anyns_registry")
	parsed.RawQuery = query.Encode()
	return parsed.String(), "0x" + registryHex, nil
}

func ensDomainName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func ensRecordsForQType(ctx context.Context, client *http.Client, backendURL, apiKey string, timeout time.Duration, resolverAddress, node, qname, qtype, walletChain string) []plugins.RR {
	var records []plugins.RR
	if qtype == "" || qtype == "ANY" || qtype == "WALLET" || qtype == "TYPE262" {
		if result, err := ethCall(ctx, client, backendURL, apiKey, timeout, resolverAddress, "0x"+ensAddrSelector+node); err == nil {
			if address := abiAddressResult(result); address != "" && address != ensZeroAddress {
				records = append(records, plugins.RR{Name: qname, Type: "WALLET", TTL: ensTextRecordDefaultTTL, Value: strings.ToLower(walletChain) + " " + address})
			}
		}
	}
	if qtype == "" || qtype == "ANY" || qtype == "TXT" {
		for _, key := range ensTextKeys {
			data := "0x" + ensTextSelector + node + abiStringArg(key)
			if result, err := ethCall(ctx, client, backendURL, apiKey, timeout, resolverAddress, data); err == nil {
				if value := abiStringResult(result); value != "" {
					records = append(records, plugins.RR{Name: qname, Type: "TXT", TTL: ensTextRecordDefaultTTL, Value: key + "=" + value})
				}
			}
		}
	}
	if qtype == "" || qtype == "ANY" || qtype == "URI" || qtype == "TXT" {
		if result, err := ethCall(ctx, client, backendURL, apiKey, timeout, resolverAddress, "0x"+ensContenthashSelector+node); err == nil {
			if value := abiBytesResult(result); value != "" {
				records = append(records, plugins.RR{Name: qname, Type: "URI", TTL: ensTextRecordDefaultTTL, Value: ensContenthashURI(value)})
			}
		}
	}
	return records
}

func ethCall(ctx context.Context, client *http.Client, backendURL, apiKey string, timeout time.Duration, to, data string) (string, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "anyns-ens-json-rpc",
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": to, "data": data},
			ensJSONRPCLatestBlock,
		},
	})
	if err != nil {
		return "", err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, backendURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-ens-json-rpc/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ens json-rpc status %d", resp.StatusCode)
	}
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return "", err
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("ens json-rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func abiAddressResult(value string) string {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if len(raw) < 64 || raw == ensZeroAddressReturn {
		return ""
	}
	addr := raw[len(raw)-40:]
	if addr == strings.Repeat("0", 40) {
		return ensZeroAddress
	}
	return "0x" + addr
}

func abiStringArg(value string) string {
	encoded := hex.EncodeToString([]byte(value))
	return leftPadHex("40", 64) + leftPadHex(fmt.Sprintf("%x", len(value)), 64) + rightPadHex(encoded, 64)
}

func abiStringResult(value string) string {
	raw := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	data, err := hex.DecodeString(raw)
	if err != nil || len(data) < 64 {
		return ""
	}
	offset := abiWordUint(data[:32])
	if offset < 0 || offset+32 > len(data) {
		return ""
	}
	length := abiWordUint(data[offset : offset+32])
	if length < 0 || offset+32+length > len(data) {
		return ""
	}
	return string(data[offset+32 : offset+32+length])
}

func abiBytesResult(value string) string {
	raw := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	data, err := hex.DecodeString(raw)
	if err != nil || len(data) < 64 {
		return ""
	}
	offset := abiWordUint(data[:32])
	if offset < 0 || offset+32 > len(data) {
		return ""
	}
	length := abiWordUint(data[offset : offset+32])
	if length <= 0 || offset+32+length > len(data) {
		return ""
	}
	return "0x" + hex.EncodeToString(data[offset+32:offset+32+length])
}

func abiWordUint(word []byte) int {
	if len(word) != 32 {
		return -1
	}
	n := 0
	for _, b := range word {
		if n > (1<<31-1-int(b))/256 {
			return -1
		}
		n = n*256 + int(b)
	}
	return n
}

func ensContenthashURI(value string) string {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if strings.HasPrefix(raw, "e301") {
		return "ipfs://0x" + raw[4:]
	}
	if strings.HasPrefix(raw, "e501") {
		return "ipns://0x" + raw[4:]
	}
	return "ens-contenthash:0x" + raw
}

func ensNamehash(name string) (string, error) {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	node := make([]byte, 32)
	if normalized == "" {
		return hex.EncodeToString(node), nil
	}
	labels := strings.Split(normalized, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		label := strings.TrimSpace(labels[i])
		if label == "" {
			return "", errors.New("empty ENS label")
		}
		labelHash := legacyKeccak256([]byte(label))
		buf := make([]byte, 64)
		copy(buf[:32], node)
		copy(buf[32:], labelHash)
		node = legacyKeccak256(buf)
	}
	return hex.EncodeToString(node), nil
}

func leftPadHex(value string, width int) string {
	value = strings.TrimPrefix(value, "0x")
	if len(value) >= width {
		return value
	}
	return strings.Repeat("0", width-len(value)) + value
}

func rightPadHex(value string, blockWidth int) string {
	if rem := len(value) % blockWidth; rem != 0 {
		value += strings.Repeat("0", blockWidth-rem)
	}
	return value
}

func legacyKeccak256(input []byte) []byte {
	const rate = 136
	var state [25]uint64
	for len(input) >= rate {
		xorKeccakBlock(&state, input[:rate])
		keccakF1600(&state)
		input = input[rate:]
	}
	var block [rate]byte
	copy(block[:], input)
	block[len(input)] ^= 0x01
	block[rate-1] ^= 0x80
	xorKeccakBlock(&state, block[:])
	keccakF1600(&state)
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], state[i])
	}
	return out
}

func xorKeccakBlock(state *[25]uint64, block []byte) {
	for i := 0; i < len(block)/8; i++ {
		state[i] ^= binary.LittleEndian.Uint64(block[i*8:])
	}
}

func keccakF1600(a *[25]uint64) {
	roundConstants := [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
		0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}
	rotation := [25]uint{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14}
	for _, rc := range roundConstants {
		var c, d [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				a[x+5*y] ^= d[x]
			}
		}
		var b [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], int(rotation[x+5*y]))
			}
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				a[x+5*y] = b[x+5*y] ^ ((^b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
			}
		}
		a[0] ^= rc
	}
}

func (p *Plugin) resolveNamecoinJSONRPC(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	baseName, subdomain, ok := namecoinBitName(req.QName)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_namecoin_bit_name"
		return result, nil
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0",
		"id":      "anyns-namecoin-bit",
		"method":  "name_show",
		"params":  []string{"d/" + baseName},
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
	httpReq.Header.Set("User-Agent", "anyns-namecoin-bit-json-rpc/0")
	if apiKey != "" {
		if user, pass, ok := strings.Cut(apiKey, ":"); ok {
			httpReq.SetBasicAuth(user, pass)
		} else {
			httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var rpcResp namecoinRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if rpcResp.Error != nil {
		if rpcResp.Error.Code == -4 || strings.Contains(strings.ToLower(rpcResp.Error.Message), "name not found") {
			result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
			result.RawRecord["backend"] = "namecoin-json-rpc"
			result.AuditMetadata["reason"] = "namecoin_name_not_found"
			result.AuditMetadata["namecoin_name"] = "d/" + baseName
			return result, nil
		}
		result := serviceFailure(p.name, "backend_rpc_error", started)
		result.AuditMetadata["namecoin_error_code"] = rpcResp.Error.Code
		result.AuditMetadata["namecoin_error"] = rpcResp.Error.Message
		return result, fmt.Errorf("%s backend rpc error %d: %s", p.name, rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		return serviceFailure(p.name, "backend_missing_result", started), errors.New("namecoin backend missing result")
	}
	records, rawRecord, err := mapNamecoinValue(req.QName, req.QType, subdomain, rpcResp.Result.Value)
	if err != nil {
		result := serviceFailure(p.name, "backend_value_decode_failed", started)
		result.AuditMetadata["namecoin_name"] = "d/" + baseName
		return result, err
	}
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "namecoin-json-rpc"
	result.RawRecord["namecoin_name"] = "d/" + baseName
	result.RawRecord["namecoin_subdomain"] = subdomain
	result.RawRecord["namecoin_value"] = rawRecord
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "namecoin_type_not_found"
	}
	return result, nil
}

type namecoinRPCResponse struct {
	Result *struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func namecoinBitName(qname string) (string, string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if !strings.HasSuffix(trimmed, ".bit") {
		return "", "", false
	}
	labels := strings.Split(strings.TrimSuffix(trimmed, ".bit"), ".")
	if len(labels) == 0 || labels[len(labels)-1] == "" {
		return "", "", false
	}
	base := labels[len(labels)-1]
	if len(labels) == 1 {
		return base, "", true
	}
	return base, strings.Join(labels[:len(labels)-1], "."), true
}

func mapNamecoinValue(qname, qtype, subdomain, value string) ([]plugins.RR, map[string]any, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return nil, nil, err
	}
	selected := raw
	if subdomain != "" {
		if mapped, ok := namecoinSubdomainRecord(raw, subdomain); ok {
			selected = mapped
		} else {
			return nil, raw, nil
		}
	}
	records := namecoinRecordsFromMap(plugins.NormalizeQName(qname), selected)
	return filterRecords(records, plugins.NormalizeQType(qtype)), raw, nil
}

func namecoinSubdomainRecord(raw map[string]any, subdomain string) (map[string]any, bool) {
	maps, ok := raw["map"].(map[string]any)
	if !ok {
		return nil, false
	}
	current := maps
	labels := strings.Split(subdomain, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		next, ok := current[labels[i]].(map[string]any)
		if !ok {
			next, ok = current["*"].(map[string]any)
		}
		if !ok {
			return nil, false
		}
		if i == 0 {
			return next, true
		}
		nested, ok := next["map"].(map[string]any)
		if !ok {
			return nil, false
		}
		current = nested
	}
	return nil, false
}

func namecoinRecordsFromMap(name string, raw map[string]any) []plugins.RR {
	var records []plugins.RR
	for _, value := range stringValues(raw["ip"]) {
		if ip := net.ParseIP(value); ip != nil {
			rrType := "A"
			if ip.To4() == nil {
				rrType = "AAAA"
			}
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for _, value := range stringValues(raw["ip6"]) {
		if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
			records = append(records, plugins.RR{Name: name, Type: "AAAA", TTL: 300, Value: value})
		}
	}
	for _, value := range stringValues(raw["ns"]) {
		records = append(records, plugins.RR{Name: name, Type: "NS", TTL: 300, Value: plugins.NormalizeQName(value)})
	}
	for _, value := range namecoinTupleRecords(raw["ds"], "DS") {
		records = append(records, plugins.RR{Name: name, Type: "DS", TTL: 300, Value: value})
	}
	for _, value := range namecoinTupleRecords(raw["tls"], "TLSA") {
		records = append(records, plugins.RR{Name: name, Type: "TLSA", TTL: 300, Value: value})
	}
	for _, rrType := range []string{"MX", "SRV", "URI", "CAA"} {
		for _, value := range namecoinPresentationRecords(raw[strings.ToLower(rrType)], rrType) {
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for _, field := range []string{"txt", "info"} {
		for _, value := range stringValues(raw[field]) {
			records = append(records, plugins.RR{Name: name, Type: "TXT", TTL: 300, Value: value})
		}
	}
	for _, field := range []string{"alias", "translate"} {
		values := stringValues(raw[field])
		if len(values) > 0 {
			records = append(records, plugins.RR{Name: name, Type: "CNAME", TTL: 300, Value: plugins.NormalizeQName(values[0])})
			break
		}
	}
	return records
}

func namecoinPresentationRecords(value any, rrType string) []string {
	switch v := value.(type) {
	case string:
		if formatted := namecoinPresentationRecord([]any{v}, rrType); formatted != "" {
			return []string{formatted}
		}
	case []any:
		if out, ok := namecoinStringListRecords(v, rrType); ok {
			return out
		}
		if formatted := namecoinPresentationRecord(v, rrType); formatted != "" {
			return []string{formatted}
		}
		out := make([]string, 0, len(v))
		for _, item := range v {
			switch nested := item.(type) {
			case string:
				if formatted := namecoinPresentationRecord([]any{nested}, rrType); formatted != "" {
					out = append(out, formatted)
				}
			case []any:
				if formatted := namecoinPresentationRecord(nested, rrType); formatted != "" {
					out = append(out, formatted)
				}
			}
		}
		return out
	}
	return nil
}

func namecoinStringListRecords(items []any, rrType string) ([]string, bool) {
	if len(items) < 2 {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		if formatted := namecoinPresentationRecord([]any{text}, rrType); formatted != "" {
			out = append(out, formatted)
		}
	}
	return out, true
}

func namecoinPresentationRecord(fields []any, rrType string) string {
	if len(fields) == 0 {
		return ""
	}
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		switch v := field.(type) {
		case string:
			v = strings.TrimSpace(v)
			if v == "" {
				return ""
			}
			tokens = append(tokens, v)
		case float64:
			if v < 0 || v != float64(int(v)) {
				return ""
			}
			tokens = append(tokens, fmt.Sprintf("%d", int(v)))
		default:
			return ""
		}
	}
	if rrType == "MX" || rrType == "SRV" {
		tokens[len(tokens)-1] = plugins.NormalizeQName(tokens[len(tokens)-1])
	}
	return strings.Join(tokens, " ")
}

func namecoinTupleRecords(value any, rrType string) []string {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	case []any:
		if tuple, ok := namecoinTupleRecord(v, rrType); ok {
			return []string{tuple}
		}
		out := make([]string, 0, len(v))
		for _, item := range v {
			switch nested := item.(type) {
			case string:
				if strings.TrimSpace(nested) != "" {
					out = append(out, strings.TrimSpace(nested))
				}
			case []any:
				if tuple, ok := namecoinTupleRecord(nested, rrType); ok {
					out = append(out, tuple)
				}
			}
		}
		return out
	default:
		return nil
	}
}

func namecoinTupleRecord(tuple []any, rrType string) (string, bool) {
	if len(tuple) < 4 {
		return "", false
	}
	first, ok := namecoinNumberToken(tuple[0])
	if !ok {
		return "", false
	}
	second, ok := namecoinNumberToken(tuple[1])
	if !ok {
		return "", false
	}
	third, ok := namecoinNumberToken(tuple[2])
	if !ok {
		return "", false
	}
	data, ok := tuple[3].(string)
	if !ok || strings.TrimSpace(data) == "" {
		return "", false
	}
	data = strings.TrimSpace(data)
	if rrType == "TLSA" {
		if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
			data = strings.ToUpper(hex.EncodeToString(decoded))
		} else {
			data = strings.ToUpper(strings.ReplaceAll(data, " ", ""))
		}
	}
	return strings.Join([]string{first, second, third, data}, " "), true
}

func namecoinNumberToken(value any) (string, bool) {
	switch v := value.(type) {
	case float64:
		if v < 0 || v != float64(int(v)) {
			return "", false
		}
		return fmt.Sprintf("%d", int(v)), true
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return "", false
		}
		return v, true
	default:
		return "", false
	}
}

func stringValues(value any) []string {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func filterRecords(records []plugins.RR, qtype string) []plugins.RR {
	if qtype == "" || qtype == "ANY" {
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

func (p *Plugin) resolveUnstoppableResolutionAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := unstoppableDomainName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_unstoppable_domain"
		return result, nil
	}
	endpoint, err := unstoppableDomainEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-unstoppable-resolution-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "unstoppable-resolution-api"
		result.AuditMetadata["reason"] = "unstoppable_domain_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Meta    map[string]any    `json:"meta"`
		Records map[string]string `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	records := filterRecords(unstoppableRecordsFromMap(plugins.NormalizeQName(req.QName), apiResp.Records), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "unstoppable-resolution-api"
	result.RawRecord["unstoppable_domain"] = domain
	result.RawRecord["unstoppable_records"] = apiResp.Records
	if len(apiResp.Meta) > 0 {
		result.RawRecord["unstoppable_meta"] = apiResp.Meta
	}
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "unstoppable_type_not_found"
	}
	return result, nil
}

func unstoppableDomainName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func unstoppableDomainEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("unstoppable backend url must be absolute")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/domains/" + url.PathEscape(domain)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func unstoppableRecordsFromMap(name string, raw map[string]string) []plugins.RR {
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for key, value := range raw {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		switch normalizedKey {
		case "dns.a":
			if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
				add("A", value)
			}
		case "dns.aaaa":
			if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
				add("AAAA", value)
			}
		case "dns.cname":
			add("CNAME", plugins.NormalizeQName(value))
		case "dns.txt":
			add("TXT", value)
		case "browser.redirect_url":
			add("URI", value)
		case "ipfs.html.value", "ipfs.redirect_domain.value":
			add("URI", unstoppableURIValue(value))
		default:
			if chain, ok := unstoppableWalletChain(normalizedKey); ok {
				add("WALLET", strings.ToLower(chain)+" "+value)
			}
		}
	}
	return records
}

func unstoppableURIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "ipfs://" + value
}

func unstoppableWalletChain(key string) (string, bool) {
	if !strings.HasPrefix(key, "crypto.") || !strings.HasSuffix(key, ".address") {
		return "", false
	}
	parts := strings.Split(key, ".")
	if len(parts) < 3 || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func (p *Plugin) resolvePNSPolkadotAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := pnsPolkadotName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_pns_polkadot_name"
		return result, nil
	}
	endpoint, err := pnsPolkadotNameEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-pns-polkadot-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "pns-polkadot-api"
		result.RawRecord["pns_polkadot_name"] = domain
		result.AuditMetadata["reason"] = "pns_polkadot_name_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Result string         `json:"result"`
		Data   map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if apiResp.Data == nil {
		return serviceFailure(p.name, "backend_missing_data", started), errors.New("PNS Polkadot backend missing data")
	}
	records := filterRecords(pnsPolkadotRecordsFromData(plugins.NormalizeQName(req.QName), apiResp.Data), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "pns-polkadot-api"
	result.RawRecord["pns_polkadot_name"] = domain
	result.RawRecord["pns_polkadot_response"] = apiResp.Data
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "pns_polkadot_type_not_found"
	}
	return result, nil
}

func pnsPolkadotName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func pnsPolkadotNameEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("PNS Polkadot backend url must be absolute")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/name/" + url.PathEscape(domain)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func pnsPolkadotRecordsFromData(name string, data map[string]any) []plugins.RR {
	rawRecords, _ := data["records"].(map[string]any)
	if rawRecords == nil {
		rawRecords = data
	}
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for key, value := range rawRecords {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		switch normalizedKey {
		case "dns.a", "a", "ip", "ipv4":
			for _, item := range stringValues(value) {
				if ip := net.ParseIP(item); ip != nil && ip.To4() != nil {
					add("A", item)
				}
			}
		case "dns.aaaa", "aaaa", "ip6", "ipv6":
			for _, item := range stringValues(value) {
				if ip := net.ParseIP(item); ip != nil && ip.To4() == nil {
					add("AAAA", item)
				}
			}
		case "dns.cname", "cname":
			for _, item := range stringValues(value) {
				add("CNAME", plugins.NormalizeQName(item))
			}
		case "dns.txt", "txt":
			for _, item := range stringValues(value) {
				add("TXT", item)
			}
		case "website", "url", "dapp", "browser.redirect_url":
			for _, item := range stringValues(value) {
				add("URI", pnsPolkadotURIValue(item))
			}
		case "ipfs", "ipfs.html.value", "contenthash":
			for _, item := range stringValues(value) {
				add("URI", pnsPolkadotContentURI(item))
			}
		case "address", "account", "owner", "wallet":
			for _, item := range stringValues(value) {
				add("WALLET", "dot "+item)
			}
		case "addresses", "wallets":
			for _, rr := range pnsPolkadotWalletRecords(name, value) {
				records = append(records, rr)
			}
		default:
			for _, item := range stringValues(value) {
				add("TXT", normalizedKey+"="+item)
			}
		}
	}
	return records
}

func pnsPolkadotWalletRecords(name string, value any) []plugins.RR {
	var records []plugins.RR
	add := func(chain, address string) {
		chain = strings.ToLower(strings.TrimSpace(chain))
		address = strings.TrimSpace(address)
		if chain == "" {
			chain = "dot"
		}
		if address != "" {
			records = append(records, plugins.RR{Name: name, Type: "WALLET", TTL: 300, Value: chain + " " + address})
		}
	}
	for _, item := range stringValues(value) {
		add("dot", item)
	}
	if items, ok := value.([]any); ok {
		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			add(firstStringValue(entry["network"]), firstStringValue(entry["address"]))
		}
	}
	if raw, ok := value.(map[string]any); ok {
		for chain, address := range raw {
			for _, item := range stringValues(address) {
				add(chain, item)
			}
		}
	}
	return records
}

func pnsPolkadotURIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "https://" + value
}

func pnsPolkadotContentURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "ipfs://" + value
}

func (p *Plugin) resolveSpaceIDAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := spaceIDName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_space_id_name"
		return result, nil
	}
	endpoint, err := spaceIDAddressEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-space-id-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "space-id-api"
		result.RawRecord["space_id_domain"] = domain
		result.AuditMetadata["reason"] = "space_id_name_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Address string `json:"address"`
		Code    int    `json:"code"`
		Msg     string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if apiResp.Code == 1 {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "space-id-api"
		result.RawRecord["space_id_domain"] = domain
		result.AuditMetadata["reason"] = "space_id_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		if apiResp.Msg != "" {
			result.AuditMetadata["space_id_msg"] = apiResp.Msg
		}
		return result, nil
	}
	if apiResp.Code != 0 {
		result := serviceFailure(p.name, "backend_api_error", started)
		result.AuditMetadata["space_id_code"] = apiResp.Code
		result.AuditMetadata["space_id_msg"] = apiResp.Msg
		return result, fmt.Errorf("%s backend code %d: %s", p.name, apiResp.Code, apiResp.Msg)
	}
	if strings.TrimSpace(apiResp.Address) == "" {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "space-id-api"
		result.RawRecord["space_id_domain"] = domain
		result.AuditMetadata["reason"] = "space_id_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		if apiResp.Msg != "" {
			result.AuditMetadata["space_id_msg"] = apiResp.Msg
		}
		return result, nil
	}
	records := filterRecords(spaceIDRecords(domain, plugins.NormalizeQName(req.QName), apiResp.Address), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "space-id-api"
	result.RawRecord["space_id_domain"] = domain
	result.RawRecord["space_id_address"] = apiResp.Address
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "space_id_type_not_found"
	}
	return result, nil
}

func spaceIDName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func spaceIDAddressEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("SPACE ID backend url must be absolute")
	}
	if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/getAddress") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/getAddress"
	}
	query := parsed.Query()
	query.Set("domain", domain)
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func spaceIDRecords(domain, qname, address string) []plugins.RR {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	chain := "evm"
	switch {
	case strings.HasSuffix(domain, ".bnb"):
		chain = "bnb"
	case strings.HasSuffix(domain, ".arb"):
		chain = "arb"
	}
	return []plugins.RR{{Name: qname, Type: "WALLET", TTL: 300, Value: chain + " " + address}}
}

func (p *Plugin) resolveTezosDomainsAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := tezosDomainName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_tezos_domain_name"
		return result, nil
	}
	endpoint, err := tezosDomainsGraphQLEndpoint(backendURL)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	body, err := json.Marshal(map[string]any{
		"query": `query anyNSTezosDomain($name: String!) {
			domain(name: $name) {
				name
				address
				owner
				data {
					key
					rawValue
					value
				}
			}
		}`,
		"variables": map[string]string{"name": domain},
	})
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-tezos-domains-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Data struct {
			Domain *struct {
				Name    string `json:"name"`
				Address string `json:"address"`
				Owner   string `json:"owner"`
				Data    []struct {
					Key      string `json:"key"`
					RawValue string `json:"rawValue"`
					Value    any    `json:"value"`
				} `json:"data"`
			} `json:"domain"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if len(apiResp.Errors) > 0 {
		result := serviceFailure(p.name, "backend_graphql_error", started)
		result.AuditMetadata["tezos_domains_error"] = apiResp.Errors[0].Message
		return result, fmt.Errorf("%s backend GraphQL error: %s", p.name, apiResp.Errors[0].Message)
	}
	if apiResp.Data.Domain == nil {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "tezos-domains-api"
		result.RawRecord["tezos_domain"] = domain
		result.AuditMetadata["reason"] = "tezos_domain_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	records := filterRecords(tezosDomainRecords(plugins.NormalizeQName(req.QName), apiResp.Data.Domain.Address, apiResp.Data.Domain.Owner, apiResp.Data.Domain.Data), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "tezos-domains-api"
	result.RawRecord["tezos_domain"] = domain
	result.RawRecord["tezos_domain_name"] = apiResp.Data.Domain.Name
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "tezos_domain_type_not_found"
	}
	return result, nil
}

func tezosDomainName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func tezosDomainsGraphQLEndpoint(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("Tezos Domains backend url must be absolute")
	}
	if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/graphql") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/graphql"
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func tezosDomainRecords(name string, address string, owner string, dataItems []struct {
	Key      string `json:"key"`
	RawValue string `json:"rawValue"`
	Value    any    `json:"value"`
}) []plugins.RR {
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		switch rrType {
		case "CNAME", "NS":
			value = plugins.NormalizeQName(value)
		}
		records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
	}
	if strings.TrimSpace(address) != "" {
		add("WALLET", "tez "+address)
	}
	if strings.TrimSpace(owner) != "" && !strings.EqualFold(strings.TrimSpace(owner), strings.TrimSpace(address)) {
		add("TXT", "owner="+owner)
	}
	for _, item := range dataItems {
		key := strings.ToLower(strings.TrimSpace(item.Key))
		for _, value := range tezosDataValues(item.Value, item.RawValue) {
			switch key {
			case "dns.a", "a", "ip", "ipv4":
				if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
					add("A", value)
				}
			case "dns.aaaa", "aaaa", "ip6", "ipv6":
				if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
					add("AAAA", value)
				}
			case "dns.cname", "cname":
				add("CNAME", value)
			case "dns.ns", "ns":
				add("NS", value)
			case "dns.txt", "txt":
				add("TXT", value)
			case "website", "url", "homepage":
				add("URI", tezosURIValue(value))
			case "ipfs", "contenthash":
				add("URI", tezosContentURI(value))
			case "email", "nickname", "twitter", "github", "avatar", "description", "physicaladdress":
				add("TXT", key+"="+value)
			default:
				add("TXT", key+"="+value)
			}
		}
	}
	return records
}

func tezosDataValues(value any, rawValue string) []string {
	values := stringValues(value)
	if len(values) > 0 {
		return values
	}
	var decoded any
	if err := json.Unmarshal([]byte(rawValue), &decoded); err == nil {
		values = stringValues(decoded)
		if len(values) > 0 {
			return values
		}
	}
	rawValue = strings.Trim(rawValue, `"`)
	if strings.TrimSpace(rawValue) == "" || rawValue == "null" {
		return nil
	}
	return []string{rawValue}
}

func tezosURIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "https://" + value
}

func tezosContentURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "ipfs://" + value
}

func (p *Plugin) resolveAptosNamesAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, lookupName, ok := aptosName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_aptos_name"
		return result, nil
	}
	endpoint, err := aptosNamesAddressEndpoint(backendURL, lookupName)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-aptos-names-api/0")
	if apiKey != "" {
		httpReq.Header.Set("X-API-Key", apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "aptos-names-api"
		result.RawRecord["aptos_name"] = domain
		result.AuditMetadata["reason"] = "aptos_name_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Address string `json:"address"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if strings.TrimSpace(apiResp.Error) != "" {
		result := serviceFailure(p.name, "backend_api_error", started)
		result.AuditMetadata["aptos_names_error"] = apiResp.Error
		if strings.TrimSpace(apiResp.Message) != "" {
			result.AuditMetadata["aptos_names_message"] = apiResp.Message
		}
		return result, fmt.Errorf("%s backend error: %s", p.name, apiResp.Error)
	}
	if strings.TrimSpace(apiResp.Address) == "" {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "aptos-names-api"
		result.RawRecord["aptos_name"] = domain
		result.AuditMetadata["reason"] = "aptos_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		if strings.TrimSpace(apiResp.Message) != "" {
			result.AuditMetadata["aptos_names_message"] = apiResp.Message
		}
		return result, nil
	}
	records := filterRecords(aptosNameRecords(plugins.NormalizeQName(req.QName), apiResp.Address), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "aptos-names-api"
	result.RawRecord["aptos_name"] = domain
	result.RawRecord["aptos_lookup_name"] = lookupName
	result.RawRecord["aptos_address"] = apiResp.Address
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "aptos_name_type_not_found"
	}
	return result, nil
}

func aptosName(qname string, suffixes []string) (string, string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			lookupName := strings.TrimSuffix(trimmed, strings.TrimPrefix(strings.ToLower(suffix), "."))
			lookupName = strings.TrimSuffix(lookupName, ".")
			if lookupName == "" {
				return "", "", false
			}
			return trimmed, lookupName, true
		}
	}
	return "", "", false
}

func aptosNamesAddressEndpoint(baseURL, lookupName string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("Aptos Names backend url must be absolute")
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(basePath, "/v3/address") {
		parsed.Path = basePath + "/" + url.PathEscape(lookupName)
	} else {
		parsed.Path = basePath + "/v3/address/" + url.PathEscape(lookupName)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func aptosNameRecords(name, address string) []plugins.RR {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	return []plugins.RR{{Name: name, Type: "WALLET", TTL: 300, Value: "aptos " + address}}
}

func (p *Plugin) resolveSolanaSNSQuickNode(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := solanaSNSName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_solana_sns_name"
		return result, nil
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "anyns-solana-sns",
		"method":  "sns_resolveDomain",
		"params":  []string{domain},
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
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-solana-sns-quicknode/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if rpcResp.Error != nil {
		reason := "backend_jsonrpc_error"
		if strings.Contains(strings.ToLower(rpcResp.Error.Message), "not found") {
			result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
			result.RawRecord["backend"] = "solana-sns-quicknode"
			result.RawRecord["solana_sns_domain"] = domain
			result.AuditMetadata["reason"] = "solana_sns_name_not_found"
			result.AuditMetadata["backend_url"] = backendURL
			result.AuditMetadata["solana_sns_error_code"] = rpcResp.Error.Code
			result.AuditMetadata["solana_sns_error_message"] = rpcResp.Error.Message
			return result, nil
		}
		result := serviceFailure(p.name, reason, started)
		result.AuditMetadata["solana_sns_error_code"] = rpcResp.Error.Code
		result.AuditMetadata["solana_sns_error_message"] = rpcResp.Error.Message
		return result, fmt.Errorf("%s backend JSON-RPC error %d: %s", p.name, rpcResp.Error.Code, rpcResp.Error.Message)
	}
	address := solanaSNSAddressResult(rpcResp.Result)
	if address == "" {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "solana-sns-quicknode"
		result.RawRecord["solana_sns_domain"] = domain
		result.AuditMetadata["reason"] = "solana_sns_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	records := filterRecords(solanaSNSRecords(plugins.NormalizeQName(req.QName), address), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "solana-sns-quicknode"
	result.RawRecord["solana_sns_domain"] = domain
	result.RawRecord["solana_sns_address"] = address
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "solana_sns_type_not_found"
	}
	return result, nil
}

func solanaSNSName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func solanaSNSAddressResult(raw json.RawMessage) string {
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return strings.TrimSpace(value)
	}
	var wrapped struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return strings.TrimSpace(wrapped.Value)
	}
	return ""
}

func solanaSNSRecords(name, address string) []plugins.RR {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	return []plugins.RR{{Name: name, Type: "WALLET", TTL: 300, Value: "sol " + address}}
}

func (p *Plugin) resolveFIOChainAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	fioAddress, ok := fioHandleAddress(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_fio_handle"
		return result, nil
	}
	endpoint, chainCode, tokenCode, err := fioChainAPIEndpoint(backendURL)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	body, err := json.Marshal(map[string]string{
		"fio_address": fioAddress,
		"chain_code":  chainCode,
		"token_code":  tokenCode,
	})
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-fio-chain-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "fio-chain-api"
		result.RawRecord["fio_address"] = fioAddress
		result.RawRecord["fio_chain_code"] = chainCode
		result.RawRecord["fio_token_code"] = tokenCode
		result.AuditMetadata["reason"] = "fio_public_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		PublicAddress string `json:"public_address"`
		Message       string `json:"message"`
		Error         string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if strings.TrimSpace(apiResp.Error) != "" {
		result := serviceFailure(p.name, "backend_api_error", started)
		result.AuditMetadata["fio_error"] = apiResp.Error
		if strings.TrimSpace(apiResp.Message) != "" {
			result.AuditMetadata["fio_message"] = apiResp.Message
		}
		return result, fmt.Errorf("%s backend error: %s", p.name, apiResp.Error)
	}
	if strings.TrimSpace(apiResp.PublicAddress) == "" {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "fio-chain-api"
		result.RawRecord["fio_address"] = fioAddress
		result.RawRecord["fio_chain_code"] = chainCode
		result.RawRecord["fio_token_code"] = tokenCode
		result.AuditMetadata["reason"] = "fio_public_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		if strings.TrimSpace(apiResp.Message) != "" {
			result.AuditMetadata["fio_message"] = apiResp.Message
		}
		return result, nil
	}
	records := filterRecords(fioHandleRecords(plugins.NormalizeQName(req.QName), chainCode, tokenCode, apiResp.PublicAddress), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "fio-chain-api"
	result.RawRecord["fio_address"] = fioAddress
	result.RawRecord["fio_chain_code"] = chainCode
	result.RawRecord["fio_token_code"] = tokenCode
	result.RawRecord["fio_public_address"] = apiResp.PublicAddress
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "fio_handle_type_not_found"
	}
	return result, nil
}

func fioHandleAddress(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if !plugins.MatchSuffix(normalized, suffix) {
			continue
		}
		base := strings.TrimSuffix(trimmed, strings.TrimPrefix(strings.ToLower(suffix), "."))
		base = strings.TrimSuffix(base, ".")
		if base == "" {
			return "", false
		}
		if strings.Contains(base, "@") {
			parts := strings.Split(base, "@")
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				return base, true
			}
			return "", false
		}
		labels := strings.Split(base, ".")
		if len(labels) < 2 || labels[0] == "" || labels[len(labels)-1] == "" {
			return "", false
		}
		account := strings.Join(labels[:len(labels)-1], ".")
		domain := labels[len(labels)-1]
		return account + "@" + domain, true
	}
	return "", false
}

func fioChainAPIEndpoint(baseURL string) (string, string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", "", "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", "", "", errors.New("FIO Chain API backend url must be absolute")
	}
	query := parsed.Query()
	chainCode := strings.ToUpper(strings.TrimSpace(query.Get("chain_code")))
	tokenCode := strings.ToUpper(strings.TrimSpace(query.Get("token_code")))
	if chainCode == "" {
		chainCode = "ETH"
	}
	if tokenCode == "" {
		tokenCode = chainCode
	}
	query.Del("chain_code")
	query.Del("token_code")
	parsed.RawQuery = query.Encode()
	if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/v1/chain/get_pub_address") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/chain/get_pub_address"
	}
	parsed.Fragment = ""
	return parsed.String(), chainCode, tokenCode, nil
}

func fioHandleRecords(name, chainCode, tokenCode, publicAddress string) []plugins.RR {
	publicAddress = strings.TrimSpace(publicAddress)
	if publicAddress == "" {
		return nil
	}
	chain := strings.ToLower(strings.TrimSpace(chainCode))
	token := strings.ToLower(strings.TrimSpace(tokenCode))
	walletValue := chain + " " + publicAddress
	if token != "" && token != chain {
		walletValue = chain + ":" + token + " " + publicAddress
	}
	return []plugins.RR{{Name: name, Type: "WALLET", TTL: 300, Value: walletValue}}
}

func (p *Plugin) resolveFreenameResolutionAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := freenameDomainName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_freename_domain"
		return result, nil
	}
	endpoint, err := freenameResolutionEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-freename-resolution-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "freename-resolution-api"
		result.RawRecord["freename_domain"] = domain
		result.AuditMetadata["reason"] = "freename_domain_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Host    string `json:"host"`
		Network string `json:"network"`
		TLD     string `json:"tld"`
		SLD     string `json:"sld"`
		Records []struct {
			Key   string `json:"key"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	allRecords := freenameRecordsFromAPI(plugins.NormalizeQName(req.QName), apiResp.Records)
	records := filterRecords(allRecords, plugins.NormalizeQType(req.QType))
	if len(allRecords) == 0 {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "freename-resolution-api"
		result.RawRecord["freename_domain"] = domain
		result.RawRecord["freename_host"] = apiResp.Host
		result.RawRecord["freename_network"] = apiResp.Network
		result.AuditMetadata["reason"] = "freename_record_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "freename-resolution-api"
	result.RawRecord["freename_domain"] = domain
	result.RawRecord["freename_host"] = apiResp.Host
	result.RawRecord["freename_network"] = apiResp.Network
	result.RawRecord["freename_tld"] = apiResp.TLD
	result.RawRecord["freename_sld"] = apiResp.SLD
	result.RawRecord["freename_record_count"] = len(apiResp.Records)
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "freename_type_not_found"
	}
	return result, nil
}

func freenameDomainName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func freenameResolutionEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("Freename Resolution API backend url must be absolute")
	}
	if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/domain/resolve") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/domain/resolve"
	}
	query := parsed.Query()
	query.Set("q", domain)
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func freenameRecordsFromAPI(name string, apiRecords []struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value string `json:"value"`
}) []plugins.RR {
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for _, record := range apiRecords {
		key := strings.ToLower(strings.TrimSpace(record.Key))
		recordType := strings.ToLower(strings.TrimSpace(record.Type))
		value := strings.TrimSpace(record.Value)
		if value == "" {
			continue
		}
		switch {
		case strings.HasPrefix(key, "token.") || freenameWalletType(recordType):
			chain := recordType
			if chain == "" {
				parts := strings.Split(key, ".")
				if len(parts) >= 2 {
					chain = parts[1]
				}
			}
			add("WALLET", strings.ToLower(chain)+" "+value)
		case key == "redirect.website.0" || recordType == "website" || recordType == "url":
			add("URI", freenameURIValue(value))
		case key == "record.txt.0" || recordType == "txt":
			add("TXT", value)
		case strings.HasPrefix(key, "profile.") || recordType == "owner" || recordType == "profile":
			label := recordType
			if label == "" {
				label = strings.TrimPrefix(key, "profile.")
			}
			add("TXT", strings.ToLower(label)+"="+value)
		case recordType == "ipfs" || strings.Contains(key, "ipfs") || recordType == "contenthash":
			add("URI", freenameContentURI(value))
		default:
			if recordType != "" {
				add("TXT", recordType+"="+value)
			} else if key != "" {
				add("TXT", key+"="+value)
			}
		}
	}
	return records
}

func freenameWalletType(recordType string) bool {
	recordType = strings.ToLower(strings.TrimSpace(recordType))
	if recordType == "" {
		return false
	}
	switch recordType {
	case "btc", "eth", "matic", "bnb", "usdt", "usdc", "euroc", "aurora", "xdai", "busd", "cro", "polygon":
		return true
	default:
		return false
	}
}

func freenameURIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "https://" + value
}

func freenameContentURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "ipfs://" + value
}

func (p *Plugin) resolveDIDUniversalResolver(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	did, ok := bitDID(req.QName)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_did_bit_name"
		return result, nil
	}
	endpoint, err := didUniversalResolverEndpoint(backendURL, did)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/did+json, application/json")
	httpReq.Header.Set("User-Agent", "anyns-did-universal-resolver/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "did-universal-resolver"
		result.RawRecord["did"] = did
		result.AuditMetadata["reason"] = "did_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var resolution didResolutionResult
	if err := json.NewDecoder(resp.Body).Decode(&resolution); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if resolution.Document == nil {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "did-universal-resolver"
		result.RawRecord["did"] = did
		result.RawRecord["did_resolution_metadata"] = resolution.ResolutionMetadata
		result.AuditMetadata["reason"] = "did_document_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	allRecords := didDocumentRecords(plugins.NormalizeQName(req.QName), resolution.Document)
	records := filterRecords(allRecords, plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "did-universal-resolver"
	result.RawRecord["did"] = did
	result.RawRecord["did_document_id"] = stringField(resolution.Document["id"])
	result.RawRecord["did_resolution_metadata"] = resolution.ResolutionMetadata
	result.AuditMetadata["backend_url"] = backendURL
	if len(allRecords) == 0 {
		result.AuditMetadata["reason"] = "did_document_has_no_dns_records"
	} else if len(records) == 0 {
		result.AuditMetadata["reason"] = "did_type_not_found"
	}
	return result, nil
}

type didResolutionResult struct {
	Document           map[string]any `json:"didDocument"`
	ResolutionMetadata map[string]any `json:"didResolutionMetadata"`
	DocumentMetadata   map[string]any `json:"didDocumentMetadata"`
}

func bitDID(qname string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	var label string
	switch {
	case strings.HasSuffix(trimmed, ".did.bit"):
		label = strings.TrimSuffix(trimmed, ".did.bit")
	case strings.HasSuffix(trimmed, ".bit"):
		label = strings.TrimSuffix(trimmed, ".bit")
	default:
		return "", false
	}
	label = strings.Trim(label, ".")
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return "did:bit:" + label, true
}

func didUniversalResolverEndpoint(baseURL, did string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("DID Universal Resolver backend url must be absolute")
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(basePath, "/identifiers") {
		basePath += "/1.0/identifiers"
	}
	parsed.Path = basePath + "/" + url.PathEscape(did)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func didDocumentRecords(name string, doc map[string]any) []plugins.RR {
	var records []plugins.RR
	for _, value := range didDocumentWalletValues(doc) {
		records = append(records, plugins.RR{Name: name, Type: "WALLET", TTL: 300, Value: value})
	}
	for _, value := range didDocumentTXTValues(doc) {
		records = append(records, plugins.RR{Name: name, Type: "TXT", TTL: 300, Value: value})
	}
	for _, value := range didDocumentURIValues(doc) {
		records = append(records, plugins.RR{Name: name, Type: "URI", TTL: 300, Value: value})
	}
	return records
}

func didDocumentWalletValues(doc map[string]any) []string {
	var out []string
	for _, item := range objectList(doc["verificationMethod"]) {
		for _, field := range []string{"blockchainAccountId", "ethereumAddress", "publicKeyBase58", "publicKeyMultibase"} {
			value := stringField(item[field])
			if value == "" {
				continue
			}
			chain := "did"
			if before, _, ok := strings.Cut(value, ":"); ok && before != "" {
				chain = strings.ToLower(before)
			}
			out = append(out, chain+" "+value)
			break
		}
	}
	return out
}

func didDocumentTXTValues(doc map[string]any) []string {
	var out []string
	if id := stringField(doc["id"]); id != "" {
		out = append(out, "id="+id)
	}
	if controller := stringField(doc["controller"]); controller != "" {
		out = append(out, "controller="+controller)
	}
	for _, item := range objectList(doc["service"]) {
		if serviceType := stringField(item["type"]); serviceType != "" {
			out = append(out, "service="+serviceType)
		}
	}
	return out
}

func didDocumentURIValues(doc map[string]any) []string {
	var out []string
	for _, item := range objectList(doc["service"]) {
		for _, endpoint := range stringValues(item["serviceEndpoint"]) {
			if strings.Contains(endpoint, "://") {
				out = append(out, endpoint)
			}
		}
	}
	return out
}

func objectList(value any) []map[string]any {
	switch v := value.(type) {
	case map[string]any:
		return []map[string]any{v}
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if mapped, ok := item.(map[string]any); ok {
				out = append(out, mapped)
			}
		}
		return out
	default:
		return nil
	}
}

func stringField(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func (p *Plugin) resolveOpenAliasDNSTXT(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := openAliasName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_openalias_name"
		return result, nil
	}
	endpoint, err := openAliasDNSTXTEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-openalias-dns-txt/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "openalias-dns-txt"
		result.RawRecord["openalias_domain"] = domain
		result.AuditMetadata["reason"] = "openalias_record_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	txtRecords, err := decodeOpenAliasTXTRecords(resp.Body)
	if err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	openAliasRecords := parseOpenAliasTXTRecords(txtRecords)
	if len(openAliasRecords) == 0 {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "openalias-dns-txt"
		result.RawRecord["openalias_domain"] = domain
		result.AuditMetadata["reason"] = "openalias_record_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	records := filterRecords(openAliasRRs(plugins.NormalizeQName(req.QName), openAliasRecords), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "openalias-dns-txt"
	result.RawRecord["openalias_domain"] = domain
	result.RawRecord["openalias_record_count"] = len(openAliasRecords)
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "openalias_type_not_found"
	}
	return result, nil
}

func openAliasName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func openAliasDNSTXTEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("OpenAlias DNS TXT backend url must be absolute")
	}
	query := parsed.Query()
	query.Set("name", domain)
	query.Set("type", "TXT")
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func decodeOpenAliasTXTRecords(r io.Reader) ([]string, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, err
	}
	var direct []string
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct, nil
	}
	var wrapped struct {
		TXT     []string `json:"txt"`
		Records []struct {
			Type  string   `json:"type"`
			Value string   `json:"value"`
			Data  string   `json:"data"`
			Text  string   `json:"text"`
			Parts []string `json:"parts"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	out := append([]string{}, wrapped.TXT...)
	for _, record := range wrapped.Records {
		if record.Type != "" && !strings.EqualFold(record.Type, "TXT") {
			continue
		}
		switch {
		case len(record.Parts) > 0:
			out = append(out, strings.Join(record.Parts, ""))
		case strings.TrimSpace(record.Value) != "":
			out = append(out, record.Value)
		case strings.TrimSpace(record.Data) != "":
			out = append(out, record.Data)
		case strings.TrimSpace(record.Text) != "":
			out = append(out, record.Text)
		}
	}
	return out, nil
}

type openAliasRecord struct {
	Asset  string
	Fields map[string]string
}

func parseOpenAliasTXTRecords(txtRecords []string) []openAliasRecord {
	var records []openAliasRecord
	for _, txt := range txtRecords {
		record, ok := parseOpenAliasTXT(txt)
		if ok {
			records = append(records, record)
		}
	}
	return records
}

func parseOpenAliasTXT(txt string) (openAliasRecord, bool) {
	txt = strings.TrimSpace(strings.Trim(txt, `"`))
	if !strings.HasPrefix(strings.ToLower(txt), "oa1:") {
		return openAliasRecord{}, false
	}
	rest := strings.TrimSpace(txt[len("oa1:"):])
	asset, body, _ := strings.Cut(rest, " ")
	asset = strings.ToLower(strings.TrimSpace(asset))
	if asset == "" {
		return openAliasRecord{}, false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(body, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(strings.Trim(value, `"`))
		if key != "" && value != "" {
			fields[key] = value
		}
	}
	if fields["recipient_address"] == "" {
		return openAliasRecord{}, false
	}
	return openAliasRecord{Asset: asset, Fields: fields}, true
}

func openAliasRRs(name string, records []openAliasRecord) []plugins.RR {
	var out []plugins.RR
	txtKeys := []string{"recipient_name", "tx_description", "tx_amount", "tx_payment_id", "address_signature", "checksum"}
	for _, record := range records {
		address := strings.TrimSpace(record.Fields["recipient_address"])
		if address == "" {
			continue
		}
		out = append(out, plugins.RR{Name: name, Type: "WALLET", TTL: 300, Value: record.Asset + " " + address})
		for _, key := range txtKeys {
			if value := strings.TrimSpace(record.Fields[key]); value != "" {
				out = append(out, plugins.RR{Name: name, Type: "TXT", TTL: 300, Value: key + "=" + value})
			}
		}
	}
	return out
}

func (p *Plugin) resolveADAHandleAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	handle, ok := adaHandleName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_ada_handle"
		return result, nil
	}
	endpoint, err := adaHandleAPIEndpoint(backendURL, handle)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-ada-handle-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "ada-handle-api"
		result.RawRecord["ada_handle"] = handle
		result.AuditMetadata["reason"] = "ada_handle_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	allRecords := adaHandleRecordsFromMap(plugins.NormalizeQName(req.QName), raw)
	records := filterRecords(allRecords, plugins.NormalizeQType(req.QType))
	if len(allRecords) == 0 {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "ada-handle-api"
		result.RawRecord["ada_handle"] = handle
		result.RawRecord["ada_handle_response"] = raw
		result.AuditMetadata["reason"] = "ada_handle_record_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "ada-handle-api"
	result.RawRecord["ada_handle"] = handle
	result.RawRecord["ada_handle_response"] = raw
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "ada_handle_type_not_found"
	}
	return result, nil
}

func adaHandleName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if !plugins.MatchSuffix(normalized, suffix) {
			continue
		}
		base := strings.TrimSuffix(trimmed, strings.TrimPrefix(strings.ToLower(suffix), "."))
		base = strings.TrimSuffix(base, ".")
		base = strings.TrimPrefix(base, "$")
		if base == "" {
			return "", false
		}
		return base, true
	}
	return "", false
}

func adaHandleAPIEndpoint(baseURL, handle string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("ADA Handle API backend url must be absolute")
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(basePath, "/handles") {
		basePath += "/handles"
	}
	parsed.Path = basePath + "/" + url.PathEscape(handle)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func adaHandleRecordsFromMap(name string, raw map[string]any) []plugins.RR {
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for _, address := range adaHandleAddressValues(raw) {
		add("WALLET", "ada "+address)
	}
	for _, key := range []string{"handle", "name", "display_name", "description", "website", "twitter", "discord"} {
		for _, value := range stringValues(raw[key]) {
			add("TXT", key+"="+value)
		}
	}
	for _, key := range []string{"image", "standard_image", "pfp", "avatar", "url"} {
		for _, value := range stringValues(raw[key]) {
			add("URI", stacksBNSURIValue(value))
		}
	}
	for _, key := range []string{"asset", "policy", "policy_id", "hex", "fingerprint"} {
		for _, value := range stringValues(raw[key]) {
			add("TXT", key+"="+value)
		}
	}
	return records
}

func adaHandleAddressValues(raw map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, key := range []string{"address", "payment_address", "resolved_address", "holder", "holder_address", "owner", "stake_address"} {
		for _, value := range stringValues(raw[key]) {
			add(value)
		}
	}
	for _, key := range []string{"addresses", "resolved_addresses"} {
		for _, value := range stringValues(raw[key]) {
			add(value)
		}
		if entries, ok := raw[key].([]any); ok {
			for _, item := range entries {
				if entry, ok := item.(map[string]any); ok {
					add(firstStringValue(entry["address"]))
					add(firstStringValue(entry["payment_address"]))
					add(firstStringValue(entry["value"]))
				}
			}
		}
	}
	return out
}

func (p *Plugin) resolveTONCenterV3DNS(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := tonDNSName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_ton_dns_name"
		return result, nil
	}
	endpoint, err := tonCenterV3DNSEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-toncenter-v3-dns/0")
	if apiKey != "" {
		httpReq.Header.Set("X-API-Key", apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "toncenter-v3-dns"
		result.RawRecord["ton_dns_domain"] = domain
		result.AuditMetadata["reason"] = "ton_dns_name_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var apiResp struct {
		Records []struct {
			Domain         string `json:"domain"`
			Wallet         string `json:"dns_wallet"`
			SiteADNL       string `json:"dns_site_adnl"`
			StorageBagID   string `json:"dns_storage_bag_id"`
			NextResolver   string `json:"dns_next_resolver"`
			NFTItemAddress string `json:"nft_item_address"`
			NFTItemOwner   string `json:"nft_item_owner"`
		} `json:"records"`
		Code  int    `json:"code"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if strings.TrimSpace(apiResp.Error) != "" {
		result := serviceFailure(p.name, "backend_api_error", started)
		result.AuditMetadata["toncenter_error"] = apiResp.Error
		result.AuditMetadata["toncenter_code"] = apiResp.Code
		return result, fmt.Errorf("%s backend error: %s", p.name, apiResp.Error)
	}
	records := filterRecords(tonDNSRecords(plugins.NormalizeQName(req.QName), domain, apiResp.Records), plugins.NormalizeQType(req.QType))
	if len(records) == 0 && len(apiResp.Records) == 0 {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "toncenter-v3-dns"
		result.RawRecord["ton_dns_domain"] = domain
		result.AuditMetadata["reason"] = "ton_dns_name_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "toncenter-v3-dns"
	result.RawRecord["ton_dns_domain"] = domain
	result.RawRecord["ton_dns_record_count"] = len(apiResp.Records)
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "ton_dns_type_not_found"
	}
	return result, nil
}

func tonDNSName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func tonCenterV3DNSEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("TON Center v3 DNS backend url must be absolute")
	}
	if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/api/v3/dns/records") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v3/dns/records"
	}
	query := parsed.Query()
	query.Set("domain", domain)
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func tonDNSRecords(name, domain string, apiRecords []struct {
	Domain         string `json:"domain"`
	Wallet         string `json:"dns_wallet"`
	SiteADNL       string `json:"dns_site_adnl"`
	StorageBagID   string `json:"dns_storage_bag_id"`
	NextResolver   string `json:"dns_next_resolver"`
	NFTItemAddress string `json:"nft_item_address"`
	NFTItemOwner   string `json:"nft_item_owner"`
}) []plugins.RR {
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
	}
	for _, record := range apiRecords {
		if record.Domain != "" && !strings.EqualFold(strings.TrimSuffix(record.Domain, "."), domain) {
			continue
		}
		add("WALLET", "ton "+record.Wallet)
		add("URI", tonDNSURI("adnl", record.SiteADNL))
		add("URI", tonDNSURI("tonstorage", record.StorageBagID))
		add("TXT", tonDNSTXT("dns_next_resolver", record.NextResolver))
		add("TXT", tonDNSTXT("nft_item_address", record.NFTItemAddress))
		add("TXT", tonDNSTXT("nft_item_owner", record.NFTItemOwner))
	}
	return records
}

func tonDNSURI(scheme, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return scheme + "://" + value
}

func tonDNSTXT(key, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return key + "=" + value
}

func (p *Plugin) resolveSuiNSJSONRPC(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := suinsName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_suins_name"
		return result, nil
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "anyns-suins",
		"method":  "suix_resolveNameServiceAddress",
		"params":  []string{domain},
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
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "anyns-suins-json-rpc/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	var rpcResp struct {
		Result *string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	if rpcResp.Error != nil {
		result := serviceFailure(p.name, "backend_jsonrpc_error", started)
		result.AuditMetadata["suins_error_code"] = rpcResp.Error.Code
		result.AuditMetadata["suins_error_message"] = rpcResp.Error.Message
		return result, fmt.Errorf("%s backend JSON-RPC error %d: %s", p.name, rpcResp.Error.Code, rpcResp.Error.Message)
	}
	address := ""
	if rpcResp.Result != nil {
		address = strings.TrimSpace(*rpcResp.Result)
	}
	if address == "" {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "suins-json-rpc"
		result.RawRecord["suins_domain"] = domain
		result.AuditMetadata["reason"] = "suins_address_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	records := filterRecords(suinsRecords(plugins.NormalizeQName(req.QName), address), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "suins-json-rpc"
	result.RawRecord["suins_domain"] = domain
	result.RawRecord["suins_address"] = address
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "suins_type_not_found"
	}
	return result, nil
}

func suinsName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func suinsRecords(name, address string) []plugins.RR {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	return []plugins.RR{{Name: name, Type: "WALLET", TTL: 300, Value: "sui " + address}}
}

func (p *Plugin) resolveStacksBNSAPI(ctx context.Context, req plugins.ResolveRequest, backendURL, apiKey string, timeout time.Duration, client *http.Client, started time.Time) (plugins.ResolveResult, error) {
	domain, ok := stacksBNSName(req.QName, p.suffixes)
	if !ok {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.AuditMetadata["reason"] = "invalid_stacks_bns_name"
		return result, nil
	}
	endpoint, err := stacksBNSZonefileEndpoint(backendURL, domain)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return plugins.ResolveResult{}, err
	}
	httpReq.Header.Set("Accept", "application/json,text/plain")
	httpReq.Header.Set("User-Agent", "anyns-stacks-bns-api/0")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return serviceFailure(p.name, "backend_request_failed", started), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		result := plugins.NewResult(p.name, plugins.RCodeNXDomain, 300, nil, started)
		result.RawRecord["backend"] = "stacks-bns-api"
		result.AuditMetadata["reason"] = "stacks_bns_name_not_found"
		result.AuditMetadata["backend_url"] = backendURL
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceFailure(p.name, fmt.Sprintf("backend_status_%d", resp.StatusCode), started), fmt.Errorf("%s backend status %d", p.name, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return serviceFailure(p.name, "backend_read_failed", started), err
	}
	zonefile, rawRecord, err := decodeStacksBNSZonefile(body)
	if err != nil {
		return serviceFailure(p.name, "backend_decode_failed", started), err
	}
	records := filterRecords(stacksBNSRecords(plugins.NormalizeQName(req.QName), zonefile), plugins.NormalizeQType(req.QType))
	result := plugins.NewResult(p.name, plugins.RCodeNoError, minPositiveTTL(records, 300), records, started)
	result.RawRecord["backend"] = "stacks-bns-api"
	result.RawRecord["stacks_bns_name"] = domain
	result.RawRecord["stacks_bns_zonefile"] = rawRecord
	result.AuditMetadata["backend_url"] = backendURL
	if len(records) == 0 {
		result.AuditMetadata["reason"] = "stacks_bns_type_not_found"
	}
	return result, nil
}

func stacksBNSName(qname string, suffixes []string) (string, bool) {
	normalized := plugins.NormalizeQName(qname)
	trimmed := strings.TrimSuffix(normalized, ".")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	for _, suffix := range suffixes {
		if plugins.MatchSuffix(normalized, suffix) {
			return trimmed, true
		}
	}
	return "", false
}

func stacksBNSZonefileEndpoint(baseURL, domain string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("stacks BNS backend url must be absolute")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/names/" + url.PathEscape(domain) + "/zonefile"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func decodeStacksBNSZonefile(body []byte) (string, any, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", nil, errors.New("empty stacks BNS zonefile response")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return trimmed, trimmed, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", nil, err
	}
	if zonefile, ok := raw["zonefile"].(string); ok {
		return zonefile, raw, nil
	}
	if _, ok := raw["addresses"].([]any); ok {
		return trimmed, raw, nil
	}
	if _, ok := raw["owner"].(string); ok {
		return trimmed, raw, nil
	}
	return "", raw, errors.New("stacks BNS response missing zonefile")
}

func stacksBNSRecords(name, zonefile string) []plugins.RR {
	trimmed := strings.TrimSpace(zonefile)
	if strings.HasPrefix(trimmed, "{") {
		return stacksBNSJSONRecords(name, trimmed)
	}
	return stacksBNSLegacyZoneRecords(name, trimmed)
}

func stacksBNSJSONRecords(name, zonefile string) []plugins.RR {
	var raw map[string]any
	if err := json.Unmarshal([]byte(zonefile), &raw); err != nil {
		return nil
	}
	var records []plugins.RR
	add := func(rrType, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			records = append(records, plugins.RR{Name: name, Type: rrType, TTL: 300, Value: value})
		}
	}
	for _, key := range []string{"owner", "name", "bio", "location"} {
		for _, value := range stringValues(raw[key]) {
			add("TXT", key+"="+value)
		}
	}
	for _, value := range stringValues(raw["website"]) {
		add("URI", stacksBNSURIValue(value))
	}
	for _, value := range stringValues(raw["pfp"]) {
		add("URI", stacksBNSURIValue(value))
	}
	for _, value := range stringValues(raw["btc"]) {
		add("WALLET", "btc "+value)
	}
	if addresses, ok := raw["addresses"].([]any); ok {
		for _, item := range addresses {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			network := firstStringValue(entry["network"])
			address := firstStringValue(entry["address"])
			if network != "" && address != "" {
				add("WALLET", strings.ToLower(network)+" "+address)
			}
		}
	}
	if meta, ok := raw["meta"].([]any); ok {
		for _, item := range meta {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			key := firstStringValue(entry["name"])
			value := firstStringValue(entry["value"])
			if key != "" && value != "" {
				add("TXT", key+"="+value)
			}
		}
	}
	return records
}

func stacksBNSLegacyZoneRecords(name, zonefile string) []plugins.RR {
	var records []plugins.RR
	defaultTTL := 300
	for _, line := range strings.Split(zonefile, "\n") {
		line = strings.TrimSpace(stripZoneComment(line))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "$TTL") && len(fields) > 1 {
			if ttl, ok := parsePositiveInt(fields[1]); ok {
				defaultTTL = ttl
			}
			continue
		}
		typeIndex := zoneRRTypeIndex(fields)
		if typeIndex < 0 || typeIndex+1 >= len(fields) {
			continue
		}
		rrType := strings.ToUpper(fields[typeIndex])
		ttl := defaultTTL
		if typeIndex > 0 {
			if parsed, ok := parsePositiveInt(fields[typeIndex-1]); ok {
				ttl = parsed
			}
		}
		value := zoneRRValue(rrType, fields[typeIndex+1:])
		if value == "" {
			continue
		}
		switch rrType {
		case "A":
			if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
				continue
			}
		case "AAAA":
			if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
				continue
			}
		case "CNAME", "NS":
			value = plugins.NormalizeQName(value)
		}
		records = append(records, plugins.RR{Name: name, Type: rrType, TTL: ttl, Value: value})
	}
	return records
}

func firstStringValue(value any) string {
	values := stringValues(value)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func stacksBNSURIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return value
	}
	return "https://" + value
}

func stripZoneComment(line string) string {
	if idx := strings.Index(line, ";"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func zoneRRTypeIndex(fields []string) int {
	known := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "TXT": true, "NS": true, "MX": true,
		"SRV": true, "URI": true, "HTTPS": true, "SVCB": true, "TLSA": true, "CAA": true,
	}
	for i, field := range fields {
		if known[strings.ToUpper(field)] {
			return i
		}
	}
	return -1
}

func zoneRRValue(rrType string, fields []string) string {
	switch rrType {
	case "TXT":
		return strings.Trim(strings.Join(fields, " "), `"`)
	case "URI":
		return strings.Trim(fields[len(fields)-1], `"`)
	default:
		return strings.Trim(strings.Join(fields, " "), `"`)
	}
}

func parsePositiveInt(value string) (int, bool) {
	var n int
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, n > 0
}
