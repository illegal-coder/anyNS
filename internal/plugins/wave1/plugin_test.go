package wave1

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/plugins"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestRemoteBackendResolveUsesJSONContract(t *testing.T) {
	plugin := New("ens", []string{".eth"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		URL:            "https://ens-backend.example/resolve",
		APIKey:         "backend-secret",
		RequestTimeout: 250 * time.Millisecond,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://ens-backend.example/resolve" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer backend-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			for _, want := range []string{`"plugin":"ens"`, `"qname":"vitalik.eth."`, `"qtype":"A"`} {
				if !strings.Contains(string(body), want) {
					t.Fatalf("request body missing %q in %s", want, string(body))
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"result": {
						"rrset": [{"name":"vitalik.eth.","type":"A","ttl":120,"value":"203.0.113.44"}],
						"rcode": "NOERROR",
						"ttl": 120,
						"confidence": "backend"
					}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "Vitalik.ETH",
		QType: "a",
		Context: plugins.QueryContext{
			TraceID: "wave1-remote",
			Tenant:  "default",
		},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "ens" || result.RCode != plugins.RCodeNoError || result.TTL != 120 {
		t.Fatalf("result = %#v", result)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Value != "203.0.113.44" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
	if result.RawRecord["backend"] != "remote-http" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
}

func TestRemoteBackendStatusFailureReturnsServFail(t *testing.T) {
	plugin := New("namecoin-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		URL: "https://namecoin.example/resolve",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`bad gateway`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "example.bit", QType: "A"})
	if err == nil {
		t.Fatalf("expected backend error")
	}
	if result.RCode != plugins.RCodeServFail || result.SourcePlugin != "namecoin-bit" {
		t.Fatalf("result = %#v", result)
	}
	if result.AuditMetadata["reason"] != "backend_status_502" {
		t.Fatalf("audit metadata = %#v", result.AuditMetadata)
	}
}

func TestRemoteBackendAcceptsDirectResolveResult(t *testing.T) {
	plugin := New("unstoppable-domains", []string{".crypto"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		URL: "https://unstoppable.example/resolve",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"rrset": [{"name":"alice.crypto.","type":"TXT","ttl":90,"value":"owner=0xabc"}],
					"rcode": "NOERROR"
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.crypto", QType: "TXT"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "unstoppable-domains" || result.TTL != 90 {
		t.Fatalf("result = %#v", result)
	}
}

func TestDIDUniversalResolverBackendMapsDocumentRecords(t *testing.T) {
	plugin := New("did-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "did-universal-resolver",
		URL:    "https://resolver.example",
		APIKey: "resolver-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://resolver.example/1.0/identifiers/did:bit:alice" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer resolver-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"didDocument": {
						"id": "did:bit:alice",
						"controller": "did:bit:controller",
						"verificationMethod": [{
							"id": "did:bit:alice#owner",
							"type": "EcdsaSecp256k1RecoveryMethod2020",
							"blockchainAccountId": "eip155:1:0x1234567890abcdef1234567890abcdef12345678"
						}],
						"service": [{
							"id": "did:bit:alice#website",
							"type": "LinkedDomains",
							"serviceEndpoint": "https://alice.example"
						}]
					},
					"didResolutionMetadata": {"contentType": "application/did+json"}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.DID.Bit", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "did-bit" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "did-universal-resolver" || result.RawRecord["did"] != "did:bit:alice" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"WALLET=eip155 eip155:1:0x1234567890abcdef1234567890abcdef12345678": false,
		"TXT=id=did:bit:alice":              false,
		"TXT=controller=did:bit:controller": false,
		"TXT=service=LinkedDomains":         false,
		"URI=https://alice.example":         false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestDIDUniversalResolverBackendMissingDocumentReturnsNXDomain(t *testing.T) {
	plugin := New("did-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "did-universal-resolver",
		URL:  "https://resolver.example/1.0/identifiers",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://resolver.example/1.0/identifiers/did:bit:missing" {
				t.Fatalf("url = %s", r.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"didDocument": null,
					"didResolutionMetadata": {"error": "notFound"}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.bit", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "did_document_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestENSJSONRPCBackendMapsWalletTextAndContenthash(t *testing.T) {
	plugin := New("ens", []string{".eth"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "ens-json-rpc",
		URL:    "https://ethereum-rpc.example",
		APIKey: "rpc-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://ethereum-rpc.example" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer rpc-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			switch {
			case strings.Contains(text, ensResolverSelector):
				return ensRPCResponse(`0x0000000000000000000000001234567890abcdef1234567890abcdef12345678`), nil
			case strings.Contains(text, ensAddrSelector):
				return ensRPCResponse(`0x0000000000000000000000000000000000000000000000000000000000000001`), nil
			case strings.Contains(text, ensTextSelector) && strings.Contains(text, hexString("email")):
				return ensRPCResponse(abiStringReturn("alice@example.test")), nil
			case strings.Contains(text, ensTextSelector):
				return ensRPCResponse(abiStringReturn("")), nil
			case strings.Contains(text, ensContenthashSelector):
				return ensRPCResponse(abiBytesReturn([]byte{0xe3, 0x01, 0x01, 0x70})), nil
			default:
				t.Fatalf("unexpected RPC body %s", text)
				return nil, nil
			}
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.ETH", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "ens" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "ens-json-rpc" || result.RawRecord["ens_name"] != "alice.eth" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"WALLET=eth 0x0000000000000000000000000000000000000001": false,
		"TXT=email=alice@example.test":                          false,
		"URI=ipfs://0x0170":                                     false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestENSJSONRPCBackendNoResolverReturnsNXDomain(t *testing.T) {
	plugin := New("ens", []string{".eth"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "ens-json-rpc",
		URL:  "https://ethereum-rpc.example",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return ensRPCResponse(`0x` + ensZeroAddressReturn), nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.eth", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "ens_resolver_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestENSNamehashUsesLegacyKeccak(t *testing.T) {
	got, err := ensNamehash("ens.eth")
	if err != nil {
		t.Fatalf("namehash: %v", err)
	}
	want := "4e34d3a81dc3a20f71bbdf2160492ddaa17ee7e5523757d47153379c13cb46df"
	if got != want {
		t.Fatalf("namehash = %s, want %s", got, want)
	}
}

func TestPulseChainPNSJSONRPCBackendMapsWalletTextAndContenthash(t *testing.T) {
	plugin := New("pns-pulsechain", []string{".pls"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "pulsechain-pns-json-rpc",
		URL:    "https://pulse-rpc.example?registry=0x1111111111111111111111111111111111111111",
		APIKey: "pulse-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://pulse-rpc.example" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer pulse-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			switch {
			case strings.Contains(text, ensResolverSelector):
				if !strings.Contains(text, "1111111111111111111111111111111111111111") {
					t.Fatalf("resolver lookup did not target configured registry: %s", text)
				}
				return ensRPCResponse(`0x0000000000000000000000002222222222222222222222222222222222222222`), nil
			case strings.Contains(text, ensAddrSelector):
				return ensRPCResponse(`0x0000000000000000000000003333333333333333333333333333333333333333`), nil
			case strings.Contains(text, ensTextSelector) && strings.Contains(text, hexString("url")):
				return ensRPCResponse(abiStringReturn("https://alice.pls")), nil
			case strings.Contains(text, ensTextSelector):
				return ensRPCResponse(abiStringReturn("")), nil
			case strings.Contains(text, ensContenthashSelector):
				return ensRPCResponse(abiBytesReturn([]byte{0xe5, 0x01, 0x01, 0x70})), nil
			default:
				t.Fatalf("unexpected RPC body %s", text)
				return nil, nil
			}
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.PLS", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "pns-pulsechain" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "pulsechain-pns-json-rpc" || result.RawRecord["pulsechain_pns_name"] != "alice.pls" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"WALLET=pls 0x3333333333333333333333333333333333333333": false,
		"TXT=url=https://alice.pls":                             false,
		"URI=ipns://0x0170":                                     false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestPulseChainPNSJSONRPCBackendRequiresRegistry(t *testing.T) {
	for _, backendURL := range []string{
		"https://pulse-rpc.example",
		"https://pulse-rpc.example?registry=not-a-hex-address",
		"https://pulse-rpc.example?registry=0x0000000000000000000000000000000000000000",
	} {
		plugin := New("pns-pulsechain", []string{".pls"})
		plugin.SetEnabled(true)
		plugin.ConfigureBackend(BackendConfig{
			Type: "pulsechain-pns-json-rpc",
			URL:  backendURL,
		})

		result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.pls", QType: "WALLET"})
		if err == nil {
			t.Fatalf("expected registry error for %s", backendURL)
		}
		if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_registry_required" {
			t.Fatalf("result = %#v", result)
		}
	}
}

func TestRIFRNSJSONRPCBackendMapsWalletTextAndContenthash(t *testing.T) {
	plugin := New("rif-rns", []string{".rsk"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "rif-rns-json-rpc",
		URL:    "https://rsk-rpc.example?registry=0x4444444444444444444444444444444444444444",
		APIKey: "rns-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://rsk-rpc.example" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer rns-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			switch {
			case strings.Contains(text, ensResolverSelector):
				if !strings.Contains(text, "4444444444444444444444444444444444444444") {
					t.Fatalf("resolver lookup did not target configured registry: %s", text)
				}
				return ensRPCResponse(`0x0000000000000000000000005555555555555555555555555555555555555555`), nil
			case strings.Contains(text, ensAddrSelector):
				return ensRPCResponse(`0x0000000000000000000000006666666666666666666666666666666666666666`), nil
			case strings.Contains(text, ensTextSelector) && strings.Contains(text, hexString("url")):
				return ensRPCResponse(abiStringReturn("https://alice.rsk")), nil
			case strings.Contains(text, ensTextSelector):
				return ensRPCResponse(abiStringReturn("")), nil
			case strings.Contains(text, ensContenthashSelector):
				return ensRPCResponse(abiBytesReturn([]byte{0xe3, 0x01, 0x01, 0x70})), nil
			default:
				t.Fatalf("unexpected RPC body %s", text)
				return nil, nil
			}
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.RSK", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "rif-rns" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "rif-rns-json-rpc" || result.RawRecord["rif_rns_name"] != "alice.rsk" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"WALLET=rbtc 0x6666666666666666666666666666666666666666": false,
		"TXT=url=https://alice.rsk":                              false,
		"URI=ipfs://0x0170":                                      false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestRIFRNSJSONRPCBackendRequiresRegistry(t *testing.T) {
	plugin := New("rif-rns", []string{".rsk"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "rif-rns-json-rpc",
		URL:  "https://rsk-rpc.example",
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.rsk", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected registry error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_registry_required" {
		t.Fatalf("result = %#v", result)
	}
}

func ensRPCResponse(result string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":"anyns-ens-json-rpc","result":"` + result + `"}`)),
	}
}

func abiStringReturn(value string) string {
	return "0x" + leftPadHex("20", 64) + leftPadHex(fmt.Sprintf("%x", len(value)), 64) + rightPadHex(hexString(value), 64)
}

func abiBytesReturn(value []byte) string {
	encoded := hex.EncodeToString(value)
	return "0x" + leftPadHex("20", 64) + leftPadHex(fmt.Sprintf("%x", len(value)), 64) + rightPadHex(encoded, 64)
}

func hexString(value string) string {
	return hex.EncodeToString([]byte(value))
}

func TestNamecoinJSONRPCBackendMapsRecords(t *testing.T) {
	plugin := New("namecoin-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "namecoin-json-rpc",
		URL:    "http://namecoind.example/",
		APIKey: "rpcuser:rpcpass",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if got := r.Header.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("rpcuser:rpcpass")) {
				t.Fatalf("authorization = %q", got)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			for _, want := range []string{`"method":"name_show"`, `"d/example"`} {
				if !strings.Contains(string(body), want) {
					t.Fatalf("request body missing %q in %s", want, string(body))
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"result": {
						"name": "d/example",
						"value": "{\"ip\":[\"203.0.113.7\",\"2001:db8::7\"],\"ns\":[\"ns1.example.bit\"],\"txt\":\"root text\",\"map\":{\"www\":{\"ip\":\"203.0.113.8\",\"info\":\"sub text\"}}}"
					},
					"error": null,
					"id": "anyns-namecoin-bit"
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "www.example.bit", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "namecoin-bit" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "namecoin-json-rpc" || result.RawRecord["namecoin_name"] != "d/example" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if len(result.RRSet) != 2 {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
	want := map[string]string{"A": "203.0.113.8", "TXT": "sub text"}
	for _, rr := range result.RRSet {
		if want[rr.Type] != rr.Value {
			t.Fatalf("unexpected rr %#v in %#v", rr, result.RRSet)
		}
	}
}

func TestNamecoinJSONRPCBackendNameNotFoundReturnsNXDomain(t *testing.T) {
	plugin := New("namecoin-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "namecoin-json-rpc",
		URL:  "http://namecoind.example/",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"result":null,"error":{"code":-4,"message":"name not found"},"id":"anyns-namecoin-bit"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.bit", QType: "A"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "namecoin_name_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestNamecoinJSONRPCBackendMapsDSAndWildcardTLSA(t *testing.T) {
	const dsDigest = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	plugin := New("namecoin-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "namecoin-json-rpc",
		URL:  "http://namecoind.example/",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			value := map[string]any{
				"ip": "203.0.113.9",
				"ns": "ns1.example.bit",
				"ds": []any{
					[]any{12345, 13, 2, dsDigest},
				},
				"map": map[string]any{
					"*": map[string]any{
						"tls": []any{
							[]any{2, 1, 0, base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0xab})},
						},
					},
				},
			}
			payload, err := jsonPayloadForNamecoin(value)
			if err != nil {
				t.Fatalf("payload: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		})},
	})

	dsResult, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "example.bit", QType: "DS"})
	if err != nil {
		t.Fatalf("resolve DS: %v", err)
	}
	if len(dsResult.RRSet) != 1 || dsResult.RRSet[0].Type != "DS" || dsResult.RRSet[0].Value != "12345 13 2 "+dsDigest {
		t.Fatalf("DS result = %#v", dsResult.RRSet)
	}

	tlsaResult, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "www.example.bit", QType: "TLSA"})
	if err != nil {
		t.Fatalf("resolve TLSA: %v", err)
	}
	if len(tlsaResult.RRSet) != 1 || tlsaResult.RRSet[0].Type != "TLSA" || tlsaResult.RRSet[0].Value != "2 1 0 0102AB" {
		t.Fatalf("TLSA result = %#v", tlsaResult.RRSet)
	}
}

func TestNamecoinTupleRecordRejectsMalformedSecurityRecords(t *testing.T) {
	tests := []struct {
		name   string
		tuple  []any
		rrType string
	}{
		{name: "short DS digest", tuple: []any{float64(12345), float64(13), float64(2), "ABCD1234"}, rrType: "DS"},
		{name: "non-hex DS digest", tuple: []any{float64(12345), float64(13), float64(2), strings.Repeat("Z", 64)}, rrType: "DS"},
		{name: "invalid TLSA usage", tuple: []any{float64(4), float64(1), float64(0), "AQI="}, rrType: "TLSA"},
		{name: "short TLSA SHA-256", tuple: []any{float64(3), float64(1), float64(1), "AQI="}, rrType: "TLSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if value, ok := namecoinTupleRecord(tt.tuple, tt.rrType); ok {
				t.Fatalf("namecoinTupleRecord() = %q, true; want rejected", value)
			}
		})
	}
}

func TestNamecoinJSONRPCBackendMapsModernPresentationRecords(t *testing.T) {
	plugin := New("namecoin-bit", []string{".bit"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "namecoin-json-rpc",
		URL:  "http://namecoind.example/",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			value := map[string]any{
				"mx":  []any{10, "mail.example.bit"},
				"srv": []any{0, 5, 443, "service.example.bit"},
				"uri": []any{
					"10 1 https://example.bit/",
					"20 1 ipfs://bafyexample",
				},
				"caa": []any{0, "issue", "letsencrypt.org"},
			}
			payload, err := jsonPayloadForNamecoin(value)
			if err != nil {
				t.Fatalf("payload: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		})},
	})

	tests := []struct {
		qtype string
		want  string
	}{
		{qtype: "MX", want: "10 mail.example.bit."},
		{qtype: "SRV", want: "0 5 443 service.example.bit."},
		{qtype: "URI", want: "10 1 https://example.bit/"},
		{qtype: "CAA", want: "0 issue letsencrypt.org"},
	}
	for _, tt := range tests {
		result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "example.bit", QType: tt.qtype})
		if err != nil {
			t.Fatalf("resolve %s: %v", tt.qtype, err)
		}
		if len(result.RRSet) == 0 {
			t.Fatalf("%s result has no records", tt.qtype)
		}
		if result.RRSet[0].Type != tt.qtype || result.RRSet[0].Value != tt.want {
			t.Fatalf("%s result = %#v, want %q", tt.qtype, result.RRSet, tt.want)
		}
	}
}

func jsonPayloadForNamecoin(value map[string]any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"result": map[string]any{
			"name":  "d/example",
			"value": string(encoded),
		},
		"error": nil,
		"id":    "anyns-namecoin-bit",
	})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func TestUnstoppableResolutionAPIBackendMapsRecords(t *testing.T) {
	plugin := New("unstoppable-domains", []string{".crypto", ".wallet"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "unstoppable-resolution-api",
		URL:    "https://api.unstoppabledomains.com/resolve",
		APIKey: "ud-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://api.unstoppabledomains.com/resolve/domains/alice.crypto" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer ud-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"meta": {"domain":"alice.crypto","type":"Uns"},
					"records": {
						"dns.A": "203.0.113.55",
						"dns.AAAA": "2001:db8::55",
						"dns.CNAME": "target.example",
						"browser.redirect_url": "https://example.test",
						"ipfs.html.value": "bafybeigdyrzt",
						"crypto.ETH.address": "0x0000000000000000000000000000000000000001",
						"crypto.BTC.address": "bc1qexample"
					}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.Crypto", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "unstoppable-domains" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "unstoppable-resolution-api" || result.RawRecord["unstoppable_domain"] != "alice.crypto" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"A=203.0.113.55": false, "AAAA=2001:db8::55": false, "CNAME=target.example.": false,
		"URI=https://example.test": false, "URI=ipfs://bafybeigdyrzt": false,
		"WALLET=eth 0x0000000000000000000000000000000000000001": false, "WALLET=btc bc1qexample": false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestUnstoppableResolutionAPIBackendNotFoundReturnsNXDomain(t *testing.T) {
	plugin := New("unstoppable-domains", []string{".crypto"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "unstoppable-resolution-api",
		URL:  "https://api.unstoppabledomains.com/resolve",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"message":"not found"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.crypto", QType: "A"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "unstoppable_domain_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestPNSPolkadotAPIBackendMapsRecords(t *testing.T) {
	plugin := New("pns-polkadot", []string{".dot"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "pns-polkadot-api",
		URL:    "https://api.ddns.so",
		APIKey: "pns-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://api.ddns.so/name/alice.dot" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer pns-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"result": "ok",
					"data": {
						"name": "alice.dot",
						"name_hash": "0x1234",
						"records": {
							"address": "15Znnr...",
							"addresses": [{"network":"ksm","address":"HFXk..."}],
							"website": "alice.example",
							"ipfs": "bafybeigdyrzt",
							"twitter": "@alice",
							"dns.A": "203.0.113.77",
							"dns.AAAA": "2001:db8::77"
						}
					}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.DOT", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "pns-polkadot" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "pns-polkadot-api" || result.RawRecord["pns_polkadot_name"] != "alice.dot" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"WALLET=dot 15Znnr...":      false,
		"WALLET=ksm HFXk...":        false,
		"URI=https://alice.example": false,
		"URI=ipfs://bafybeigdyrzt":  false,
		"TXT=twitter=@alice":        false,
		"A=203.0.113.77":            false,
		"AAAA=2001:db8::77":         false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestPNSPolkadotAPIBackendNotFoundReturnsNXDomain(t *testing.T) {
	plugin := New("pns-polkadot", []string{".dot"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "pns-polkadot-api",
		URL:  "https://api.ddns.so",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"message":"not found"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.dot", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "pns_polkadot_name_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSpaceIDAPIBackendMapsAddressToWallet(t *testing.T) {
	plugin := New("space-id", []string{".bnb", ".arb"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "space-id-api",
		URL:    "https://nameapi.space.id",
		APIKey: "space-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://nameapi.space.id/getAddress?domain=alice.bnb" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer space-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"address":"0xb5932a6B7d50A966AEC6C74C97385412Fb497540","code":0,"msg":"success"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.BNB", QType: "TYPE262"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "space-id" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "space-id-api" || result.RawRecord["space_id_domain"] != "alice.bnb" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Type != "WALLET" || result.RRSet[0].Value != "bnb 0xb5932a6B7d50A966AEC6C74C97385412Fb497540" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
}

func TestSpaceIDAPIBackendNoAddressReturnsNXDomain(t *testing.T) {
	plugin := New("space-id", []string{".bnb", ".arb"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "space-id-api",
		URL:  "https://nameapi.space.id/getAddress",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://nameapi.space.id/getAddress?domain=missing.arb" {
				t.Fatalf("url = %s", r.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"code":1,"msg":"no address found"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.arb", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "space_id_address_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSpaceIDAPIBackendErrorCodeReturnsServFail(t *testing.T) {
	plugin := New("space-id", []string{".bnb", ".arb"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "space-id-api",
		URL:  "https://nameapi.space.id",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"code":-1,"msg":"backend error"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.bnb", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected API error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_api_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestTezosDomainsAPIBackendMapsGraphQLDomain(t *testing.T) {
	plugin := New("tezos-domains", []string{".tez"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "tezos-domains-api",
		URL:    "https://api.tezos.domains",
		APIKey: "tezos-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://api.tezos.domains/graphql" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer tezos-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			for _, want := range []string{`"name":"alice.tez"`, `domain(name: $name)`, `address`, `data`} {
				if !strings.Contains(text, want) {
					t.Fatalf("request body missing %q in %s", want, text)
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"data": {
						"domain": {
							"name": "alice.tez",
							"address": "tz1VBLpuDKMoJuHRLZ4HrCgRuiLpEr7zZx2E",
							"owner": "tz1Owner11111111111111111111111111111111",
							"data": [
								{"key":"website","rawValue":"alice.example","value":"alice.example"},
								{"key":"email","rawValue":"alice@example.test","value":"alice@example.test"},
								{"key":"dns.a","rawValue":"203.0.113.10","value":"203.0.113.10"},
								{"key":"ipfs","rawValue":"bafybeigdyrzt","value":"bafybeigdyrzt"}
							]
						}
					}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.TEZ", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "tezos-domains" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "tezos-domains-api" || result.RawRecord["tezos_domain"] != "alice.tez" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"WALLET=tez tz1VBLpuDKMoJuHRLZ4HrCgRuiLpEr7zZx2E":    false,
		"TXT=owner=tz1Owner11111111111111111111111111111111": false,
		"URI=https://alice.example":                          false,
		"TXT=email=alice@example.test":                       false,
		"A=203.0.113.10":                                     false,
		"URI=ipfs://bafybeigdyrzt":                           false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestTezosDomainsAPIBackendMissingDomainReturnsNXDomain(t *testing.T) {
	plugin := New("tezos-domains", []string{".tez"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "tezos-domains-api",
		URL:  "https://api.tezos.domains/graphql",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"data":{"domain":null}}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.tez", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "tezos_domain_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestTezosDomainsAPIBackendGraphQLErrorReturnsServFail(t *testing.T) {
	plugin := New("tezos-domains", []string{".tez"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "tezos-domains-api",
		URL:  "https://api.tezos.domains/graphql",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"errors":[{"message":"rate limited"}]}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.tez", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected GraphQL error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_graphql_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAptosNamesAPIBackendMapsAddressToWallet(t *testing.T) {
	plugin := New("aptos-names", []string{".apt"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "aptos-names-api",
		URL:    "https://www.aptosnames.com/api/mainnet",
		APIKey: "aptos-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://www.aptosnames.com/api/mainnet/v3/address/alice" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("X-API-Key") != "aptos-secret" {
				t.Fatalf("x-api-key = %q", r.Header.Get("X-API-Key"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"address":"0x1234567890abcdef"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.APT", QType: "TYPE262"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "aptos-names" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "aptos-names-api" || result.RawRecord["aptos_name"] != "alice.apt" || result.RawRecord["aptos_lookup_name"] != "alice" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Type != "WALLET" || result.RRSet[0].Value != "aptos 0x1234567890abcdef" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
}

func TestAptosNamesAPIBackendNotFoundReturnsNXDomain(t *testing.T) {
	plugin := New("aptos-names", []string{".apt"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "aptos-names-api",
		URL:  "https://www.aptosnames.com/api/mainnet/v3/address",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://www.aptosnames.com/api/mainnet/v3/address/missing" {
				t.Fatalf("url = %s", r.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"message":"not found"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.apt", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "aptos_name_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAptosNamesAPIBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("aptos-names", []string{".apt"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "aptos-names-api",
		URL:  "https://www.aptosnames.com/api/mainnet",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"error":"rate_limited","message":"API key required"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.apt", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected API error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_api_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSolanaSNSQuickNodeBackendMapsAddressToWallet(t *testing.T) {
	plugin := New("solana-sns", []string{".sol"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "solana-sns-quicknode",
		URL:    "https://solana-mainnet.quiknode.pro/token/",
		APIKey: "sns-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://solana-mainnet.quiknode.pro/token/" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer sns-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			for _, want := range []string{`"method":"sns_resolveDomain"`, `"bonfida.sol"`} {
				if !strings.Contains(text, want) {
					t.Fatalf("request body missing %q in %s", want, text)
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":"HKKp49qGWXd639QsuH7JiLijfVW5UtCVY4s1n2HANwEA","id":42}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Bonfida.SOL", QType: "TYPE262"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "solana-sns" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "solana-sns-quicknode" || result.RawRecord["solana_sns_domain"] != "bonfida.sol" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Type != "WALLET" || result.RRSet[0].Value != "sol HKKp49qGWXd639QsuH7JiLijfVW5UtCVY4s1n2HANwEA" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
}

func TestSolanaSNSQuickNodeBackendNoAddressReturnsNXDomain(t *testing.T) {
	plugin := New("solana-sns", []string{".sol"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "solana-sns-quicknode",
		URL:  "https://solana-mainnet.quiknode.pro/token/",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":{"value":""},"id":42}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.sol", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "solana_sns_address_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSolanaSNSQuickNodeBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("solana-sns", []string{".sol"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "solana-sns-quicknode",
		URL:  "https://solana-mainnet.quiknode.pro/token/",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"rate limited"},"id":42}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "bonfida.sol", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected JSON-RPC error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_jsonrpc_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestFIOChainAPIBackendMapsHandleToWallet(t *testing.T) {
	plugin := New("fio-handle", []string{".fio"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "fio-chain-api",
		URL:    "https://fio.blockpane.com?chain_code=ETH&token_code=USDT",
		APIKey: "fio-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://fio.blockpane.com/v1/chain/get_pub_address" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer fio-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			for _, want := range []string{`"fio_address":"alice@safu"`, `"chain_code":"ETH"`, `"token_code":"USDT"`} {
				if !strings.Contains(text, want) {
					t.Fatalf("request body missing %q in %s", want, text)
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"public_address":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.SAFU.FIO", QType: "TYPE262"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "fio-handle" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "fio-chain-api" || result.RawRecord["fio_address"] != "alice@safu" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Type != "WALLET" || result.RRSet[0].Value != "eth:usdt 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
}

func TestFIOChainAPIBackendNotFoundReturnsNXDomain(t *testing.T) {
	plugin := New("fio-handle", []string{".fio"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "fio-chain-api",
		URL:  "https://fio.blockpane.com/v1/chain/get_pub_address",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"message":"Public address not found"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.safu.fio", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "fio_public_address_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestFIOChainAPIBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("fio-handle", []string{".fio"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "fio-chain-api",
		URL:  "https://fio.blockpane.com",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"error":"Invalid Chain Code","message":"bad chain_code"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.safu.fio", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected API error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_api_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestOpenAliasDNSTXTBackendMapsRecords(t *testing.T) {
	plugin := New("openalias", []string{".openalias"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "openalias-dns-txt",
		URL:    "https://openalias-dns-adapter.example/txt",
		APIKey: "oa-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://openalias-dns-adapter.example/txt?name=alice.openalias&type=TXT" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer oa-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"records": [
						{"type":"TXT","parts":["oa1:xmr recipient_address=46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em; recipient_name=Monero Development; tx_description=Donation; tx_payment_id=1234abcd;"]},
						{"type":"TXT","value":"v=spf1 -all"}
					]
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.OpenAlias", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "openalias" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "openalias-dns-txt" || result.RawRecord["openalias_domain"] != "alice.openalias" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	values := map[string]bool{}
	for _, rr := range result.RRSet {
		values[rr.Type+" "+rr.Value] = true
	}
	for _, want := range []string{
		"WALLET xmr 46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em",
		"TXT recipient_name=Monero Development",
		"TXT tx_description=Donation",
		"TXT tx_payment_id=1234abcd",
	} {
		if !values[want] {
			t.Fatalf("missing %q in rrset %#v", want, result.RRSet)
		}
	}
}

func TestOpenAliasDNSTXTBackendNoRecordReturnsNXDomain(t *testing.T) {
	plugin := New("openalias", []string{".openalias"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "openalias-dns-txt",
		URL:  "https://openalias-dns-adapter.example/txt",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"txt":["v=spf1 -all"]}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.openalias", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "openalias_record_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestOpenAliasDNSTXTBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("openalias", []string{".openalias"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "openalias-dns-txt",
		URL:  "https://openalias-dns-adapter.example/txt",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`bad gateway`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.openalias", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected backend status error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_status_502" {
		t.Fatalf("result = %#v", result)
	}
}

func TestADAHandleAPIBackendMapsRecords(t *testing.T) {
	plugin := New("ada-handle", []string{".ada"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "ada-handle-api",
		URL:    "https://api.handle.me",
		APIKey: "ada-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://api.handle.me/handles/iog" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer ada-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"handle": "iog",
					"address": "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3wzhf5",
					"display_name": "Input Output",
					"image": "ipfs://bafybeiadahandle"
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "IOG.ADA", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "ada-handle" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "ada-handle-api" || result.RawRecord["ada_handle"] != "iog" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	values := map[string]bool{}
	for _, rr := range result.RRSet {
		values[rr.Type+" "+rr.Value] = true
	}
	for _, want := range []string{
		"WALLET ada addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3wzhf5",
		"TXT handle=iog",
		"TXT display_name=Input Output",
		"URI ipfs://bafybeiadahandle",
	} {
		if !values[want] {
			t.Fatalf("missing %q in rrset %#v", want, result.RRSet)
		}
	}
}

func TestADAHandleAPIBackendNoRecordReturnsNXDomain(t *testing.T) {
	plugin := New("ada-handle", []string{".ada"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "ada-handle-api",
		URL:  "https://api.handle.me",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.ada", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "ada_handle_record_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestADAHandleAPIBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("ada-handle", []string{".ada"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "ada-handle-api",
		URL:  "https://api.handle.me",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`bad gateway`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "iog.ada", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected backend status error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_status_502" {
		t.Fatalf("result = %#v", result)
	}
}

func TestFreenameResolutionAPIBackendMapsRecords(t *testing.T) {
	plugin := New("freename-fns", []string{".fns"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "freename-resolution-api",
		URL:    "https://rslvr.freename.io",
		APIKey: "freename-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://rslvr.freename.io/domain/resolve?q=alice.fns" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer freename-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"host": "alice.fns",
					"network": "POLYGON",
					"tld": "fns",
					"sld": "alice",
					"records": [
						{"key":"token.ETH.0","type":"ETH","value":"0x0000000000000000000000000000000000000001"},
						{"key":"token.BTC.0","type":"BTC","value":"bc1qalice"},
						{"key":"redirect.WEBSITE.0","type":"WEBSITE","value":"example.com"},
						{"key":"record.TXT.0","type":"TXT","value":"hello=world"},
						{"key":"profile.OWNER.0","type":"OWNER","value":"Alice"}
					]
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.FNS", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "freename-fns" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "freename-resolution-api" || result.RawRecord["freename_domain"] != "alice.fns" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	values := map[string]bool{}
	for _, rr := range result.RRSet {
		values[rr.Type+"="+rr.Value] = true
	}
	for _, want := range []string{
		"WALLET=eth 0x0000000000000000000000000000000000000001",
		"WALLET=btc bc1qalice",
		"URI=https://example.com",
		"TXT=hello=world",
		"TXT=owner=Alice",
	} {
		if !values[want] {
			t.Fatalf("missing %q in rrset %#v", want, result.RRSet)
		}
	}
}

func TestFreenameResolutionAPIBackendNoRecordsReturnsNXDomain(t *testing.T) {
	plugin := New("freename-fns", []string{".fns"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "freename-resolution-api",
		URL:  "https://rslvr.freename.io/domain/resolve",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"host":"missing.fns","records":[]}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.fns", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "freename_record_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestFreenameResolutionAPIBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("freename-fns", []string{".fns"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "freename-resolution-api",
		URL:  "https://rslvr.freename.io",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`rate limited`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.fns", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected backend status error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_status_429" {
		t.Fatalf("result = %#v", result)
	}
}

func TestTONCenterV3DNSBackendMapsRecords(t *testing.T) {
	plugin := New("ton-dns", []string{".ton"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "toncenter-v3-dns",
		URL:    "https://toncenter.com",
		APIKey: "ton-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://toncenter.com/api/v3/dns/records?domain=alice.ton" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("X-API-Key") != "ton-secret" {
				t.Fatalf("x-api-key = %q", r.Header.Get("X-API-Key"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"records": [{
						"domain": "alice.ton",
						"dns_wallet": "EQCwallet",
						"dns_site_adnl": "0123456789abcdef",
						"dns_storage_bag_id": "bagid",
						"dns_next_resolver": "EQCresolver",
						"nft_item_address": "EQCnft",
						"nft_item_owner": "EQCowner"
					}]
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.TON", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "ton-dns" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "toncenter-v3-dns" || result.RawRecord["ton_dns_domain"] != "alice.ton" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	values := map[string]bool{}
	for _, rr := range result.RRSet {
		values[rr.Type+" "+rr.Value] = true
	}
	for _, want := range []string{
		"WALLET ton EQCwallet",
		"URI adnl://0123456789abcdef",
		"URI tonstorage://bagid",
		"TXT dns_next_resolver=EQCresolver",
		"TXT nft_item_address=EQCnft",
		"TXT nft_item_owner=EQCowner",
	} {
		if !values[want] {
			t.Fatalf("missing %q in rrset %#v", want, result.RRSet)
		}
	}
}

func TestTONCenterV3DNSBackendNoRecordsReturnsNXDomain(t *testing.T) {
	plugin := New("ton-dns", []string{".ton"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "toncenter-v3-dns",
		URL:  "https://toncenter.com/api/v3/dns/records",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"records":[]}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.ton", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "ton_dns_name_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestTONCenterV3DNSBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("ton-dns", []string{".ton"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "toncenter-v3-dns",
		URL:  "https://toncenter.com",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"code":429,"error":"rate limited"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.ton", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected backend API error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_api_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSuiNSJSONRPCBackendMapsAddressToWallet(t *testing.T) {
	plugin := New("suins", []string{".sui"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "suins-json-rpc",
		URL:    "https://fullnode.mainnet.sui.io:443",
		APIKey: "sui-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://fullnode.mainnet.sui.io:443" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer sui-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			text := string(body)
			for _, want := range []string{`"method":"suix_resolveNameServiceAddress"`, `"alice.sui"`} {
				if !strings.Contains(text, want) {
					t.Fatalf("request body missing %q in %s", want, text)
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":"0x1234567890abcdef","id":"anyns-suins"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.SUI", QType: "TYPE262"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "suins" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "suins-json-rpc" || result.RawRecord["suins_domain"] != "alice.sui" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Type != "WALLET" || result.RRSet[0].Value != "sui 0x1234567890abcdef" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
}

func TestSuiNSJSONRPCBackendNullAddressReturnsNXDomain(t *testing.T) {
	plugin := New("suins", []string{".sui"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "suins-json-rpc",
		URL:  "https://fullnode.mainnet.sui.io:443",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":null,"id":"anyns-suins"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.sui", QType: "WALLET"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "suins_address_not_found" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSuiNSJSONRPCBackendErrorReturnsServFail(t *testing.T) {
	plugin := New("suins", []string{".sui"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "suins-json-rpc",
		URL:  "https://fullnode.mainnet.sui.io:443",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"rate limited"},"id":"anyns-suins"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.sui", QType: "WALLET"})
	if err == nil {
		t.Fatal("expected JSON-RPC error")
	}
	if result.RCode != plugins.RCodeServFail || result.AuditMetadata["reason"] != "backend_jsonrpc_error" {
		t.Fatalf("result = %#v", result)
	}
}

func TestStacksBNSAPIBackendMapsLegacyZonefile(t *testing.T) {
	plugin := New("stacks-bns", []string{".btc", ".stx"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type:   "stacks-bns-api",
		URL:    "https://api.mainnet.hiro.so/v1",
		APIKey: "hiro-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://api.mainnet.hiro.so/v1/names/alice.btc/zonefile" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer hiro-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"zonefile": "$ORIGIN alice.btc\n$TTL 3600\n@ A 203.0.113.88\n@ AAAA 2001:db8::88\n@ TXT \"owner=SP123\"\n_https._tcp URI 10 1 \"https://gaia.example/profile.json\"\n"
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "Alice.BTC", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "stacks-bns" || result.RCode != plugins.RCodeNoError {
		t.Fatalf("result = %#v", result)
	}
	if result.RawRecord["backend"] != "stacks-bns-api" || result.RawRecord["stacks_bns_name"] != "alice.btc" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	want := map[string]bool{
		"A=203.0.113.88": false, "AAAA=2001:db8::88": false,
		"TXT=owner=SP123": false, "URI=https://gaia.example/profile.json": false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if rr.TTL != 3600 {
			t.Fatalf("rr ttl = %d for %#v", rr.TTL, rr)
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestStacksBNSAPIBackendMapsJSONZonefile(t *testing.T) {
	plugin := New("stacks-bns", []string{".btc"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "stacks-bns-api",
		URL:  "https://api.mainnet.hiro.so/v1",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"zonefile": "{\"owner\":\"SP123\",\"website\":\"example.com\",\"btc\":\"bc1qalice\",\"addresses\":[{\"network\":\"eth\",\"address\":\"0x0000000000000000000000000000000000000001\",\"type\":\"wallet\"}],\"meta\":[{\"name\":\"profile\",\"value\":\"alice\"}]}"
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "alice.btc", QType: "ANY"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := map[string]bool{
		"TXT=owner=SP123": false, "TXT=profile=alice": false, "URI=https://example.com": false,
		"WALLET=btc bc1qalice": false, "WALLET=eth 0x0000000000000000000000000000000000000001": false,
	}
	for _, rr := range result.RRSet {
		key := rr.Type + "=" + rr.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing rr %s in %#v", key, result.RRSet)
		}
	}
}

func TestStacksBNSAPIBackendNotFoundReturnsNXDomain(t *testing.T) {
	plugin := New("stacks-bns", []string{".btc"})
	plugin.SetEnabled(true)
	plugin.ConfigureBackend(BackendConfig{
		Type: "stacks-bns-api",
		URL:  "https://api.mainnet.hiro.so/v1",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.btc", QType: "A"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain || result.AuditMetadata["reason"] != "stacks_bns_name_not_found" {
		t.Fatalf("result = %#v", result)
	}
}
