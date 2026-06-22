package hns

import (
	"bytes"
	"context"
	"encoding/binary"
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

func TestResolveWalletAsType262Compatible(t *testing.T) {
	plugin := New()
	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "wallet.hns", QType: "TYPE262"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if result.RCode != plugins.RCodeNoError {
		t.Fatalf("rcode = %s", result.RCode)
	}
	if len(result.RRSet) != 2 {
		t.Fatalf("rr count = %d, want WALLET and TYPE262 compatibility records", len(result.RRSet))
	}
}

func TestResolveMissingNameReturnsNXDomain(t *testing.T) {
	plugin := New()
	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "missing.hns", QType: "A"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain {
		t.Fatalf("rcode = %s, want NXDOMAIN", result.RCode)
	}
}

func TestRemoteBackendResolveUsesRuntimeJSONContract(t *testing.T) {
	plugin := New()
	plugin.ConfigureBackend(BackendConfig{
		URL:            "https://hns-backend.example/resolve",
		APIKey:         "hns-secret",
		RequestTimeout: 250 * time.Millisecond,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.String() != "https://hns-backend.example/resolve" {
				t.Fatalf("url = %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer hns-secret" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			for _, want := range []string{`"plugin":"hns"`, `"qname":"example.hns."`, `"qtype":"A"`, `"trace_id":"hns-remote"`} {
				if !strings.Contains(string(body), want) {
					t.Fatalf("request body missing %q in %s", want, string(body))
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"result": {
						"rrset": [{"name":"example.hns.","type":"A","ttl":120,"value":"198.51.100.10"}],
						"rcode": "NOERROR",
						"ttl": 120,
						"confidence": "hns-remote"
					}
				}`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{
		QName: "Example.HNS",
		QType: "a",
		Context: plugins.QueryContext{
			TraceID: "hns-remote",
			Tenant:  "default",
		},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.SourcePlugin != "hns" || result.RCode != plugins.RCodeNoError || result.TTL != 120 {
		t.Fatalf("result = %#v", result)
	}
	if len(result.RRSet) != 1 || result.RRSet[0].Value != "198.51.100.10" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
	if result.RawRecord["backend"] != "remote-http" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
}

func TestRemoteBackendStatusFailureReturnsServFail(t *testing.T) {
	plugin := New()
	plugin.ConfigureBackend(BackendConfig{
		URL: "https://hns-backend.example/resolve",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`bad gateway`)),
			}, nil
		})},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "example.hns", QType: "A"})
	if err == nil {
		t.Fatalf("expected backend error")
	}
	if result.RCode != plugins.RCodeServFail || result.SourcePlugin != "hns" {
		t.Fatalf("result = %#v", result)
	}
	if result.AuditMetadata["reason"] != "backend_status_502" {
		t.Fatalf("audit metadata = %#v", result.AuditMetadata)
	}
}

func TestDNSBackendAddressDefaultsPort(t *testing.T) {
	addr, err := dnsBackendAddress("dns://127.0.0.1")
	if err != nil {
		t.Fatalf("dns backend address: %v", err)
	}
	if addr != "127.0.0.1:53" {
		t.Fatalf("addr = %q", addr)
	}
	addr, err = dnsBackendAddress("dns://[::1]:5350")
	if err != nil {
		t.Fatalf("dns backend ipv6 address: %v", err)
	}
	if addr != "[::1]:5350" {
		t.Fatalf("ipv6 addr = %q", addr)
	}
}

func TestDNSBackendQNameTranslation(t *testing.T) {
	tests := map[string]string{
		"example.hns":           "example.",
		"www.example.hns.":      "www.example.",
		"_443._tcp.example.hns": "_443._tcp.example.",
		"example.hsd":           "example.",
		"example":               "example.",
		"灵.hns":                 "xn--5nx.",
	}
	for input, want := range tests {
		got, err := hnsDNSBackendQName(input)
		if err != nil {
			t.Fatalf("hnsDNSBackendQName(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("hnsDNSBackendQName(%q) = %q, want %q", input, got, want)
		}
	}
	if got := restoreHNSDNSAnswerName("www.example.", "example.", "example.hns."); got != "www.example.hns." {
		t.Fatalf("restored answer = %q", got)
	}
}

func TestDNSBackendQNameRejectsMalformedRootLabels(t *testing.T) {
	for _, input := range []string{
		"bad/name.hns",
		`bad\name.hns`,
		"bad%2fname.hns",
		"bad;name.hns",
		"bad\"name.hns",
		"*.hns",
		"-example.hns",
		"example-.hns",
		"www.bad/name.hns",
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := hnsDNSBackendQName(input); err == nil {
				t.Fatalf("hnsDNSBackendQName(%q) = %q, want error", input, got)
			}
		})
	}
}

func TestDNSBackendResolveRejectsMalformedRootLabelBeforeExchange(t *testing.T) {
	called := false
	plugin := New()
	plugin.ConfigureBackend(BackendConfig{
		URL: "dns://127.0.0.1:5350",
		DNSExchange: func(context.Context, string, []byte, uint16) ([]byte, string, error) {
			called = true
			return nil, "", nil
		},
	})
	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "bad/name.hns", QType: "A"})
	if err == nil {
		t.Fatalf("expected malformed HNS backend query to fail")
	}
	if called {
		t.Fatalf("malformed HNS backend query reached DNS exchange")
	}
	if result.RCode != plugins.RCodeServFail ||
		result.SourcePlugin != "hns" ||
		result.AuditMetadata["reason"] != "dns_query_name_invalid" {
		t.Fatalf("result = %#v", result)
	}
}

func TestDNSBackendFallsBackToTCPOnTruncatedUDP(t *testing.T) {
	plugin := New()
	calls := []string{}
	plugin.ConfigureBackend(BackendConfig{
		URL: "dns://127.0.0.1:5350",
		DNSExchange: func(ctx context.Context, address string, packet []byte, wantID uint16) ([]byte, string, error) {
			if address != "127.0.0.1:5350" {
				t.Fatalf("address = %q", address)
			}
			return exchangeDNSWith(ctx, address, packet, wantID,
				func(_ context.Context, _ string, _ []byte) ([]byte, error) {
					calls = append(calls, "udp")
					truncated := dnsResponsePacket(t, wantID, "example.", nil)
					truncated[2] = truncated[2] | 0x02
					if !dnsResponseTruncated(truncated, wantID) {
						t.Fatalf("expected truncated helper to detect TC bit")
					}
					return truncated, nil
				},
				func(_ context.Context, _ string, _ []byte) ([]byte, error) {
					calls = append(calls, "tcp")
					return dnsResponsePacket(t, wantID, "example.", []dnsAnswer{
						{name: "example.", typ: 1, ttl: 90, rdata: []byte{198, 51, 100, 42}},
					}), nil
				},
			)
		},
	})

	result, err := plugin.Resolve(context.Background(), plugins.ResolveRequest{QName: "example.hns", QType: "A"})
	if err != nil {
		t.Fatalf("resolve dns backend: %v", err)
	}
	if result.RCode != plugins.RCodeNoError || len(result.RRSet) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if result.RRSet[0].Value != "198.51.100.42" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
	if result.RRSet[0].Name != "example.hns." {
		t.Fatalf("rr name = %q", result.RRSet[0].Name)
	}
	if result.RawRecord["backend_transport"] != "tcp" {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if result.RawRecord["backend_query_name"] != "example." {
		t.Fatalf("raw record = %#v", result.RawRecord)
	}
	if strings.Join(calls, ",") != "udp,tcp" {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestParseDNSResponseMapsHNSDNSAnswers(t *testing.T) {
	packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
		{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		{name: "example.hns.", typ: 16, ttl: 180, rdata: append([]byte{11}, []byte("hello-world")...)},
	})
	result, err := parseDNSResponse(packet, 0x1234, "example.hns.", time.Now())
	if err != nil {
		t.Fatalf("parse dns response: %v", err)
	}
	if result.RCode != plugins.RCodeNoError || result.TTL != 120 {
		t.Fatalf("result = %#v", result)
	}
	if len(result.RRSet) != 2 {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
	if result.RRSet[0].Type != "A" || result.RRSet[0].Value != "198.51.100.10" {
		t.Fatalf("a record = %#v", result.RRSet[0])
	}
	if result.RRSet[1].Type != "TXT" || result.RRSet[1].Value != "hello-world" {
		t.Fatalf("txt record = %#v", result.RRSet[1])
	}
}

func TestParseDNSResponseMapsNXDomain(t *testing.T) {
	packet := dnsResponsePacket(t, 0x1234, "missing.hns.", nil)
	packet[3] = packet[3] | 3
	result, err := parseDNSResponse(packet, 0x1234, "missing.hns.", time.Now())
	if err != nil {
		t.Fatalf("parse nxdomain: %v", err)
	}
	if result.RCode != plugins.RCodeNXDomain {
		t.Fatalf("result = %#v", result)
	}
	if result.AuditMetadata["reason"] != "dns_backend_nxdomain" {
		t.Fatalf("audit = %#v", result.AuditMetadata)
	}
}

func TestFormatRDATAFormatsDNSKEYAndTLSA(t *testing.T) {
	dnskey, ok := formatRDATA(nil, 0, []byte{0x01, 0x01, 0x03, 0x0d, 0x01, 0x02, 0x03}, 48)
	if !ok || dnskey != "257 3 13 AQID" {
		t.Fatalf("DNSKEY=%q ok=%v", dnskey, ok)
	}
	tlsa, ok := formatRDATA(nil, 0, append([]byte{3, 1, 1}, make([]byte, 32)...), 52)
	if !ok || tlsa != "3 1 1 "+strings.Repeat("00", 32) {
		t.Fatalf("TLSA=%q ok=%v", tlsa, ok)
	}
}

type dnsAnswer struct {
	name  string
	typ   uint16
	ttl   uint32
	rdata []byte
}

func dnsResponsePacket(t *testing.T, id uint16, qname string, answers []dnsAnswer) []byte {
	t.Helper()
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, id)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x8180))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(answers)))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	if err := writeDNSName(&buf, qname); err != nil {
		t.Fatalf("write qname: %v", err)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	for _, answer := range answers {
		if err := writeDNSName(&buf, answer.name); err != nil {
			t.Fatalf("write answer name: %v", err)
		}
		_ = binary.Write(&buf, binary.BigEndian, answer.typ)
		_ = binary.Write(&buf, binary.BigEndian, uint16(1))
		_ = binary.Write(&buf, binary.BigEndian, answer.ttl)
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(answer.rdata)))
		buf.Write(answer.rdata)
	}
	return buf.Bytes()
}
