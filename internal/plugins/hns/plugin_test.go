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
	result, err := parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
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
	result, err := parseDNSResponse(packet, 0x1234, "missing.hns.", 1, time.Now())
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

func TestParseDNSResponseRejectsNonResponseAndQuestionMismatch(t *testing.T) {
	t.Run("non-response packet", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", nil)
		packet[2] &^= 0x80
		_, err := parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "DNS packet is not a response") {
			t.Fatalf("parse err = %v, want non-response error", err)
		}
	})

	t.Run("question name mismatch", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "evil.hns.", []dnsAnswer{
			{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		})
		_, err := parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "DNS question name mismatch") {
			t.Fatalf("parse err = %v, want question mismatch error", err)
		}
	})
}

func TestParseDNSResponseRejectsQuestionCountAndClassMismatch(t *testing.T) {
	t.Run("zero questions", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
			{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		})
		binary.BigEndian.PutUint16(packet[4:6], 0)
		_, err := parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "DNS response question count mismatch") {
			t.Fatalf("parse err = %v, want question count mismatch", err)
		}
	})

	t.Run("multiple questions", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", nil)
		binary.BigEndian.PutUint16(packet[4:6], 2)
		_, err := parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "DNS response question count mismatch") {
			t.Fatalf("parse err = %v, want question count mismatch", err)
		}
	})

	t.Run("question class mismatch", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", nil)
		_, questionEnd, err := readDNSName(packet, 12)
		if err != nil {
			t.Fatalf("read question: %v", err)
		}
		binary.BigEndian.PutUint16(packet[questionEnd+2:questionEnd+4], 3)
		_, err = parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "DNS question class mismatch") {
			t.Fatalf("parse err = %v, want question class mismatch", err)
		}
	})

	t.Run("question type mismatch", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", nil)
		_, questionEnd, err := readDNSName(packet, 12)
		if err != nil {
			t.Fatalf("read question: %v", err)
		}
		binary.BigEndian.PutUint16(packet[questionEnd:questionEnd+2], 28)
		_, err = parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "DNS question type mismatch") {
			t.Fatalf("parse err = %v, want question type mismatch", err)
		}
	})
}

func TestParseDNSResponseFiltersUnrelatedAnswerNames(t *testing.T) {
	packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
		{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		{name: "evil.hns.", typ: 1, ttl: 30, rdata: []byte{203, 0, 113, 66}},
	})
	result, err := parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
	if err != nil {
		t.Fatalf("parse dns response: %v", err)
	}
	if len(result.RRSet) != 1 {
		t.Fatalf("rrset = %#v, want only matching answer", result.RRSet)
	}
	if result.RRSet[0].Name != "example.hns." || result.RRSet[0].Value != "198.51.100.10" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
	if result.TTL != 120 {
		t.Fatalf("ttl = %d, want matching answer ttl", result.TTL)
	}
}

func TestParseDNSResponseSkipsNameRDATAThatExceedsRDLength(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x1234))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x8180))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(2))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	if err := writeDNSName(&buf, "example.hns."); err != nil {
		t.Fatalf("write question: %v", err)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))

	if err := writeDNSName(&buf, "example.hns."); err != nil {
		t.Fatalf("write cname owner: %v", err)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint16(5))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint32(30))
	_ = binary.Write(&buf, binary.BigEndian, uint16(2))
	buf.Write([]byte{1, 'x'})

	if err := writeDNSName(&buf, "example.hns."); err != nil {
		t.Fatalf("write a owner: %v", err)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint32(120))
	_ = binary.Write(&buf, binary.BigEndian, uint16(4))
	buf.Write([]byte{198, 51, 100, 10})

	result, err := parseDNSResponse(buf.Bytes(), 0x1234, "example.hns.", 1, time.Now())
	if err != nil {
		t.Fatalf("parse dns response: %v", err)
	}
	if len(result.RRSet) != 1 {
		t.Fatalf("rrset = %#v, want malformed CNAME skipped", result.RRSet)
	}
	if result.RRSet[0].Type != "A" || result.RRSet[0].Value != "198.51.100.10" {
		t.Fatalf("rrset = %#v", result.RRSet)
	}
}

func TestParseDNSResponseValidatesAuthorityAndAdditionalSections(t *testing.T) {
	t.Run("valid additional ignored", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
			{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		})
		binary.BigEndian.PutUint16(packet[10:12], 1)
		var buf bytes.Buffer
		buf.Write(packet)
		if err := writeDNSName(&buf, "ns.example.hns."); err != nil {
			t.Fatalf("write additional owner: %v", err)
		}
		_ = binary.Write(&buf, binary.BigEndian, uint16(1))
		_ = binary.Write(&buf, binary.BigEndian, uint16(1))
		_ = binary.Write(&buf, binary.BigEndian, uint32(60))
		_ = binary.Write(&buf, binary.BigEndian, uint16(4))
		buf.Write([]byte{203, 0, 113, 53})

		result, err := parseDNSResponse(buf.Bytes(), 0x1234, "example.hns.", 1, time.Now())
		if err != nil {
			t.Fatalf("parse dns response: %v", err)
		}
		if len(result.RRSet) != 1 || result.RRSet[0].Value != "198.51.100.10" {
			t.Fatalf("rrset = %#v", result.RRSet)
		}
	})

	t.Run("short additional header", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
			{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		})
		binary.BigEndian.PutUint16(packet[10:12], 1)
		var buf bytes.Buffer
		buf.Write(packet)
		if err := writeDNSName(&buf, "ns.example.hns."); err != nil {
			t.Fatalf("write additional owner: %v", err)
		}

		_, err := parseDNSResponse(buf.Bytes(), 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "short DNS RR header") {
			t.Fatalf("parse err = %v, want short DNS RR header", err)
		}
	})

	t.Run("short authority rdata", func(t *testing.T) {
		packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
			{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
		})
		binary.BigEndian.PutUint16(packet[8:10], 1)
		var buf bytes.Buffer
		buf.Write(packet)
		if err := writeDNSName(&buf, "ns.example.hns."); err != nil {
			t.Fatalf("write authority owner: %v", err)
		}
		_ = binary.Write(&buf, binary.BigEndian, uint16(1))
		_ = binary.Write(&buf, binary.BigEndian, uint16(1))
		_ = binary.Write(&buf, binary.BigEndian, uint32(60))
		_ = binary.Write(&buf, binary.BigEndian, uint16(4))
		buf.Write([]byte{203, 0})

		_, err := parseDNSResponse(buf.Bytes(), 0x1234, "example.hns.", 1, time.Now())
		if err == nil || !strings.Contains(err.Error(), "short DNS RDATA") {
			t.Fatalf("parse err = %v, want short DNS RDATA", err)
		}
	})
}

func TestBuildDNSQueryRejectsOverlongQName(t *testing.T) {
	label := strings.Repeat("a", 63)
	overlongName := strings.Join([]string{label, label, label, label}, ".") + "."
	if _, _, err := buildDNSQuery(overlongName, 1); err == nil {
		t.Fatal("build overlong qname succeeded, want error")
	}
}

func TestParseDNSResponseRejectsMalformedCompressedNames(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func([]byte, int) []byte
		wantErr string
	}{
		{
			name: "compression pointer loop",
			mutate: func(packet []byte, answerOffset int) []byte {
				packet[answerOffset] = 0xc0
				packet[answerOffset+1] = byte(answerOffset)
				return packet
			},
			wantErr: "DNS compression pointer loop",
		},
		{
			name: "compression pointer out of range",
			mutate: func(packet []byte, answerOffset int) []byte {
				packet[answerOffset] = 0xc0
				packet[answerOffset+1] = 0xff
				return packet
			},
			wantErr: "DNS compression pointer out of range",
		},
		{
			name: "short compression pointer",
			mutate: func(packet []byte, answerOffset int) []byte {
				packet[answerOffset] = 0xc0
				return packet[:answerOffset+1]
			},
			wantErr: "short DNS compression pointer",
		},
		{
			name: "unsupported label encoding",
			mutate: func(packet []byte, answerOffset int) []byte {
				packet[answerOffset] = 0x40
				return packet
			},
			wantErr: "unsupported DNS label encoding",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packet := dnsResponsePacket(t, 0x1234, "example.hns.", []dnsAnswer{
				{name: "example.hns.", typ: 1, ttl: 120, rdata: []byte{198, 51, 100, 10}},
			})
			_, questionEnd, err := readDNSName(packet, 12)
			if err != nil {
				t.Fatalf("read question: %v", err)
			}
			answerOffset := questionEnd + 4
			packet = tc.mutate(packet, answerOffset)
			_, err = parseDNSResponse(packet, 0x1234, "example.hns.", 1, time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parse err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseDNSResponseRejectsOverlongExpandedName(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x1234))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x8180))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	if err := writeDNSName(&buf, "example.hns."); err != nil {
		t.Fatalf("write question: %v", err)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	for i := 0; i < 4; i++ {
		buf.WriteByte(63)
		buf.WriteString(strings.Repeat("a", 63))
	}
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint32(60))
	_ = binary.Write(&buf, binary.BigEndian, uint16(4))
	buf.Write([]byte{198, 51, 100, 10})

	_, err := parseDNSResponse(buf.Bytes(), 0x1234, "example.hns.", 1, time.Now())
	if err == nil || !strings.Contains(err.Error(), "DNS name too long") {
		t.Fatalf("parse overlong name err = %v, want DNS name too long", err)
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
