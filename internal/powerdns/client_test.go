package powerdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/config"
)

func TestSnapshotReadsBothPowerDNSServices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			t.Fatalf("missing API key for %s", r.URL.Path)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/statistics"):
			_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "questions", "type": "StatisticItem", "value": "42"}})
		case strings.HasSuffix(r.URL.Path, "/config"):
			_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "webserver", "type": "ConfigSetting", "value": "yes"}})
		case strings.HasSuffix(r.URL.Path, "/zones"):
			_ = json.NewEncoder(w).Encode([]Zone{{ID: "example.org.", Name: "example.org.", Kind: "Native", DNSSEC: true}})
		default:
			_ = json.NewEncoder(w).Encode(Server{ID: "localhost", DaemonType: "authoritative", Version: "5.0.5"})
		}
	}))
	defer server.Close()

	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	cfg.AuthoritativeAPIKey = "secret"
	cfg.RecursorURL = server.URL
	cfg.RecursorAPIKey = "secret"
	client := NewWithHTTPClient(cfg, server.Client())

	snapshot := client.Snapshot(context.Background())
	if !snapshot.Authoritative.Healthy || !snapshot.Recursor.Healthy {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if len(snapshot.Authoritative.Zones) != 1 || snapshot.Authoritative.Zones[0].Name != "example.org." {
		t.Fatalf("authoritative zones = %#v", snapshot.Authoritative.Zones)
	}
	if snapshot.Recursor.Statistics["questions"] != "42" {
		t.Fatalf("recursor statistics = %#v", snapshot.Recursor.Statistics)
	}
}

func TestCreateDeleteZoneAndFlushCache(t *testing.T) {
	var created CreateZoneRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/zones"):
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatalf("decode create zone: %v", err)
			}
			_ = json.NewEncoder(w).Encode(Zone{ID: created.Name, Name: created.Name, Kind: created.Kind})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/cache/flush"):
			if r.URL.Query().Get("domain") != "example.org." || r.URL.Query().Get("subtree") != "true" {
				t.Fatalf("flush query = %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(CacheFlushResult{Count: 3, Result: "Flushed cache"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	cfg.RecursorURL = server.URL
	cfg.RequestTimeout = time.Second
	client := NewWithHTTPClient(cfg, server.Client())

	zone, err := client.CreateAuthoritativeZone(context.Background(), CreateZoneRequest{Name: "example.org", Nameservers: []string{"ns1.example.org."}})
	if err != nil {
		t.Fatalf("create zone: %v", err)
	}
	if zone.Name != "example.org." || created.Kind != "Native" {
		t.Fatalf("zone=%#v request=%#v", zone, created)
	}
	if err := client.DeleteAuthoritativeZone(context.Background(), zone.ID); err != nil {
		t.Fatalf("delete zone: %v", err)
	}
	result, err := client.FlushRecursorCache(context.Background(), "example.org", true)
	if err != nil || result.Count != 3 {
		t.Fatalf("flush result=%#v err=%v", result, err)
	}
}

func TestCreateUnicodeHNSZoneInitializesSOAAndGlue(t *testing.T) {
	var created powerDNSCreateZoneRequest
	var patched PatchZoneRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatalf("decode create zone: %v", err)
			}
			_ = json.NewEncoder(w).Encode(Zone{ID: created.Name, Name: created.Name, Kind: created.Kind})
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatalf("decode patch zone: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	client := NewWithHTTPClient(cfg, server.Client())
	zone, err := client.CreateAuthoritativeZone(context.Background(), CreateZoneRequest{
		Name:     "灵.hns",
		HNS:      true,
		GlueIPv4: "192.0.2.53",
		SOA: &SOAConfig{
			TTL:     600,
			Refresh: 7200,
		},
	})
	if err != nil {
		t.Fatalf("create Unicode HNS zone: %v", err)
	}
	if created.Name != "xn--5nx." || len(created.Nameservers) != 1 || created.Nameservers[0] != "ns1.xn--5nx." {
		t.Fatalf("created=%#v", created)
	}
	if zone.UnicodeName != "灵." {
		t.Fatalf("zone=%#v", zone)
	}
	if len(patched.RRSets) != 3 {
		t.Fatalf("patched=%#v", patched)
	}
	rrsets := map[string]RRSet{}
	for _, rrset := range patched.RRSets {
		rrsets[rrset.Type] = rrset
	}
	if rrsets["SOA"].TTL != 600 ||
		!strings.HasPrefix(rrsets["SOA"].Records[0].Content, "ns1.xn--5nx. hostmaster.xn--5nx.") ||
		!strings.Contains(rrsets["SOA"].Records[0].Content, " 7200 600 86400 300") {
		t.Fatalf("SOA=%#v", rrsets["SOA"])
	}
	if rrsets["NS"].Records[0].Content != "ns1.xn--5nx." {
		t.Fatalf("NS=%#v", rrsets["NS"])
	}
	if rrsets["A"].Name != "ns1.xn--5nx." || rrsets["A"].Records[0].Content != "192.0.2.53" {
		t.Fatalf("A=%#v", rrsets["A"])
	}
}

func TestReadAndPatchAuthoritativeZone(t *testing.T) {
	var patched PatchZoneRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(Zone{
				ID:   "example.",
				Name: "example.",
				RRSets: []RRSet{{
					Name: "www.example.",
					Type: "A",
					TTL:  300,
					Records: []Record{{
						Content: "192.0.2.10",
					}},
				}},
			})
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatalf("decode patch: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	client := NewWithHTTPClient(cfg, server.Client())

	zone, err := client.AuthoritativeZone(context.Background(), "example")
	if err != nil || len(zone.RRSets) != 1 {
		t.Fatalf("zone=%#v err=%v", zone, err)
	}
	err = client.PatchAuthoritativeZone(context.Background(), "example", PatchZoneRequest{
		RRSets: []RRSet{{
			Name:       "www.example",
			Type:       "a",
			ChangeType: "replace",
			Records:    []Record{{Content: " 192.0.2.20 "}},
		}},
	})
	if err != nil {
		t.Fatalf("patch zone: %v", err)
	}
	if patched.RRSets[0].Name != "www.example." ||
		patched.RRSets[0].Type != "A" ||
		patched.RRSets[0].ChangeType != "REPLACE" ||
		patched.RRSets[0].TTL != 300 ||
		patched.RRSets[0].Records[0].Content != "192.0.2.20" {
		t.Fatalf("patched=%#v", patched)
	}
}

func TestUpdateAuthoritativeSOAIncrementsSerialAndValidates(t *testing.T) {
	var patched PatchZoneRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(Zone{
				ID:   "example.",
				Name: "example.",
				RRSets: []RRSet{{
					Name: "example.",
					Type: "SOA",
					TTL:  300,
					Records: []Record{{
						Content: "ns1.example. hostmaster.example. 42 3600 600 86400 300",
					}},
				}},
			})
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
				t.Fatalf("decode patch: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	client := NewWithHTTPClient(cfg, server.Client())

	soa, err := client.UpdateAuthoritativeSOA(context.Background(), "example.", SOAConfig{Refresh: 7200})
	if err != nil {
		t.Fatalf("update SOA: %v", err)
	}
	if soa.Serial != 43 || soa.Refresh != 7200 {
		t.Fatalf("soa=%#v", soa)
	}
	if len(patched.RRSets) != 1 ||
		patched.RRSets[0].Name != "example." ||
		patched.RRSets[0].Type != "SOA" ||
		patched.RRSets[0].Records[0].Content != "ns1.example. hostmaster.example. 43 7200 600 86400 300" {
		t.Fatalf("patched=%#v", patched)
	}

	if _, err := client.UpdateAuthoritativeSOA(context.Background(), "example.", SOAConfig{Serial: 42}); !IsValidationError(err) {
		t.Fatalf("expected validation error for serial rollback, got %v", err)
	}
	if _, err := client.UpdateAuthoritativeSOA(context.Background(), "example.", SOAConfig{Retry: 1}); !IsValidationError(err) {
		t.Fatalf("expected validation error for retry boundary, got %v", err)
	}
}

func TestPatchAuthoritativeZoneNormalizesUnicodeOwnerAndTarget(t *testing.T) {
	var patched PatchZoneRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
			t.Fatalf("decode patch: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	client := NewWithHTTPClient(cfg, server.Client())
	err := client.PatchAuthoritativeZone(context.Background(), "灵", PatchZoneRequest{
		RRSets: []RRSet{{
			Name:       "钱包.灵",
			Type:       "CNAME",
			ChangeType: "REPLACE",
			Records:    []Record{{Content: "目标.灵"}},
		}},
	})
	if err != nil {
		t.Fatalf("patch Unicode zone: %v", err)
	}
	if patched.RRSets[0].Name != "xn--uir314m.xn--5nx." ||
		patched.RRSets[0].Records[0].Content != "xn--iwvq54a.xn--5nx." {
		t.Fatalf("patched=%#v", patched)
	}
}

func TestPatchAuthoritativeZoneRejectsOutOfZoneRecords(t *testing.T) {
	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = "http://powerdns.invalid"
	client := New(cfg)
	err := client.PatchAuthoritativeZone(context.Background(), "example", PatchZoneRequest{
		RRSets: []RRSet{{
			Name:       "outside.test",
			Type:       "A",
			ChangeType: "REPLACE",
			Records:    []Record{{Content: "192.0.2.20"}},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "inside zone") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateHNSZoneRejectsMultipleLabels(t *testing.T) {
	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = "http://powerdns.invalid"
	client := New(cfg)
	_, err := client.CreateAuthoritativeZone(context.Background(), CreateZoneRequest{Name: "www.灵", HNS: true})
	if err == nil || !IsValidationError(err) || !strings.Contains(err.Error(), "single top-level label") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateHNSZoneRejectsMalformedTopLevelLabels(t *testing.T) {
	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = "http://powerdns.invalid"
	client := New(cfg)
	for _, input := range []string{
		"_service",
		"bad/name",
		`bad\name`,
		"bad%2fname",
		"bad;name",
		"bad\"name",
		"*",
		"-example",
		"example-",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := client.CreateAuthoritativeZone(context.Background(), CreateZoneRequest{Name: input, HNS: true})
			if err == nil || !IsValidationError(err) {
				t.Fatalf("CreateAuthoritativeZone(%q) err=%v", input, err)
			}
		})
	}
}

func TestPatchAuthoritativeZoneValidatesDNSSECDANEAndCAARecords(t *testing.T) {
	var patched PatchZoneRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	client := NewWithHTTPClient(cfg, server.Client())
	err := client.PatchAuthoritativeZone(context.Background(), "example.", PatchZoneRequest{RRSets: []RRSet{
		{Name: "example.", Type: "DS", ChangeType: "REPLACE", Records: []Record{{Content: "12345 13 2 " + strings.Repeat("ab", 32)}}},
		{Name: "example.", Type: "DNSKEY", ChangeType: "REPLACE", Records: []Record{{Content: "257 3 13 AQIDBA=="}}},
		{Name: "_443._tcp.example.", Type: "TLSA", ChangeType: "REPLACE", Records: []Record{{Content: "3 1 1 " + strings.Repeat("cd", 32)}}},
		{Name: "example.", Type: "CAA", ChangeType: "REPLACE", Records: []Record{{Content: `0 ISSUE "letsencrypt.org"`}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if patched.RRSets[0].Records[0].Content != "12345 13 2 "+strings.Repeat("AB", 32) {
		t.Fatalf("DS=%q", patched.RRSets[0].Records[0].Content)
	}
	if patched.RRSets[3].Records[0].Content != `0 issue "letsencrypt.org"` {
		t.Fatalf("CAA=%q", patched.RRSets[3].Records[0].Content)
	}

	err = client.PatchAuthoritativeZone(context.Background(), "example.", PatchZoneRequest{RRSets: []RRSet{{
		Name: "_443._tcp.example.", Type: "TLSA", ChangeType: "REPLACE",
		Records: []Record{{Content: "3 1 1 ABCD"}},
	}}})
	if err == nil || !IsValidationError(err) {
		t.Fatalf("malformed TLSA err=%v", err)
	}
}

func TestPatchAuthoritativeZoneRejectsUnsafeRRSetMutations(t *testing.T) {
	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = "http://powerdns.invalid"
	client := New(cfg)
	tests := []struct {
		name   string
		rrset  RRSet
		errMsg string
	}{
		{
			name: "dnskey child owner",
			rrset: RRSet{
				Name:       "child.example.",
				Type:       "DNSKEY",
				ChangeType: "REPLACE",
				Records:    []Record{{Content: "257 3 13 AQIDBA=="}},
			},
			errMsg: "zone apex",
		},
		{
			name: "tlsa missing underscores",
			rrset: RRSet{
				Name:       "443.tcp.example.",
				Type:       "TLSA",
				ChangeType: "REPLACE",
				Records:    []Record{{Content: "3 1 1 " + strings.Repeat("AB", 32)}},
			},
			errMsg: "port label",
		},
		{
			name: "tlsa unsupported protocol",
			rrset: RRSet{
				Name:       "_443._ftp.example.",
				Type:       "TLSA",
				ChangeType: "REPLACE",
				Records:    []Record{{Content: "3 1 1 " + strings.Repeat("AB", 32)}},
			},
			errMsg: "protocol label",
		},
		{
			name: "tlsa invalid port",
			rrset: RRSet{
				Name:       "_0._tcp.example.",
				Type:       "TLSA",
				ChangeType: "REPLACE",
				Records:    []Record{{Content: "3 1 1 " + strings.Repeat("AB", 32)}},
			},
			errMsg: "port label",
		},
		{
			name: "literal newline injection",
			rrset: RRSet{
				Name:       "example.",
				Type:       "TXT",
				ChangeType: "REPLACE",
				Records:    []Record{{Content: "\"ok\"\nmalicious.example. 300 IN A 192.0.2.1"}},
			},
			errMsg: "control characters",
		},
		{
			name: "oversized content",
			rrset: RRSet{
				Name:       "example.",
				Type:       "TXT",
				ChangeType: "REPLACE",
				Records:    []Record{{Content: strings.Repeat("A", maxRecordContentLength+1)}},
			},
			errMsg: "exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.PatchAuthoritativeZone(context.Background(), "example.", PatchZoneRequest{RRSets: []RRSet{tt.rrset}})
			if err == nil || !IsValidationError(err) || !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("PatchAuthoritativeZone err=%v, want validation containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestAuthoritativeCryptoKeyLifecycle(t *testing.T) {
	var created CreateCryptoKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode([]CryptoKey{{ID: 7, KeyType: "csk", Active: true, Published: true, DS: []string{"12345 13 2 ABCD"}}})
		case http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(CryptoKey{ID: 8, KeyType: created.KeyType, Active: created.Active, Published: created.Published})
		case http.MethodDelete:
			if !strings.HasSuffix(r.URL.Path, "/cryptokeys/8") {
				t.Fatalf("delete path=%s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	cfg := config.Default().PowerDNS
	cfg.AuthoritativeURL = server.URL
	client := NewWithHTTPClient(cfg, server.Client())
	keys, err := client.AuthoritativeCryptoKeys(context.Background(), "example")
	if err != nil || len(keys) != 1 || keys[0].ID != 7 {
		t.Fatalf("keys=%+v err=%v", keys, err)
	}
	key, err := client.CreateAuthoritativeCryptoKey(context.Background(), "example", CreateCryptoKeyRequest{Active: true, Published: true})
	if err != nil || key.ID != 8 || created.KeyType != "csk" {
		t.Fatalf("key=%+v request=%+v err=%v", key, created, err)
	}
	if err := client.DeleteAuthoritativeCryptoKey(context.Background(), "example", 8); err != nil {
		t.Fatal(err)
	}
}

func TestDeriveDSFromDNSKEY(t *testing.T) {
	ds, err := DeriveDS(
		"example.",
		"257 3 13 m5OSnKq7UTi6UjJ6pZcE2P1pHW0RrQ5P4P6xQmJ3Y7n8jP1wM2xL6Wf4dYt5Yq5xVhQm1qgA2v8Qm3pP7Q==",
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(ds)
	if len(fields) != 4 || fields[2] != "2" || len(fields[3]) != 64 {
		t.Fatalf("DS=%q", ds)
	}
}
