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
