package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/config"
)

type Client struct {
	cfg        config.PowerDNSConfig
	httpClient *http.Client
}

type Server struct {
	ID         string `json:"id"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
	URL        string `json:"url"`
	ZonesURL   string `json:"zones_url"`
	ConfigURL  string `json:"config_url"`
}

type Zone struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	DNSSEC         bool     `json:"dnssec"`
	Serial         uint32   `json:"serial"`
	NotifiedSerial uint32   `json:"notified_serial"`
	LastCheck      int64    `json:"last_check"`
	Masters        []string `json:"masters"`
	Account        string   `json:"account"`
	URL            string   `json:"url"`
	RRSets         []RRSet  `json:"rrsets,omitempty"`
}

type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type Comment struct {
	Content    string `json:"content"`
	Account    string `json:"account,omitempty"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

type RRSet struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	TTL        uint32    `json:"ttl,omitempty"`
	ChangeType string    `json:"changetype,omitempty"`
	Records    []Record  `json:"records,omitempty"`
	Comments   []Comment `json:"comments,omitempty"`
}

type PatchZoneRequest struct {
	RRSets []RRSet `json:"rrsets"`
}

type ServiceSnapshot struct {
	Configured bool           `json:"configured"`
	Healthy    bool           `json:"healthy"`
	URL        string         `json:"url,omitempty"`
	Server     *Server        `json:"server,omitempty"`
	Zones      []Zone         `json:"zones"`
	Statistics map[string]any `json:"statistics"`
	Config     []any          `json:"config,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type Snapshot struct {
	Authoritative ServiceSnapshot `json:"authoritative"`
	Recursor      ServiceSnapshot `json:"recursor"`
}

type CreateZoneRequest struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Nameservers []string `json:"nameservers,omitempty"`
	Masters     []string `json:"masters,omitempty"`
	DNSSEC      bool     `json:"dnssec,omitempty"`
}

type CacheFlushResult struct {
	Count  int    `json:"count"`
	Result string `json:"result,omitempty"`
}

func New(cfg config.PowerDNSConfig) *Client {
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: timeout},
	}
}

func NewWithHTTPClient(cfg config.PowerDNSConfig, client *http.Client) *Client {
	out := New(cfg)
	if client != nil {
		out.httpClient = client
	}
	return out
}

func (c *Client) Snapshot(ctx context.Context) Snapshot {
	return Snapshot{
		Authoritative: c.serviceSnapshot(ctx, "authoritative"),
		Recursor:      c.serviceSnapshot(ctx, "recursor"),
	}
}

func (c *Client) Zones(ctx context.Context, service string) ([]Zone, error) {
	var zones []Zone
	err := c.doJSON(ctx, service, http.MethodGet, c.serverPath(service, "/zones"), nil, &zones)
	return zones, err
}

func (c *Client) CreateAuthoritativeZone(ctx context.Context, request CreateZoneRequest) (Zone, error) {
	request.Name = normalizeZoneName(request.Name)
	if request.Name == "." || strings.TrimSpace(request.Name) == "" {
		return Zone{}, fmt.Errorf("zone name is required")
	}
	if request.Kind == "" {
		request.Kind = "Native"
	}
	var zone Zone
	err := c.doJSON(ctx, "authoritative", http.MethodPost, c.serverPath("authoritative", "/zones"), request, &zone)
	return zone, err
}

func (c *Client) AuthoritativeZone(ctx context.Context, zoneID string) (Zone, error) {
	zoneID = normalizeZoneName(zoneID)
	if zoneID == "." || strings.TrimSpace(zoneID) == "" {
		return Zone{}, fmt.Errorf("zone id is required")
	}
	var zone Zone
	err := c.doJSON(ctx, "authoritative", http.MethodGet, c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)), nil, &zone)
	return zone, err
}

func (c *Client) PatchAuthoritativeZone(ctx context.Context, zoneID string, request PatchZoneRequest) error {
	zoneID = normalizeZoneName(zoneID)
	if zoneID == "." || strings.TrimSpace(zoneID) == "" {
		return fmt.Errorf("zone id is required")
	}
	if len(request.RRSets) == 0 {
		return fmt.Errorf("at least one rrset is required")
	}
	for index := range request.RRSets {
		rrset := &request.RRSets[index]
		rrset.Name = normalizeZoneName(rrset.Name)
		rrset.Type = strings.ToUpper(strings.TrimSpace(rrset.Type))
		rrset.ChangeType = strings.ToUpper(strings.TrimSpace(rrset.ChangeType))
		if rrset.Name == "." || rrset.Name == "" {
			return fmt.Errorf("rrsets[%d].name is required", index)
		}
		if rrset.Name != zoneID && !strings.HasSuffix(rrset.Name, "."+zoneID) {
			return fmt.Errorf("rrsets[%d].name must be inside zone %s", index, zoneID)
		}
		if !validRecordType(rrset.Type) {
			return fmt.Errorf("rrsets[%d].type is invalid", index)
		}
		switch rrset.ChangeType {
		case "REPLACE":
			if rrset.TTL == 0 {
				rrset.TTL = 300
			}
			if len(rrset.Records) == 0 {
				return fmt.Errorf("rrsets[%d].records is required for REPLACE", index)
			}
			for recordIndex := range rrset.Records {
				rrset.Records[recordIndex].Content = strings.TrimSpace(rrset.Records[recordIndex].Content)
				if rrset.Records[recordIndex].Content == "" {
					return fmt.Errorf("rrsets[%d].records[%d].content is required", index, recordIndex)
				}
			}
		case "DELETE":
			rrset.TTL = 0
			rrset.Records = nil
			rrset.Comments = nil
		default:
			return fmt.Errorf("rrsets[%d].changetype must be REPLACE or DELETE", index)
		}
	}
	return c.doJSON(
		ctx,
		"authoritative",
		http.MethodPatch,
		c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)),
		request,
		nil,
	)
}

func (c *Client) DeleteAuthoritativeZone(ctx context.Context, zoneID string) error {
	zoneID = strings.TrimSpace(zoneID)
	if zoneID == "" {
		return fmt.Errorf("zone id is required")
	}
	return c.doJSON(ctx, "authoritative", http.MethodDelete, c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)), nil, nil)
}

func (c *Client) FlushRecursorCache(ctx context.Context, domain string, subtree bool) (CacheFlushResult, error) {
	domain = normalizeZoneName(domain)
	if domain == "." {
		domain = ""
	}
	values := url.Values{}
	values.Set("domain", domain)
	values.Set("subtree", strconv.FormatBool(subtree))
	var result CacheFlushResult
	err := c.doJSON(ctx, "recursor", http.MethodPut, c.serverPath("recursor", "/cache/flush")+"?"+values.Encode(), nil, &result)
	return result, err
}

func (c *Client) serviceSnapshot(ctx context.Context, service string) ServiceSnapshot {
	endpoint, _ := c.endpoint(service)
	snapshot := ServiceSnapshot{
		Configured: endpoint != "",
		URL:        endpoint,
		Zones:      []Zone{},
		Statistics: map[string]any{},
	}
	if endpoint == "" {
		return snapshot
	}
	var server Server
	if err := c.doJSON(ctx, service, http.MethodGet, c.serverPath(service, ""), nil, &server); err != nil {
		snapshot.Error = err.Error()
		return snapshot
	}
	snapshot.Server = &server
	snapshot.Healthy = true
	if zones, err := c.Zones(ctx, service); err == nil {
		snapshot.Zones = zones
	} else {
		snapshot.Error = err.Error()
	}
	var statistics []struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value any    `json:"value"`
	}
	if err := c.doJSON(ctx, service, http.MethodGet, c.serverPath(service, "/statistics"), nil, &statistics); err == nil {
		for _, statistic := range statistics {
			snapshot.Statistics[statistic.Name] = statistic.Value
		}
	}
	var settings []any
	if err := c.doJSON(ctx, service, http.MethodGet, c.serverPath(service, "/config"), nil, &settings); err == nil {
		snapshot.Config = settings
	}
	return snapshot
}

func (c *Client) serverPath(service, suffix string) string {
	return "/api/v1/servers/" + url.PathEscape(c.cfg.ServerID) + suffix
}

func (c *Client) endpoint(service string) (string, string) {
	switch service {
	case "authoritative":
		return strings.TrimRight(strings.TrimSpace(c.cfg.AuthoritativeURL), "/"), c.cfg.AuthoritativeAPIKey
	case "recursor":
		return strings.TrimRight(strings.TrimSpace(c.cfg.RecursorURL), "/"), c.cfg.RecursorAPIKey
	default:
		return "", ""
	}
}

func (c *Client) doJSON(ctx context.Context, service, method, path string, input, output any) error {
	endpoint, apiKey := c.endpoint(service)
	if endpoint == "" {
		return fmt.Errorf("%s PowerDNS endpoint is not configured", service)
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(responseBody))
		if message == "" {
			message = response.Status
		}
		return fmt.Errorf("%s PowerDNS API %s %s: %s", service, method, path, message)
	}
	if output == nil || len(responseBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, output); err != nil {
		return fmt.Errorf("decode %s PowerDNS response: %w", service, err)
	}
	return nil
}

func normalizeZoneName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".") + "."
}

func validRecordType(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' {
			continue
		}
		if index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
