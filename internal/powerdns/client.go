package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/dnsname"
	"github.com/anyns/anyns/internal/dnsrr"
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
	UnicodeName    string   `json:"unicode_name,omitempty"`
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
	Name        string    `json:"name"`
	UnicodeName string    `json:"unicode_name,omitempty"`
	Type        string    `json:"type"`
	TTL         uint32    `json:"ttl,omitempty"`
	ChangeType  string    `json:"changetype,omitempty"`
	Records     []Record  `json:"records,omitempty"`
	Comments    []Comment `json:"comments,omitempty"`
}

type PatchZoneRequest struct {
	RRSets []RRSet `json:"rrsets"`
}

const maxRecordContentLength = 4096

type CryptoKey struct {
	ID        int      `json:"id"`
	KeyType   string   `json:"keytype"`
	Active    bool     `json:"active"`
	Published bool     `json:"published"`
	DNSKey    string   `json:"dnskey,omitempty"`
	DS        []string `json:"ds,omitempty"`
}

type CreateCryptoKeyRequest struct {
	KeyType   string `json:"keytype,omitempty"`
	Active    bool   `json:"active"`
	Published bool   `json:"published"`
	Algorithm string `json:"algorithm,omitempty"`
	Bits      int    `json:"bits,omitempty"`
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
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Nameservers []string   `json:"nameservers,omitempty"`
	Masters     []string   `json:"masters,omitempty"`
	DNSSEC      bool       `json:"dnssec,omitempty"`
	HNS         bool       `json:"hns,omitempty"`
	GlueIPv4    string     `json:"glue_ipv4,omitempty"`
	GlueIPv6    string     `json:"glue_ipv6,omitempty"`
	SOA         *SOAConfig `json:"soa,omitempty"`
}

type SOAConfig struct {
	PrimaryNS  string `json:"primary_ns,omitempty"`
	Hostmaster string `json:"hostmaster,omitempty"`
	Serial     uint32 `json:"serial,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
	Refresh    uint32 `json:"refresh,omitempty"`
	Retry      uint32 `json:"retry,omitempty"`
	Expire     uint32 `json:"expire,omitempty"`
	Minimum    uint32 `json:"minimum,omitempty"`
}

type SOARecord struct {
	PrimaryNS  string `json:"primary_ns"`
	Hostmaster string `json:"hostmaster"`
	Serial     uint32 `json:"serial"`
	TTL        uint32 `json:"ttl"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	Minimum    uint32 `json:"minimum"`
}

type powerDNSCreateZoneRequest struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Nameservers []string `json:"nameservers,omitempty"`
	Masters     []string `json:"masters,omitempty"`
	DNSSEC      bool     `json:"dnssec,omitempty"`
}

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func IsValidationError(err error) bool {
	var validationError *ValidationError
	return errors.As(err, &validationError)
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
	for index := range zones {
		decorateZone(&zones[index])
	}
	return zones, err
}

func (c *Client) CreateAuthoritativeZone(ctx context.Context, request CreateZoneRequest) (Zone, error) {
	if request.HNS {
		request.Name = trimHNSSuffix(request.Name)
	}
	zoneName, err := normalizeZoneName(request.Name)
	if err != nil {
		return Zone{}, validationErrorf("invalid zone name: %v", err)
	}
	if zoneName == "." || strings.TrimSpace(zoneName) == "" {
		return Zone{}, validationErrorf("zone name is required")
	}
	if request.HNS && strings.Contains(strings.TrimSuffix(zoneName, "."), ".") {
		return Zone{}, validationErrorf("HNS zone must be a single top-level label")
	}
	if request.HNS {
		if err := validateHNSTopLevelLabel(zoneName); err != nil {
			return Zone{}, err
		}
	}
	if request.Kind == "" {
		request.Kind = "Native"
	}
	nameservers := make([]string, 0, len(request.Nameservers)+1)
	for index, nameserver := range request.Nameservers {
		normalized, normalizeErr := normalizeZoneName(nameserver)
		if normalizeErr != nil || normalized == "" || normalized == "." {
			return Zone{}, validationErrorf("nameservers[%d] is invalid: %v", index, normalizeErr)
		}
		nameservers = append(nameservers, normalized)
	}
	if len(nameservers) == 0 && (request.HNS || request.SOA != nil) {
		nameservers = append(nameservers, "ns1."+zoneName)
	}
	powerDNSRequest := powerDNSCreateZoneRequest{
		Name:        zoneName,
		Kind:        request.Kind,
		Nameservers: nameservers,
		Masters:     request.Masters,
		DNSSEC:      request.DNSSEC,
	}
	var initialRRSets []RRSet
	if request.HNS || request.SOA != nil || request.GlueIPv4 != "" || request.GlueIPv6 != "" {
		initialRRSets, err = initialZoneRRSets(zoneName, nameservers, request)
		if err != nil {
			return Zone{}, err
		}
	}
	var zone Zone
	if err := c.doJSON(ctx, "authoritative", http.MethodPost, c.serverPath("authoritative", "/zones"), powerDNSRequest, &zone); err != nil {
		return Zone{}, err
	}
	decorateZone(&zone)
	if len(initialRRSets) == 0 {
		return zone, nil
	}
	if err := c.PatchAuthoritativeZone(ctx, zoneName, PatchZoneRequest{RRSets: initialRRSets}); err != nil {
		_ = c.deleteAuthoritativeZone(ctx, zoneName)
		return Zone{}, fmt.Errorf("initialize authoritative zone %s: %w", zoneName, err)
	}
	return zone, nil
}

func (c *Client) AuthoritativeZone(ctx context.Context, zoneID string) (Zone, error) {
	var err error
	zoneID, err = normalizeZoneName(zoneID)
	if err != nil {
		return Zone{}, validationErrorf("invalid zone id: %v", err)
	}
	if zoneID == "." || strings.TrimSpace(zoneID) == "" {
		return Zone{}, validationErrorf("zone id is required")
	}
	var zone Zone
	err = c.doJSON(ctx, "authoritative", http.MethodGet, c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)), nil, &zone)
	decorateZone(&zone)
	return zone, err
}

func (c *Client) PatchAuthoritativeZone(ctx context.Context, zoneID string, request PatchZoneRequest) error {
	var err error
	zoneID, err = normalizeZoneName(zoneID)
	if err != nil {
		return validationErrorf("invalid zone id: %v", err)
	}
	if zoneID == "." || strings.TrimSpace(zoneID) == "" {
		return validationErrorf("zone id is required")
	}
	if len(request.RRSets) == 0 {
		return validationErrorf("at least one rrset is required")
	}
	for index := range request.RRSets {
		rrset := &request.RRSets[index]
		rrset.Name, err = normalizeZoneName(rrset.Name)
		if err != nil {
			return validationErrorf("rrsets[%d].name is invalid: %v", index, err)
		}
		rrset.UnicodeName = ""
		rrset.Type = strings.ToUpper(strings.TrimSpace(rrset.Type))
		rrset.ChangeType = strings.ToUpper(strings.TrimSpace(rrset.ChangeType))
		if rrset.Name == "." || rrset.Name == "" {
			return validationErrorf("rrsets[%d].name is required", index)
		}
		if rrset.Name != zoneID && !strings.HasSuffix(rrset.Name, "."+zoneID) {
			return validationErrorf("rrsets[%d].name must be inside zone %s", index, zoneID)
		}
		if !validRecordType(rrset.Type) {
			return validationErrorf("rrsets[%d].type is invalid", index)
		}
		if err := validateRRSetOwnerForType(zoneID, rrset.Name, rrset.Type); err != nil {
			return validationErrorf("rrsets[%d].name is invalid for %s: %v", index, rrset.Type, err)
		}
		switch rrset.ChangeType {
		case "REPLACE":
			if rrset.TTL == 0 {
				rrset.TTL = 300
			}
			if len(rrset.Records) == 0 {
				return validationErrorf("rrsets[%d].records is required for REPLACE", index)
			}
			for recordIndex := range rrset.Records {
				if err := validateRecordContentSafety(rrset.Records[recordIndex].Content); err != nil {
					return validationErrorf("rrsets[%d].records[%d].content is invalid: %v", index, recordIndex, err)
				}
				content, normalizeErr := normalizeRecordContent(rrset.Type, rrset.Records[recordIndex].Content)
				if normalizeErr != nil {
					return validationErrorf("rrsets[%d].records[%d].content is invalid: %v", index, recordIndex, normalizeErr)
				}
				rrset.Records[recordIndex].Content = content
				if content == "" {
					return validationErrorf("rrsets[%d].records[%d].content is required", index, recordIndex)
				}
			}
		case "DELETE":
			rrset.TTL = 0
			rrset.Records = nil
			rrset.Comments = nil
		default:
			return validationErrorf("rrsets[%d].changetype must be REPLACE or DELETE", index)
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

func (c *Client) UpdateAuthoritativeSOA(ctx context.Context, zoneID string, update SOAConfig) (SOARecord, error) {
	zoneID, err := requiredZoneID(zoneID)
	if err != nil {
		return SOARecord{}, err
	}
	zone, err := c.AuthoritativeZone(ctx, zoneID)
	if err != nil {
		return SOARecord{}, err
	}
	current, err := zoneSOA(zone)
	if err != nil {
		return SOARecord{}, err
	}
	next := current
	if strings.TrimSpace(update.PrimaryNS) != "" {
		next.PrimaryNS, err = normalizeZoneName(update.PrimaryNS)
		if err != nil {
			return SOARecord{}, validationErrorf("soa.primary_ns is invalid: %v", err)
		}
	}
	if strings.TrimSpace(update.Hostmaster) != "" {
		next.Hostmaster, err = normalizeZoneName(update.Hostmaster)
		if err != nil {
			return SOARecord{}, validationErrorf("soa.hostmaster is invalid: %v", err)
		}
	}
	if update.Serial != 0 {
		if update.Serial <= current.Serial {
			return SOARecord{}, validationErrorf("soa.serial must be greater than current serial %d", current.Serial)
		}
		next.Serial = update.Serial
	} else {
		if current.Serial == ^uint32(0) {
			return SOARecord{}, validationErrorf("soa.serial cannot be incremented beyond %d", current.Serial)
		}
		next.Serial = current.Serial + 1
	}
	if update.TTL != 0 {
		next.TTL = update.TTL
	}
	if update.Refresh != 0 {
		next.Refresh = update.Refresh
	}
	if update.Retry != 0 {
		next.Retry = update.Retry
	}
	if update.Expire != 0 {
		next.Expire = update.Expire
	}
	if update.Minimum != 0 {
		next.Minimum = update.Minimum
	}
	if err := validateSOARecord(next); err != nil {
		return SOARecord{}, err
	}
	if err := c.PatchAuthoritativeZone(ctx, zoneID, PatchZoneRequest{RRSets: []RRSet{{
		Name:       zoneID,
		Type:       "SOA",
		TTL:        next.TTL,
		ChangeType: "REPLACE",
		Records:    []Record{{Content: next.content()}},
	}}}); err != nil {
		return SOARecord{}, err
	}
	return next, nil
}

func (c *Client) AuthoritativeCryptoKeys(ctx context.Context, zoneID string) ([]CryptoKey, error) {
	zoneID, err := requiredZoneID(zoneID)
	if err != nil {
		return nil, err
	}
	var keys []CryptoKey
	err = c.doJSON(
		ctx,
		"authoritative",
		http.MethodGet,
		c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)+"/cryptokeys"),
		nil,
		&keys,
	)
	return keys, err
}

func (c *Client) CreateAuthoritativeCryptoKey(ctx context.Context, zoneID string, request CreateCryptoKeyRequest) (CryptoKey, error) {
	zoneID, err := requiredZoneID(zoneID)
	if err != nil {
		return CryptoKey{}, err
	}
	request.KeyType = strings.ToLower(strings.TrimSpace(request.KeyType))
	if request.KeyType == "" {
		request.KeyType = "csk"
	}
	switch request.KeyType {
	case "csk", "ksk", "zsk":
	default:
		return CryptoKey{}, validationErrorf("keytype must be csk, ksk, or zsk")
	}
	if request.Algorithm != "" {
		request.Algorithm = strings.ToUpper(strings.TrimSpace(request.Algorithm))
	}
	var key CryptoKey
	err = c.doJSON(
		ctx,
		"authoritative",
		http.MethodPost,
		c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)+"/cryptokeys"),
		request,
		&key,
	)
	return key, err
}

func (c *Client) DeleteAuthoritativeCryptoKey(ctx context.Context, zoneID string, keyID int) error {
	zoneID, err := requiredZoneID(zoneID)
	if err != nil {
		return err
	}
	if keyID < 0 {
		return validationErrorf("key id must not be negative")
	}
	return c.doJSON(
		ctx,
		"authoritative",
		http.MethodDelete,
		c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)+"/cryptokeys/"+strconv.Itoa(keyID)),
		nil,
		nil,
	)
}

func DeriveDS(zoneName, dnskeyContent string, digestType uint8) (string, error) {
	zoneName, err := normalizeZoneName(zoneName)
	if err != nil {
		return "", validationErrorf("invalid zone name: %v", err)
	}
	value, err := dnsrr.DSFromDNSKEY(zoneName, dnskeyContent, digestType)
	if err != nil {
		return "", validationErrorf("derive DS: %v", err)
	}
	return value, nil
}

func (c *Client) DeleteAuthoritativeZone(ctx context.Context, zoneID string) error {
	normalized, err := normalizeZoneName(zoneID)
	if err != nil {
		return validationErrorf("invalid zone id: %v", err)
	}
	if normalized == "" || normalized == "." {
		return validationErrorf("zone id is required")
	}
	return c.deleteAuthoritativeZone(ctx, normalized)
}

func (c *Client) FlushRecursorCache(ctx context.Context, domain string, subtree bool) (CacheFlushResult, error) {
	var err error
	domain, err = normalizeZoneName(domain)
	if err != nil {
		return CacheFlushResult{}, validationErrorf("invalid cache domain: %v", err)
	}
	if domain == "." {
		domain = ""
	}
	values := url.Values{}
	values.Set("domain", domain)
	values.Set("subtree", strconv.FormatBool(subtree))
	var result CacheFlushResult
	err = c.doJSON(ctx, "recursor", http.MethodPut, c.serverPath("recursor", "/cache/flush")+"?"+values.Encode(), nil, &result)
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

func normalizeZoneName(name string) (string, error) {
	return dnsname.ToASCII(name)
}

func trimHNSSuffix(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	lower := strings.ToLower(name)
	for _, suffix := range []string{".hns", ".hsd"} {
		if strings.HasSuffix(lower, suffix) {
			return name[:len(name)-len(suffix)]
		}
	}
	return name
}

func validateHNSTopLevelLabel(zoneName string) error {
	label := strings.TrimSuffix(zoneName, ".")
	if label == "" || strings.Contains(label, ".") {
		return validationErrorf("HNS zone must be a single top-level label")
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return validationErrorf("HNS zone label must not start or end with hyphen")
	}
	for _, character := range label {
		if character >= 'a' && character <= 'z' {
			continue
		}
		if character >= '0' && character <= '9' {
			continue
		}
		if character == '-' {
			continue
		}
		return validationErrorf("HNS zone label must contain only letters, digits, and hyphen after IDNA normalization")
	}
	return nil
}

func initialZoneRRSets(zoneName string, nameservers []string, request CreateZoneRequest) ([]RRSet, error) {
	if len(nameservers) == 0 {
		return nil, validationErrorf("at least one nameserver is required to initialize SOA")
	}
	config := SOAConfig{}
	if request.SOA != nil {
		config = *request.SOA
	}
	primaryNS := nameservers[0]
	if strings.TrimSpace(config.PrimaryNS) != "" {
		var err error
		primaryNS, err = normalizeZoneName(config.PrimaryNS)
		if err != nil {
			return nil, validationErrorf("soa.primary_ns is invalid: %v", err)
		}
	}
	hostmaster := "hostmaster." + zoneName
	if strings.TrimSpace(config.Hostmaster) != "" {
		var err error
		hostmaster, err = normalizeZoneName(config.Hostmaster)
		if err != nil {
			return nil, validationErrorf("soa.hostmaster is invalid: %v", err)
		}
	}
	serial := config.Serial
	if serial == 0 {
		serialValue, _ := strconv.ParseUint(time.Now().UTC().Format("20060102")+"01", 10, 32)
		serial = uint32(serialValue)
	}
	ttl := defaultUint32(config.TTL, 300)
	refresh := defaultUint32(config.Refresh, 3600)
	retry := defaultUint32(config.Retry, 600)
	expire := defaultUint32(config.Expire, 86400)
	minimum := defaultUint32(config.Minimum, 300)

	nsRecords := make([]Record, 0, len(nameservers))
	for _, nameserver := range nameservers {
		nsRecords = append(nsRecords, Record{Content: nameserver})
	}
	rrsets := []RRSet{
		{
			Name:       zoneName,
			Type:       "SOA",
			TTL:        ttl,
			ChangeType: "REPLACE",
			Records: []Record{{
				Content: fmt.Sprintf("%s %s %d %d %d %d %d", primaryNS, hostmaster, serial, refresh, retry, expire, minimum),
			}},
		},
		{
			Name:       zoneName,
			Type:       "NS",
			TTL:        ttl,
			ChangeType: "REPLACE",
			Records:    nsRecords,
		},
	}
	if strings.TrimSpace(request.GlueIPv4) != "" {
		if ip := net.ParseIP(strings.TrimSpace(request.GlueIPv4)); ip == nil || ip.To4() == nil {
			return nil, validationErrorf("glue_ipv4 must be a valid IPv4 address")
		}
		if !nameInsideZone(primaryNS, zoneName) {
			return nil, validationErrorf("glue_ipv4 requires primary nameserver %s to be inside zone %s", primaryNS, zoneName)
		}
		rrsets = append(rrsets, RRSet{
			Name:       primaryNS,
			Type:       "A",
			TTL:        ttl,
			ChangeType: "REPLACE",
			Records:    []Record{{Content: strings.TrimSpace(request.GlueIPv4)}},
		})
	}
	if strings.TrimSpace(request.GlueIPv6) != "" {
		if ip := net.ParseIP(strings.TrimSpace(request.GlueIPv6)); ip == nil || ip.To4() != nil {
			return nil, validationErrorf("glue_ipv6 must be a valid IPv6 address")
		}
		if !nameInsideZone(primaryNS, zoneName) {
			return nil, validationErrorf("glue_ipv6 requires primary nameserver %s to be inside zone %s", primaryNS, zoneName)
		}
		rrsets = append(rrsets, RRSet{
			Name:       primaryNS,
			Type:       "AAAA",
			TTL:        ttl,
			ChangeType: "REPLACE",
			Records:    []Record{{Content: strings.TrimSpace(request.GlueIPv6)}},
		})
	}
	return rrsets, nil
}

func zoneSOA(zone Zone) (SOARecord, error) {
	for _, rrset := range zone.RRSets {
		if strings.ToUpper(strings.TrimSpace(rrset.Type)) != "SOA" {
			continue
		}
		if rrset.Name != zone.Name {
			return SOARecord{}, validationErrorf("apex SOA name %s does not match zone %s", rrset.Name, zone.Name)
		}
		for _, record := range rrset.Records {
			if record.Disabled {
				continue
			}
			soa, err := parseSOAContent(record.Content)
			if err != nil {
				return SOARecord{}, err
			}
			soa.TTL = defaultUint32(rrset.TTL, 300)
			return soa, nil
		}
	}
	return SOARecord{}, validationErrorf("zone %s has no active apex SOA record", zone.Name)
}

func parseSOAContent(content string) (SOARecord, error) {
	fields := strings.Fields(content)
	if len(fields) != 7 {
		return SOARecord{}, validationErrorf("SOA record requires seven fields")
	}
	primaryNS, err := normalizeZoneName(fields[0])
	if err != nil {
		return SOARecord{}, validationErrorf("SOA primary nameserver is invalid: %v", err)
	}
	hostmaster, err := normalizeZoneName(fields[1])
	if err != nil {
		return SOARecord{}, validationErrorf("SOA hostmaster is invalid: %v", err)
	}
	values := make([]uint32, 5)
	for index, field := range fields[2:] {
		parsed, parseErr := strconv.ParseUint(field, 10, 32)
		if parseErr != nil {
			return SOARecord{}, validationErrorf("SOA numeric field %d is invalid", index+3)
		}
		values[index] = uint32(parsed)
	}
	soa := SOARecord{
		PrimaryNS:  primaryNS,
		Hostmaster: hostmaster,
		Serial:     values[0],
		Refresh:    values[1],
		Retry:      values[2],
		Expire:     values[3],
		Minimum:    values[4],
	}
	if err := validateSOARecord(soa); err != nil {
		return SOARecord{}, err
	}
	return soa, nil
}

func validateSOARecord(soa SOARecord) error {
	switch {
	case strings.TrimSpace(soa.PrimaryNS) == "":
		return validationErrorf("soa.primary_ns is required")
	case strings.TrimSpace(soa.Hostmaster) == "":
		return validationErrorf("soa.hostmaster is required")
	case soa.Serial == 0:
		return validationErrorf("soa.serial must be greater than zero")
	case soa.TTL != 0 && soa.TTL < 60:
		return validationErrorf("soa.ttl must be at least 60 seconds")
	case soa.Refresh < 60:
		return validationErrorf("soa.refresh must be at least 60 seconds")
	case soa.Retry < 60:
		return validationErrorf("soa.retry must be at least 60 seconds")
	case soa.Expire < 300:
		return validationErrorf("soa.expire must be at least 300 seconds")
	case soa.Minimum < 60:
		return validationErrorf("soa.minimum must be at least 60 seconds")
	}
	return nil
}

func (s SOARecord) content() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", s.PrimaryNS, s.Hostmaster, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
}

func normalizeRecordContent(recordType, content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", nil
	}
	fields := strings.Fields(content)
	normalizeField := func(index int) error {
		if index >= len(fields) || fields[index] == "." {
			return nil
		}
		normalized, err := normalizeZoneName(fields[index])
		if err != nil {
			return err
		}
		fields[index] = normalized
		return nil
	}
	switch recordType {
	case "CNAME", "DNAME", "NS", "PTR":
		if len(fields) != 1 {
			return "", fmt.Errorf("%s record requires one DNS name", recordType)
		}
		if err := normalizeField(0); err != nil {
			return "", err
		}
	case "MX":
		if len(fields) != 2 {
			return "", fmt.Errorf("MX record requires priority and target")
		}
		if err := normalizeField(1); err != nil {
			return "", err
		}
	case "SRV":
		if len(fields) != 4 {
			return "", fmt.Errorf("SRV record requires priority, weight, port, and target")
		}
		if err := normalizeField(3); err != nil {
			return "", err
		}
	case "SOA":
		if len(fields) != 7 {
			return "", fmt.Errorf("SOA record requires seven fields")
		}
		if err := normalizeField(0); err != nil {
			return "", err
		}
		if err := normalizeField(1); err != nil {
			return "", err
		}
	case "SVCB", "HTTPS":
		if len(fields) < 2 {
			return "", fmt.Errorf("%s record requires priority and target", recordType)
		}
		if err := normalizeField(1); err != nil {
			return "", err
		}
	}
	content = strings.Join(fields, " ")
	if dnsrr.ManagedType(recordType) {
		normalized, err := dnsrr.Normalize("_validation.invalid.", recordType, content)
		if err != nil {
			return "", err
		}
		return normalized, nil
	}
	return content, nil
}

func validateRRSetOwnerForType(zoneID, owner, recordType string) error {
	switch recordType {
	case "SOA", "DNSKEY":
		if owner != zoneID {
			return fmt.Errorf("%s records must be at the zone apex", recordType)
		}
	case "TLSA":
		if err := validateTLSAOwner(owner, zoneID); err != nil {
			return err
		}
	}
	return nil
}

func validateTLSAOwner(owner, zoneID string) error {
	if owner == zoneID {
		return fmt.Errorf("TLSA owner must include _port._protocol labels")
	}
	relative := strings.TrimSuffix(owner, "."+zoneID)
	if relative == owner || relative == "" {
		return fmt.Errorf("TLSA owner must be inside zone and include _port._protocol labels")
	}
	labels := strings.Split(relative, ".")
	if len(labels) < 2 {
		return fmt.Errorf("TLSA owner must include _port._protocol labels")
	}
	portLabel := strings.TrimPrefix(labels[0], "_")
	if portLabel == labels[0] || portLabel == "" {
		return fmt.Errorf("TLSA port label must start with underscore")
	}
	port, err := strconv.Atoi(portLabel)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("TLSA port label must be between _1 and _65535")
	}
	switch labels[1] {
	case "_tcp", "_udp", "_sctp":
		return nil
	default:
		return fmt.Errorf("TLSA protocol label must be _tcp, _udp, or _sctp")
	}
}

func validateRecordContentSafety(content string) error {
	content = strings.TrimSpace(content)
	if len(content) > maxRecordContentLength {
		return fmt.Errorf("record content exceeds %d bytes", maxRecordContentLength)
	}
	for _, character := range content {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("record content must not contain literal control characters")
		}
	}
	return nil
}

func decorateZone(zone *Zone) {
	if zone == nil {
		return
	}
	zone.UnicodeName = dnsname.ToUnicode(zone.Name)
	for index := range zone.RRSets {
		zone.RRSets[index].UnicodeName = dnsname.ToUnicode(zone.RRSets[index].Name)
	}
}

func (c *Client) deleteAuthoritativeZone(ctx context.Context, zoneID string) error {
	return c.doJSON(ctx, "authoritative", http.MethodDelete, c.serverPath("authoritative", "/zones/"+url.PathEscape(zoneID)), nil, nil)
}

func nameInsideZone(name, zoneName string) bool {
	return name == zoneName || strings.HasSuffix(name, "."+zoneName)
}

func defaultUint32(value, fallback uint32) uint32 {
	if value == 0 {
		return fallback
	}
	return value
}

func validationErrorf(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

func requiredZoneID(zoneID string) (string, error) {
	normalized, err := normalizeZoneName(zoneID)
	if err != nil {
		return "", validationErrorf("invalid zone id: %v", err)
	}
	if normalized == "" || normalized == "." {
		return "", validationErrorf("zone id is required")
	}
	return normalized, nil
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
