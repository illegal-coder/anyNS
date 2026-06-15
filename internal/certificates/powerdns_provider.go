package certificates

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/anyns/anyns/internal/powerdns"
)

type PowerDNSProvider struct {
	client *powerdns.Client
}

func NewPowerDNSProvider(client *powerdns.Client) *PowerDNSProvider {
	return &PowerDNSProvider{client: client}
}

func (p *PowerDNSProvider) Present(ctx context.Context, fqdn, value string) error {
	zone, rrset, err := p.challengeRRSet(ctx, fqdn)
	if err != nil {
		return err
	}
	quoted := strconv.Quote(value)
	records := append([]powerdns.Record(nil), rrset.Records...)
	for _, record := range records {
		if record.Content == quoted {
			return nil
		}
	}
	records = append(records, powerdns.Record{Content: quoted})
	return p.client.PatchAuthoritativeZone(ctx, zone.ID, powerdns.PatchZoneRequest{RRSets: []powerdns.RRSet{{
		Name:       fqdn,
		Type:       "TXT",
		TTL:        60,
		ChangeType: "REPLACE",
		Records:    records,
	}}})
}

func (p *PowerDNSProvider) Cleanup(ctx context.Context, fqdn, value string) error {
	zone, rrset, err := p.challengeRRSet(ctx, fqdn)
	if err != nil {
		return err
	}
	quoted := strconv.Quote(value)
	records := make([]powerdns.Record, 0, len(rrset.Records))
	for _, record := range rrset.Records {
		if record.Content != quoted {
			records = append(records, record)
		}
	}
	changeType := "REPLACE"
	if len(records) == 0 {
		changeType = "DELETE"
	}
	return p.client.PatchAuthoritativeZone(ctx, zone.ID, powerdns.PatchZoneRequest{RRSets: []powerdns.RRSet{{
		Name:       fqdn,
		Type:       "TXT",
		TTL:        60,
		ChangeType: changeType,
		Records:    records,
	}}})
}

func (p *PowerDNSProvider) challengeRRSet(ctx context.Context, fqdn string) (powerdns.Zone, powerdns.RRSet, error) {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	zones, err := p.client.Zones(ctx, "authoritative")
	if err != nil {
		return powerdns.Zone{}, powerdns.RRSet{}, err
	}
	var selected powerdns.Zone
	for _, zone := range zones {
		name := strings.ToLower(zone.Name)
		if (fqdn == name || strings.HasSuffix(fqdn, "."+name)) && len(name) > len(selected.Name) {
			selected = zone
		}
	}
	if selected.ID == "" {
		return powerdns.Zone{}, powerdns.RRSet{}, fmt.Errorf("no authoritative PowerDNS zone contains %s", fqdn)
	}
	detail, err := p.client.AuthoritativeZone(ctx, selected.ID)
	if err != nil {
		return powerdns.Zone{}, powerdns.RRSet{}, err
	}
	for _, rrset := range detail.RRSets {
		if strings.EqualFold(rrset.Name, fqdn) && strings.EqualFold(rrset.Type, "TXT") {
			return detail, rrset, nil
		}
	}
	return detail, powerdns.RRSet{Name: fqdn, Type: "TXT"}, nil
}
