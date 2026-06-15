package dnsrr

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var managedTypes = map[string]bool{
	"A": true, "AAAA": true, "CAA": true, "CNAME": true, "DNAME": true,
	"DNSKEY": true, "DS": true, "HTTPS": true, "MX": true, "NS": true,
	"PTR": true, "SOA": true, "SRV": true, "SVCB": true, "TLSA": true,
	"TXT": true, "URI": true,
}

func ManagedType(recordType string) bool {
	return managedTypes[strings.ToUpper(strings.TrimSpace(recordType))]
}

func Normalize(owner, recordType, content string) (string, error) {
	owner = dns.Fqdn(strings.TrimSpace(owner))
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	content = strings.TrimSpace(content)
	if owner == "." || content == "" {
		return "", fmt.Errorf("owner and record content are required")
	}
	if !ManagedType(recordType) {
		return "", fmt.Errorf("record type %s is not managed by anyNS", recordType)
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN %s %s", owner, recordType, content))
	if err != nil {
		return "", err
	}
	switch value := rr.(type) {
	case *dns.DS:
		if err := validateDS(value); err != nil {
			return "", err
		}
		value.Digest = strings.ToUpper(value.Digest)
	case *dns.DNSKEY:
		if value.Protocol != 3 {
			return "", fmt.Errorf("DNSKEY protocol must be 3")
		}
		if _, err := base64.StdEncoding.DecodeString(value.PublicKey); err != nil {
			return "", fmt.Errorf("DNSKEY public key is not valid base64: %w", err)
		}
	case *dns.TLSA:
		if err := validateTLSA(value); err != nil {
			return "", err
		}
		value.Certificate = strings.ToUpper(value.Certificate)
	case *dns.CAA:
		if value.Tag == "" {
			return "", fmt.Errorf("CAA tag is required")
		}
		for _, r := range value.Tag {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				return "", fmt.Errorf("CAA tag must contain only ASCII letters and digits")
			}
		}
		value.Tag = strings.ToLower(value.Tag)
	}
	return rrContent(rr), nil
}

func DSFromDNSKEY(owner, dnskeyContent string, digestType uint8) (string, error) {
	normalized, err := Normalize(owner, "DNSKEY", dnskeyContent)
	if err != nil {
		return "", err
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN DNSKEY %s", dns.Fqdn(owner), normalized))
	if err != nil {
		return "", err
	}
	key := rr.(*dns.DNSKEY)
	ds := key.ToDS(digestType)
	if ds == nil {
		return "", fmt.Errorf("unsupported DS digest type %d", digestType)
	}
	if err := validateDS(ds); err != nil {
		return "", err
	}
	ds.Digest = strings.ToUpper(ds.Digest)
	return rrContent(ds), nil
}

func TLSAFromCertificatePEM(certificatePEM []byte, usage, selector, matchingType uint8) (string, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	var selected []byte
	switch selector {
	case 0:
		selected = certificate.Raw
	case 1:
		selected = certificate.RawSubjectPublicKeyInfo
	default:
		return "", fmt.Errorf("TLSA selector must be 0 or 1")
	}
	var association []byte
	switch matchingType {
	case 0:
		association = selected
	case 1:
		sum := sha256.Sum256(selected)
		association = sum[:]
	default:
		return "", fmt.Errorf("TLSA matching type must be 0 or 1; SHA-512 generation is not enabled")
	}
	record := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: ".", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Certificate:  strings.ToUpper(hex.EncodeToString(association)),
	}
	if err := validateTLSA(record); err != nil {
		return "", err
	}
	return rrContent(record), nil
}

func validateDS(record *dns.DS) error {
	if record.DigestType != dns.SHA1 && record.DigestType != dns.SHA256 && record.DigestType != dns.SHA384 {
		return fmt.Errorf("DS digest type must be 1 (SHA-1), 2 (SHA-256), or 4 (SHA-384)")
	}
	digest, err := hex.DecodeString(record.Digest)
	if err != nil {
		return fmt.Errorf("DS digest must be hexadecimal")
	}
	want := map[uint8]int{dns.SHA1: 20, dns.SHA256: 32, dns.SHA384: 48}[record.DigestType]
	if len(digest) != want {
		return fmt.Errorf("DS digest type %d requires %d bytes, got %d", record.DigestType, want, len(digest))
	}
	return nil
}

func validateTLSA(record *dns.TLSA) error {
	if record.Usage > 3 {
		return fmt.Errorf("TLSA certificate usage must be between 0 and 3")
	}
	if record.Selector > 1 {
		return fmt.Errorf("TLSA selector must be 0 or 1")
	}
	if record.MatchingType > 2 {
		return fmt.Errorf("TLSA matching type must be between 0 and 2")
	}
	association, err := hex.DecodeString(record.Certificate)
	if err != nil || len(association) == 0 {
		return fmt.Errorf("TLSA association data must be non-empty hexadecimal")
	}
	switch record.MatchingType {
	case 1:
		if len(association) != sha256.Size {
			return fmt.Errorf("TLSA SHA-256 association data must be %d bytes", sha256.Size)
		}
	case 2:
		if len(association) != 64 {
			return fmt.Errorf("TLSA SHA-512 association data must be 64 bytes")
		}
	}
	return nil
}

func rrContent(rr dns.RR) string {
	fields := strings.Fields(rr.String())
	if len(fields) < 5 {
		return ""
	}
	return strings.Join(fields[4:], " ")
}

func ParseTLSAOwner(port uint16, protocol, domain string) (string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" && protocol != "sctp" {
		return "", fmt.Errorf("TLSA protocol must be tcp, udp, or sctp")
	}
	domain = dns.Fqdn(strings.TrimSpace(domain))
	if domain == "." {
		return "", fmt.Errorf("TLSA domain is required")
	}
	return "_" + strconv.Itoa(int(port)) + "._" + protocol + "." + domain, nil
}
