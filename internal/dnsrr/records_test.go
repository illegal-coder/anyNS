package dnsrr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNormalizeSecurityRecords(t *testing.T) {
	dsDigest := strings.Repeat("ab", 32)
	tlsaDigest := strings.Repeat("cd", 32)
	tests := []struct {
		recordType string
		content    string
		want       string
	}{
		{recordType: "DS", content: "12345 13 2 " + dsDigest, want: "12345 13 2 " + strings.ToUpper(dsDigest)},
		{recordType: "DNSKEY", content: "257 3 13 AQIDBA==", want: "257 3 13 AQIDBA=="},
		{recordType: "TLSA", content: "3 1 1 " + tlsaDigest, want: "3 1 1 " + strings.ToUpper(tlsaDigest)},
		{recordType: "CAA", content: `0 ISSUE "letsencrypt.org"`, want: `0 issue "letsencrypt.org"`},
		{recordType: "NS", content: "ns1.example.", want: "ns1.example."},
	}
	for _, tt := range tests {
		t.Run(tt.recordType, func(t *testing.T) {
			got, err := Normalize("example.", tt.recordType, tt.content)
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Normalize=%q want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeRejectsMalformedSecurityRecords(t *testing.T) {
	tests := []struct {
		recordType string
		content    string
	}{
		{recordType: "DS", content: "12345 13 2 ABCD"},
		{recordType: "DS", content: "12345 13 3 " + strings.Repeat("AB", 32)},
		{recordType: "DNSKEY", content: "257 2 13 AQIDBA=="},
		{recordType: "DNSKEY", content: "257 3 13 not-base64"},
		{recordType: "TLSA", content: "4 1 1 " + strings.Repeat("AB", 32)},
		{recordType: "TLSA", content: "3 2 1 " + strings.Repeat("AB", 32)},
		{recordType: "TLSA", content: "3 1 1 ABCD"},
		{recordType: "CAA", content: `0 bad-tag "ca.example"`},
	}
	for _, tt := range tests {
		t.Run(tt.recordType+"-"+tt.content[:2], func(t *testing.T) {
			if _, err := Normalize("example.", tt.recordType, tt.content); err == nil {
				t.Fatalf("Normalize(%s, %q) succeeded", tt.recordType, tt.content)
			}
		})
	}
}

func TestDSFromDNSKEY(t *testing.T) {
	got, err := DSFromDNSKEY(
		"example.",
		"257 3 13 m5OSnKq7UTi6UjJ6pZcE2P1pHW0RrQ5P4P6xQmJ3Y7n8jP1wM2xL6Wf4dYt5Yq5xVhQm1qgA2v8Qm3pP7Q==",
		2,
	)
	if err != nil {
		t.Fatalf("DSFromDNSKEY: %v", err)
	}
	fields := strings.Fields(got)
	if len(fields) != 4 || fields[2] != "2" || len(fields[3]) != 64 {
		t.Fatalf("DS=%q", got)
	}
}

func TestTLSAFromCertificatePEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	got, err := TLSAFromCertificatePEM(certificatePEM, 3, 1, 1)
	if err != nil {
		t.Fatalf("TLSAFromCertificatePEM: %v", err)
	}
	fields := strings.Fields(got)
	if len(fields) != 4 || fields[0] != "3" || fields[1] != "1" || fields[2] != "1" || len(fields[3]) != 64 {
		t.Fatalf("TLSA=%q", got)
	}
}

func TestParseTLSAOwner(t *testing.T) {
	got, err := ParseTLSAOwner(443, "TCP", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if got != "_443._tcp.example.test." {
		t.Fatalf("owner=%q", got)
	}
	if _, err := ParseTLSAOwner(443, "http", "example.test"); err == nil {
		t.Fatal("invalid protocol accepted")
	}
}
