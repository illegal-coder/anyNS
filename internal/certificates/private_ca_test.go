package certificates

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/config"
)

func TestPrivateRootIssuerCreatesRootAndIssuesLeafChain(t *testing.T) {
	cfg := config.CertificatesConfig{StorageDir: t.TempDir()}
	issuer, err := NewPrivateRootIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rootKeyPath := filepath.Join(cfg.StorageDir, "private-ca", privateRootKeyFile)
	rootCertPath := filepath.Join(cfg.StorageDir, "private-ca", privateRootCertFile)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(rootKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("root private key mode=%o", info.Mode().Perm())
		}
	}
	rootPEM, err := os.ReadFile(rootCertPath)
	if err != nil {
		t.Fatal(err)
	}
	root := firstCertificate(t, rootPEM)
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("root CA constraints invalid: isCA=%v keyUsage=%v", root.IsCA, root.KeyUsage)
	}
	if len(root.SubjectKeyId) == 0 || !bytes.Equal(root.SubjectKeyId, root.AuthorityKeyId) {
		t.Fatalf("root SKI/AKI invalid: ski=%x aki=%x", root.SubjectKeyId, root.AuthorityKeyId)
	}

	var status string
	output, err := issuer.Issue(context.Background(), []string{"example.test", "*.example.test"}, func(next string) {
		status = next
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusFinalizing {
		t.Fatalf("issuer status=%q", status)
	}
	certs := certificateChain(t, output.CertificatePEM)
	if len(certs) != 2 {
		t.Fatalf("chain length=%d", len(certs))
	}
	leaf := certs[0]
	if leaf.IsCA {
		t.Fatal("leaf certificate is a CA")
	}
	if !bytes.Equal(leaf.AuthorityKeyId, root.SubjectKeyId) {
		t.Fatalf("leaf AKI=%x root SKI=%x", leaf.AuthorityKeyId, root.SubjectKeyId)
	}
	if !containsExtKeyUsage(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("leaf EKU=%v", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatalf("leaf key usage=%v", leaf.KeyUsage)
	}
	if !stringSlicesEqual(leaf.DNSNames, []string{"example.test", "*.example.test"}) {
		t.Fatalf("leaf DNSNames=%v", leaf.DNSNames)
	}
	if leaf.NotAfter.After(root.NotAfter) {
		t.Fatalf("leaf NotAfter %s exceeds root %s", leaf.NotAfter, root.NotAfter)
	}
	if err := leaf.CheckSignatureFrom(root); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}
	if output.NotBefore.IsZero() || output.NotAfter.Before(time.Now().UTC()) {
		t.Fatalf("invalid output validity: %+v", output)
	}
	if len(output.PrivateKeyPEM) == 0 {
		t.Fatal("leaf private key was not returned to manager storage path")
	}
	if block, _ := pem.Decode(output.PrivateKeyPEM); block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("leaf private key PEM block=%v", block)
	}
}

func TestPrivateRootIssuerReloadsExistingRoot(t *testing.T) {
	cfg := config.CertificatesConfig{StorageDir: t.TempDir()}
	first, err := NewPrivateRootIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPrivateRootIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.rootCert.Raw, second.rootCert.Raw) {
		t.Fatal("private root was regenerated instead of reloaded")
	}
}

func TestPrivateRootMetadataExcludesPEMAndKeyMaterial(t *testing.T) {
	cfg := config.CertificatesConfig{StorageDir: t.TempDir()}
	if _, err := NewPrivateRootIssuer(cfg); err != nil {
		t.Fatal(err)
	}
	metadata, err := PrivateRootMetadataForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.IssuerMode != "private-ca" || !metadata.IsCA {
		t.Fatalf("metadata=%+v", metadata)
	}
	if metadata.SHA256Fingerprint == "" || metadata.SerialNumber == "" || metadata.SubjectKeyID == "" {
		t.Fatalf("metadata missing identity fields: %+v", metadata)
	}
	if !containsString(metadata.KeyUsage, "cert_sign") || !containsString(metadata.KeyUsage, "crl_sign") {
		t.Fatalf("metadata key usage=%v", metadata.KeyUsage)
	}
	if !metadata.RootKeyPresent || metadata.RootKeyMode != "0600" {
		t.Fatalf("root key metadata=%+v", metadata)
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("BEGIN ")) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatalf("metadata leaked PEM/key material: %s", body)
	}
}

func TestPrivateRootDisableBlocksIssuanceAndPersists(t *testing.T) {
	cfg := config.CertificatesConfig{StorageDir: t.TempDir()}
	issuer, err := NewPrivateRootIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := SetPrivateRootDisabled(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.Disabled || metadata.DisabledAt == nil || metadata.UpdatedAt == nil {
		t.Fatalf("disabled metadata=%+v", metadata)
	}
	if _, err := issuer.Issue(context.Background(), []string{"blocked.example"}, nil); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled issue err=%v", err)
	}
	reloaded, err := NewPrivateRootIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Issue(context.Background(), []string{"still-blocked.example"}, nil); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("reloaded disabled issue err=%v", err)
	}
	metadata, err = SetPrivateRootDisabled(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Disabled || metadata.DisabledAt != nil {
		t.Fatalf("enabled metadata=%+v", metadata)
	}
	if _, err := reloaded.Issue(context.Background(), []string{"allowed.example"}, nil); err != nil {
		t.Fatalf("enabled issue: %v", err)
	}
}

func TestPrivateRootBackupStatusRequiresCurrentFingerprint(t *testing.T) {
	cfg := config.CertificatesConfig{StorageDir: t.TempDir()}
	if _, err := NewPrivateRootIssuer(cfg); err != nil {
		t.Fatal(err)
	}
	metadata, err := PrivateRootMetadataForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BackupStatus.Status != "missing" {
		t.Fatalf("initial backup status=%+v", metadata.BackupStatus)
	}
	if _, err := RecordPrivateRootBackup(cfg, "BADF00D"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched backup err=%v", err)
	}
	metadata, err = RecordPrivateRootBackup(cfg, strings.ToLower(metadata.SHA256Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BackupStatus.Status != "current" || metadata.BackupStatus.RecordedAt == nil || metadata.BackupStatus.SHA256Fingerprint != metadata.SHA256Fingerprint {
		t.Fatalf("current backup status=%+v metadata=%+v", metadata.BackupStatus, metadata)
	}
	stale := privateRootBackupState{SHA256Fingerprint: "00", RecordedAt: time.Now().UTC()}
	body, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(privateRootDir(cfg), privateRootBackupFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	metadata, err = PrivateRootMetadataForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BackupStatus.Status != "stale" {
		t.Fatalf("stale backup status=%+v", metadata.BackupStatus)
	}
}

func TestImportPrivateRootReplacesRootAndRequiresMatchingKey(t *testing.T) {
	cfg := config.CertificatesConfig{StorageDir: t.TempDir()}
	if _, err := NewPrivateRootIssuer(cfg); err != nil {
		t.Fatal(err)
	}
	original, err := PrivateRootMetadataForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordPrivateRootBackup(cfg, original.SHA256Fingerprint); err != nil {
		t.Fatal(err)
	}

	importDir := t.TempDir()
	importKeyPath := filepath.Join(importDir, "root-key.pem")
	importCertPath := filepath.Join(importDir, "root-cert.pem")
	_, importCert, _, err := createPrivateRoot(importKeyPath, importCertPath)
	if err != nil {
		t.Fatal(err)
	}
	importKeyPEM, err := os.ReadFile(importKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	importCertPEM, err := os.ReadFile(importCertPath)
	if err != nil {
		t.Fatal(err)
	}

	mismatchDir := t.TempDir()
	mismatchKeyPath := filepath.Join(mismatchDir, "root-key.pem")
	mismatchCertPath := filepath.Join(mismatchDir, "root-cert.pem")
	if _, _, _, err := createPrivateRoot(mismatchKeyPath, mismatchCertPath); err != nil {
		t.Fatal(err)
	}
	mismatchKeyPEM, err := os.ReadFile(mismatchKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportPrivateRoot(cfg, importCertPEM, mismatchKeyPEM); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched import err=%v", err)
	}
	afterMismatch, err := PrivateRootMetadataForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if afterMismatch.SHA256Fingerprint != original.SHA256Fingerprint {
		t.Fatalf("mismatched import changed root: before=%s after=%s", original.SHA256Fingerprint, afterMismatch.SHA256Fingerprint)
	}

	imported, err := ImportPrivateRoot(cfg, importCertPEM, importKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if imported.SHA256Fingerprint == original.SHA256Fingerprint {
		t.Fatalf("import did not replace root fingerprint=%s", imported.SHA256Fingerprint)
	}
	if imported.BackupStatus.Status != "stale" {
		t.Fatalf("backup status after import=%+v", imported.BackupStatus)
	}
	if !imported.RootKeyPresent || imported.RootKeyMode != "0600" {
		t.Fatalf("imported root key metadata=%+v", imported)
	}
	issuer, err := NewPrivateRootIssuer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	output, err := issuer.Issue(context.Background(), []string{"imported.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := certificateChain(t, output.CertificatePEM)
	if len(chain) != 2 {
		t.Fatalf("chain length=%d", len(chain))
	}
	if !bytes.Equal(chain[1].Raw, importCert.Raw) {
		t.Fatal("issued chain did not include imported root")
	}
	if err := chain[0].CheckSignatureFrom(importCert); err != nil {
		t.Fatalf("leaf signature from imported root: %v", err)
	}
}

func containsExtKeyUsage(values []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func firstCertificate(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	certs := certificateChain(t, body)
	if len(certs) == 0 {
		t.Fatal("no certificate found")
	}
	return certs[0]
}

func certificateChain(t *testing.T, body []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(body)
		if block == nil {
			break
		}
		body = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
	return certs
}
