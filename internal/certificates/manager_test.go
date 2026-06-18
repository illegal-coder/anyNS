package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/config"
)

type fakeIssuer struct {
	mu          sync.Mutex
	failures    int
	issues      int
	revocations int
	output      IssueOutput
}

func (f *fakeIssuer) Issue(_ context.Context, _ []string, state func(string)) (IssueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues++
	if f.failures > 0 {
		f.failures--
		return IssueOutput{}, errors.New("temporary ACME failure")
	}
	if state != nil {
		state(StatusFinalizing)
	}
	return f.output, nil
}

func (f *fakeIssuer) Revoke(_ context.Context, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revocations++
	return nil
}

func TestManagerIssueIsIdempotentAndPersistsPrivateKey(t *testing.T) {
	cfg := testConfig(t)
	issuer := &fakeIssuer{output: testCertificate(t)}
	manager, err := NewManager(cfg, issuer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	request := IssueRequest{Domains: []string{"WWW.Example.Test", "example.test"}, IdempotencyKey: "request-1"}
	first, created, err := manager.Start(request)
	if err != nil || !created {
		t.Fatalf("Start created=%v err=%v", created, err)
	}
	second, created, err := manager.Start(request)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("idempotent Start created=%v job=%+v err=%v", created, second, err)
	}
	issued := waitForStatus(t, manager, first.ID, StatusIssued)
	if issued.NotAfter == nil || issuer.issues != 1 {
		t.Fatalf("issued=%+v issues=%d", issued, issuer.issues)
	}
	keyPath := filepath.Join(cfg.StorageDir, "certs", first.ID, "private-key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%o", info.Mode().Perm())
	}
	if body, err := os.ReadFile(filepath.Join(cfg.StorageDir, "state.json")); err != nil || string(body) == "" {
		t.Fatalf("state body=%q err=%v", body, err)
	}
}

func TestManagerRetriesThenIssues(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxAttempts = 2
	issuer := &fakeIssuer{failures: 1, output: testCertificate(t)}
	manager, err := NewManager(cfg, issuer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	job, _, err := manager.Start(IssueRequest{Domains: []string{"example.test"}, IdempotencyKey: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	issued := waitForStatus(t, manager, job.ID, StatusIssued)
	if issued.Attempt != 2 || issuer.issues != 2 {
		t.Fatalf("issued=%+v issues=%d", issued, issuer.issues)
	}
}

func TestManagerFailureRenewalAndRevocation(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxAttempts = 1
	issuer := &fakeIssuer{failures: 1, output: testCertificate(t)}
	manager, err := NewManager(cfg, issuer)
	if err != nil {
		t.Fatal(err)
	}
	failed, _, err := manager.Start(IssueRequest{Domains: []string{"example.test"}, IdempotencyKey: "failure"})
	if err != nil {
		t.Fatal(err)
	}
	failed = waitForStatus(t, manager, failed.ID, StatusFailed)
	if failed.Error == "" {
		t.Fatal("failed job has no error")
	}

	issuer.failures = 0
	issued, _, err := manager.Start(IssueRequest{Domains: []string{"example.test"}, IdempotencyKey: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	issued = waitForStatus(t, manager, issued.ID, StatusIssued)
	renewed, created, err := manager.Renew(issued.ID, "renewed", true)
	if err != nil || !created {
		t.Fatalf("Renew created=%v err=%v", created, err)
	}
	_ = waitForStatus(t, manager, renewed.ID, StatusIssued)
	revoked, err := manager.Revoke(context.Background(), issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked || issuer.revocations != 1 {
		t.Fatalf("revoked=%+v count=%d", revoked, issuer.revocations)
	}
}

func TestManagerRejectsIdempotencyReplayWithDifferentDomains(t *testing.T) {
	manager, err := NewManager(testConfig(t), &fakeIssuer{output: testCertificate(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	if _, _, err := manager.Start(IssueRequest{Domains: []string{"example.test"}, IdempotencyKey: "same"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Start(IssueRequest{Domains: []string{"other.test"}, IdempotencyKey: "same"}); err == nil {
		t.Fatal("idempotency replay with different domains succeeded")
	}
}

func TestManagerRejectsStartAfterClose(t *testing.T) {
	manager, err := NewManager(testConfig(t), &fakeIssuer{output: testCertificate(t)})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if _, _, err := manager.Start(IssueRequest{
		Domains:        []string{"example.test"},
		IdempotencyKey: "closed",
	}); err == nil {
		t.Fatal("Start succeeded after Close")
	}
}

func TestManagerMarksInterruptedJobsFailedOnLoad(t *testing.T) {
	cfg := testConfig(t)
	now := time.Now().UTC().Add(-time.Minute)
	body := `[
	  {"id":"pending","domains":["example.test"],"status":"pending","created_at":"` + now.Format(time.RFC3339Nano) + `","updated_at":"` + now.Format(time.RFC3339Nano) + `"},
	  {"id":"issued","domains":["example.test"],"status":"issued","created_at":"` + now.Format(time.RFC3339Nano) + `","updated_at":"` + now.Format(time.RFC3339Nano) + `"}
	]`
	if err := os.WriteFile(filepath.Join(cfg.StorageDir, "state.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(cfg, &fakeIssuer{output: testCertificate(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)

	pending, ok := manager.Get("pending")
	if !ok || pending.Status != StatusFailed || pending.Error == "" {
		t.Fatalf("pending job=%+v ok=%v", pending, ok)
	}
	issued, ok := manager.Get("issued")
	if !ok || issued.Status != StatusIssued {
		t.Fatalf("issued job=%+v ok=%v", issued, ok)
	}
	persisted, err := os.ReadFile(filepath.Join(cfg.StorageDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), `"status": "pending"`) {
		t.Fatalf("interrupted status was not persisted: %s", persisted)
	}
}

func testConfig(t *testing.T) config.CertificatesConfig {
	t.Helper()
	return config.CertificatesConfig{
		StorageDir:            t.TempDir(),
		RequestTimeout:        5 * time.Second,
		MaxAttempts:           2,
		RenewBeforeDays:       30,
		DNSPropagationTimeout: time.Second,
		DNSPollInterval:       10 * time.Millisecond,
	}
}

func testCertificate(t *testing.T) IssueOutput {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return IssueOutput{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
	}
}

func waitForStatus(t *testing.T, manager *Manager, id, status string) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := manager.Get(id)
		if ok && job.Status == status {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, _ := manager.Get(id)
	t.Fatalf("job did not reach %s: %+v", status, job)
	return Job{}
}
