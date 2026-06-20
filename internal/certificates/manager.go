package certificates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/dnsname"
)

const (
	StatusPending    = "pending"
	StatusValidating = "validating"
	StatusFinalizing = "finalizing"
	StatusIssued     = "issued"
	StatusFailed     = "failed"
	StatusRevoked    = "revoked"
)

type IssueRequest struct {
	Domains        []string `json:"domains"`
	IdempotencyKey string   `json:"idempotency_key"`
	RenewalOf      string   `json:"renewal_of,omitempty"`
}

type Job struct {
	ID             string     `json:"id"`
	Domains        []string   `json:"domains"`
	Status         string     `json:"status"`
	Attempt        int        `json:"attempt"`
	MaxAttempts    int        `json:"max_attempts"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	NotBefore      *time.Time `json:"not_before,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
	Error          string     `json:"error,omitempty"`
	RenewalOf      string     `json:"renewal_of,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	IdempotencyKey string     `json:"-"`
}

type IssueOutput struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	NotBefore      time.Time
	NotAfter       time.Time
}

type Issuer interface {
	Issue(ctx context.Context, domains []string, state func(string)) (IssueOutput, error)
	Revoke(ctx context.Context, certificatePEM []byte) error
}

type Manager struct {
	cfg    config.CertificatesConfig
	issuer Issuer

	mu   sync.RWMutex
	jobs map[string]Job
	work chan struct{}
	wg   sync.WaitGroup

	closed bool
}

func NewManager(cfg config.CertificatesConfig, issuer Issuer) (*Manager, error) {
	if issuer == nil {
		return nil, errors.New("certificate issuer is required")
	}
	if err := os.MkdirAll(filepath.Join(cfg.StorageDir, "certs"), 0o700); err != nil {
		return nil, fmt.Errorf("create certificate storage: %w", err)
	}
	manager := &Manager{
		cfg:    cfg,
		issuer: issuer,
		jobs:   map[string]Job{},
		work:   make(chan struct{}, 1),
	}
	if err := manager.load(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) Start(request IssueRequest) (Job, bool, error) {
	domains, err := normalizeDomains(request.Domains)
	if err != nil {
		return Job{}, false, err
	}
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.IdempotencyKey == "" || len(request.IdempotencyKey) > 128 {
		return Job{}, false, errors.New("idempotency_key is required and must be at most 128 characters")
	}
	id := jobID(request.IdempotencyKey)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Job{}, false, errors.New("certificate manager is closed")
	}
	if existing, ok := m.jobs[id]; ok {
		m.mu.Unlock()
		if strings.Join(existing.Domains, "\x00") != strings.Join(domains, "\x00") {
			return Job{}, false, errors.New("idempotency_key was already used for different domains")
		}
		return publicJob(existing), false, nil
	}
	now := time.Now().UTC()
	job := Job{
		ID:             id,
		Domains:        domains,
		Status:         StatusPending,
		MaxAttempts:    m.cfg.MaxAttempts,
		CreatedAt:      now,
		UpdatedAt:      now,
		RenewalOf:      strings.TrimSpace(request.RenewalOf),
		IdempotencyKey: request.IdempotencyKey,
	}
	m.jobs[id] = job
	if err := m.saveLocked(); err != nil {
		delete(m.jobs, id)
		m.mu.Unlock()
		return Job{}, false, err
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		m.run(id)
	}()
	return publicJob(job), true, nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Manager) SetIssuer(issuer Issuer) error {
	if issuer == nil {
		return errors.New("certificate issuer is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("certificate manager is closed")
	}
	m.issuer = issuer
	return nil
}

func (m *Manager) Get(id string) (Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	return publicJob(job), ok
}

func (m *Manager) List() []Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		out = append(out, publicJob(job))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *Manager) Renew(id, idempotencyKey string, force bool) (Job, bool, error) {
	current, ok := m.Get(id)
	if !ok {
		return Job{}, false, errors.New("certificate job not found")
	}
	if current.Status != StatusIssued {
		return Job{}, false, errors.New("only issued certificates can be renewed")
	}
	if !force && current.NotAfter != nil {
		renewAt := current.NotAfter.Add(-time.Duration(m.cfg.RenewBeforeDays) * 24 * time.Hour)
		if time.Now().UTC().Before(renewAt) {
			return Job{}, false, fmt.Errorf("certificate is not due for renewal before %s", renewAt.Format(time.RFC3339))
		}
	}
	return m.Start(IssueRequest{
		Domains:        current.Domains,
		IdempotencyKey: idempotencyKey,
		RenewalOf:      current.ID,
	})
}

func (m *Manager) Revoke(ctx context.Context, id string) (Job, error) {
	current, ok := m.Get(id)
	if !ok {
		return Job{}, errors.New("certificate job not found")
	}
	if current.Status == StatusRevoked {
		return current, nil
	}
	if current.Status != StatusIssued {
		return Job{}, errors.New("only issued certificates can be revoked")
	}
	certificatePEM, err := m.CertificatePEM(id)
	if err != nil {
		return Job{}, err
	}
	m.mu.RLock()
	issuer := m.issuer
	m.mu.RUnlock()
	if err := issuer.Revoke(ctx, certificatePEM); err != nil {
		return Job{}, err
	}
	now := time.Now().UTC()
	m.mu.Lock()
	job := m.jobs[id]
	job.Status = StatusRevoked
	job.RevokedAt = &now
	job.UpdatedAt = now
	job.Error = ""
	m.jobs[id] = job
	err = m.saveLocked()
	m.mu.Unlock()
	return publicJob(job), err
}

func (m *Manager) CertificatePEM(id string) ([]byte, error) {
	job, ok := m.Get(id)
	if !ok || (job.Status != StatusIssued && job.Status != StatusRevoked) {
		return nil, errors.New("certificate is not available")
	}
	return os.ReadFile(filepath.Join(m.cfg.StorageDir, "certs", id, "fullchain.pem"))
}

func (m *Manager) RevokedCertificatePEMs() ([][]byte, error) {
	m.mu.RLock()
	ids := make([]string, 0)
	for _, job := range m.jobs {
		if job.Status == StatusRevoked {
			ids = append(ids, job.ID)
		}
	}
	m.mu.RUnlock()
	sort.Strings(ids)
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		body, err := os.ReadFile(filepath.Join(m.cfg.StorageDir, "certs", id, "fullchain.pem"))
		if err != nil {
			return nil, err
		}
		out = append(out, body)
	}
	return out, nil
}

func (m *Manager) run(id string) {
	m.work <- struct{}{}
	defer func() { <-m.work }()

	for attempt := 1; attempt <= m.cfg.MaxAttempts; attempt++ {
		m.update(id, func(job *Job) {
			job.Attempt = attempt
			job.Status = StatusValidating
			job.Error = ""
		})
		m.mu.RLock()
		domains := append([]string(nil), m.jobs[id].Domains...)
		issuer := m.issuer
		m.mu.RUnlock()
		ctx, cancel := context.WithTimeout(context.Background(), m.cfg.RequestTimeout)
		output, err := issuer.Issue(ctx, domains, func(status string) {
			if status == StatusFinalizing {
				m.update(id, func(job *Job) { job.Status = StatusFinalizing })
			}
		})
		cancel()
		if err == nil {
			err = m.saveCertificate(id, output)
		}
		if err == nil {
			m.update(id, func(job *Job) {
				job.Status = StatusIssued
				job.NotBefore = timePointer(output.NotBefore.UTC())
				job.NotAfter = timePointer(output.NotAfter.UTC())
				job.Error = ""
			})
			return
		}
		m.update(id, func(job *Job) {
			job.Error = sanitizedError(err)
			if attempt == m.cfg.MaxAttempts {
				job.Status = StatusFailed
			} else {
				job.Status = StatusPending
			}
		})
		if attempt < m.cfg.MaxAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
}

func (m *Manager) update(id string, mutate func(*Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return
	}
	mutate(&job)
	job.UpdatedAt = time.Now().UTC()
	m.jobs[id] = job
	_ = m.saveLocked()
}

func (m *Manager) saveCertificate(id string, output IssueOutput) error {
	dir := filepath.Join(m.cfg.StorageDir, "certs", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, "fullchain.pem"), output.CertificatePEM, 0o600); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "private-key.pem"), output.PrivateKeyPEM, 0o600)
}

func (m *Manager) load() error {
	body, err := os.ReadFile(filepath.Join(m.cfg.StorageDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read certificate state: %w", err)
	}
	var jobs []Job
	if err := json.Unmarshal(body, &jobs); err != nil {
		return fmt.Errorf("decode certificate state: %w", err)
	}
	changed := false
	for _, job := range jobs {
		if job.Status == StatusPending || job.Status == StatusValidating || job.Status == StatusFinalizing {
			job.Status = StatusFailed
			job.Error = "issuance interrupted by process restart; submit a new idempotency key"
			job.UpdatedAt = time.Now().UTC()
			changed = true
		}
		m.jobs[job.ID] = job
	}
	if changed {
		return m.saveLocked()
	}
	return nil
}

func (m *Manager) saveLocked() error {
	jobs := make([]Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.Before(jobs[j].CreatedAt) })
	body, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.cfg.StorageDir, "state.json"), append(body, '\n'), 0o600)
}

func atomicWrite(path string, body []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".anyns-certificate-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func normalizeDomains(domains []string) ([]string, error) {
	if len(domains) == 0 || len(domains) > 10 {
		return nil, errors.New("between 1 and 10 domains are required")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(domains))
	for index, domain := range domains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		wildcard := strings.HasPrefix(domain, "*.")
		if wildcard {
			domain = strings.TrimPrefix(domain, "*.")
		}
		ascii, err := dnsname.ToASCII(domain)
		if err != nil {
			return nil, fmt.Errorf("domains[%d] is invalid: %w", index, err)
		}
		ascii = strings.TrimSuffix(ascii, ".")
		if ascii == "" || ascii == "." {
			return nil, fmt.Errorf("domains[%d] is required", index)
		}
		if wildcard {
			ascii = "*." + ascii
		}
		if !seen[ascii] {
			seen[ascii] = true
			out = append(out, ascii)
		}
	}
	sort.Strings(out)
	return out, nil
}

func jobID(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return hex.EncodeToString(sum[:16])
}

func sanitizedError(err error) string {
	message := strings.TrimSpace(err.Error())
	message = strings.ReplaceAll(message, "\r", " ")
	message = strings.ReplaceAll(message, "\n", " ")
	if len(message) > 500 {
		message = message[:500]
	}
	return message
}

func publicJob(job Job) Job {
	job.IdempotencyKey = ""
	return job
}

func timePointer(value time.Time) *time.Time {
	return &value
}
