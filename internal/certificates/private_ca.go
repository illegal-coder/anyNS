package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/config"
	"golang.org/x/crypto/ocsp"
)

const (
	privateRootKeyFile    = "root-key.pem"
	privateRootCertFile   = "root-cert.pem"
	privateRootStateFile  = "root-state.json"
	privateRootBackupFile = "root-backup.json"
)

type PrivateRootIssuer struct {
	cfg      config.CertificatesConfig
	rootKey  crypto.Signer
	rootCert *x509.Certificate
	rootPEM  []byte
}

type PrivateRootMetadata struct {
	IssuerMode        string       `json:"issuer_mode"`
	Subject           string       `json:"subject"`
	Issuer            string       `json:"issuer"`
	SerialNumber      string       `json:"serial_number"`
	NotBefore         time.Time    `json:"not_before"`
	NotAfter          time.Time    `json:"not_after"`
	SHA256Fingerprint string       `json:"sha256_fingerprint"`
	SubjectKeyID      string       `json:"subject_key_id,omitempty"`
	AuthorityKeyID    string       `json:"authority_key_id,omitempty"`
	IsCA              bool         `json:"is_ca"`
	KeyUsage          []string     `json:"key_usage"`
	RootKeyPresent    bool         `json:"root_key_present"`
	RootKeyMode       string       `json:"root_key_mode,omitempty"`
	Disabled          bool         `json:"disabled"`
	DisabledAt        *time.Time   `json:"disabled_at,omitempty"`
	UpdatedAt         *time.Time   `json:"updated_at,omitempty"`
	BackupStatus      BackupStatus `json:"backup_status"`
}

type privateRootState struct {
	Disabled   bool       `json:"disabled"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type BackupStatus struct {
	Status            string     `json:"status"`
	RecordedAt        *time.Time `json:"recorded_at,omitempty"`
	SHA256Fingerprint string     `json:"sha256_fingerprint,omitempty"`
}

type privateRootBackupState struct {
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
	RecordedAt        time.Time `json:"recorded_at"`
}

func NewPrivateRootIssuer(cfg config.CertificatesConfig) (*PrivateRootIssuer, error) {
	rootDir := privateRootDir(cfg)
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("create private CA storage: %w", err)
	}
	rootKeyPath := filepath.Join(rootDir, privateRootKeyFile)
	rootCertPath := filepath.Join(rootDir, privateRootCertFile)
	key, cert, certPEM, err := loadPrivateRoot(rootKeyPath, rootCertPath)
	if err == nil {
		return &PrivateRootIssuer{cfg: cfg, rootKey: key, rootCert: cert, rootPEM: certPEM}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, cert, certPEM, err = createPrivateRoot(rootKeyPath, rootCertPath)
	if err != nil {
		return nil, err
	}
	return &PrivateRootIssuer{cfg: cfg, rootKey: key, rootCert: cert, rootPEM: certPEM}, nil
}

func PrivateRootMetadataForConfig(cfg config.CertificatesConfig) (PrivateRootMetadata, error) {
	rootDir := privateRootDir(cfg)
	rootKeyPath := filepath.Join(rootDir, privateRootKeyFile)
	rootCertPath := filepath.Join(rootDir, privateRootCertFile)
	certBody, err := os.ReadFile(rootCertPath)
	if errors.Is(err, os.ErrNotExist) {
		return PrivateRootMetadata{}, errors.New("private CA root certificate is not initialized")
	}
	if err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root certificate cannot be read")
	}
	cert, err := parseCertificatePEM(certBody)
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	metadata := privateRootMetadata(cert)
	if info, statErr := os.Stat(rootKeyPath); statErr == nil {
		metadata.RootKeyPresent = true
		metadata.RootKeyMode = fmt.Sprintf("%04o", info.Mode().Perm())
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return PrivateRootMetadata{}, errors.New("private CA root key status cannot be read")
	}
	state, err := loadPrivateRootState(cfg)
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	metadata.Disabled = state.Disabled
	metadata.DisabledAt = state.DisabledAt
	if !state.UpdatedAt.IsZero() {
		updatedAt := state.UpdatedAt
		metadata.UpdatedAt = &updatedAt
	}
	backupStatus, err := privateRootBackupStatus(cfg, metadata.SHA256Fingerprint)
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	metadata.BackupStatus = backupStatus
	return metadata, nil
}

func PrivateRootCertificatePEM(cfg config.CertificatesConfig) ([]byte, error) {
	rootCertPath := filepath.Join(privateRootDir(cfg), privateRootCertFile)
	certBody, err := os.ReadFile(rootCertPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("private CA root certificate is not initialized")
	}
	if err != nil {
		return nil, errors.New("private CA root certificate cannot be read")
	}
	cert, err := parseCertificatePEM(certBody)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateRootCertificate(cert); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

func SetPrivateRootDisabled(cfg config.CertificatesConfig, disabled bool) (PrivateRootMetadata, error) {
	if _, err := PrivateRootMetadataForConfig(cfg); err != nil {
		return PrivateRootMetadata{}, err
	}
	now := time.Now().UTC()
	state := privateRootState{Disabled: disabled, UpdatedAt: now}
	if disabled {
		state.DisabledAt = &now
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	if err := atomicWrite(filepath.Join(privateRootDir(cfg), privateRootStateFile), append(body, '\n'), 0o600); err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root state cannot be written")
	}
	return PrivateRootMetadataForConfig(cfg)
}

func RecordPrivateRootBackup(cfg config.CertificatesConfig, sha256Fingerprint string) (PrivateRootMetadata, error) {
	metadata, err := PrivateRootMetadataForConfig(cfg)
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(sha256Fingerprint), metadata.SHA256Fingerprint) {
		return PrivateRootMetadata{}, errors.New("backup fingerprint does not match current private CA root")
	}
	state := privateRootBackupState{
		SHA256Fingerprint: metadata.SHA256Fingerprint,
		RecordedAt:        time.Now().UTC(),
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	if err := atomicWrite(filepath.Join(privateRootDir(cfg), privateRootBackupFile), append(body, '\n'), 0o600); err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root backup status cannot be written")
	}
	return PrivateRootMetadataForConfig(cfg)
}

func ImportPrivateRoot(cfg config.CertificatesConfig, certPEM, keyPEM []byte) (PrivateRootMetadata, error) {
	if len(bytes.TrimSpace(certPEM)) == 0 {
		return PrivateRootMetadata{}, errors.New("private root certificate PEM is required")
	}
	if len(bytes.TrimSpace(keyPEM)) == 0 {
		return PrivateRootMetadata{}, errors.New("private root key PEM is required")
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return PrivateRootMetadata{}, err
	}
	if err := validatePrivateRoot(key, cert); err != nil {
		return PrivateRootMetadata{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return PrivateRootMetadata{}, errors.New("private root key cannot be encoded")
	}
	rootDir := privateRootDir(cfg)
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root storage cannot be created")
	}
	if err := atomicWrite(filepath.Join(rootDir, privateRootKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root key cannot be written")
	}
	if err := atomicWrite(filepath.Join(rootDir, privateRootCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root certificate cannot be written")
	}
	return PrivateRootMetadataForConfig(cfg)
}

func RotatePrivateRoot(cfg config.CertificatesConfig) (PrivateRootMetadata, error) {
	rootDir := privateRootDir(cfg)
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return PrivateRootMetadata{}, errors.New("private CA root storage cannot be created")
	}
	if _, _, _, err := createPrivateRoot(filepath.Join(rootDir, privateRootKeyFile), filepath.Join(rootDir, privateRootCertFile)); err != nil {
		return PrivateRootMetadata{}, err
	}
	return PrivateRootMetadataForConfig(cfg)
}

func PrivateRootCRLPEM(cfg config.CertificatesConfig, revokedChains [][]byte, now time.Time) ([]byte, error) {
	rootDir := privateRootDir(cfg)
	key, cert, _, err := loadPrivateRoot(filepath.Join(rootDir, privateRootKeyFile), filepath.Join(rootDir, privateRootCertFile))
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	revoked := make([]pkix.RevokedCertificate, 0, len(revokedChains))
	for _, chain := range revokedChains {
		certs, err := parseCertificateChainPEM(chain)
		if err != nil {
			return nil, err
		}
		if len(certs) == 0 {
			continue
		}
		leaf := certs[0]
		if len(leaf.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 && !bytes.Equal(leaf.AuthorityKeyId, cert.SubjectKeyId) {
			continue
		}
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   leaf.SerialNumber,
			RevocationTime: now,
		})
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificates: revoked,
		Number:              big.NewInt(now.Unix()),
		ThisUpdate:          now,
		NextUpdate:          now.Add(7 * 24 * time.Hour),
	}, cert, key)
	if err != nil {
		return nil, fmt.Errorf("create private root CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), nil
}

func PrivateRootOCSPResponse(cfg config.CertificatesConfig, certificateChainPEM []byte, revoked bool, revokedAt *time.Time, now time.Time) ([]byte, error) {
	rootDir := privateRootDir(cfg)
	key, root, _, err := loadPrivateRoot(filepath.Join(rootDir, privateRootKeyFile), filepath.Join(rootDir, privateRootCertFile))
	if err != nil {
		return nil, err
	}
	certs, err := parseCertificateChainPEM(certificateChainPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf := certs[0]
	if err := leaf.CheckSignatureFrom(root); err != nil {
		return nil, errors.New("certificate was not issued by current private CA root")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := ocsp.Good
	var revokedTime time.Time
	if revoked {
		status = ocsp.Revoked
		if revokedAt != nil && !revokedAt.IsZero() {
			revokedTime = revokedAt.UTC()
		} else {
			revokedTime = now
		}
	}
	return ocsp.CreateResponse(root, root, ocsp.Response{
		Status:           status,
		SerialNumber:     leaf.SerialNumber,
		ThisUpdate:       now.UTC(),
		NextUpdate:       now.UTC().Add(7 * 24 * time.Hour),
		RevokedAt:        revokedTime,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       crypto.SHA256,
	}, key)
}

func (i *PrivateRootIssuer) Issue(ctx context.Context, domains []string, state func(string)) (IssueOutput, error) {
	select {
	case <-ctx.Done():
		return IssueOutput{}, ctx.Err()
	default:
	}
	if len(domains) == 0 {
		return IssueOutput{}, errors.New("at least one DNS name is required")
	}
	rootState, err := loadPrivateRootState(i.cfg)
	if err != nil {
		return IssueOutput{}, err
	}
	if rootState.Disabled {
		return IssueOutput{}, errors.New("private CA root is disabled")
	}
	if state != nil {
		state(StatusFinalizing)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("generate leaf key: %w", err)
	}
	notBefore := time.Now().UTC().Add(-1 * time.Minute)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	if notAfter.After(i.rootCert.NotAfter) {
		notAfter = i.rootCert.NotAfter
	}
	serial, err := randomSerial()
	if err != nil {
		return IssueOutput{}, err
	}
	subjectKeyID, err := publicKeyID(leafKey.Public())
	if err != nil {
		return IssueOutput{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domains[0]},
		DNSNames:              append([]string(nil), domains...),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        append([]byte(nil), i.rootCert.SubjectKeyId...),
	}
	if crlURL := strings.TrimSpace(i.cfg.CRLDistributionURL); crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.rootCert, leafKey.Public(), i.rootKey)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("create leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("encode leaf key: %w", err)
	}
	var chain bytes.Buffer
	_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain.Write(i.rootPEM)
	return IssueOutput{
		CertificatePEM: chain.Bytes(),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}, nil
}

func privateRootDir(cfg config.CertificatesConfig) string {
	return filepath.Join(cfg.StorageDir, "private-ca")
}

func loadPrivateRootState(cfg config.CertificatesConfig) (privateRootState, error) {
	body, err := os.ReadFile(filepath.Join(privateRootDir(cfg), privateRootStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return privateRootState{}, nil
	}
	if err != nil {
		return privateRootState{}, errors.New("private CA root state cannot be read")
	}
	var state privateRootState
	if err := json.Unmarshal(body, &state); err != nil {
		return privateRootState{}, errors.New("private CA root state is invalid")
	}
	return state, nil
}

func loadPrivateRootBackupState(cfg config.CertificatesConfig) (privateRootBackupState, error) {
	body, err := os.ReadFile(filepath.Join(privateRootDir(cfg), privateRootBackupFile))
	if errors.Is(err, os.ErrNotExist) {
		return privateRootBackupState{}, nil
	}
	if err != nil {
		return privateRootBackupState{}, errors.New("private CA root backup status cannot be read")
	}
	var state privateRootBackupState
	if err := json.Unmarshal(body, &state); err != nil {
		return privateRootBackupState{}, errors.New("private CA root backup status is invalid")
	}
	return state, nil
}

func privateRootBackupStatus(cfg config.CertificatesConfig, currentFingerprint string) (BackupStatus, error) {
	state, err := loadPrivateRootBackupState(cfg)
	if err != nil {
		return BackupStatus{}, err
	}
	if state.SHA256Fingerprint == "" || state.RecordedAt.IsZero() {
		return BackupStatus{Status: "missing"}, nil
	}
	recordedAt := state.RecordedAt
	status := "stale"
	if state.SHA256Fingerprint == currentFingerprint {
		status = "current"
	}
	return BackupStatus{
		Status:            status,
		RecordedAt:        &recordedAt,
		SHA256Fingerprint: state.SHA256Fingerprint,
	}, nil
}

func (i *PrivateRootIssuer) Revoke(context.Context, []byte) error {
	return nil
}

func loadPrivateRoot(keyPath, certPath string) (crypto.Signer, *x509.Certificate, []byte, error) {
	keyBody, keyErr := os.ReadFile(keyPath)
	certBody, certErr := os.ReadFile(certPath)
	if errors.Is(keyErr, os.ErrNotExist) && errors.Is(certErr, os.ErrNotExist) {
		return nil, nil, nil, os.ErrNotExist
	}
	if keyErr != nil {
		return nil, nil, nil, fmt.Errorf("read private root key: %w", keyErr)
	}
	if certErr != nil {
		return nil, nil, nil, fmt.Errorf("read private root certificate: %w", certErr)
	}
	key, err := parsePrivateKeyPEM(keyBody)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := parseCertificatePEM(certBody)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validatePrivateRoot(key, cert); err != nil {
		return nil, nil, nil, err
	}
	return key, cert, certBody, nil
}

func createPrivateRoot(keyPath, certPath string) (crypto.Signer, *x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate private root key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode private root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	subjectKeyID, err := publicKeyID(key.Public())
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "anyNS Private Root CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        subjectKeyID,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create private root certificate: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := atomicWrite(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write private root key: %w", err)
	}
	if err := atomicWrite(certPath, certPEM, 0o644); err != nil {
		return nil, nil, nil, fmt.Errorf("write private root certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse private root certificate: %w", err)
	}
	return key, cert, certPEM, nil
}

func parsePrivateKeyPEM(body []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("private root key PEM is invalid")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("private root key PEM type is unsupported")
	}
	if err != nil {
		return nil, fmt.Errorf("parse private root key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private root key is not a signing key")
	}
	return signer, nil
}

func parseCertificatePEM(body []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("private root certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private root certificate: %w", err)
	}
	return cert, nil
}

func parseCertificateChainPEM(body []byte) ([]*x509.Certificate, error) {
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
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func validatePrivateRoot(key crypto.Signer, cert *x509.Certificate) error {
	if err := validatePrivateRootCertificate(cert); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return errors.New("private root key public component cannot be encoded")
	}
	certDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return errors.New("private root certificate public key cannot be encoded")
	}
	if !bytes.Equal(keyDER, certDER) {
		return errors.New("private root key does not match certificate")
	}
	return nil
}

func validatePrivateRootCertificate(cert *x509.Certificate) error {
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("private root certificate is not a valid CA")
	}
	if len(cert.SubjectKeyId) == 0 || len(cert.AuthorityKeyId) == 0 || !bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
		return errors.New("private root certificate must include matching SKI and AKI")
	}
	if time.Now().UTC().After(cert.NotAfter) {
		return errors.New("private root certificate is expired")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return errors.New("private root certificate must be self-signed")
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func publicKeyID(publicKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:], nil
}

func privateRootMetadata(cert *x509.Certificate) PrivateRootMetadata {
	fingerprint := sha256.Sum256(cert.Raw)
	return PrivateRootMetadata{
		IssuerMode:        "private-ca",
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.String(),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SHA256Fingerprint: fmt.Sprintf("%X", fingerprint[:]),
		SubjectKeyID:      fmt.Sprintf("%X", cert.SubjectKeyId),
		AuthorityKeyID:    fmt.Sprintf("%X", cert.AuthorityKeyId),
		IsCA:              cert.IsCA,
		KeyUsage:          keyUsageNames(cert.KeyUsage),
	}
}

func keyUsageNames(usage x509.KeyUsage) []string {
	flags := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	names := make([]string, 0, len(flags))
	for _, item := range flags {
		if usage&item.flag != 0 {
			names = append(names, item.name)
		}
	}
	return names
}
