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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/anyns/anyns/internal/config"
)

const (
	privateRootKeyFile  = "root-key.pem"
	privateRootCertFile = "root-cert.pem"
)

type PrivateRootIssuer struct {
	cfg      config.CertificatesConfig
	rootKey  crypto.Signer
	rootCert *x509.Certificate
	rootPEM  []byte
}

func NewPrivateRootIssuer(cfg config.CertificatesConfig) (*PrivateRootIssuer, error) {
	rootDir := filepath.Join(cfg.StorageDir, "private-ca")
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

func (i *PrivateRootIssuer) Issue(ctx context.Context, domains []string, state func(string)) (IssueOutput, error) {
	select {
	case <-ctx.Done():
		return IssueOutput{}, ctx.Err()
	default:
	}
	if len(domains) == 0 {
		return IssueOutput{}, errors.New("at least one DNS name is required")
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
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, nil, errors.New("private root certificate is not a CA")
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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
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
