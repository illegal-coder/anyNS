package certificates

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/anyns/anyns/internal/config"
)

type DNS01Provider interface {
	Present(ctx context.Context, fqdn, value string) error
	Cleanup(ctx context.Context, fqdn, value string) error
}

type ACMEIssuer struct {
	cfg      config.CertificatesConfig
	provider DNS01Provider
	client   *acme.Client
}

func NewACMEIssuer(cfg config.CertificatesConfig, provider DNS01Provider) (*ACMEIssuer, error) {
	if provider == nil {
		return nil, errors.New("DNS-01 provider is required")
	}
	key, err := loadOrCreateAccountKey(filepath.Join(cfg.StorageDir, "account-key.pem"))
	if err != nil {
		return nil, err
	}
	return &ACMEIssuer{
		cfg:      cfg,
		provider: provider,
		client: &acme.Client{
			Key:          key,
			DirectoryURL: cfg.DirectoryURL,
		},
	}, nil
}

func (i *ACMEIssuer) Issue(ctx context.Context, domains []string, state func(string)) (IssueOutput, error) {
	account, err := i.client.Register(ctx, &acme.Account{
		Contact: []string{"mailto:" + i.cfg.AccountEmail},
	}, func(string) bool { return i.cfg.AcceptTOS })
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return IssueOutput{}, fmt.Errorf("register ACME account: %w", err)
	}
	if account != nil && account.URI != "" {
		i.client.KID = acme.KeyID(account.URI)
	}

	identifiers := make([]acme.AuthzID, 0, len(domains))
	for _, domain := range domains {
		identifiers = append(identifiers, acme.AuthzID{Type: "dns", Value: domain})
	}
	order, err := i.client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("create ACME order: %w", err)
	}
	orderURL := order.URI
	if strings.TrimSpace(orderURL) == "" {
		return IssueOutput{}, errors.New("ACME order did not include an order URL")
	}
	finalizeURL, err := selectFinalizeURL(order.FinalizeURL, "")
	if err != nil {
		return IssueOutput{}, err
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := i.client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return IssueOutput{}, fmt.Errorf("read ACME authorization: %w", err)
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := dnsChallenge(authorization.Challenges)
		if challenge == nil {
			return IssueOutput{}, fmt.Errorf("ACME server did not offer dns-01 for %s", authorization.Identifier.Value)
		}
		value, err := i.client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return IssueOutput{}, fmt.Errorf("build dns-01 record: %w", err)
		}
		domain := strings.TrimPrefix(authorization.Identifier.Value, "*.")
		fqdn := "_acme-challenge." + strings.TrimSuffix(domain, ".") + "."
		if err := i.provider.Present(ctx, fqdn, value); err != nil {
			return IssueOutput{}, fmt.Errorf("present dns-01 record: %w", err)
		}
		cleanup := func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = i.provider.Cleanup(cleanupCtx, fqdn, value)
		}
		if err := waitForTXT(ctx, fqdn, value, i.cfg.DNSPropagationTimeout, i.cfg.DNSPollInterval); err != nil {
			cleanup()
			return IssueOutput{}, err
		}
		if _, err := i.client.Accept(ctx, challenge); err != nil {
			cleanup()
			return IssueOutput{}, fmt.Errorf("accept dns-01 challenge: %w", err)
		}
		if _, err := i.client.WaitAuthorization(ctx, authorizationURL); err != nil {
			cleanup()
			return IssueOutput{}, fmt.Errorf("wait for dns-01 authorization: %w", err)
		}
		cleanup()
	}
	if state != nil {
		state(StatusFinalizing)
	}
	order, err = i.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("wait for ACME order: %w", err)
	}
	finalizeURL, err = selectFinalizeURL(finalizeURL, order.FinalizeURL)
	if err != nil {
		return IssueOutput{}, err
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("generate certificate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certificateKey)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("create certificate request: %w", err)
	}
	chainDER, _, err := i.client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if isEmptyACMEPollURLError(err) {
		recoveredOrder, waitErr := i.client.WaitOrder(ctx, orderURL)
		if waitErr != nil {
			return IssueOutput{}, fmt.Errorf("recover finalized ACME order: %w", waitErr)
		}
		if strings.TrimSpace(recoveredOrder.CertURL) == "" {
			return IssueOutput{}, errors.New("finalized ACME order did not include a certificate URL")
		}
		chainDER, err = i.client.FetchCert(ctx, recoveredOrder.CertURL, true)
	}
	if err != nil {
		return IssueOutput{}, fmt.Errorf("finalize ACME order: %w", err)
	}
	if len(chainDER) == 0 {
		return IssueOutput{}, errors.New("ACME server returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return IssueOutput{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	var certificatePEM []byte
	for _, der := range chainDER {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificateKey)
	if err != nil {
		return IssueOutput{}, fmt.Errorf("encode certificate key: %w", err)
	}
	return IssueOutput{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotBefore:      leaf.NotBefore,
		NotAfter:       leaf.NotAfter,
	}, nil
}

func (i *ACMEIssuer) Revoke(ctx context.Context, certificatePEM []byte) error {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("stored certificate is invalid")
	}
	// A nil signer selects account KID authorization. Passing the account key
	// explicitly would embed it as a JWK and incorrectly claim it is the
	// certificate private key.
	if err := i.client.RevokeCert(ctx, nil, block.Bytes, acme.CRLReasonUnspecified); err != nil {
		return fmt.Errorf("revoke ACME certificate: %w", err)
	}
	return nil
}

func dnsChallenge(challenges []*acme.Challenge) *acme.Challenge {
	for _, challenge := range challenges {
		if challenge != nil && challenge.Type == "dns-01" {
			return challenge
		}
	}
	return nil
}

func selectFinalizeURL(created, refreshed string) (string, error) {
	if strings.TrimSpace(refreshed) != "" {
		return refreshed, nil
	}
	if strings.TrimSpace(created) != "" {
		return created, nil
	}
	return "", errors.New("ACME order did not include a finalize URL")
}

func isEmptyACMEPollURLError(err error) bool {
	var requestError *url.Error
	return errors.As(err, &requestError) && requestError.URL == ""
}

func waitForTXT(ctx context.Context, fqdn, value string, timeout, poll time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if poll <= 0 {
		poll = 2 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		records, err := net.DefaultResolver.LookupTXT(waitCtx, fqdn)
		if err == nil {
			for _, record := range records {
				if record == value {
					return nil
				}
			}
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("dns-01 TXT record %s did not propagate before timeout", fqdn)
		case <-ticker.C:
		}
	}
}

func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	body, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(body)
		if block == nil {
			return nil, errors.New("ACME account key PEM is invalid")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("ACME account key is not a signing key")
		}
		return signer, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ACME account key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
