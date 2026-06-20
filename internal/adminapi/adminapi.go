package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/app"
	"github.com/anyns/anyns/internal/certificates"
	"github.com/anyns/anyns/internal/config"
	"github.com/anyns/anyns/internal/controlplane"
	"github.com/anyns/anyns/internal/dnsrr"
	"github.com/anyns/anyns/internal/httpapi"
	"github.com/anyns/anyns/internal/powerdns"
)

type Handler struct {
	application      *app.App
	cfg              *config.Config
	httpClient       *http.Client
	certificates     *certificates.Manager
	certificateError string
}

type ServiceStatus struct {
	Configured bool   `json:"configured"`
	Healthy    bool   `json:"healthy"`
	URL        string `json:"url,omitempty"`
	Error      string `json:"error,omitempty"`
}

type FeatureCapability struct {
	Available bool     `json:"available"`
	Read      bool     `json:"read"`
	Write     bool     `json:"write"`
	Mode      string   `json:"mode"`
	Reason    string   `json:"reason,omitempty"`
	Endpoints []string `json:"endpoints"`
}

type CapabilitiesResponse struct {
	Version     int                          `json:"version"`
	GeneratedAt time.Time                    `json:"generated_at"`
	Features    map[string]FeatureCapability `json:"features"`
}

func Register(mux *http.ServeMux, application *app.App, cfg *config.Config) {
	handler := &Handler{
		application: application,
		cfg:         cfg,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	if cfg.Certificates.Enabled {
		issuer, err := certificateIssuer(*cfg)
		if err == nil {
			handler.certificates, err = certificates.NewManager(cfg.Certificates, issuer)
		}
		if err != nil {
			handler.certificateError = err.Error()
		}
	}
	mux.HandleFunc("/api/v1/capabilities", handler.capabilities)
	mux.HandleFunc("/api/v1/dashboard", handler.dashboard)
	mux.HandleFunc("/api/v1/configuration", handler.configuration)
	mux.HandleFunc("/api/v1/powerdns/status", handler.powerDNSStatus)
	mux.HandleFunc("/api/v1/powerdns/zones", handler.powerDNSZones)
	mux.HandleFunc("/api/v1/powerdns/authoritative/zones", handler.authoritativeZones)
	mux.HandleFunc("/api/v1/powerdns/authoritative/zones/", handler.authoritativeZone)
	mux.HandleFunc("/api/v1/powerdns/recursor/cache/flush", handler.recursorCacheFlush)
	mux.HandleFunc("/api/v1/certificates/orders", handler.certificateOrders)
	mux.HandleFunc("/api/v1/certificates/orders/", handler.certificateOrder)
	mux.HandleFunc("/api/v1/certificates/private-ca/crl", handler.certificatePrivateCACRL)
	mux.HandleFunc("/api/v1/certificates/private-ca/root", handler.certificatePrivateCARoot)
	mux.HandleFunc("/api/v1/certificates/private-ca/root/backup-status", handler.certificatePrivateCARootBackupStatus)
	mux.HandleFunc("/api/v1/certificates/private-ca/root/import", handler.certificatePrivateCARootImport)
	mux.HandleFunc("/api/v1/certificates/private-ca/root/rotate", handler.certificatePrivateCARootRotate)
	mux.HandleFunc("/api/v1/certificates/tlsa", handler.certificateTLSA)
}

func certificateIssuer(cfg config.Config) (certificates.Issuer, error) {
	switch strings.TrimSpace(cfg.Certificates.IssuerMode) {
	case "", "acme":
		provider := certificates.NewPowerDNSProvider(powerdns.New(cfg.PowerDNS))
		return certificates.NewACMEIssuer(cfg.Certificates, provider)
	case "private-ca":
		return certificates.NewPrivateRootIssuer(cfg.Certificates)
	default:
		return nil, fmt.Errorf("unsupported certificate issuer mode %q", cfg.Certificates.IssuerMode)
	}
}

func (h *Handler) capabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.PrincipalFromRequest(r, current)
	if !ok {
		httpapi.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	editable := current.Editable()
	authoritativeConfigured := strings.TrimSpace(current.PowerDNS.AuthoritativeURL) != ""
	recursorConfigured := strings.TrimSpace(current.PowerDNS.RecursorURL) != ""
	powerDNSConfigured := authoritativeConfigured || recursorConfigured
	policyConfigured := strings.TrimSpace(current.ConfigFile) != ""
	certificatesAvailable := current.Certificates.Enabled && h.certificates != nil

	feature := func(readScope, writeScope string, available, writable bool, endpoints ...string) FeatureCapability {
		read := principal.HasScope(readScope)
		write := read && writable && writeScope != "" && principal.HasScope(writeScope)
		mode := "hidden"
		reason := "access_denied"
		switch {
		case !read:
		case !available:
			mode = "unavailable"
			reason = "backend_not_configured"
			write = false
		case write:
			mode = "readwrite"
			reason = ""
		default:
			mode = "readonly"
			reason = "write_not_available"
		}
		return FeatureCapability{
			Available: available,
			Read:      read,
			Write:     write,
			Mode:      mode,
			Reason:    reason,
			Endpoints: endpoints,
		}
	}

	features := map[string]FeatureCapability{
		"overview": feature(httpapi.ScopeManagementRead, "", true, false, "GET /api/v1/dashboard"),
		"powerdns": feature(
			httpapi.ScopePowerDNSRead, httpapi.ScopePowerDNSWrite, powerDNSConfigured, true,
			"GET /api/v1/powerdns/status",
			"GET /api/v1/powerdns/zones",
		),
		"powerdns_authoritative": feature(
			httpapi.ScopePowerDNSRead, httpapi.ScopePowerDNSWrite, authoritativeConfigured, true,
			"POST /api/v1/powerdns/authoritative/zones",
			"GET /api/v1/powerdns/authoritative/zones/{id}",
			"PATCH /api/v1/powerdns/authoritative/zones/{id}/soa",
			"PATCH /api/v1/powerdns/authoritative/zones/{id}/rrsets",
			"GET /api/v1/powerdns/authoritative/zones/{id}/cryptokeys",
			"POST /api/v1/powerdns/authoritative/zones/{id}/cryptokeys",
			"DELETE /api/v1/powerdns/authoritative/zones/{id}/cryptokeys/{key_id}",
			"POST /api/v1/powerdns/authoritative/zones/{id}/derive-ds",
			"DELETE /api/v1/powerdns/authoritative/zones/{id}",
		),
		"powerdns_recursor": feature(
			httpapi.ScopePowerDNSRead, httpapi.ScopePowerDNSWrite, recursorConfigured, true,
			"POST /api/v1/powerdns/recursor/cache/flush",
		),
		"certificates": feature(
			httpapi.ScopeCertificatesRead, httpapi.ScopeCertificatesWrite, certificatesAvailable, true,
			"GET /api/v1/certificates/orders",
			"POST /api/v1/certificates/orders",
			"GET /api/v1/certificates/orders/{id}",
			"GET /api/v1/certificates/orders/{id}/certificate",
			"POST /api/v1/certificates/orders/{id}/renew",
			"POST /api/v1/certificates/orders/{id}/revoke",
			"GET /api/v1/certificates/private-ca/crl",
			"GET /api/v1/certificates/private-ca/root",
			"PATCH /api/v1/certificates/private-ca/root",
			"POST /api/v1/certificates/private-ca/root/backup-status",
			"POST /api/v1/certificates/private-ca/root/import",
			"POST /api/v1/certificates/private-ca/root/rotate",
			"POST /api/v1/certificates/tlsa",
		),
		"plugins": feature(
			httpapi.ScopePluginsRead, httpapi.ScopePluginsWrite, true, true,
			"GET /api/v1/plugins",
			"POST /api/v1/plugins/{name}/enable",
			"POST /api/v1/plugins/{name}/disable",
		),
		"security": feature(
			httpapi.ScopeConfigRead, httpapi.ScopeConfigWrite, true, editable.Writable,
			"GET /api/v1/configuration",
			"PUT /api/v1/configuration",
		),
		"audit": feature(
			httpapi.ScopeAuditRead, "", true, false,
			"GET /api/v1/audit/events",
			"GET /api/v1/audit/summary",
		),
		"config": feature(
			httpapi.ScopeConfigRead, httpapi.ScopeConfigWrite, true, editable.Writable,
			"GET /api/v1/configuration",
			"PUT /api/v1/configuration",
		),
		"cache": feature(
			httpapi.ScopeCacheRead, httpapi.ScopeCacheWrite, true, true,
			"GET /api/v1/cache/stats",
			"POST /api/v1/cache/flush",
		),
		"policy": feature(
			httpapi.ScopeManagementRead, httpapi.ScopePolicyWrite, policyConfigured, true,
			"POST /api/v1/policies/reload",
		),
	}
	httpapi.WriteJSON(w, http.StatusOK, CapabilitiesResponse{
		Version:     1,
		GeneratedAt: time.Now().UTC(),
		Features:    features,
	})
}
func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeManagementRead)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), powerDNSTimeout(current))
	defer cancel()
	services := map[string]any{
		"admin":   ServiceStatus{Configured: true, Healthy: true, URL: current.AdminAddr},
		"runtime": h.runtimeStatus(ctx, current),
	}
	response := map[string]any{
		"generated_at": time.Now().UTC(),
		"services":     services,
	}
	if principal.HasScope(httpapi.ScopePowerDNSRead) {
		services["powerdns"] = powerdns.New(current.PowerDNS).Snapshot(ctx)
	}
	if principal.HasScope(httpapi.ScopePluginsRead) {
		response["plugins"] = h.pluginViews(ctx, r, current)
	}
	if principal.HasScope(httpapi.ScopeCacheRead) {
		response["cache"] = h.application.Registry.CacheStats()
	}
	if principal.HasScope(httpapi.ScopeAuditRead) {
		response["audit_summary"] = h.application.DNSLog.Summary(8)
		response["recent_events"] = h.application.DNSLog.ListFilteredPage(
			httpapi.AuditEventFilterFromQuery(r),
			httpapi.QueryIntBounded(r, "event_limit", 20, 1, 100),
			"",
		).Events
	}
	if principal.HasScope(httpapi.ScopeConfigRead) {
		response["configuration"] = current.Editable()
	}
	httpapi.WriteJSON(w, http.StatusOK, response)
}

func (h *Handler) certificateOrders(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeCertificatesRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, h.certificates.List())
	case http.MethodPost:
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
		if !ok {
			return
		}
		var request certificates.IssueRequest
		if err := httpapi.DecodeJSON(r, &request); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		job, created, err := h.certificates.Start(request)
		if err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusAccepted
			h.application.AppendManagementAudit("certificate.issue", principal.ID, r.Method, r.URL.Path, "accepted", map[string]any{
				"job_id":  job.ID,
				"domains": job.Domains,
			})
		}
		httpapi.WriteJSON(w, status, job)
	default:
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) certificateOrder(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/api/v1/certificates/orders/")
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		httpapi.Error(w, http.StatusBadRequest, "certificate job id is required")
		return
	}
	jobID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if action == "" {
		if r.Method != http.MethodGet {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeCertificatesRead) {
			return
		}
		job, ok := h.certificates.Get(jobID)
		if !ok {
			httpapi.Error(w, http.StatusNotFound, "certificate job not found")
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, job)
		return
	}
	switch action {
	case "certificate":
		if r.Method != http.MethodGet {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeCertificatesRead) {
			return
		}
		body, err := h.certificates.CertificatePEM(jobID)
		if err != nil {
			httpapi.Error(w, http.StatusNotFound, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	case "renew":
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
		if !ok {
			return
		}
		var request struct {
			IdempotencyKey string `json:"idempotency_key"`
			Force          bool   `json:"force"`
		}
		if err := httpapi.DecodeJSON(r, &request); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		job, created, err := h.certificates.Renew(jobID, request.IdempotencyKey, request.Force)
		if err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if created {
			h.application.AppendManagementAudit("certificate.renew", principal.ID, r.Method, r.URL.Path, "accepted", map[string]any{
				"job_id":     job.ID,
				"renewal_of": jobID,
			})
		}
		httpapi.WriteJSON(w, http.StatusAccepted, job)
	case "revoke":
		if r.Method != http.MethodPost {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), current.Certificates.RequestTimeout)
		defer cancel()
		job, err := h.certificates.Revoke(ctx, jobID)
		if err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		h.application.AppendManagementAudit("certificate.revoke", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"job_id": job.ID,
		})
		httpapi.WriteJSON(w, http.StatusOK, job)
	default:
		httpapi.Error(w, http.StatusNotFound, "certificate action not found")
	}
}

func (h *Handler) certificatePrivateCACRL(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !httpapi.RequireScope(w, r, current, httpapi.ScopeCertificatesRead) {
		return
	}
	if strings.TrimSpace(current.Certificates.IssuerMode) != "private-ca" {
		httpapi.Error(w, http.StatusNotFound, "private CA root is not configured")
		return
	}
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	revoked, err := h.certificates.RevokedCertificatePEMs()
	if err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, "revoked certificates cannot be read")
		return
	}
	crlPEM, err := certificates.PrivateRootCRLPEM(current.Certificates, revoked, time.Now().UTC())
	if err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(crlPEM)
}

func (h *Handler) certificatePrivateCARoot(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if strings.TrimSpace(current.Certificates.IssuerMode) != "private-ca" {
		httpapi.Error(w, http.StatusNotFound, "private CA root is not configured")
		return
	}
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeCertificatesRead) {
			return
		}
		metadata, err := certificates.PrivateRootMetadataForConfig(current.Certificates)
		if err != nil {
			httpapi.Error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, metadata)
	case http.MethodPatch:
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
		if !ok {
			return
		}
		var request struct {
			Disabled *bool `json:"disabled"`
		}
		if err := httpapi.DecodeJSON(r, &request); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if request.Disabled == nil {
			httpapi.Error(w, http.StatusBadRequest, "disabled is required")
			return
		}
		metadata, err := certificates.SetPrivateRootDisabled(current.Certificates, *request.Disabled)
		if err != nil {
			httpapi.Error(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		h.application.AppendManagementAudit("certificate.private_ca.root.update", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"disabled":           metadata.Disabled,
			"sha256_fingerprint": metadata.SHA256Fingerprint,
		})
		httpapi.WriteJSON(w, http.StatusOK, metadata)
	default:
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) certificatePrivateCARootBackupStatus(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
	if !ok {
		return
	}
	if strings.TrimSpace(current.Certificates.IssuerMode) != "private-ca" {
		httpapi.Error(w, http.StatusNotFound, "private CA root is not configured")
		return
	}
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	var request struct {
		SHA256Fingerprint string `json:"sha256_fingerprint"`
	}
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(request.SHA256Fingerprint) == "" {
		httpapi.Error(w, http.StatusBadRequest, "sha256_fingerprint is required")
		return
	}
	metadata, err := certificates.RecordPrivateRootBackup(current.Certificates, strings.TrimSpace(request.SHA256Fingerprint))
	if err != nil {
		status := http.StatusServiceUnavailable
		if strings.Contains(err.Error(), "does not match") {
			status = http.StatusBadRequest
		}
		httpapi.Error(w, status, err.Error())
		return
	}
	h.application.AppendManagementAudit("certificate.private_ca.root.backup_status", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"backup_status":      metadata.BackupStatus.Status,
		"sha256_fingerprint": metadata.SHA256Fingerprint,
	})
	httpapi.WriteJSON(w, http.StatusOK, metadata)
}

func (h *Handler) certificatePrivateCARootImport(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
	if !ok {
		return
	}
	if strings.TrimSpace(current.Certificates.IssuerMode) != "private-ca" {
		httpapi.Error(w, http.StatusNotFound, "private CA root is not configured")
		return
	}
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	var request struct {
		CertificatePEM string `json:"certificate_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
	}
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	metadata, err := certificates.ImportPrivateRoot(current.Certificates, []byte(request.CertificatePEM), []byte(request.PrivateKeyPEM))
	if err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	issuer, err := certificates.NewPrivateRootIssuer(current.Certificates)
	if err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, "private CA root issuer cannot be reloaded")
		return
	}
	if err := h.certificates.SetIssuer(issuer); err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	h.application.AppendManagementAudit("certificate.private_ca.root.import", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"sha256_fingerprint": metadata.SHA256Fingerprint,
	})
	httpapi.WriteJSON(w, http.StatusOK, metadata)
}

func (h *Handler) certificatePrivateCARootRotate(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
	if !ok {
		return
	}
	if strings.TrimSpace(current.Certificates.IssuerMode) != "private-ca" {
		httpapi.Error(w, http.StatusNotFound, "private CA root is not configured")
		return
	}
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	metadata, err := certificates.RotatePrivateRoot(current.Certificates)
	if err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	issuer, err := certificates.NewPrivateRootIssuer(current.Certificates)
	if err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, "private CA root issuer cannot be reloaded")
		return
	}
	if err := h.certificates.SetIssuer(issuer); err != nil {
		httpapi.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	h.application.AppendManagementAudit("certificate.private_ca.root.rotate", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"sha256_fingerprint": metadata.SHA256Fingerprint,
	})
	httpapi.WriteJSON(w, http.StatusOK, metadata)
}

func (h *Handler) certificateTLSA(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeCertificatesWrite)
	if !ok {
		return
	}
	if h.certificates == nil {
		httpapi.Error(w, http.StatusServiceUnavailable, h.certificateUnavailable())
		return
	}
	var request struct {
		JobID        string `json:"job_id"`
		Domain       string `json:"domain"`
		Port         uint16 `json:"port"`
		Protocol     string `json:"protocol"`
		Usage        uint8  `json:"usage"`
		Selector     uint8  `json:"selector"`
		MatchingType uint8  `json:"matching_type"`
		Publish      bool   `json:"publish"`
		TTL          uint32 `json:"ttl"`
	}
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	certificatePEM, err := h.certificates.CertificatePEM(request.JobID)
	if err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	owner, err := dnsrr.ParseTLSAOwner(request.Port, request.Protocol, request.Domain)
	if err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	value, err := dnsrr.TLSAFromCertificatePEM(certificatePEM, request.Usage, request.Selector, request.MatchingType)
	if err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Publish {
		if request.TTL == 0 {
			request.TTL = 300
		}
		if err := publishTLSA(r.Context(), powerdns.New(current.PowerDNS), owner, value, request.TTL); err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		h.application.AppendManagementAudit("certificate.tlsa.publish", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"job_id": request.JobID,
			"owner":  owner,
		})
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{
		"owner":     owner,
		"type":      "TLSA",
		"value":     value,
		"published": request.Publish,
	})
}

func publishTLSA(ctx context.Context, client *powerdns.Client, owner, value string, ttl uint32) error {
	zones, err := client.Zones(ctx, "authoritative")
	if err != nil {
		return err
	}
	var zone powerdns.Zone
	for _, candidate := range zones {
		if (owner == candidate.Name || strings.HasSuffix(owner, "."+candidate.Name)) && len(candidate.Name) > len(zone.Name) {
			zone = candidate
		}
	}
	if zone.ID == "" {
		return fmt.Errorf("no authoritative PowerDNS zone contains %s", owner)
	}
	return client.PatchAuthoritativeZone(ctx, zone.ID, powerdns.PatchZoneRequest{RRSets: []powerdns.RRSet{{
		Name:       owner,
		Type:       "TLSA",
		TTL:        ttl,
		ChangeType: "REPLACE",
		Records:    []powerdns.Record{{Content: value}},
	}}})
}

func (h *Handler) certificateUnavailable() string {
	if h.certificateError != "" {
		return "certificate service is unavailable: " + h.certificateError
	}
	return "certificate service is not enabled"
}

func (h *Handler) configuration(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	switch r.Method {
	case http.MethodGet:
		if !httpapi.RequireScope(w, r, current, httpapi.ScopeConfigRead) {
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, current.Editable())
	case http.MethodPut:
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopeConfigWrite)
		if !ok {
			return
		}
		var edit config.EditableConfig
		decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&edit); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		next := config.ApplyEditable(current, edit)
		if err := next.Validate(); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := config.SaveEditableFile(current.ConfigFile, edit); err != nil {
			httpapi.Error(w, http.StatusConflict, err.Error())
			return
		}
		reloaded, err := config.LoadFileWithEnvOverrides(current.ConfigFile)
		if err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := reloaded.Validate(); err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		if err := h.application.ReloadFromConfig(reloaded); err != nil {
			httpapi.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		*h.cfg = reloaded
		runtimeReload := h.reloadRuntime(r, reloaded)
		h.application.AppendManagementAudit("config.update", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"config_file":    reloaded.ConfigFile,
			"runtime_reload": runtimeReload,
			"plugins":        len(reloaded.Plugins),
			"routes":         len(reloaded.Routes),
			"scope":          "admin-api",
		})
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{
			"status":         "saved",
			"runtime_reload": runtimeReload,
			"configuration":  reloaded.Editable(),
		})
	default:
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) powerDNSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), powerDNSTimeout(current))
	defer cancel()
	httpapi.WriteJSON(w, http.StatusOK, powerdns.New(current.PowerDNS).Snapshot(ctx))
}

func (h *Handler) powerDNSZones(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
		return
	}
	service := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("service")))
	if service == "" {
		service = "authoritative"
	}
	if service != "authoritative" && service != "recursor" {
		httpapi.Error(w, http.StatusBadRequest, "service must be authoritative or recursor")
		return
	}
	zones, err := powerdns.New(current.PowerDNS).Zones(r.Context(), service)
	if err != nil {
		httpapi.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, zones)
}

func (h *Handler) authoritativeZones(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		query.Set("service", "authoritative")
		r.URL.RawQuery = query.Encode()
		h.powerDNSZones(w, r)
		return
	}
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
	if !ok {
		return
	}
	var request powerdns.CreateZoneRequest
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	zone, err := powerdns.New(current.PowerDNS).CreateAuthoritativeZone(r.Context(), request)
	if err != nil {
		httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
		return
	}
	h.application.AppendManagementAudit("powerdns.zone.create", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"zone": zone.Name,
	})
	httpapi.WriteJSON(w, http.StatusCreated, zone)
}

func (h *Handler) authoritativeZone(w http.ResponseWriter, r *http.Request) {
	current := *h.cfg
	rawID := strings.TrimPrefix(r.URL.Path, "/api/v1/powerdns/authoritative/zones/")
	if strings.Contains(rawID, "/cryptokeys") {
		h.authoritativeCryptoKeys(w, r, current, rawID)
		return
	}
	if strings.HasSuffix(rawID, "/derive-ds") {
		h.deriveDS(w, r, current, strings.TrimSuffix(rawID, "/derive-ds"))
		return
	}
	isSOARequest := strings.HasSuffix(rawID, "/soa")
	if isSOARequest {
		rawID = strings.TrimSuffix(rawID, "/soa")
	}
	isRRSetRequest := strings.HasSuffix(rawID, "/rrsets")
	if isRRSetRequest {
		rawID = strings.TrimSuffix(rawID, "/rrsets")
	}
	zoneID, err := url.PathUnescape(rawID)
	if err != nil || strings.TrimSpace(zoneID) == "" {
		httpapi.Error(w, http.StatusBadRequest, "zone id is required")
		return
	}

	if isSOARequest {
		if r.Method != http.MethodPatch {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
		if !ok {
			return
		}
		var request powerdns.SOAConfig
		if err := httpapi.DecodeJSON(r, &request); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		soa, err := powerdns.New(current.PowerDNS).UpdateAuthoritativeSOA(r.Context(), zoneID, request)
		if err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		h.application.AppendManagementAudit("powerdns.soa.update", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"zone_id": zoneID,
			"serial":  soa.Serial,
		})
		httpapi.WriteJSON(w, http.StatusOK, soa)
		return
	}

	if isRRSetRequest {
		if r.Method != http.MethodPatch {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
		if !ok {
			return
		}
		var request powerdns.PatchZoneRequest
		if err := httpapi.DecodeJSON(r, &request); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := powerdns.New(current.PowerDNS).PatchAuthoritativeZone(r.Context(), zoneID, request); err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		h.application.AppendManagementAudit("powerdns.rrset.patch", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"zone_id": zoneID,
			"rrsets":  len(request.RRSets),
		})
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
			return
		}
		zone, err := powerdns.New(current.PowerDNS).AuthoritativeZone(r.Context(), zoneID)
		if err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, zone)
	case http.MethodDelete:
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
		if !ok {
			return
		}
		if err := powerdns.New(current.PowerDNS).DeleteAuthoritativeZone(r.Context(), zoneID); err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		h.application.AppendManagementAudit("powerdns.zone.delete", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"zone_id": zoneID,
		})
		w.WriteHeader(http.StatusNoContent)
	default:
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) authoritativeCryptoKeys(w http.ResponseWriter, r *http.Request, current config.Config, rawPath string) {
	parts := strings.Split(rawPath, "/cryptokeys")
	if len(parts) != 2 {
		httpapi.Error(w, http.StatusBadRequest, "invalid cryptokey path")
		return
	}
	zoneID, err := url.PathUnescape(strings.TrimSuffix(parts[0], "/"))
	if err != nil || strings.TrimSpace(zoneID) == "" {
		httpapi.Error(w, http.StatusBadRequest, "zone id is required")
		return
	}
	keySuffix := strings.Trim(parts[1], "/")
	client := powerdns.New(current.PowerDNS)
	if keySuffix != "" {
		if r.Method != http.MethodDelete {
			httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
		if !ok {
			return
		}
		keyID, parseErr := strconv.Atoi(keySuffix)
		if parseErr != nil {
			httpapi.Error(w, http.StatusBadRequest, "key id must be an integer")
			return
		}
		if err := client.DeleteAuthoritativeCryptoKey(r.Context(), zoneID, keyID); err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		h.application.AppendManagementAudit("powerdns.dnssec.key.delete", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"zone_id": zoneID,
			"key_id":  keyID,
		})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
			return
		}
		keys, err := client.AuthoritativeCryptoKeys(r.Context(), zoneID)
		if err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, keys)
	case http.MethodPost:
		principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
		if !ok {
			return
		}
		var request powerdns.CreateCryptoKeyRequest
		if err := httpapi.DecodeJSON(r, &request); err != nil {
			httpapi.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		key, err := client.CreateAuthoritativeCryptoKey(r.Context(), zoneID, request)
		if err != nil {
			httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
			return
		}
		h.application.AppendManagementAudit("powerdns.dnssec.key.create", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
			"zone_id": zoneID,
			"key_id":  key.ID,
			"keytype": key.KeyType,
		})
		httpapi.WriteJSON(w, http.StatusCreated, key)
	default:
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) deriveDS(w http.ResponseWriter, r *http.Request, current config.Config, rawZoneID string) {
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !httpapi.RequireScope(w, r, current, httpapi.ScopePowerDNSRead) {
		return
	}
	zoneID, err := url.PathUnescape(strings.TrimSuffix(rawZoneID, "/"))
	if err != nil || strings.TrimSpace(zoneID) == "" {
		httpapi.Error(w, http.StatusBadRequest, "zone id is required")
		return
	}
	var request struct {
		DNSKey     string `json:"dnskey"`
		DigestType uint8  `json:"digest_type"`
	}
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.DigestType == 0 {
		request.DigestType = 2
	}
	ds, err := powerdns.DeriveDS(zoneID, request.DNSKey, request.DigestType)
	if err != nil {
		httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
		return
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{
		"zone":        zoneID,
		"digest_type": request.DigestType,
		"ds":          ds,
	})
}

func (h *Handler) recursorCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	current := *h.cfg
	principal, ok := httpapi.RequireScopePrincipal(w, r, current, httpapi.ScopePowerDNSWrite)
	if !ok {
		return
	}
	var request struct {
		Domain  string `json:"domain"`
		Subtree bool   `json:"subtree"`
	}
	if err := httpapi.DecodeJSON(r, &request); err != nil {
		httpapi.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := powerdns.New(current.PowerDNS).FlushRecursorCache(r.Context(), request.Domain, request.Subtree)
	if err != nil {
		httpapi.Error(w, powerDNSErrorStatus(err), err.Error())
		return
	}
	h.application.AppendManagementAudit("powerdns.cache.flush", principal.ID, r.Method, r.URL.Path, "ok", map[string]any{
		"domain":  request.Domain,
		"subtree": request.Subtree,
		"count":   result.Count,
	})
	httpapi.WriteJSON(w, http.StatusOK, result)
}

func powerDNSErrorStatus(err error) int {
	if powerdns.IsValidationError(err) {
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

func (h *Handler) runtimeStatus(ctx context.Context, cfg config.Config) ServiceStatus {
	status := ServiceStatus{
		Configured: cfg.ControlPlane.RuntimeControlURL != "",
		URL:        cfg.ControlPlane.RuntimeControlURL,
	}
	if !status.Configured {
		return status
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(status.URL, "/")+"/healthz", nil)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	response, err := h.httpClient.Do(req)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer response.Body.Close()
	status.Healthy = response.StatusCode >= 200 && response.StatusCode < 300
	if !status.Healthy {
		status.Error = response.Status
	}
	return status
}

func (h *Handler) reloadRuntime(original *http.Request, cfg config.Config) string {
	if cfg.ControlPlane.RuntimeControlURL == "" {
		return "not_configured"
	}
	target := strings.TrimRight(cfg.ControlPlane.RuntimeControlURL, "/") + "/api/v1/policies/reload"
	req, err := http.NewRequestWithContext(original.Context(), http.MethodPost, target, nil)
	if err != nil {
		return "failed: " + err.Error()
	}
	if authorization := original.Header.Get("Authorization"); authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response, err := h.httpClient.Do(req)
	if err != nil {
		return "failed: " + err.Error()
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return "failed: " + response.Status + " " + strings.TrimSpace(string(body))
	}
	return "loaded"
}

func (h *Handler) pluginViews(ctx context.Context, original *http.Request, cfg config.Config) []controlplane.PluginView {
	if !cfg.ControlPlane.AdminProxyRuntime || strings.TrimSpace(cfg.ControlPlane.RuntimeControlURL) == "" {
		return pluginViews(ctx, h.application)
	}
	target := strings.TrimRight(cfg.ControlPlane.RuntimeControlURL, "/") + "/api/v1/plugins"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return pluginViews(ctx, h.application)
	}
	if authorization := original.Header.Get("Authorization"); authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response, err := h.httpClient.Do(req)
	if err != nil {
		return pluginViews(ctx, h.application)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return pluginViews(ctx, h.application)
	}
	var views []controlplane.PluginView
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&views); err != nil {
		return pluginViews(ctx, h.application)
	}
	return views
}
func pluginViews(ctx context.Context, application *app.App) []controlplane.PluginView {
	views := make([]controlplane.PluginView, 0)
	for _, plugin := range application.Registry.Plugins() {
		err := plugin.Health(ctx)
		view := controlplane.PluginView{
			Name:     plugin.Name(),
			Enabled:  plugin.Enabled(),
			Suffixes: plugin.Suffixes(),
			Healthy:  err == nil,
		}
		if err != nil {
			view.LastError = err.Error()
		}
		views = append(views, view)
	}
	return views
}

func powerDNSTimeout(cfg config.Config) time.Duration {
	if cfg.PowerDNS.RequestTimeout > 0 {
		return cfg.PowerDNS.RequestTimeout
	}
	return 5 * time.Second
}
