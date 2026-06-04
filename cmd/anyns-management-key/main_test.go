package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/config"
)

func TestGenerateAddsManagementKeyAndPrintsTokenOnce(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"roles": [
				{"id": "ops-reader", "scopes": ["management:read"]}
			],
			"keys": [
				{"id": "existing", "api_key": "existing-secret", "roles": ["ops-reader"]}
			]
		}
	}`)

	var out bytes.Buffer
	err := run([]string{
		"generate",
		"--config", path,
		"--id", "successor",
		"--api-key", "successor-secret",
		"--role", "ops-reader",
		"--not-before", "2026-06-01T00:00:00Z",
		"--expires-at", "2026-07-01T00:00:00Z",
		"--allowed-client-cidr", "127.0.0.1/32",
	}, &out)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(out.String(), "successor-secret") {
		t.Fatalf("generate output should include one-time token: %s", out.String())
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("load generated config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate generated config: %v", err)
	}
	if len(cfg.Management.Keys) != 2 {
		t.Fatalf("management keys = %#v", cfg.Management.Keys)
	}
	key := cfg.Management.Keys[1]
	if key.ID != "successor" ||
		key.APIKey != "successor-secret" ||
		key.Roles[0] != "ops-reader" ||
		key.NotBefore != "2026-06-01T00:00:00Z" ||
		key.ExpiresAt != "2026-07-01T00:00:00Z" ||
		key.AllowedClientCIDRs[0] != "127.0.0.1/32" {
		t.Fatalf("generated key = %#v", key)
	}
}

func TestGenerateReloadsControlPlaneAfterConfigWrite(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "reload", "api_key": "reload-secret", "scopes": ["policy:write"]}
			]
		}
	}`)
	var calls int
	restore := stubReloadHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/policies/reload" {
			t.Fatalf("reload request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer reload-secret" {
			t.Fatalf("authorization = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"status":"loaded"}`)),
			Header:     make(http.Header),
		}, nil
	})
	defer restore()

	var out bytes.Buffer
	err := run([]string{
		"generate",
		"--config", path,
		"--id", "successor",
		"--api-key", "successor-secret",
		"--scope", "management:read",
		"--reload-url", "http://runtime.local",
		"--reload-api-key", "reload-secret",
	}, &out)
	if err != nil {
		t.Fatalf("generate with reload: %v", err)
	}
	if calls != 1 {
		t.Fatalf("reload calls = %d", calls)
	}
	var response map[string]any
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("decode generate output: %v", err)
	}
	reload, ok := response["reload"].(map[string]any)
	if !ok || reload["attempted"] != true || reload["status_code"].(float64) != 200 {
		t.Fatalf("reload response = %#v", response["reload"])
	}
}

func TestGenerateReloadsMultipleControlPlanes(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "reload", "api_key": "reload-secret", "scopes": ["policy:write"]}
			]
		}
	}`)
	var paths []string
	restore := stubReloadHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.String())
		if r.Method != http.MethodPost {
			t.Fatalf("reload method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer reload-secret" {
			t.Fatalf("authorization = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"status":"loaded"}`)),
			Header:     make(http.Header),
		}, nil
	})
	defer restore()

	var out bytes.Buffer
	err := run([]string{
		"generate",
		"--config", path,
		"--id", "successor",
		"--api-key", "successor-secret",
		"--scope", "management:read",
		"--reload-url", "http://admin.local",
		"--reload-url", "http://runtime.local/api/v1/policies/reload",
		"--reload-api-key", "reload-secret",
	}, &out)
	if err != nil {
		t.Fatalf("generate with multiple reloads: %v", err)
	}
	if len(paths) != 2 ||
		paths[0] != "http://admin.local/api/v1/policies/reload" ||
		paths[1] != "http://runtime.local/api/v1/policies/reload" {
		t.Fatalf("reload paths = %#v", paths)
	}
	var response map[string]any
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("decode generate output: %v", err)
	}
	reload, ok := response["reload"].(map[string]any)
	if !ok || reload["attempted"] != true || reload["count"].(float64) != 2 {
		t.Fatalf("reload response = %#v", response["reload"])
	}
	results, ok := reload["results"].([]any)
	if !ok || len(results) != 2 {
		t.Fatalf("reload results = %#v", reload["results"])
	}
	if _, hasSingleURL := reload["url"]; hasSingleURL {
		t.Fatalf("multi-reload response should not expose ambiguous top-level url: %#v", reload)
	}
}

func TestRevokeMarksManagementKeyWithoutRemovingAuditMetadata(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "ops", "api_key": "ops-secret", "scopes": ["management:read"]}
			]
		}
	}`)

	var out bytes.Buffer
	err := run([]string{
		"revoke",
		"--config", path,
		"--id", "ops",
		"--revoked-at", "2026-06-01T12:00:00Z",
	}, &out)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if strings.Contains(out.String(), "ops-secret") {
		t.Fatalf("revoke output leaked token: %s", out.String())
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("load revoked config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate revoked config: %v", err)
	}
	key := cfg.Management.Keys[0]
	if key.ID != "ops" || key.APIKey != "ops-secret" || key.RevokedAt != "2026-06-01T12:00:00Z" {
		t.Fatalf("revoked key = %#v", key)
	}

	var response map[string]any
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("decode revoke output: %v", err)
	}
	if response["status"] != "revoked" || response["id"] != "ops" {
		t.Fatalf("revoke response = %#v", response)
	}
}

func TestRevokeSurfacesReloadFailureAfterConfigWrite(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "ops", "api_key": "ops-secret", "scopes": ["policy:write"]}
			]
		}
	}`)
	restore := stubReloadHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Body:       io.NopCloser(strings.NewReader("reload rejected")),
			Header:     make(http.Header),
		}, nil
	})
	defer restore()

	err := run([]string{
		"revoke",
		"--config", path,
		"--id", "ops",
		"--revoked-at", "2026-06-01T12:00:00Z",
		"--reload-url", "http://runtime.local/api/v1/policies/reload",
	}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "reload control plane") {
		t.Fatalf("reload failure err = %v", err)
	}
	cfg, loadErr := config.LoadFile(path)
	if loadErr != nil {
		t.Fatalf("load config after reload failure: %v", loadErr)
	}
	if cfg.Management.Keys[0].RevokedAt != "2026-06-01T12:00:00Z" {
		t.Fatalf("config mutation should remain durable after reload failure: %#v", cfg.Management.Keys[0])
	}
}

func TestRotateAddsSuccessorWithCopiedAuthorizationMetadata(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"roles": [
				{"id": "ops-reader", "scopes": ["management:read", "audit:read"]}
			],
			"keys": [
				{
					"id": "ops-read",
					"api_key": "old-secret",
					"roles": ["ops-reader"],
					"allowed_client_cidrs": ["127.0.0.1/32"],
					"expires_at": "2026-06-10T00:00:00Z"
				}
			]
		}
	}`)

	var out bytes.Buffer
	err := run([]string{
		"rotate",
		"--config", path,
		"--id", "ops-read",
		"--new-id", "ops-read-next",
		"--api-key", "new-secret",
		"--not-before", "2026-06-05T00:00:00Z",
		"--expires-at", "2026-09-05T00:00:00Z",
	}, &out)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !strings.Contains(out.String(), "new-secret") || strings.Contains(out.String(), "old-secret") {
		t.Fatalf("rotate output should include only successor token: %s", out.String())
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("load rotated config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate rotated config: %v", err)
	}
	if len(cfg.Management.Keys) != 2 {
		t.Fatalf("management keys = %#v", cfg.Management.Keys)
	}
	successor := cfg.Management.Keys[1]
	if successor.ID != "ops-read-next" ||
		successor.APIKey != "new-secret" ||
		successor.Roles[0] != "ops-reader" ||
		successor.AllowedClientCIDRs[0] != "127.0.0.1/32" ||
		successor.NotBefore != "2026-06-05T00:00:00Z" ||
		successor.ExpiresAt != "2026-09-05T00:00:00Z" {
		t.Fatalf("successor key = %#v", successor)
	}
	if cfg.Management.Keys[0].RevokedAt != "" {
		t.Fatalf("rotate should not revoke existing key by default: %#v", cfg.Management.Keys[0])
	}
}

func TestRotateLiveGuardRejectsExistingSuccessor(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "ops", "api_key": "old-secret", "scopes": ["management:read"], "expires_at": "2026-06-10T00:00:00Z"}
			]
		}
	}`)
	restore := stubControlPlaneHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/management/keys" {
			t.Fatalf("status guard request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer read-secret" {
			t.Fatalf("authorization = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body: io.NopCloser(strings.NewReader(`{
				"keys": [
					{
						"id": "ops",
						"scopes": ["management:read"],
						"status": "active",
						"has_overlapping_successor": true,
						"rotation_due": false,
						"lifecycle_action": "successor_overlap_ready"
					}
				]
			}`)),
			Header: make(http.Header),
		}, nil
	})
	defer restore()

	err := run([]string{
		"rotate",
		"--config", path,
		"--id", "ops",
		"--new-id", "ops-next",
		"--api-key", "new-secret",
		"--status-url", "http://runtime.local",
		"--status-api-key", "read-secret",
	}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "already has an overlapping successor") {
		t.Fatalf("existing successor err = %v", err)
	}
	cfg, loadErr := config.LoadFile(path)
	if loadErr != nil {
		t.Fatalf("load config after rejected rotate: %v", loadErr)
	}
	if len(cfg.Management.Keys) != 1 {
		t.Fatalf("rotate guard should not mutate config: %#v", cfg.Management.Keys)
	}
}

func TestStatusFetchesManagementKeyLifecyclePlan(t *testing.T) {
	var calls int
	restore := stubControlPlaneHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/management/keys" {
			t.Fatalf("status request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer read-secret" {
			t.Fatalf("authorization = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body: io.NopCloser(strings.NewReader(`{
				"auth_required": true,
				"legacy_key_configured": false,
				"configured_role_count": 1,
				"configured_key_count": 3,
				"active_key_count": 2,
				"rotation_warning_hours": 168,
				"token_material_exposed": false,
				"keys": [
					{
						"id": "healthy",
						"scopes": ["management:read"],
						"status": "active",
						"rotation_due": false,
						"lifecycle_action": "active"
					},
					{
						"id": "expiring",
						"scopes": ["management:read"],
						"status": "active",
						"rotation_due": true,
						"lifecycle_action": "schedule_successor_before_expiry",
						"expires_in_seconds": 3600
					},
					{
						"id": "revoked",
						"scopes": ["plugins:write"],
						"status": "revoked",
						"rotation_due": true,
						"lifecycle_action": "remove_revoked_key"
					}
				]
			}`)),
			Header: make(http.Header),
		}, nil
	})
	defer restore()

	var out bytes.Buffer
	err := run([]string{
		"status",
		"--url", "http://runtime.local",
		"--api-key", "read-secret",
	}, &out)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if calls != 1 {
		t.Fatalf("status calls = %d", calls)
	}
	if strings.Contains(out.String(), "api_key") || strings.Contains(out.String(), "read-secret") {
		t.Fatalf("status output leaked token material: %s", out.String())
	}
	var response struct {
		Status               string                `json:"status"`
		URL                  string                `json:"url"`
		ConfiguredKeyCount   int                   `json:"configured_key_count"`
		ActiveKeyCount       int                   `json:"active_key_count"`
		KeysRequiringAction  []managementKeyStatus `json:"keys_requiring_action"`
		TokenMaterialExposed bool                  `json:"token_material_exposed"`
		RotationWarningHours int                   `json:"rotation_warning_hours"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("decode status output: %v", err)
	}
	if response.Status != "ok" ||
		response.URL != "http://runtime.local/api/v1/management/keys" ||
		response.ConfiguredKeyCount != 3 ||
		response.ActiveKeyCount != 2 ||
		response.RotationWarningHours != 168 ||
		response.TokenMaterialExposed {
		t.Fatalf("status response = %#v", response)
	}
	if len(response.KeysRequiringAction) != 2 ||
		response.KeysRequiringAction[0].ID != "expiring" ||
		response.KeysRequiringAction[1].ID != "revoked" {
		t.Fatalf("keys requiring action = %#v", response.KeysRequiringAction)
	}
}

func TestStatusSurfacesEndpointFailure(t *testing.T) {
	restore := stubControlPlaneHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Body:       io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)),
			Header:     make(http.Header),
		}, nil
	})
	defer restore()

	err := run([]string{
		"status",
		"--url", "http://runtime.local/api/v1/management/keys",
	}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "fetch management key status") {
		t.Fatalf("status failure err = %v", err)
	}
}

func stubReloadHTTPClient(t *testing.T, fn func(*http.Request) (*http.Response, error)) func() {
	return stubControlPlaneHTTPClient(t, fn)
}

func stubControlPlaneHTTPClient(t *testing.T, fn func(*http.Request) (*http.Response, error)) func() {
	t.Helper()
	previous := newControlPlaneHTTPClient
	newControlPlaneHTTPClient = func(timeout time.Duration) *http.Client {
		return &http.Client{
			Timeout:   timeout,
			Transport: roundTripFunc(fn),
		}
	}
	return func() {
		newControlPlaneHTTPClient = previous
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestGenerateRejectsDuplicateManagementKeyID(t *testing.T) {
	path := writeTestConfig(t, `{
		"management": {
			"auth_required": true,
			"keys": [
				{"id": "ops", "api_key": "ops-secret", "scopes": ["management:read"]}
			]
		}
	}`)

	err := run([]string{
		"generate",
		"--config", path,
		"--id", "ops",
		"--api-key", "new-secret",
		"--scope", "management:read",
	}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate generate err = %v", err)
	}
}

func writeTestConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anyns.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
