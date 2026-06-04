package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/config"
)

type repeatedFlag []string

type reloadOptions struct {
	URLs    []string
	APIKey  string
	Timeout time.Duration
}

var newControlPlaneHTTPClient = func(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

type managementKeysEndpointResponse struct {
	AuthRequired         bool                  `json:"auth_required"`
	ConfiguredKeyCount   int                   `json:"configured_key_count"`
	ActiveKeyCount       int                   `json:"active_key_count"`
	RotationWarningHours int                   `json:"rotation_warning_hours"`
	Keys                 []managementKeyStatus `json:"keys"`
	TokenMaterialExposed bool                  `json:"token_material_exposed"`
	LegacyKeyConfigured  bool                  `json:"legacy_key_configured"`
	ConfiguredRoleCount  int                   `json:"configured_role_count"`
}

type managementKeyStatus struct {
	ID                       string   `json:"id"`
	Scopes                   []string `json:"scopes"`
	Roles                    []string `json:"roles,omitempty"`
	NotBefore                string   `json:"not_before,omitempty"`
	ExpiresAt                string   `json:"expires_at,omitempty"`
	RevokedAt                string   `json:"revoked_at,omitempty"`
	ExpiresInSeconds         int64    `json:"expires_in_seconds,omitempty"`
	AllowedClientCIDRCount   int      `json:"allowed_client_cidr_count"`
	ClientRestrictionEnabled bool     `json:"client_restriction_enabled"`
	Status                   string   `json:"status"`
	RotationDue              bool     `json:"rotation_due"`
	HasOverlappingSuccessor  bool     `json:"has_overlapping_successor"`
	LifecycleAction          string   `json:"lifecycle_action"`
}

func (f *repeatedFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *repeatedFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*f = append(*f, value)
	}
	return nil
}

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: anyns-management-key <generate|revoke|rotate|status> [flags]")
	}
	switch args[0] {
	case "generate":
		return runGenerate(args[1:], out)
	case "revoke":
		return runRevoke(args[1:], out)
	case "rotate":
		return runRotate(args[1:], out)
	case "status":
		return runStatus(args[1:], out)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runGenerate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var scopes, roles, cidrs, reloadURLs repeatedFlag
	configPath := fs.String("config", "", "anyNS JSON config path")
	id := fs.String("id", "", "management key id")
	apiKey := fs.String("api-key", "", "explicit API key; if empty, a random key is generated")
	tokenBytes := fs.Int("token-bytes", 32, "random API key byte length")
	notBefore := fs.String("not-before", "", "RFC3339 activation time")
	expiresAt := fs.String("expires-at", "", "RFC3339 expiration time")
	reloadAPIKey := fs.String("reload-api-key", "", "Bearer token for reload-url")
	reloadTimeout := fs.Duration("reload-timeout", 5*time.Second, "control-plane reload request timeout")
	fs.Var(&scopes, "scope", "direct management scope; repeatable")
	fs.Var(&roles, "role", "management role id; repeatable")
	fs.Var(&cidrs, "allowed-client-cidr", "allowed client IP/CIDR; repeatable")
	fs.Var(&reloadURLs, "reload-url", "admin or runtime control-plane URL to reload after writing config; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*id) == "" {
		return fmt.Errorf("generate requires --config and --id")
	}
	if len(scopes) == 0 && len(roles) == 0 {
		return fmt.Errorf("generate requires at least one --scope or --role")
	}
	token := strings.TrimSpace(*apiKey)
	if token == "" {
		generated, err := randomToken(*tokenBytes)
		if err != nil {
			return err
		}
		token = generated
	}
	key := map[string]any{
		"id":      strings.TrimSpace(*id),
		"api_key": token,
	}
	if len(scopes) > 0 {
		key["scopes"] = []string(scopes)
	}
	if len(roles) > 0 {
		key["roles"] = []string(roles)
	}
	if strings.TrimSpace(*notBefore) != "" {
		key["not_before"] = strings.TrimSpace(*notBefore)
	}
	if strings.TrimSpace(*expiresAt) != "" {
		key["expires_at"] = strings.TrimSpace(*expiresAt)
	}
	if len(cidrs) > 0 {
		key["allowed_client_cidrs"] = []string(cidrs)
	}

	raw, err := loadRawConfig(*configPath)
	if err != nil {
		return err
	}
	management := ensureObject(raw, "management")
	keys := ensureArray(management, "keys")
	if findKeyIndex(keys, *id) >= 0 {
		return fmt.Errorf("management key %q already exists", strings.TrimSpace(*id))
	}
	management["keys"] = append(keys, key)
	if err := writeValidatedConfig(*configPath, raw); err != nil {
		return err
	}
	reload, err := reloadControlPlane(reloadOptions{
		URLs:    []string(reloadURLs),
		APIKey:  *reloadAPIKey,
		Timeout: *reloadTimeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"status":       "generated",
		"config_file":  *configPath,
		"id":           strings.TrimSpace(*id),
		"api_key":      token,
		"reload":       reload,
		"token_notice": "store this value securely; it is not exposed by management metadata endpoints",
	})
}

func runRevoke(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var reloadURLs repeatedFlag
	configPath := fs.String("config", "", "anyNS JSON config path")
	id := fs.String("id", "", "management key id")
	revokedAt := fs.String("revoked-at", time.Now().UTC().Format(time.RFC3339), "RFC3339 revocation time")
	reloadAPIKey := fs.String("reload-api-key", "", "Bearer token for reload-url")
	reloadTimeout := fs.Duration("reload-timeout", 5*time.Second, "control-plane reload request timeout")
	fs.Var(&reloadURLs, "reload-url", "admin or runtime control-plane URL to reload after writing config; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*id) == "" {
		return fmt.Errorf("revoke requires --config and --id")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*revokedAt)); err != nil {
		return fmt.Errorf("--revoked-at must be RFC3339: %w", err)
	}
	raw, err := loadRawConfig(*configPath)
	if err != nil {
		return err
	}
	management := ensureObject(raw, "management")
	keys := ensureArray(management, "keys")
	index := findKeyIndex(keys, *id)
	if index < 0 {
		return fmt.Errorf("management key %q not found", strings.TrimSpace(*id))
	}
	key, ok := keys[index].(map[string]any)
	if !ok {
		return fmt.Errorf("management.keys[%d] is not an object", index)
	}
	key["revoked_at"] = strings.TrimSpace(*revokedAt)
	management["keys"] = keys
	if err := writeValidatedConfig(*configPath, raw); err != nil {
		return err
	}
	reload, err := reloadControlPlane(reloadOptions{
		URLs:    []string(reloadURLs),
		APIKey:  *reloadAPIKey,
		Timeout: *reloadTimeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"status":       "revoked",
		"config_file":  *configPath,
		"id":           strings.TrimSpace(*id),
		"revoked_at":   strings.TrimSpace(*revokedAt),
		"reload":       reload,
		"token_notice": "token material was left in config for audit continuity but is inactive after revoked_at",
	})
}

func runRotate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var reloadURLs repeatedFlag
	configPath := fs.String("config", "", "anyNS JSON config path")
	id := fs.String("id", "", "existing management key id")
	newID := fs.String("new-id", "", "successor management key id")
	apiKey := fs.String("api-key", "", "explicit successor API key; if empty, a random key is generated")
	tokenBytes := fs.Int("token-bytes", 32, "random API key byte length")
	notBefore := fs.String("not-before", time.Now().UTC().Format(time.RFC3339), "RFC3339 successor activation time")
	expiresAt := fs.String("expires-at", "", "RFC3339 successor expiration time")
	validFor := fs.Duration("valid-for", 90*24*time.Hour, "successor validity duration when --expires-at is omitted")
	statusURL := fs.String("status-url", "", "admin or runtime management-key metadata URL used as a live rotation guard")
	statusAPIKey := fs.String("status-api-key", "", "Bearer token for status-url")
	statusTimeout := fs.Duration("status-timeout", 5*time.Second, "management-key metadata request timeout")
	reloadAPIKey := fs.String("reload-api-key", "", "Bearer token for reload-url")
	reloadTimeout := fs.Duration("reload-timeout", 5*time.Second, "control-plane reload request timeout")
	force := fs.Bool("force", false, "allow rotation even when a successor already appears to exist")
	fs.Var(&reloadURLs, "reload-url", "admin or runtime control-plane URL to reload after writing config; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*id) == "" || strings.TrimSpace(*newID) == "" {
		return fmt.Errorf("rotate requires --config, --id, and --new-id")
	}
	if strings.TrimSpace(*id) == strings.TrimSpace(*newID) {
		return fmt.Errorf("--new-id must differ from --id")
	}
	activation, err := time.Parse(time.RFC3339, strings.TrimSpace(*notBefore))
	if err != nil {
		return fmt.Errorf("--not-before must be RFC3339: %w", err)
	}
	expiry := strings.TrimSpace(*expiresAt)
	if expiry == "" {
		if *validFor <= 0 {
			return fmt.Errorf("--valid-for must be greater than zero")
		}
		expiry = activation.Add(*validFor).UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, expiry); err != nil {
		return fmt.Errorf("--expires-at must be RFC3339: %w", err)
	}
	if strings.TrimSpace(*statusURL) != "" {
		if err := guardLiveRotation(*statusURL, *statusAPIKey, *statusTimeout, *id, *force); err != nil {
			return err
		}
	}

	raw, err := loadRawConfig(*configPath)
	if err != nil {
		return err
	}
	management := ensureObject(raw, "management")
	keys := ensureArray(management, "keys")
	index := findKeyIndex(keys, *id)
	if index < 0 {
		return fmt.Errorf("management key %q not found", strings.TrimSpace(*id))
	}
	if findKeyIndex(keys, *newID) >= 0 {
		return fmt.Errorf("management key %q already exists", strings.TrimSpace(*newID))
	}
	existing, ok := keys[index].(map[string]any)
	if !ok {
		return fmt.Errorf("management.keys[%d] is not an object", index)
	}
	if !*force {
		if err := guardLocalRotation(*configPath, *id); err != nil {
			return err
		}
	}
	token := strings.TrimSpace(*apiKey)
	if token == "" {
		generated, err := randomToken(*tokenBytes)
		if err != nil {
			return err
		}
		token = generated
	}
	successor := rotatedSuccessor(existing, strings.TrimSpace(*newID), token, strings.TrimSpace(*notBefore), expiry)
	management["keys"] = append(keys, successor)
	if err := writeValidatedConfig(*configPath, raw); err != nil {
		return err
	}
	reload, err := reloadControlPlane(reloadOptions{
		URLs:    []string(reloadURLs),
		APIKey:  *reloadAPIKey,
		Timeout: *reloadTimeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"status":       "rotated",
		"config_file":  *configPath,
		"id":           strings.TrimSpace(*id),
		"new_id":       strings.TrimSpace(*newID),
		"api_key":      token,
		"not_before":   strings.TrimSpace(*notBefore),
		"expires_at":   expiry,
		"reload":       reload,
		"token_notice": "store this successor token securely; it is not exposed by management metadata endpoints",
	})
}

func runStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	url := fs.String("url", "", "admin or runtime control-plane URL to query for management key status")
	apiKey := fs.String("api-key", "", "Bearer token for url")
	timeout := fs.Duration("timeout", 5*time.Second, "control-plane status request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*url) == "" {
		return fmt.Errorf("status requires --url")
	}
	status, err := fetchManagementKeyStatus(*url, *apiKey, *timeout)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(status)
}

func guardLiveRotation(rawURL, apiKey string, timeout time.Duration, id string, force bool) error {
	status, _, err := fetchManagementKeyEndpoint(rawURL, apiKey, timeout)
	if err != nil {
		return err
	}
	key, ok := findStatusKey(status.Keys, id)
	if !ok {
		return fmt.Errorf("management key %q not found in live status", strings.TrimSpace(id))
	}
	if key.Status == "revoked" || key.Status == "expired" {
		return fmt.Errorf("management key %q is %s; remove or replace it instead of rotating it", strings.TrimSpace(id), key.Status)
	}
	if key.HasOverlappingSuccessor && !force {
		return fmt.Errorf("management key %q already has an overlapping successor; use --force to create another successor", strings.TrimSpace(id))
	}
	return nil
}

func guardLocalRotation(path, id string) error {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, key := range cfg.Management.Keys {
		if strings.TrimSpace(key.ID) != strings.TrimSpace(id) {
			continue
		}
		status := localKeyStatus(key, now)
		if status == "revoked" || status == "expired" {
			return fmt.Errorf("management key %q is %s; remove or replace it instead of rotating it", strings.TrimSpace(id), status)
		}
		if localHasOverlappingSuccessor(cfg, key, now) {
			return fmt.Errorf("management key %q already has an overlapping successor; use --force to create another successor", strings.TrimSpace(id))
		}
		return nil
	}
	return fmt.Errorf("management key %q not found", strings.TrimSpace(id))
}

func rotatedSuccessor(existing map[string]any, id, token, notBefore, expiresAt string) map[string]any {
	successor := map[string]any{
		"id":         id,
		"api_key":    token,
		"not_before": notBefore,
		"expires_at": expiresAt,
	}
	copyIfPresent(successor, existing, "scopes")
	copyIfPresent(successor, existing, "roles")
	copyIfPresent(successor, existing, "allowed_client_cidrs")
	return successor
}

func reloadControlPlane(opts reloadOptions) (map[string]any, error) {
	urls := cleanReloadURLs(opts.URLs)
	if len(urls) == 0 {
		return map[string]any{"attempted": false}, nil
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("--reload-timeout must be greater than zero")
	}
	client := newControlPlaneHTTPClient(opts.Timeout)
	results := make([]map[string]any, 0, len(urls))
	for _, rawURL := range urls {
		endpoint := reloadEndpoint(rawURL)
		req, err := http.NewRequest(http.MethodPost, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if token := strings.TrimSpace(opts.APIKey); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("reload control plane %s: %w", endpoint, err)
		}
		result := map[string]any{
			"url":         endpoint,
			"status_code": resp.StatusCode,
			"status":      resp.Status,
		}
		results = append(results, result)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("reload control plane %s: %s: %s", endpoint, resp.Status, strings.TrimSpace(string(body)))
		}
		resp.Body.Close()
	}
	response := map[string]any{
		"attempted": true,
		"count":     len(results),
		"results":   results,
	}
	if len(results) == 1 {
		response["url"] = results[0]["url"]
		response["status_code"] = results[0]["status_code"]
		response["status"] = results[0]["status"]
	}
	return response, nil
}

func cleanReloadURLs(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, rawURL := range urls {
		if trimmed := strings.TrimSpace(rawURL); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func reloadEndpoint(rawURL string) string {
	endpoint := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if !strings.HasSuffix(endpoint, "/api/v1/policies/reload") {
		endpoint += "/api/v1/policies/reload"
	}
	return endpoint
}

func fetchManagementKeyStatus(rawURL, apiKey string, timeout time.Duration) (map[string]any, error) {
	body, endpoint, err := fetchManagementKeyEndpoint(rawURL, apiKey, timeout)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status":                 "ok",
		"url":                    endpoint,
		"auth_required":          body.AuthRequired,
		"legacy_key_configured":  body.LegacyKeyConfigured,
		"configured_role_count":  body.ConfiguredRoleCount,
		"configured_key_count":   body.ConfiguredKeyCount,
		"active_key_count":       body.ActiveKeyCount,
		"rotation_warning_hours": body.RotationWarningHours,
		"keys_requiring_action":  keysRequiringLifecycleAction(body.Keys),
		"token_material_exposed": body.TokenMaterialExposed,
	}, nil
}

func fetchManagementKeyEndpoint(rawURL, apiKey string, timeout time.Duration) (managementKeysEndpointResponse, string, error) {
	if timeout <= 0 {
		return managementKeysEndpointResponse{}, "", fmt.Errorf("--timeout must be greater than zero")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if !strings.HasSuffix(endpoint, "/api/v1/management/keys") {
		endpoint += "/api/v1/management/keys"
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return managementKeysEndpointResponse{}, "", err
	}
	if token := strings.TrimSpace(apiKey); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := newControlPlaneHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return managementKeysEndpointResponse{}, "", fmt.Errorf("fetch management key status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return managementKeysEndpointResponse{}, "", fmt.Errorf("fetch management key status: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var body managementKeysEndpointResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return managementKeysEndpointResponse{}, "", fmt.Errorf("decode management key status: %w", err)
	}
	return body, endpoint, nil
}

func keysRequiringLifecycleAction(keys []managementKeyStatus) []managementKeyStatus {
	out := []managementKeyStatus{}
	for _, key := range keys {
		if key.RotationDue || key.Status != "active" {
			out = append(out, key)
		}
	}
	return out
}

func findStatusKey(keys []managementKeyStatus, id string) (managementKeyStatus, bool) {
	id = strings.TrimSpace(id)
	for _, key := range keys {
		if strings.TrimSpace(key.ID) == id {
			return key, true
		}
	}
	return managementKeyStatus{}, false
}

func localKeyStatus(key config.ManagementKey, now time.Time) string {
	if t, ok := parseRFC3339(key.RevokedAt); ok && !t.After(now) {
		return "revoked"
	}
	if t, ok := parseRFC3339(key.NotBefore); ok && t.After(now) {
		return "not_yet_active"
	}
	if t, ok := parseRFC3339(key.ExpiresAt); ok && !t.After(now) {
		return "expired"
	}
	return "active"
}

func localHasOverlappingSuccessor(cfg config.Config, key config.ManagementKey, now time.Time) bool {
	keyExpiresAt, ok := parseRFC3339(key.ExpiresAt)
	if !ok || !keyExpiresAt.After(now) {
		return false
	}
	keyID := strings.TrimSpace(key.ID)
	keyScopes := cfg.Management.ScopesForKey(key)
	for _, candidate := range cfg.Management.Keys {
		if strings.TrimSpace(candidate.ID) == keyID || !sameStrings(keyScopes, cfg.Management.ScopesForKey(candidate)) {
			continue
		}
		if candidateExpiresAt, ok := parseRFC3339(candidate.ExpiresAt); ok && !candidateExpiresAt.After(keyExpiresAt) {
			continue
		}
		if candidateNotBefore, ok := parseRFC3339(candidate.NotBefore); ok && candidateNotBefore.After(keyExpiresAt) {
			continue
		}
		if status := localKeyStatus(candidate, now); status == "active" || status == "not_yet_active" {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, value := range a {
		counts[strings.TrimSpace(strings.ToLower(value))]++
	}
	for _, value := range b {
		key := strings.TrimSpace(strings.ToLower(value))
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	return true
}

func parseRFC3339(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func copyIfPresent(dst, src map[string]any, key string) {
	if value, ok := src[key]; ok {
		dst[key] = value
	}
}

func loadRawConfig(path string) (map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func ensureObject(parent map[string]any, key string) map[string]any {
	if current, ok := parent[key].(map[string]any); ok {
		return current
	}
	created := map[string]any{}
	parent[key] = created
	return created
}

func ensureArray(parent map[string]any, key string) []any {
	if current, ok := parent[key].([]any); ok {
		return current
	}
	created := []any{}
	parent[key] = created
	return created
}

func findKeyIndex(keys []any, id string) int {
	id = strings.TrimSpace(id)
	for i, value := range keys {
		key, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if strings.TrimSpace(fmt.Sprint(key["id"])) == id {
			return i
		}
	}
	return -1
}

func writeValidatedConfig(path string, raw map[string]any) error {
	body, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	cfg := config.Default()
	if err := config.LoadWithBase(bytes.NewReader(body), &cfg, configDir(path)); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

func configDir(path string) string {
	dir := strings.TrimSpace(path)
	if dir == "" {
		return ""
	}
	if index := strings.LastIndexAny(dir, `/\`); index >= 0 {
		return dir[:index]
	}
	return ""
}

func randomToken(n int) (string, error) {
	if n < 16 {
		return "", fmt.Errorf("--token-bytes must be at least 16")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
