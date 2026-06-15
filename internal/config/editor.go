package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anyns/anyns/internal/plugins"
	"github.com/anyns/anyns/internal/security"
)

type EditablePlugin struct {
	Name                  string `json:"name"`
	Enabled               bool   `json:"enabled"`
	BackendType           string `json:"backend_type"`
	BackendURL            string `json:"backend_url"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	SecretConfigured      bool   `json:"secret_configured"`
}

type EditableHoneypot struct {
	URL                   string `json:"url"`
	FailedQueuePath       string `json:"failed_queue_path"`
	FailedQueueMaxEntries int    `json:"failed_queue_max_entries"`
	RetryIntervalSeconds  int    `json:"retry_interval_seconds"`
	MaxAttempts           int    `json:"max_attempts"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	APIKeyConfigured      bool   `json:"api_key_configured"`
	HMACSecretConfigured  bool   `json:"hmac_secret_configured"`
}

type EditablePowerDNS struct {
	AuthoritativeURL           string `json:"authoritative_url"`
	RecursorURL                string `json:"recursor_url"`
	ServerID                   string `json:"server_id"`
	RequestTimeoutSeconds      int    `json:"request_timeout_seconds"`
	AuthoritativeKeyConfigured bool   `json:"authoritative_key_configured"`
	RecursorKeyConfigured      bool   `json:"recursor_key_configured"`
}

type EditableCertificates struct {
	Enabled                      bool   `json:"enabled"`
	DirectoryURL                 string `json:"directory_url"`
	AccountEmail                 string `json:"account_email"`
	AcceptTOS                    bool   `json:"accept_tos"`
	StorageDir                   string `json:"storage_dir"`
	RequestTimeoutSeconds        int    `json:"request_timeout_seconds"`
	DNSPropagationTimeoutSeconds int    `json:"dns_propagation_timeout_seconds"`
	DNSPollIntervalSeconds       int    `json:"dns_poll_interval_seconds"`
	MaxAttempts                  int    `json:"max_attempts"`
	RenewBeforeDays              int    `json:"renew_before_days"`
}

type EditableConfig struct {
	RequestTimeoutSeconds int                  `json:"request_timeout_seconds"`
	Routes                []plugins.Route      `json:"routes"`
	Plugins               []EditablePlugin     `json:"plugins"`
	Security              security.Policy      `json:"security"`
	DNSLog                DNSLogConfig         `json:"dnslog"`
	Honeypot              EditableHoneypot     `json:"honeypot"`
	ControlPlane          ControlPlaneConfig   `json:"control_plane"`
	PowerDNS              EditablePowerDNS     `json:"powerdns"`
	Certificates          EditableCertificates `json:"certificates"`
	ConfigFile            string               `json:"config_file,omitempty"`
	Writable              bool                 `json:"writable"`
}

func (cfg Config) Editable() EditableConfig {
	pluginsOut := make([]EditablePlugin, 0, len(cfg.Plugins))
	for _, plugin := range cfg.Plugins {
		timeout := int(plugin.RequestTimeout.Duration.Seconds())
		if timeout <= 0 {
			timeout = int(cfg.RequestTimeout.Seconds())
		}
		pluginsOut = append(pluginsOut, EditablePlugin{
			Name:                  plugin.Name,
			Enabled:               plugin.Enabled,
			BackendType:           plugin.BackendType,
			BackendURL:            plugin.BackendURL,
			RequestTimeoutSeconds: timeout,
			SecretConfigured:      plugin.BackendAPIKey != "" || plugin.BackendAPIKeyFile != "",
		})
	}
	return EditableConfig{
		RequestTimeoutSeconds: int(cfg.RequestTimeout.Seconds()),
		Routes:                cfg.Routes,
		Plugins:               pluginsOut,
		Security:              cfg.Security,
		DNSLog:                cfg.DNSLog,
		Honeypot: EditableHoneypot{
			URL:                   cfg.Honeypot.URL,
			FailedQueuePath:       cfg.Honeypot.FailedQueuePath,
			FailedQueueMaxEntries: cfg.Honeypot.FailedQueueMaxEntries,
			RetryIntervalSeconds:  int(cfg.Honeypot.RetryInterval.Seconds()),
			MaxAttempts:           cfg.Honeypot.MaxAttempts,
			RequestTimeoutSeconds: int(cfg.Honeypot.RequestTimeout.Seconds()),
			APIKeyConfigured:      cfg.Honeypot.APIKey != "" || cfg.Honeypot.APIKeyFile != "",
			HMACSecretConfigured:  cfg.Honeypot.HMACSecret != "" || cfg.Honeypot.HMACSecretFile != "",
		},
		ControlPlane: cfg.ControlPlane,
		PowerDNS: EditablePowerDNS{
			AuthoritativeURL:           cfg.PowerDNS.AuthoritativeURL,
			RecursorURL:                cfg.PowerDNS.RecursorURL,
			ServerID:                   cfg.PowerDNS.ServerID,
			RequestTimeoutSeconds:      int(cfg.PowerDNS.RequestTimeout.Seconds()),
			AuthoritativeKeyConfigured: cfg.PowerDNS.AuthoritativeAPIKey != "" || cfg.PowerDNS.AuthoritativeAPIKeyFile != "",
			RecursorKeyConfigured:      cfg.PowerDNS.RecursorAPIKey != "" || cfg.PowerDNS.RecursorAPIKeyFile != "",
		},
		Certificates: EditableCertificates{
			Enabled:                      cfg.Certificates.Enabled,
			DirectoryURL:                 cfg.Certificates.DirectoryURL,
			AccountEmail:                 cfg.Certificates.AccountEmail,
			AcceptTOS:                    cfg.Certificates.AcceptTOS,
			StorageDir:                   cfg.Certificates.StorageDir,
			RequestTimeoutSeconds:        int(cfg.Certificates.RequestTimeout.Seconds()),
			DNSPropagationTimeoutSeconds: int(cfg.Certificates.DNSPropagationTimeout.Seconds()),
			DNSPollIntervalSeconds:       int(cfg.Certificates.DNSPollInterval.Seconds()),
			MaxAttempts:                  cfg.Certificates.MaxAttempts,
			RenewBeforeDays:              cfg.Certificates.RenewBeforeDays,
		},
		ConfigFile: cfg.ConfigFile,
		Writable:   configFileWritable(cfg.ConfigFile),
	}
}

func ApplyEditable(current Config, edit EditableConfig) Config {
	next := current
	if edit.RequestTimeoutSeconds > 0 {
		next.RequestTimeout = time.Duration(edit.RequestTimeoutSeconds) * time.Second
	}
	next.Routes = append([]plugins.Route(nil), edit.Routes...)
	next.Security = edit.Security.WithDefaults()
	next.DNSLog = edit.DNSLog
	next.ControlPlane = edit.ControlPlane

	currentPlugins := map[string]PluginConfig{}
	for _, plugin := range current.Plugins {
		currentPlugins[plugin.Name] = plugin
	}
	next.Plugins = make([]PluginConfig, 0, len(edit.Plugins))
	for _, plugin := range edit.Plugins {
		merged := currentPlugins[plugin.Name]
		merged.Name = plugin.Name
		merged.Enabled = plugin.Enabled
		merged.BackendType = plugin.BackendType
		merged.BackendURL = plugin.BackendURL
		merged.RequestTimeout.Duration = time.Duration(plugin.RequestTimeoutSeconds) * time.Second
		next.Plugins = append(next.Plugins, merged)
	}

	next.Honeypot.URL = edit.Honeypot.URL
	next.Honeypot.FailedQueuePath = edit.Honeypot.FailedQueuePath
	next.Honeypot.FailedQueueMaxEntries = edit.Honeypot.FailedQueueMaxEntries
	next.Honeypot.RetryInterval = time.Duration(edit.Honeypot.RetryIntervalSeconds) * time.Second
	next.Honeypot.MaxAttempts = edit.Honeypot.MaxAttempts
	next.Honeypot.RequestTimeout = time.Duration(edit.Honeypot.RequestTimeoutSeconds) * time.Second
	next.HoneypotURL = next.Honeypot.URL

	next.PowerDNS.AuthoritativeURL = edit.PowerDNS.AuthoritativeURL
	next.PowerDNS.RecursorURL = edit.PowerDNS.RecursorURL
	next.PowerDNS.ServerID = edit.PowerDNS.ServerID
	next.PowerDNS.RequestTimeout = time.Duration(edit.PowerDNS.RequestTimeoutSeconds) * time.Second
	next.PowerDNS.RequestTimeoutSeconds = edit.PowerDNS.RequestTimeoutSeconds
	next.Certificates.Enabled = edit.Certificates.Enabled
	next.Certificates.DirectoryURL = edit.Certificates.DirectoryURL
	next.Certificates.AccountEmail = edit.Certificates.AccountEmail
	next.Certificates.AcceptTOS = edit.Certificates.AcceptTOS
	next.Certificates.StorageDir = edit.Certificates.StorageDir
	next.Certificates.RequestTimeout = time.Duration(edit.Certificates.RequestTimeoutSeconds) * time.Second
	next.Certificates.RequestTimeoutSeconds = edit.Certificates.RequestTimeoutSeconds
	next.Certificates.DNSPropagationTimeout = time.Duration(edit.Certificates.DNSPropagationTimeoutSeconds) * time.Second
	next.Certificates.DNSPropagationTimeoutSecs = edit.Certificates.DNSPropagationTimeoutSeconds
	next.Certificates.DNSPollInterval = time.Duration(edit.Certificates.DNSPollIntervalSeconds) * time.Second
	next.Certificates.DNSPollIntervalSeconds = edit.Certificates.DNSPollIntervalSeconds
	next.Certificates.MaxAttempts = edit.Certificates.MaxAttempts
	next.Certificates.RenewBeforeDays = edit.Certificates.RenewBeforeDays
	return next
}

func SaveEditableFile(path string, edit EditableConfig) error {
	if path == "" {
		return fmt.Errorf("config_file is not set")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return err
	}
	set := func(name string, value any) error {
		encoded, err := json.Marshal(value)
		if err == nil {
			document[name] = encoded
		}
		return err
	}
	if err := set("request_timeout", fmt.Sprintf("%ds", edit.RequestTimeoutSeconds)); err != nil {
		return err
	}
	if err := set("routes", edit.Routes); err != nil {
		return err
	}
	if err := mergePlugins(document, edit.Plugins); err != nil {
		return err
	}
	if err := set("security", edit.Security); err != nil {
		return err
	}
	if err := set("dnslog", edit.DNSLog); err != nil {
		return err
	}
	if err := mergeHoneypot(document, edit.Honeypot); err != nil {
		return err
	}
	if err := set("control_plane", edit.ControlPlane); err != nil {
		return err
	}
	if err := mergePowerDNS(document, edit.PowerDNS); err != nil {
		return err
	}
	if err := set("certificates", map[string]any{
		"enabled":                 edit.Certificates.Enabled,
		"directory_url":           edit.Certificates.DirectoryURL,
		"account_email":           edit.Certificates.AccountEmail,
		"accept_tos":              edit.Certificates.AcceptTOS,
		"storage_dir":             edit.Certificates.StorageDir,
		"request_timeout":         fmt.Sprintf("%ds", edit.Certificates.RequestTimeoutSeconds),
		"dns_propagation_timeout": fmt.Sprintf("%ds", edit.Certificates.DNSPropagationTimeoutSeconds),
		"dns_poll_interval":       fmt.Sprintf("%ds", edit.Certificates.DNSPollIntervalSeconds),
		"max_attempts":            edit.Certificates.MaxAttempts,
		"renew_before_days":       edit.Certificates.RenewBeforeDays,
	}); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".anyns-config-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
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
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func mergePlugins(document map[string]json.RawMessage, plugins []EditablePlugin) error {
	var existing []map[string]json.RawMessage
	_ = json.Unmarshal(document["plugins"], &existing)
	byName := map[string]map[string]json.RawMessage{}
	for _, plugin := range existing {
		var name string
		_ = json.Unmarshal(plugin["name"], &name)
		byName[name] = plugin
	}
	out := make([]map[string]json.RawMessage, 0, len(plugins))
	for _, plugin := range plugins {
		entry := byName[plugin.Name]
		if entry == nil {
			entry = map[string]json.RawMessage{}
		}
		values := map[string]any{
			"name":            plugin.Name,
			"enabled":         plugin.Enabled,
			"backend_type":    plugin.BackendType,
			"backend_url":     plugin.BackendURL,
			"request_timeout": fmt.Sprintf("%ds", plugin.RequestTimeoutSeconds),
		}
		for key, value := range values {
			encoded, err := json.Marshal(value)
			if err != nil {
				return err
			}
			entry[key] = encoded
		}
		out = append(out, entry)
	}
	encoded, err := json.Marshal(out)
	if err == nil {
		document["plugins"] = encoded
	}
	return err
}

func mergeHoneypot(document map[string]json.RawMessage, edit EditableHoneypot) error {
	var current map[string]json.RawMessage
	_ = json.Unmarshal(document["honeypot"], &current)
	if current == nil {
		current = map[string]json.RawMessage{}
	}
	values := map[string]any{
		"url":                      edit.URL,
		"failed_queue_path":        edit.FailedQueuePath,
		"failed_queue_max_entries": edit.FailedQueueMaxEntries,
		"retry_interval":           fmt.Sprintf("%ds", edit.RetryIntervalSeconds),
		"max_attempts":             edit.MaxAttempts,
		"request_timeout":          fmt.Sprintf("%ds", edit.RequestTimeoutSeconds),
	}
	for key, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		current[key] = encoded
	}
	encoded, err := json.Marshal(current)
	if err == nil {
		document["honeypot"] = encoded
	}
	return err
}

func mergePowerDNS(document map[string]json.RawMessage, edit EditablePowerDNS) error {
	var current map[string]json.RawMessage
	_ = json.Unmarshal(document["powerdns"], &current)
	if current == nil {
		current = map[string]json.RawMessage{}
	}
	values := map[string]any{
		"authoritative_url": edit.AuthoritativeURL,
		"recursor_url":      edit.RecursorURL,
		"server_id":         edit.ServerID,
		"request_timeout":   fmt.Sprintf("%ds", edit.RequestTimeoutSeconds),
	}
	for key, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		current[key] = encoded
	}
	encoded, err := json.Marshal(current)
	if err == nil {
		document["powerdns"] = encoded
	}
	return err
}

func configFileWritable(path string) bool {
	if path == "" {
		return false
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	file.Close()
	return true
}
