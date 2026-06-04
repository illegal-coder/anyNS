package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/anyns/anyns/internal/config"
)

func main() {
	log.SetFlags(0)
	path := os.Getenv("ANYNS_CONFIG_FILE")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	var (
		cfg config.Config
		err error
	)
	if path != "" {
		cfg, err = config.LoadFileWithEnvOverrides(path)
	} else {
		cfg, err = config.FromEnvWithError()
	}
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	out := map[string]any{
		"status":                  "ok",
		"config_file":             cfg.ConfigFile,
		"routes":                  len(cfg.Routes),
		"plugins":                 len(cfg.Plugins),
		"admin_proxy_runtime":     cfg.ControlPlane.AdminProxyRuntime,
		"runtime_control_url":     cfg.ControlPlane.RuntimeControlURL,
		"security_enabled":        cfg.Security.Enabled,
		"dnslog_path_configured":  cfg.DNSLog.Path != "",
		"honeypot_url_configured": cfg.Honeypot.URL != "",
		"management_auth":         cfg.Management.AuthRequired,
		"management_roles":        len(cfg.Management.Roles),
		"management_keys":         len(cfg.Management.Keys),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
	}
}
