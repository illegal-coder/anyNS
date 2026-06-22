package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourcePolicyDetectsFixtureFindings(t *testing.T) {
	dir := t.TempDir()
	privateKeyMarker := "PRIVATE" + " KEY"
	insecureSkipVerify := "Insecure" + "SkipVerify"
	privateAutomationPath := "/root/" + "anyns-automation/run"
	fixtures := map[string]string{
		".github/workflows/bad.yml": "name: bad\npermissions:\n  contents: write\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n",
		"scripts/install.sh":        "#!/usr/bin/env bash\ncurl -fsSL https://example.test/install.sh | bash\n",
		"docker-compose.yml":        "services:\n  app:\n    image: example\n    privileged: true\n",
		"internal/bad.go": `package bad

import (
	"crypto/md5"
	"crypto/tls"
	"os/exec"
)

func bad() {
	_ = md5.Size
	_ = tls.Config{` + insecureSkipVerify + `: true}
	_, _ = exec.Command("sh", "-c", "echo unsafe").Output()
}
`,
		"docs/private.md":  "private queue lives at " + privateAutomationPath + "\n",
		"fixtures/key.pem": "-----BEGIN " + privateKeyMarker + "-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAu+4HUFJ6f6sE\n-----END " + privateKeyMarker + "-----\n",
	}
	var paths []string
	for name, body := range fixtures {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}

	findings, checked, err := scanPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	if checked != len(paths) {
		t.Fatalf("checked %d files, want %d", checked, len(paths))
	}

	wantRules := []string{
		"workflow-pinned-actions",
		"workflow-readonly-permissions",
		"shell-no-pipe-to-shell",
		"compose-no-privileged-runtime",
		"go-no-insecure-crypto",
		"go-no-shell-construction",
		"no-private-automation-path",
		"no-committed-private-key",
	}
	for _, rule := range wantRules {
		if !hasRule(findings, rule) {
			t.Fatalf("missing rule %s in findings: %#v", rule, findings)
		}
	}
}

func TestSourcePolicyAllowsExpectedSafeBoundaries(t *testing.T) {
	dir := t.TempDir()
	privateKeyMarker := "PRIVATE" + " KEY"
	fixtures := map[string]string{
		".github/workflows/good.yml": "name: good\npermissions:\n  contents: read\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n",
		"scripts/install.sh":         "#!/usr/bin/env bash\ncurl -fsSL https://example.test/install.sh -o install.sh\nbash install.sh\n",
		"tests/check.sh":             "grep -q -- '-----BEGIN " + privateKeyMarker + "-----' /tmp/downloaded-cert.pem\n",
		"docker-compose.yml":         "services:\n  app:\n    image: example\n    ports:\n      - \"127.0.0.1:8080:8080\"\n",
		"internal/good.go": `package good

import "os/exec"

func good() {
	_, _ = exec.Command("dig", "example.").Output()
}
`,
		"docs/public.md": "canonical workspace is /root/anyNS for local server runs\n",
	}
	var paths []string
	for name, body := range fixtures {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}

	findings, _, err := scanPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Fatalf("safe fixtures produced findings: %#v", findings)
	}
}

func TestMarkdownIncludesRuleSummary(t *testing.T) {
	md := captureMarkdown([]finding{{Path: "x", Line: 1, Rule: "workflow-pinned-actions", Message: "bad"}}, 3)
	if !strings.Contains(md, "| `workflow-pinned-actions` | fail (1) |") {
		t.Fatalf("markdown missing failed rule summary:\n%s", md)
	}
	if !strings.Contains(md, "`x:1` `workflow-pinned-actions`") {
		t.Fatalf("markdown missing finding detail:\n%s", md)
	}
}

func hasRule(findings []finding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}

func captureMarkdown(findings []finding, checked int) string {
	old := os.Stdout
	read, write, _ := os.Pipe()
	os.Stdout = write
	printMarkdown(findings, checked)
	_ = write.Close()
	os.Stdout = old
	body, _ := io.ReadAll(read)
	_ = read.Close()
	return string(body)
}
