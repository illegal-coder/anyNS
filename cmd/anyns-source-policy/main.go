package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type finding struct {
	Path    string
	Line    int
	Rule    string
	Message string
}

type ruleSummary struct {
	ID          string
	Description string
	Count       int
}

var ruleCatalog = []ruleSummary{
	{ID: "workflow-pinned-actions", Description: "GitHub Actions must use immutable commit SHAs"},
	{ID: "workflow-readonly-permissions", Description: "GitHub workflow permissions must not request write-all or write scopes"},
	{ID: "no-committed-private-key", Description: "Tracked sources must not contain PEM private-key material"},
	{ID: "no-private-automation-path", Description: "Tracked sources must not expose private automation paths"},
	{ID: "shell-no-pipe-to-shell", Description: "Shell scripts must not pipe downloaded content directly to a shell"},
	{ID: "compose-no-privileged-runtime", Description: "Compose models must not request privileged or host runtime settings"},
	{ID: "go-no-insecure-crypto", Description: "Go code must not import md5/sha1 or disable TLS verification"},
	{ID: "go-no-shell-construction", Description: "Go code must not invoke sh/bash -c through os/exec"},
}

var (
	actionUseRe        = regexp.MustCompile(`uses:\s*([^#\s]+)`)
	shaActionRefRe     = regexp.MustCompile(`@[0-9a-fA-F]{40}$`)
	privatePathRe      = regexp.MustCompile(`/root/(` + `anyns-automation|\.codex|\.ssh|\.config/gh)(/|\b)|CODEX` + `_HOME`)
	privateKeyBeginRe  = regexp.MustCompile(`^-{5}BEGIN ([A-Z0-9 ]+ )?` + `PRIVATE` + ` KEY-{5}$`)
	privateKeyEndRe    = regexp.MustCompile(`^-{5}END ([A-Z0-9 ]+ )?` + `PRIVATE` + ` KEY-{5}$`)
	pemPayloadRe       = regexp.MustCompile(`^[A-Za-z0-9+/=]{24,}$`)
	curlPipeShellRe    = regexp.MustCompile(`\b(curl|wget)\b.*\|\s*(sudo\s+)?(sh|bash)\b`)
	writePermissionRe  = regexp.MustCompile(`^\s*(write-all|contents:\s*write|pull-requests:\s*write|actions:\s*write|packages:\s*write)\b`)
	composeDangerousRe = regexp.MustCompile(`^\s*(privileged:\s*true|network_mode:\s*["']?host["']?|pid:\s*["']?host["']?|ipc:\s*["']?host["']?)\s*$`)
	insecureTLSRe      = regexp.MustCompile(`Insecure` + `SkipVerify\s*:\s*true`)
)

func main() {
	format := flag.String("format", "text", "output format: text or markdown")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		var err error
		paths, err = trackedFiles()
		if err != nil {
			fmt.Fprintf(os.Stderr, "source-policy: list tracked files: %v\n", err)
			os.Exit(2)
		}
	}

	findings, checked, err := scanPaths(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "source-policy: scan failed: %v\n", err)
		os.Exit(2)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Path < findings[j].Path
	})

	if *format == "markdown" {
		printMarkdown(findings, checked)
	} else {
		printText(findings, checked)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}

func trackedFiles() ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	fields := bytes.Split(out, []byte{0})
	paths := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) == 0 {
			continue
		}
		paths = append(paths, string(field))
	}
	return paths, nil
}

func scanPaths(paths []string) ([]finding, int, error) {
	var findings []finding
	checked := 0
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, checked, err
		}
		if info.IsDir() {
			err := filepath.WalkDir(path, func(walkPath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "dist" {
						return filepath.SkipDir
					}
					return nil
				}
				if isTextPolicyFile(walkPath) {
					nextFindings, err := scanFile(walkPath)
					if err != nil {
						return err
					}
					findings = append(findings, nextFindings...)
					checked++
				}
				return nil
			})
			if err != nil {
				return nil, checked, err
			}
			continue
		}
		if !isTextPolicyFile(path) {
			continue
		}
		nextFindings, err := scanFile(path)
		if err != nil {
			return nil, checked, err
		}
		findings = append(findings, nextFindings...)
		checked++
	}
	return findings, checked, nil
}

func isTextPolicyFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".js", ".jsx", ".json", ".md", ".pem", ".sh", ".yml", ".yaml":
		return true
	default:
		return false
	}
}

func scanFile(path string) ([]finding, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(body)
	lines := strings.Split(text, "\n")
	var findings []finding

	findings = append(findings, scanPrivateKey(path, lines)...)
	for i, line := range lines {
		lineNo := i + 1
		switch {
		case privatePathRe.MatchString(line):
			findings = append(findings, finding{Path: path, Line: lineNo, Rule: "no-private-automation-path", Message: "private automation path or Codex home reference is tracked"})
		case strings.HasSuffix(path, ".sh") && curlPipeShellRe.MatchString(line):
			findings = append(findings, finding{Path: path, Line: lineNo, Rule: "shell-no-pipe-to-shell", Message: "downloaded content is piped directly to a shell"})
		case isWorkflow(path) && actionUseRe.MatchString(line):
			ref := actionUseRe.FindStringSubmatch(line)[1]
			if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
				continue
			}
			if !shaActionRefRe.MatchString(ref) {
				findings = append(findings, finding{Path: path, Line: lineNo, Rule: "workflow-pinned-actions", Message: "third-party action is not pinned to a 40-character commit SHA"})
			}
		case isWorkflow(path) && writePermissionRe.MatchString(line):
			findings = append(findings, finding{Path: path, Line: lineNo, Rule: "workflow-readonly-permissions", Message: "workflow requests a write permission"})
		case isYAML(path) && composeDangerousRe.MatchString(line):
			findings = append(findings, finding{Path: path, Line: lineNo, Rule: "compose-no-privileged-runtime", Message: "compose file requests privileged or host runtime settings"})
		case strings.HasSuffix(path, ".go") && insecureTLSRe.MatchString(line):
			findings = append(findings, finding{Path: path, Line: lineNo, Rule: "go-no-insecure-crypto", Message: "TLS verification is disabled"})
		}
	}
	if strings.HasSuffix(path, ".go") {
		goFindings, err := scanGoAST(path, body)
		if err != nil {
			return nil, err
		}
		findings = append(findings, goFindings...)
	}
	return findings, nil
}

func scanPrivateKey(path string, lines []string) []finding {
	var findings []finding
	for i := 0; i < len(lines); i++ {
		if !privateKeyBeginRe.MatchString(strings.TrimSpace(lines[i])) {
			continue
		}
		hasPayload := false
		for j := i + 1; j < len(lines) && j < i+40; j++ {
			trimmed := strings.TrimSpace(lines[j])
			if pemPayloadRe.MatchString(trimmed) {
				hasPayload = true
				continue
			}
			if privateKeyEndRe.MatchString(trimmed) && hasPayload {
				findings = append(findings, finding{Path: path, Line: i + 1, Rule: "no-committed-private-key", Message: "PEM private-key block appears in tracked source"})
				break
			}
		}
	}
	return findings
}

func scanGoAST(path string, body []byte) ([]finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, body, 0)
	if err != nil {
		return nil, err
	}
	var findings []finding
	for _, imp := range file.Imports {
		name := strings.Trim(imp.Path.Value, `"`)
		if name == "crypto/md5" || name == "crypto/sha1" {
			pos := fset.Position(imp.Pos())
			findings = append(findings, finding{Path: path, Line: pos.Line, Rule: "go-no-insecure-crypto", Message: "insecure hash package import requires explicit security review"})
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Command" || len(call.Args) < 3 {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "exec" {
			return true
		}
		first, ok := stringLiteral(call.Args[0])
		if !ok || (first != "sh" && first != "bash") {
			return true
		}
		second, ok := stringLiteral(call.Args[1])
		if !ok || second != "-c" {
			return true
		}
		pos := fset.Position(call.Pos())
		findings = append(findings, finding{Path: path, Line: pos.Line, Rule: "go-no-shell-construction", Message: "exec.Command invokes a shell command string"})
		return true
	})
	return findings, nil
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func isWorkflow(path string) bool {
	slashed := filepath.ToSlash(path)
	return (strings.HasPrefix(slashed, ".github/workflows/") || strings.Contains(slashed, "/.github/workflows/")) && isYAML(path)
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}

func printText(findings []finding, checked int) {
	if len(findings) == 0 {
		fmt.Printf("source-policy: ok (%d files checked)\n", checked)
		return
	}
	fmt.Printf("source-policy: %d finding(s) in %d files checked\n", len(findings), checked)
	for _, f := range findings {
		fmt.Printf("%s:%d: %s: %s\n", f.Path, f.Line, f.Rule, f.Message)
	}
}

func printMarkdown(findings []finding, checked int) {
	fmt.Println("# anyNS Source Policy")
	fmt.Println()
	fmt.Printf("- Files checked: `%d`\n", checked)
	fmt.Printf("- Findings: `%d`\n", len(findings))
	fmt.Println()
	summaries := summarize(findings)
	fmt.Println("| Rule | Result | Scope |")
	fmt.Println("| --- | --- | --- |")
	for _, rule := range summaries {
		result := "pass"
		if rule.Count > 0 {
			result = fmt.Sprintf("fail (%d)", rule.Count)
		}
		fmt.Printf("| `%s` | %s | %s |\n", rule.ID, result, rule.Description)
	}
	if len(findings) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("## Findings")
	fmt.Println()
	for _, f := range findings {
		fmt.Printf("- `%s:%d` `%s`: %s\n", f.Path, f.Line, f.Rule, f.Message)
	}
}

func summarize(findings []finding) []ruleSummary {
	summaries := make([]ruleSummary, len(ruleCatalog))
	copy(summaries, ruleCatalog)
	for _, finding := range findings {
		for i := range summaries {
			if summaries[i].ID == finding.Rule {
				summaries[i].Count++
				break
			}
		}
	}
	return summaries
}
