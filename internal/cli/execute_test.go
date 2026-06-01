package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// errWriter is a writer that always returns an error.
type errWriter struct{}

func (e *errWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestExecuteNoConfig(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteWithSecretInFile(t *testing.T) {
	dir := t.TempDir()
	// Write a file containing an AWS key.
	err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`package config
const key = "AKIAIOSFODNN7EXAMPLE"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 (leaks found), got %d", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("aws-access-key-id")) {
		t.Errorf("expected aws-access-key-id in output, got: %s", stdout.String())
	}
}

func TestExecuteCleanDir(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
func main() {}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestExecuteInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	// Write a config file with invalid YAML content that causes a parse error.
	// The config loader returns an error for non-NotExist errors.
	configPath := filepath.Join(dir, "bad-config.yml")
	// Write content that will cause a YAML parse error - we need to use
	// a custom config path that points to a directory.
	if err := os.Mkdir(configPath, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ConfigPath:   configPath,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (config error), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteWithConfigFile(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory to exclude.
	secretDir := filepath.Join(dir, "secrets")
	if err := os.Mkdir(secretDir, 0755); err != nil {
		t.Fatal(err)
	}
	configContent := `exclude_paths:
  - "secrets/"
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Write file that would normally trigger a finding in excluded dir.
	if err := os.WriteFile(filepath.Join(secretDir, "config.txt"), []byte(`AKIAIOSFODNN7EXAMPLE`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (path excluded), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteCustomConfigPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom-config.yml")
	if err := os.WriteFile(configPath, []byte("exclude_paths:\n  - \"*\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ConfigPath:   configPath,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestExecuteInvalidBaseline(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		BaselinePath: filepath.Join(dir, "nonexistent-baseline.json"),
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (baseline error), got %d", code)
	}
}

func TestExecuteWithBaseline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	// Create baseline that matches the finding.
	baseline := `[{"fingerprint":"0000000:config.go:aws-access-key-id:1","rule_id":"aws-access-key-id","description":"","start_line":0,"end_line":0,"start_column":0,"end_column":0,"match":"","secret":"","file":"","entropy":0}]`
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(baselinePath, []byte(baseline), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		BaselinePath: baselinePath,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (filtered by baseline), got %d", code)
	}
}

func TestExecuteReportToFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	// Use relative path — chdir to dir so the report is created there.
	orig, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(orig)

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ReportPath:   "report.json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d; stderr: %s", code, stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	if !bytes.Contains(data, []byte("aws-access-key-id")) {
		t.Error("report file should contain aws-access-key-id")
	}
}

func TestExecuteInvalidReportPath(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ReportPath:   "nonexistent/subdir/report.json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (report create error), got %d", code)
	}
}

func TestExecuteReportAbsolutePathRejected(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ReportPath:   "/tmp/evil-report.json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (absolute report path rejected), got %d", code)
	}
}

func TestExecuteReportTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ReportPath:   "../../etc/crontab",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (traversal report path rejected), got %d", code)
	}
}

func TestExecuteVerbose(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		Verbose:      true,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("scan complete")) {
		t.Error("expected verbose output in stderr")
	}
}

func TestExecuteRedact(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		RedactPercent: 100,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if bytes.Contains(stdout.Bytes(), []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Error("secret should be redacted")
	}
}

func TestExecuteCSVFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "csv",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("RuleID")) {
		t.Error("expected CSV header in output")
	}
}

func TestRunFullIntegration(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to temp dir, run, then restore.
	orig, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"--skip-history"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}
}

func TestRunInvalidArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--invalid-flag"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestExecuteNonExistentDir(t *testing.T) {
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, "/nonexistent/path/to/dir", &stdout, &stderr)
	// Should return 0 (no findings) since the dir doesn't have readable files.
	// The scanner handles non-existent dirs gracefully.
	if code != 0 && code != 2 {
		t.Errorf("expected exit code 0 or 2, got %d", code)
	}
}

func TestExecuteWriteError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &errWriter{}, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (write error), got %d", code)
	}
}

func TestExecuteStdinMode(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	opts := Options{
		Stdin:        true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	// Stdin mode reads from os.Stdin; with no pipe it will get empty input.
	// This tests the code path through stdin scanning.
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteExtendPathValid(t *testing.T) {
	dir := t.TempDir()

	// Create an extended config file with a custom rule.
	extConfig := `rules:
  - id: custom-ext-rule
    description: "custom extended rule"
    regex: "CUSTOMSECRET[0-9]+"
`
	extPath := filepath.Join(dir, "ext-config.yml")
	if err := os.WriteFile(extPath, []byte(extConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main config that extends the external one (relative path).
	mainConfig := `extend:
  use_default: true
  path: ext-config.yml
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a file that triggers the custom rule.
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte(`const s = "CUSTOMSECRET12345"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 (custom rule from extend), got %d; stderr: %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("custom-ext-rule")) {
		t.Errorf("expected custom-ext-rule in output, got: %s", stdout.String())
	}
}

func TestExecuteExtendPathInvalid(t *testing.T) {
	dir := t.TempDir()

	// Point extend.path to a directory (which causes a read error, not IsNotExist).
	extDir := filepath.Join(dir, "ext-dir")
	if err := os.Mkdir(extDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainConfig := `extend:
  use_default: true
  path: ` + extDir + `
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (extend config error), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteExtendUseDefaultFalse(t *testing.T) {
	dir := t.TempDir()

	// Config with use_default: false means no built-in rules.
	mainConfig := `extend:
  use_default: false
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a file that would normally trigger a built-in rule.
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (no rules when use_default=false), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteExtendDisabledRules(t *testing.T) {
	dir := t.TempDir()

	// Disable the aws-access-key-id rule.
	mainConfig := `extend:
  use_default: true
  disabled_rules:
    - "aws-access-key-id"
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a file that would trigger aws-access-key-id.
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (rule disabled), got %d; stderr: %s; stdout: %s", code, stderr.String(), stdout.String())
	}
}

func TestExecuteEnableRuleFiltering(t *testing.T) {
	dir := t.TempDir()

	// Write a file that triggers aws-access-key-id.
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	// Only enable a rule that does not match this file.
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
		EnableRules:  []string{"generic-api-key"},
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (only non-matching rule enabled), got %d; stderr: %s", code, stderr.String())
	}

	// Now enable the matching rule.
	stdout.Reset()
	stderr.Reset()
	opts.EnableRules = []string{"aws-access-key-id"}
	code = execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 (matching rule enabled), got %d; stderr: %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("aws-access-key-id")) {
		t.Errorf("expected aws-access-key-id in output, got: %s", stdout.String())
	}
}

func TestExecuteStagedMode(t *testing.T) {
	dir := t.TempDir()

	// Initialize a git repo.
	cmds := [][]string{
		{"git", "init"},
		{"git", "config", "user.email", "test@test.com"},
		{"git", "config", "user.name", "Test"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to run %v: %v\n%s", args, err, out)
		}
	}

	// Create initial commit.
	cleanFile := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(cleanFile, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", "clean.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	// Stage a file with a secret.
	secretFile := filepath.Join(dir, "secret.go")
	if err := os.WriteFile(secretFile, []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("git", "add", "secret.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add secret: %v\n%s", err, out)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		Staged:       true,
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 (staged secret found), got %d; stderr: %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("aws-access-key-id")) {
		t.Errorf("expected finding in staged scan, got: %s", stdout.String())
	}
}

func TestExecuteLeakdetectorignore(t *testing.T) {
	dir := t.TempDir()

	// Write a file with a secret.
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	// First, scan without ignore to get the fingerprint.
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	// Extract fingerprint from output (may be pretty-printed).
	output := stdout.String()
	marker := `"fingerprint": "`
	fpIdx := strings.Index(output, marker)
	if fpIdx < 0 {
		marker = `"fingerprint":"`
		fpIdx = strings.Index(output, marker)
	}
	if fpIdx < 0 {
		t.Fatalf("no fingerprint in output: %s", output)
	}
	fpStart := fpIdx + len(marker)
	fpEnd := strings.Index(output[fpStart:], `"`)
	fingerprint := output[fpStart : fpStart+fpEnd]

	// Write .leakdetectorignore with that fingerprint.
	ignoreContent := "# Ignore known finding\n" + fingerprint + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".leakdetectorignore"), []byte(ignoreContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Re-scan: finding should be filtered out.
	stdout.Reset()
	stderr.Reset()
	code = execute(opts, dir, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (ignored by .leakdetectorignore), got %d; stdout: %s", code, stdout.String())
	}
}

func TestExecuteTemplateFormat(t *testing.T) {
	dir := t.TempDir()

	// Write a file with a secret.
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a template file.
	tmplContent := `Found {{len .}} issues.{{range .}}
- {{.RuleID}}: {{.File}}{{end}}
`
	tmplPath := filepath.Join(dir, "report.tmpl")
	if err := os.WriteFile(tmplPath, []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "template",
		TemplatePath: tmplPath,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Found") {
		t.Errorf("expected template output with 'Found', got: %s", out)
	}
	if !strings.Contains(out, "aws-access-key-id") {
		t.Errorf("expected rule ID in template output, got: %s", out)
	}
}

func TestExecuteTemplateFormatNoPath(t *testing.T) {
	dir := t.TempDir()

	// Write a file with a secret so template write is attempted.
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "template",
		TemplatePath: "", // No template path.
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (template path missing), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteVerboseWithFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.go"), []byte(`const key = "AKIAIOSFODNN7EXAMPLE"`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		Verbose:      true,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "scan complete") {
		t.Error("expected verbose output in stderr")
	}
	if !strings.Contains(errOut, "finding") {
		t.Errorf("expected findings count in verbose output, got: %s", errOut)
	}
}

func TestExecuteInvalidRuleRegex(t *testing.T) {
	dir := t.TempDir()

	// Create a config with an invalid regex to trigger a compile error.
	configContent := `rules:
  - id: bad-rule
    description: "rule with bad regex"
    regex: "[invalid(regex"
`
	configPath := filepath.Join(dir, "bad-rules.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ConfigPath:   configPath,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (compile error), got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed to compile rules") {
		t.Errorf("expected compile rules error in stderr, got: %s", stderr.String())
	}
}

func TestExecuteScanError(t *testing.T) {
	dir := t.TempDir()

	// Trigger a scan error by using stdin mode with a broken stdin.
	// Replace os.Stdin with a pipe that returns an error.
	origStdin := os.Stdin

	// Create a pipe and close the write end immediately, then make the read
	// end return an error by using a file that's already closed.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Write a very long line that exceeds the scanner buffer to trigger a scan error.
	// The scanner has a max buffer size; exceeding it causes bufio.Scanner.Err() to
	// return bufio.ErrTooLong. Default maxLineSize in the scanner package is
	// typically 1MB; we write 2MB without a newline.
	bigLine := strings.Repeat("A", 2*1024*1024)
	go func() {
		w.WriteString(bigLine)
		w.Close()
	}()
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	var stdout, stderr bytes.Buffer
	opts := Options{
		Stdin:        true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	r.Close()
	// The scanner should report an error for the too-long line.
	if code != 2 {
		t.Errorf("expected exit code 2 (scan error), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteExtendPathNonExistent(t *testing.T) {
	dir := t.TempDir()

	// Point extend.path to a non-existent relative file (should be tolerated).
	mainConfig := `extend:
  use_default: true
  path: nonexistent-config.yml
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	// Non-existent extend path is tolerated (os.IsNotExist).
	if code != 0 {
		t.Errorf("expected exit code 0 (non-existent extend tolerated), got %d; stderr: %s", code, stderr.String())
	}
}

func TestExecuteExtendPathAbsoluteRejected(t *testing.T) {
	dir := t.TempDir()

	mainConfig := `extend:
  path: /etc/shadow
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (absolute extend.path rejected), got %d", code)
	}
}

func TestExecuteExtendPathTraversalRejected(t *testing.T) {
	dir := t.TempDir()

	mainConfig := `extend:
  path: ../../etc/shadow
`
	if err := os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(mainConfig), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (traversal extend.path rejected), got %d", code)
	}
}

func TestExecuteMaxFindings(t *testing.T) {
	dir := t.TempDir()
	// Create multiple files with secrets to generate many findings.
	for i := 0; i < 5; i++ {
		name := filepath.Join(dir, fmt.Sprintf("secret%d.txt", i))
		os.WriteFile(name, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		MaxFindings:  2,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)

	// Should exit with non-zero (exit code) because truncated.
	if code != 1 {
		t.Errorf("expected exit code 1 (truncated), got %d", code)
	}

	// Should have warning about truncation on stderr.
	if !bytes.Contains(stderr.Bytes(), []byte("additional findings may exist")) {
		t.Errorf("expected truncation warning in stderr, got: %s", stderr.String())
	}

	// Output should contain at most 2 findings.
	var findings []map[string]interface{}
	json.Unmarshal(stdout.Bytes(), &findings)
	if len(findings) > 2 {
		t.Errorf("expected at most 2 findings, got %d", len(findings))
	}
}

func TestExecuteMaxFindingsZeroMeansNoLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		name := filepath.Join(dir, fmt.Sprintf("secret%d.txt", i))
		os.WriteFile(name, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	}

	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		MaxFindings:  0, // no limit
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	// Should NOT have truncation warning.
	if bytes.Contains(stderr.Bytes(), []byte("additional findings may exist")) {
		t.Error("unexpected truncation warning with MaxFindings=0")
	}
}
