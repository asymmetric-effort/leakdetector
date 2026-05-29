package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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

	reportPath := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	opts := Options{
		SkipHistory:  true,
		ReportFormat: "json",
		ReportPath:   reportPath,
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(reportPath)
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
		ReportPath:   filepath.Join(dir, "nonexistent", "subdir", "report.json"),
		ExitCode:     1,
	}
	code := execute(opts, dir, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 (report create error), got %d", code)
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
		Redact:       true,
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
