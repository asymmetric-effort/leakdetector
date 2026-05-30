//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Build the binary before running tests.
	tmpDir, err := os.MkdirTemp("", "leakdetector-e2e-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binaryPath = filepath.Join(tmpDir, "leakdetector"+ext)

	cmd := exec.Command("go", "build", "-o", binaryPath, "github.com/asymmetric-effort/leakdetector/cmd/leakdetector")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("failed to build binary: " + err.Error())
	}

	os.Exit(m.Run())
}

// run executes the leakdetector binary with args and optional stdin.
func run(t *testing.T, dir string, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	if dir != "" {
		cmd.Dir = dir
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run binary: %v", err)
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

// --- Happy Path Tests ---

func TestVersion(t *testing.T) {
	stdout, _, code := run(t, "", "", "--version")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.HasPrefix(stdout, "leakdetector ") {
		t.Errorf("expected version output starting with 'leakdetector ', got: %q", stdout)
	}
}

func TestHelp(t *testing.T) {
	_, stderr, code := run(t, "", "", "--help")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected help output containing 'Usage:', got: %q", stderr)
	}
	if !strings.Contains(stderr, "--skip-history") {
		t.Error("expected help to mention --skip-history")
	}
	if !strings.Contains(stderr, "--branch") {
		t.Error("expected help to mention --branch")
	}
}

func TestCleanDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history")
	if code != 0 {
		t.Errorf("expected exit code 0 for clean directory, got %d", code)
	}

	// Output should be empty JSON array.
	var findings []interface{}
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectsAWSKey(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.go"),
		[]byte("package config\nconst key = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history")
	if code != 1 {
		t.Errorf("expected exit code 1 (leaks found), got %d", code)
	}

	var findings []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	found := false
	for _, f := range findings {
		if f["rule_id"] == "aws-access-key-id" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected aws-access-key-id finding")
	}
}

func TestStdinDetection(t *testing.T) {
	input := "some normal text\nAKIAIOSFODNN7EXAMPLE\nmore text\n"
	stdout, _, code := run(t, "", input, "--stdin")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	var findings []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from stdin")
	}
}

func TestCSVOutput(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history", "--format", "csv")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stdout, "RuleID") {
		t.Error("expected CSV header row with RuleID")
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		t.Error("expected at least 2 CSV lines (header + data)")
	}
}

func TestSARIFOutput(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history", "--format", "sarif")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}
}

func TestJUnitOutput(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history", "--format", "junit")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stdout, "<?xml") {
		t.Error("expected XML declaration in JUnit output")
	}
	if !strings.Contains(stdout, "<testsuites>") {
		t.Error("expected <testsuites> element in JUnit output")
	}
}

func TestRedaction(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history", "--redact", "100")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if strings.Contains(stdout, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("secret should be redacted in output")
	}
}

func TestReportToFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	_, _, code := run(t, dir, "", "--skip-history", "--report", "report.json")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report file: %v", err)
	}
	if !strings.Contains(string(data), "aws-access-key-id") {
		t.Error("report file should contain aws-access-key-id")
	}
}

func TestVerboseOutput(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644)

	_, stderr, code := run(t, dir, "", "--skip-history", "--verbose")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stderr, "scan complete") {
		t.Errorf("expected verbose output in stderr, got: %q", stderr)
	}
}

func TestCustomExitCode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	_, _, code := run(t, dir, "", "--skip-history", "--exit-code", "42")
	if code != 42 {
		t.Errorf("expected exit code 42, got %d", code)
	}
}

func TestInlineAllow(t *testing.T) {
	dir := t.TempDir()
	content := "const key = \"AKIAIOSFODNN7EXAMPLE\" // leakdetector:allow\n"
	os.WriteFile(filepath.Join(dir, "config.go"), []byte(content), 0644)

	_, _, code := run(t, dir, "", "--skip-history")
	if code != 0 {
		t.Errorf("expected exit code 0 (inline allow), got %d", code)
	}
}

func TestGitHistoryDetection(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)

	// Commit a secret.
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	gitAdd(t, dir, "secret.txt")
	gitCommit(t, dir, "add secret")

	// Remove the secret from the file.
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("clean file\n"), 0644)
	gitAdd(t, dir, "secret.txt")
	gitCommit(t, dir, "remove secret")

	// Scan with history - should find it in history.
	stdout, _, code := run(t, dir, "")
	if code != 1 {
		t.Errorf("expected exit code 1 (leak in history), got %d", code)
	}

	var findings []map[string]interface{}
	json.Unmarshal([]byte(stdout), &findings)

	hasHistory := false
	for _, f := range findings {
		if f["commit"] != nil && f["commit"] != "" {
			hasHistory = true
			break
		}
	}
	if !hasHistory {
		t.Error("expected findings from git history")
	}
}

func TestSkipHistoryIgnoresGitHistory(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)

	// Commit a secret.
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	gitAdd(t, dir, "secret.txt")
	gitCommit(t, dir, "add secret")

	// Remove the secret.
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("clean\n"), 0644)
	gitAdd(t, dir, "secret.txt")
	gitCommit(t, dir, "clean up")

	// Scan with --skip-history should NOT find it.
	_, _, code := run(t, dir, "", "--skip-history")
	if code != 0 {
		t.Errorf("expected exit code 0 (skip history, clean files), got %d", code)
	}
}

func TestConfigExcludePaths(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor")
	os.Mkdir(vendorDir, 0755)
	os.WriteFile(filepath.Join(vendorDir, "lib.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	config := "exclude_paths:\n  - \"vendor/\"\n"
	os.WriteFile(filepath.Join(dir, ".leakdetector.yml"), []byte(config), 0644)

	_, _, code := run(t, dir, "", "--skip-history")
	if code != 0 {
		t.Errorf("expected exit code 0 (vendor excluded), got %d", code)
	}
}

// --- Sad Path Tests ---

func TestInvalidFlag(t *testing.T) {
	_, stderr, code := run(t, "", "", "--nonexistent-flag")
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid flag, got %d", code)
	}
	if !strings.Contains(stderr, "error") && !strings.Contains(stderr, "flag") {
		t.Errorf("expected error message about invalid flag, got: %q", stderr)
	}
}

func TestInvalidReportPath(t *testing.T) {
	dir := t.TempDir()
	// Absolute paths are rejected.
	_, stderr, code := run(t, dir, "", "--skip-history", "--report", "/nonexistent/dir/report.json")
	if code != 2 {
		t.Errorf("expected exit code 2 for absolute report path, got %d", code)
	}
	if !strings.Contains(stderr, "error") {
		t.Errorf("expected error message, got: %q", stderr)
	}
}

func TestInvalidConfigPath(t *testing.T) {
	dir := t.TempDir()
	// Point to a directory as config (causes read error).
	configDir := filepath.Join(dir, "configdir")
	os.Mkdir(configDir, 0755)

	_, stderr, code := run(t, dir, "", "--skip-history", "--config", configDir)
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid config, got %d", code)
	}
	if !strings.Contains(stderr, "error") {
		t.Errorf("expected error message, got: %q", stderr)
	}
}

func TestInvalidBaselinePath(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := run(t, dir, "", "--skip-history", "--baseline", "/nonexistent/baseline.json")
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid baseline, got %d", code)
	}
	if !strings.Contains(stderr, "error") {
		t.Errorf("expected error message, got: %q", stderr)
	}
}

func TestExitCode0WhenNoLeaks(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing secret here\n"), 0644)

	_, _, code := run(t, dir, "", "--skip-history")
	if code != 0 {
		t.Errorf("expected exit code 0 for clean directory, got %d", code)
	}
}

func TestMultipleSecretTypes(t *testing.T) {
	dir := t.TempDir()
	content := `
AWS_KEY=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
`
	os.WriteFile(filepath.Join(dir, "secrets.env"), []byte(content), 0644)

	stdout, _, code := run(t, dir, "", "--skip-history")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	var findings []map[string]interface{}
	json.Unmarshal([]byte(stdout), &findings)

	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		if id, ok := f["rule_id"].(string); ok {
			ruleIDs[id] = true
		}
	}

	if !ruleIDs["aws-access-key-id"] {
		t.Error("expected aws-access-key-id finding")
	}
	if !ruleIDs["github-pat"] {
		t.Error("expected github-pat finding")
	}
}

// --- Helpers ---

func gitInit(t *testing.T, dir string) {
	t.Helper()
	gitRun(t, dir, "init")
	gitRun(t, dir, "config", "user.email", "test@test.com")
	gitRun(t, dir, "config", "user.name", "Test")
}

func gitAdd(t *testing.T, dir string, files ...string) {
	t.Helper()
	args := append([]string{"add"}, files...)
	gitRun(t, dir, args...)
}

func gitCommit(t *testing.T, dir, msg string) {
	t.Helper()
	gitRun(t, dir, "commit", "-m", msg)
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@test.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
