//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/output"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
	"github.com/asymmetric-effort/leakdetector/internal/scanner"
)

// TestScannerRulesIntegration tests the full pipeline: config -> rules -> scanner -> output.
func TestScannerRulesIntegration(t *testing.T) {
	dir := t.TempDir()

	// Write files with various secret types.
	os.WriteFile(filepath.Join(dir, "aws.txt"),
		[]byte("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
	os.WriteFile(filepath.Join(dir, "github.txt"),
		[]byte("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.txt"),
		[]byte("nothing sensitive here\n"), 0644)

	// Compile rules.
	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	// Scan.
	opts := scanner.Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	// Verify different rule IDs found.
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}

	if !ruleIDs["aws-access-key-id"] {
		t.Error("expected aws-access-key-id finding")
	}
	if !ruleIDs["github-pat"] {
		t.Error("expected github-pat finding")
	}
}

// TestConfigRulesIntegration tests custom config rules override built-ins.
func TestConfigRulesIntegration(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "custom.txt"),
		[]byte("CUSTOM_TOKEN_abcdefghijklmnop0123456789abcdef01234567\n"), 0644)

	customRules := []config.RuleConfig{
		{
			ID:          "custom-token",
			Description: "Custom internal token",
			Regex:       `CUSTOM_TOKEN_[a-z0-9]{40}`,
			Keywords:    []string{"CUSTOM_TOKEN_"},
		},
	}

	rs, err := rules.Compile(customRules, nil)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	opts := scanner.Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "custom-token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected custom-token finding from custom rule")
	}
}

// TestAllowlistIntegration tests that allowlists suppress findings.
func TestAllowlistIntegration(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "test_config.go"),
		[]byte("const key = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0644)

	globalAllowlists := []config.Allowlist{
		{
			Description: "Allow test files",
			Paths:       []string{`.*_config\.go$`},
		},
	}

	rs, err := rules.Compile(nil, globalAllowlists)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	opts := scanner.Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" {
			t.Error("aws-access-key-id should be suppressed by allowlist")
		}
	}
}

// TestExcludePathsIntegration tests path exclusion.
func TestExcludePathsIntegration(t *testing.T) {
	dir := t.TempDir()

	vendorDir := filepath.Join(dir, "vendor")
	os.Mkdir(vendorDir, 0755)
	os.WriteFile(filepath.Join(vendorDir, "lib.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n"), 0644)

	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := scanner.Options{
		Dir:          dir,
		SkipHistory:  true,
		ExcludePaths: []string{"vendor/"},
		Stderr:       &bytes.Buffer{},
	}

	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.File == "vendor/lib.txt" {
			t.Error("vendor/lib.txt should be excluded")
		}
	}
}

// TestOutputFormatsIntegration tests all output formats produce valid output.
func TestOutputFormatsIntegration(t *testing.T) {
	testFindings := []finding.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test finding",
			StartLine:   1,
			EndLine:     1,
			Match:       "SECRET123",
			Secret:      "SECRET123",
			File:        "test.txt",
			Fingerprint: "0000000:test.txt:test-rule:1",
		},
	}

	formats := []string{"json", "csv", "junit", "sarif"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			w := output.New(format, false)
			var buf bytes.Buffer
			if err := w.Write(&buf, testFindings); err != nil {
				t.Fatalf("Write(%s) failed: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Errorf("expected non-empty %s output", format)
			}
		})
	}
}

// TestRedactionIntegration tests redaction across the pipeline.
func TestRedactionIntegration(t *testing.T) {
	testFindings := []finding.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test finding",
			Match:       "AKIAIOSFODNN7EXAMPLE",
			Secret:      "AKIAIOSFODNN7EXAMPLE",
			File:        "test.txt",
			Fingerprint: "0000000:test.txt:test-rule:1",
		},
	}

	w := output.New("json", true)
	var buf bytes.Buffer
	if err := w.Write(&buf, testFindings); err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(buf.Bytes(), []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Error("secret should be redacted")
	}
}

// TestBaselineFilterIntegration tests baseline filtering.
func TestBaselineFilterIntegration(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := scanner.Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	// First scan.
	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for baseline test")
	}

	// Filter with same findings as baseline.
	filtered := finding.FilterBaseline(findings, findings)
	if len(filtered) != 0 {
		t.Errorf("expected 0 findings after baseline filter, got %d", len(filtered))
	}
}

// TestGitHistoryScanIntegration tests scanning git history.
func TestGitHistoryScanIntegration(t *testing.T) {
	dir := t.TempDir()

	// Init git repo.
	gitRun(t, dir, "init")
	gitRun(t, dir, "config", "user.email", "test@test.com")
	gitRun(t, dir, "config", "user.name", "Test")

	// Commit a secret.
	os.WriteFile(filepath.Join(dir, "key.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	gitRun(t, dir, "add", "key.txt")
	gitRun(t, dir, "commit", "-m", "add secret key")

	// Remove it.
	os.WriteFile(filepath.Join(dir, "key.txt"), []byte("clean\n"), 0644)
	gitRun(t, dir, "add", "key.txt")
	gitRun(t, dir, "commit", "-m", "remove key")

	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Full scan (with history) should find it.
	opts := scanner.Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}
	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatal(err)
	}

	hasHistory := false
	for _, f := range findings {
		if f.Commit != "" {
			hasHistory = true
			break
		}
	}
	if !hasHistory {
		t.Error("expected git history findings")
	}

	// Skip history should not find it.
	opts.SkipHistory = true
	findings2, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings2 {
		if f.Commit != "" {
			t.Error("expected no git history findings with SkipHistory")
		}
	}
}

// TestExcludeCommitsIntegration tests commit exclusion.
func TestExcludeCommitsIntegration(t *testing.T) {
	dir := t.TempDir()

	gitRun(t, dir, "init")
	gitRun(t, dir, "config", "user.email", "test@test.com")
	gitRun(t, dir, "config", "user.name", "Test")

	// Commit a secret.
	os.WriteFile(filepath.Join(dir, "key.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	gitRun(t, dir, "add", "key.txt")
	gitRun(t, dir, "commit", "-m", "add key")

	// Get the commit hash.
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	hashBytes, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	commitHash := string(bytes.TrimSpace(hashBytes))

	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := scanner.Options{
		Dir:            dir,
		ExcludeCommits: []string{commitHash},
		Stderr:         &bytes.Buffer{},
	}

	findings, err := scanner.Scan(opts, rs)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Commit == commitHash {
			t.Error("expected excluded commit to be filtered out")
		}
	}
}

// TestFingerprintConsistency tests that fingerprints are consistent.
func TestFingerprintConsistency(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := scanner.Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	// Scan twice.
	findings1, _ := scanner.Scan(opts, rs)
	findings2, _ := scanner.Scan(opts, rs)

	if len(findings1) != len(findings2) {
		t.Fatalf("inconsistent finding count: %d vs %d", len(findings1), len(findings2))
	}

	for i := range findings1 {
		if findings1[i].Fingerprint != findings2[i].Fingerprint {
			t.Errorf("fingerprint mismatch at %d: %s vs %s",
				i, findings1[i].Fingerprint, findings2[i].Fingerprint)
		}
	}
}

// TestJSONRoundTrip tests that JSON output can be parsed back.
func TestJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	rs, err := rules.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := scanner.Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	findings, _ := scanner.Scan(opts, rs)

	w := output.New("json", false)
	var buf bytes.Buffer
	w.Write(&buf, findings)

	var parsed []finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(parsed) != len(findings) {
		t.Errorf("round-trip finding count mismatch: %d vs %d", len(parsed), len(findings))
	}
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
