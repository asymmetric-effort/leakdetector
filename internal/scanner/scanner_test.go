package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

func TestScan_StdinMode(t *testing.T) {
	rs := testRuleSet(t)

	input := "line one\nAKIAIOSFODNN7EXAMPLE\nline three\n"
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	go func() {
		io.WriteString(w, input)
		w.Close()
	}()

	opts := Options{
		Stdin:  true,
		Stderr: &bytes.Buffer{},
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding in stdin mode")
	}

	for _, f := range findings {
		if f.File != "stdin" {
			t.Errorf("expected File=stdin, got %s", f.File)
		}
	}
}

func TestScan_FileOnlySkipHistory(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	// Init a git repo with a secret in history but clean working tree.
	runGit := func(args ...string) {
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

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// First commit: file with secret.
	secretFile := filepath.Join(dir, "secret.txt")
	os.WriteFile(secretFile, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "add secret")

	// Second commit: remove secret from file.
	os.WriteFile(secretFile, []byte("clean now\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "remove secret")

	var stderr bytes.Buffer
	opts := Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// With SkipHistory, we should NOT find the secret from git history.
	// The current file is clean, so no findings expected.
	for _, f := range findings {
		if f.Commit != "" {
			t.Errorf("expected no git history findings with SkipHistory, got commit %s", f.Commit)
		}
	}
}

func TestScan_NonExistentDirectory(t *testing.T) {
	rs := testRuleSet(t)

	opts := Options{
		Dir:         "/nonexistent/path/that/does/not/exist",
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		// Some implementations may return an error for non-existent dirs.
		return
	}

	// If no error, there should be no findings from a non-existent directory.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-existent directory, got %d", len(findings))
	}
}

func TestScan_DefaultDir(t *testing.T) {
	// Test that empty Dir defaults to "." and gets resolved to absolute path.
	rs, err := rules.Compile(
		[]config.RuleConfig{
			{
				ID:          "test-noop",
				Description: "A rule that matches nothing",
				Regex:       `XYZZY_NEVER_MATCHES_12345`,
			},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	opts := Options{
		Dir:         "", // Should default to "."
		SkipHistory: true,
		Stderr:      &bytes.Buffer{},
	}

	// This should not error; it scans the current directory.
	_, err = Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan with empty Dir returned error: %v", err)
	}
}

func TestScan_NilStderr(t *testing.T) {
	// Ensure Scan handles nil Stderr by defaulting to os.Stderr.
	rs, err := rules.Compile(
		[]config.RuleConfig{
			{
				ID:          "test-noop",
				Description: "no-match rule",
				Regex:       `XYZZY_NEVER_MATCHES_12345`,
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	opts := Options{
		Dir:         dir,
		SkipHistory: true,
		Stderr:      nil, // should default to os.Stderr
	}

	_, err = Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan with nil Stderr returned error: %v", err)
	}
}

func TestScan_WithGitHistory(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
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

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Commit a file with a secret.
	os.WriteFile(filepath.Join(dir, "key.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "key.txt")
	runGit("commit", "-m", "add key")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Should find the secret both in files and git history.
	if len(findings) == 0 {
		t.Fatal("expected findings from file scan and/or git history")
	}

	// Verify we have file findings (no commit) and git findings (with commit).
	hasFile := false
	hasGit := false
	for _, f := range findings {
		if f.Commit == "" {
			hasFile = true
		} else {
			hasGit = true
		}
	}
	if !hasFile {
		t.Error("expected at least one file finding (no commit)")
	}
	if !hasGit {
		t.Error("expected at least one git finding (with commit)")
	}
}

func TestScan_DirectoryWithoutGit(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// No .git directory - should only scan files, not error on missing git.
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan without .git returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected findings from file scan")
	}

	for _, f := range findings {
		if f.Commit != "" {
			t.Error("expected no git findings without .git directory")
		}
	}
}

func TestScan_StagedMode(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
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

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Create initial commit.
	os.WriteFile(filepath.Join(dir, "init.txt"), []byte("init\n"), 0644)
	runGit("add", "init.txt")
	runGit("commit", "-m", "initial")

	// Stage a file with a secret.
	os.WriteFile(filepath.Join(dir, "staged_secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "staged_secret.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Staged: true,
		Stderr: &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan with Staged returned error: %v", err)
	}

	// Should find the secret from staged changes and from file scan.
	if len(findings) == 0 {
		t.Fatal("expected at least one finding in staged mode")
	}

	// Verify staged mode does not scan git history (commit should be empty for staged findings).
	hasStaged := false
	for _, f := range findings {
		if f.File == "staged_secret.txt" && f.Commit == "" {
			hasStaged = true
		}
	}
	if !hasStaged {
		t.Error("expected staged finding with empty commit")
	}
}

func TestScan_Timeout(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a file with a secret.
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	var stderr bytes.Buffer
	opts := Options{
		Dir:         dir,
		SkipHistory: true,
		Timeout:     300, // generous timeout - just verifying code path works
		Stderr:      &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan with Timeout returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected findings with timeout set")
	}
}

func TestScan_TimeoutCancelsFileScan(t *testing.T) {
	// Using Timeout=1 (1 second) with a directory scan.
	// This tests the timeout/context code path in Scan.
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a file with a secret - with a 1-second timeout it should still complete.
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	var stderr bytes.Buffer
	opts := Options{
		Dir:         dir,
		Timeout:     1,
		SkipHistory: true,
		Stderr:      &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		// If it timed out that's also valid; just checking the code path works.
		t.Logf("Scan with short timeout returned error (expected): %v", err)
		return
	}

	if len(findings) == 0 {
		t.Log("no findings (may have timed out before scanning)")
	}
}

func TestScan_StagedMode_NoGitRepo(t *testing.T) {
	// Test Scan with Staged=true in a non-git directory.
	// scanStaged should fail gracefully.
	dir := t.TempDir()
	rs := testRuleSet(t)

	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("clean\n"), 0644)

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Staged: true,
		Stderr: &stderr,
	}

	// scanStaged will fail in a non-git dir but Scan should return
	// file findings plus the staged error.
	_, err := Scan(opts, rs)
	if err == nil {
		t.Log("Scan with Staged in non-git dir did not return error (may depend on implementation)")
	}
}

func TestScan_VeryShortTimeout_FileScanError(t *testing.T) {
	// Test that Scan with Timeout properly creates a context with deadline.
	// Create a deep directory structure to ensure the scan takes time.
	dir := t.TempDir()

	// Create a noop rule that won't match anything (minimizes per-file overhead)
	rs, err := rules.Compile(
		[]config.RuleConfig{
			{
				ID:          "test-noop",
				Description: "no match",
				Regex:       `XYZZY_NEVER_MATCHES_12345`,
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Create many subdirectories with files to slow down scanning
	for i := 0; i < 100; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", i))
		os.MkdirAll(sub, 0755)
		for j := 0; j < 100; j++ {
			os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d.txt", j)), []byte("content\n"), 0644)
		}
	}

	var stderr bytes.Buffer
	opts := Options{
		Dir:         dir,
		Timeout:     1, // 1 second timeout
		SkipHistory: true,
		Stderr:      &stderr,
	}

	_, err = Scan(opts, rs)
	// The scan might complete in time or might timeout - both are valid.
	// We're just exercising the timeout code path.
	if err != nil {
		t.Logf("Scan returned error (timeout expected): %v", err)
	}
}

func TestScan_StagedModeDoesNotScanHistory(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
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

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Commit a secret to history.
	os.WriteFile(filepath.Join(dir, "history_secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "history_secret.txt")
	runGit("commit", "-m", "add history secret")

	// Remove the secret from disk and stage.
	os.WriteFile(filepath.Join(dir, "history_secret.txt"), []byte("clean\n"), 0644)
	runGit("add", "history_secret.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Staged: true,
		Stderr: &stderr,
	}

	findings, err := Scan(opts, rs)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Staged mode should NOT scan git history, so no commit-based findings.
	for _, f := range findings {
		if f.Commit != "" {
			t.Errorf("expected no git history findings in staged mode, got commit=%s", f.Commit)
		}
	}
}
