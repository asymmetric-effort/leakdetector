package scanner

import (
	"bytes"
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
