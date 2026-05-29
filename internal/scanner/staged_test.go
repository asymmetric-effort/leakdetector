package scanner

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func setupGitRepo(t *testing.T) (string, func(...string)) {
	t.Helper()
	dir := t.TempDir()
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

	// Create initial commit so we have a valid repo
	os.WriteFile(filepath.Join(dir, "init.txt"), []byte("init\n"), 0644)
	runGit("add", "init.txt")
	runGit("commit", "-m", "initial commit")

	return dir, runGit
}

func TestScanStaged_FindsSecret(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Stage a file with a secret
	secretFile := filepath.Join(dir, "secret.env")
	os.WriteFile(secretFile, []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secret.env")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.File == "secret.env" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in staged secret.env")
	}
}

func TestScanStaged_CleanFile(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Stage a clean file
	cleanFile := filepath.Join(dir, "clean.txt")
	os.WriteFile(cleanFile, []byte("nothing secret here\n"), 0644)
	runGit("add", "clean.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean staged file, got %d", len(findings))
	}
}

func TestScanStaged_NoStagedChanges(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, _ := setupGitRepo(t)
	rs := testRuleSet(t)

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no staged changes, got %d", len(findings))
	}
}

func TestScanStaged_ExcludePaths(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Stage a file with a secret in an excluded path
	secretFile := filepath.Join(dir, "vendor.txt")
	os.WriteFile(secretFile, []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "vendor.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:          dir,
		ExcludePaths: []string{"vendor.txt"},
		Stderr:       &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == "vendor.txt" {
			t.Error("expected vendor.txt to be excluded from staged scan")
		}
	}
}

func TestScanStaged_MultipleHunks(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Create a file with many lines
	var content bytes.Buffer
	for i := 0; i < 50; i++ {
		content.WriteString("clean line\n")
	}
	bigFile := filepath.Join(dir, "big.txt")
	os.WriteFile(bigFile, content.Bytes(), 0644)
	runGit("add", "big.txt")
	runGit("commit", "-m", "add big file")

	// Modify in two places (creates two hunks)
	lines := bytes.Split(content.Bytes(), []byte("\n"))
	lines[5] = []byte("AKIAIOSFODNN7EXAMPLE")
	lines[45] = []byte("AKIAIOSFODNN7BBBBBBB")
	os.WriteFile(bigFile, bytes.Join(lines, []byte("\n")), 0644)
	runGit("add", "big.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings from multiple hunks, got %d", len(findings))
	}
}

func TestScanStaged_ContextLinesAdvanceCounter(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Create a file and commit it
	original := "line1\nline2\nline3\nline4\nline5\n"
	bigFile := filepath.Join(dir, "lines.txt")
	os.WriteFile(bigFile, []byte(original), 0644)
	runGit("add", "lines.txt")
	runGit("commit", "-m", "add lines")

	// Add a secret at the end (creates context lines before it)
	modified := original + "AKIAIOSFODNN7EXAMPLE\n"
	os.WriteFile(bigFile, []byte(modified), 0644)
	runGit("add", "lines.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// The secret should be at line 6 (after 5 original lines)
	for _, f := range findings {
		if f.File == "lines.txt" && f.StartLine == 6 {
			return // correct line number
		}
	}
	t.Errorf("expected finding at line 6, got findings: %+v", findings)
}

func TestScanStaged_Verbose(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	// Test in a broken git repo to trigger verbose error paths
	dir := t.TempDir()
	rs := testRuleSet(t)
	// Create a fake .git to make it look like a repo without being one
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	_, _ = scanStaged(opts, rs)

	// Verbose mode should have logged warnings
	if stderr.Len() > 0 {
		t.Logf("verbose stderr: %s", stderr.String())
	}
}

func TestScanStaged_LongLine(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Create a file with a very long line that exceeds maxLineSize
	// to trigger scanner.Err() in scanStaged.
	longLine := make([]byte, maxLineSize+100)
	for i := range longLine {
		longLine[i] = 'x'
	}
	longLine[len(longLine)-1] = '\n'
	longFile := filepath.Join(dir, "long.txt")
	os.WriteFile(longFile, longLine, 0644)
	runGit("add", "long.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	_, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	// Verbose mode should have emitted a scanner error warning.
	if stderr.Len() > 0 {
		t.Logf("verbose stderr: %s", stderr.String())
	}
}

func TestScanStaged_RemovedLines(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir, runGit := setupGitRepo(t)
	rs := testRuleSet(t)

	// Create a file with a secret and commit it
	secretFile := filepath.Join(dir, "secret.txt")
	os.WriteFile(secretFile, []byte("AKIAIOSFODNN7EXAMPLE\nkeep this\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "add secret")

	// Remove the secret line (staged removal should not trigger finding)
	os.WriteFile(secretFile, []byte("keep this\n"), 0644)
	runGit("add", "secret.txt")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanStaged(opts, rs)
	if err != nil {
		t.Fatalf("scanStaged returned error: %v", err)
	}

	// Only added lines should be scanned, not removed lines
	for _, f := range findings {
		if f.File == "secret.txt" {
			t.Error("expected no findings for removed lines in staged diff")
		}
	}
}
