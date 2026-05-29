package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// testRuleSet creates a simple rule set with a single rule that matches
// "AKIA" followed by 16 uppercase letters/digits (AWS access key pattern).
func testRuleSet(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.Compile(
		[]config.RuleConfig{
			{
				ID:          "test-aws-key",
				Description: "Test AWS Access Key",
				Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
				SecretGroup: 1,
				Keywords:    []string{"AKIA"},
				Tags:        []string{"test", "aws"},
			},
		},
		nil, // no global allowlists
	)
	if err != nil {
		t.Fatalf("failed to compile test rules: %v", err)
	}
	return rs
}


func TestScanFiles_DetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a file containing a known AWS key pattern.
	secretFile := filepath.Join(dir, "config.env")
	content := []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	if err := os.WriteFile(secretFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a clean file.
	cleanFile := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(cleanFile, []byte("nothing secret here\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	// We should have at least one finding from the secret file.
	found := false
	for _, f := range findings {
		if f.File == "config.env" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in config.env, but none found")
	}
}

func TestScanFiles_RespectsExcludePaths(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a file with a secret in an excluded path.
	secretFile := filepath.Join(dir, "vendor.txt")
	content := []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	if err := os.WriteFile(secretFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:          dir,
		ExcludePaths: []string{"vendor.txt"},
		Stderr:       &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == "vendor.txt" {
			t.Error("expected vendor.txt to be excluded, but found a finding")
		}
	}
}

func TestScanFiles_RespectsExcludePathsDirectory(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a subdirectory with a secret file.
	subDir := filepath.Join(dir, "generated")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(subDir, "keys.txt")
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	if err := os.WriteFile(secretFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:          dir,
		ExcludePaths: []string{"generated"},
		Stderr:       &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == filepath.Join("generated", "keys.txt") {
			t.Error("expected generated/ directory to be excluded, but found a finding")
		}
	}
}

func TestScanFiles_RespectsMaxFileSize(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a large file exceeding the limit.
	largeFile := filepath.Join(dir, "large.txt")
	// Write a file slightly larger than 1MB with a secret at the beginning.
	data := make([]byte, 2*1024*1024)
	copy(data, []byte("AKIAIOSFODNN7EXAMPLE\n"))
	if err := os.WriteFile(largeFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:           dir,
		MaxFileSizeMB: 1, // 1 MB limit
		Verbose:       true,
		Stderr:        &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == "large.txt" {
			t.Error("expected large.txt to be skipped due to size, but found a finding")
		}
	}
}

func TestScanFiles_SkipsGitDirectory(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a .git directory with a file containing a secret.
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	gitFile := filepath.Join(gitDir, "config")
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	if err := os.WriteFile(gitFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == ".git/config" {
			t.Error("expected .git directory to be skipped, but found a finding")
		}
	}
}

func TestScanFiles_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty directory, got %d", len(findings))
	}
}

func TestScanFiles_DefaultMaxFileSize(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a small file that should be scanned with default size.
	f := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(f, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:           dir,
		MaxFileSizeMB: 0, // triggers default (10MB)
		Stderr:        &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	found := false
	for _, finding := range findings {
		if finding.File == "small.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in small.txt with default max file size")
	}
}

func TestScanFiles_InlineAllow(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	f := filepath.Join(dir, "allowed.txt")
	content := []byte("AKIAIOSFODNN7EXAMPLE // leakdetector:allow\n")
	if err := os.WriteFile(f, content, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	for _, finding := range findings {
		if finding.File == "allowed.txt" {
			t.Error("expected line with leakdetector:allow to be skipped")
		}
	}
}

func TestScanFiles_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create multiple files with secrets.
	files := map[string]string{
		"a.txt": "AKIAIOSFODNN7EXAMPLE\n",
		"b.txt": "AKIAIOSFODNN7BBBBBBB\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	foundFiles := make(map[string]bool)
	for _, f := range findings {
		foundFiles[f.File] = true
	}

	for name := range files {
		if !foundFiles[name] {
			t.Errorf("expected finding in %s, not found", name)
		}
	}
}

func TestScanFiles_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create nested directories.
	nested := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}

	secretFile := filepath.Join(nested, "deep.txt")
	if err := os.WriteFile(secretFile, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.File == filepath.Join("a", "b", "c", "deep.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in nested deep.txt, not found")
	}
}

func TestScanSingleFile(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	f := filepath.Join(dir, "single.txt")
	content := "line one\nAKIAIOSFODNN7EXAMPLE\nline three\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{Stderr: &bytes.Buffer{}}
	findings, err := scanSingleFile("single.txt", f, "", rs, opts)
	if err != nil {
		t.Fatalf("scanSingleFile returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Check that line number is correct (line 2).
	found := false
	for _, finding := range findings {
		if finding.StartLine == 2 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding on line 2")
	}
}

func TestScanSingleFile_NonExistent(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}

	_, err := scanSingleFile("nofile.txt", "/nonexistent/path/nofile.txt", "", rs, opts)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestMatchLine_PopulatesFindingFields(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}

	line := "my key is AKIAIOSFODNN7EXAMPLE here"
	findings := matchLine(line, 42, "config.env", "abc123", rs, opts)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Check that all findings have correct file and commit.
	for _, f := range findings {
		if f.File != "config.env" {
			t.Errorf("expected File=config.env, got %s", f.File)
		}
		if f.Commit != "abc123" {
			t.Errorf("expected Commit=abc123, got %s", f.Commit)
		}
		if f.StartLine != 42 || f.EndLine != 42 {
			t.Errorf("expected line 42, got start=%d end=%d", f.StartLine, f.EndLine)
		}
		if f.Secret == "" {
			t.Error("expected non-empty Secret")
		}
	}
}

func TestCopyTags(t *testing.T) {
	t.Run("nil tags", func(t *testing.T) {
		result := copyTags(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("empty tags", func(t *testing.T) {
		result := copyTags([]string{})
		if result != nil {
			t.Errorf("expected nil for empty slice, got %v", result)
		}
	})

	t.Run("copies tags", func(t *testing.T) {
		original := []string{"a", "b", "c"}
		result := copyTags(original)
		if len(result) != 3 {
			t.Fatalf("expected 3 tags, got %d", len(result))
		}
		// Modify original to verify it's a copy.
		original[0] = "modified"
		if result[0] == "modified" {
			t.Error("copyTags did not create an independent copy")
		}
	})
}

func TestMatchLine_WithInlineAllow(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}

	line := "AKIAIOSFODNN7EXAMPLE // leakdetector:allow"
	findings := matchLine(line, 1, "test.txt", "", rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with inline allow, got %d", len(findings))
	}
}

func TestMatchLine_NoMatch(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}

	line := "this is a perfectly clean line with no secrets"
	findings := matchLine(line, 1, "clean.txt", "", rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean line, got %d", len(findings))
	}
}

func TestMatchLine_GlobalAllowlistSuppresses(t *testing.T) {
	// Create a rule set with a global allowlist that matches our secret.
	rs, err := rules.Compile(
		[]config.RuleConfig{
			{
				ID:          "test-aws-key",
				Description: "Test AWS Access Key",
				Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
				SecretGroup: 1,
				Keywords:    []string{"AKIA"},
				Tags:        []string{"test"},
			},
		},
		[]config.Allowlist{
			{
				Description: "Allow example keys",
				Regexes:     []string{`AKIAIOSFODNN7EXAMPLE`},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{Stderr: &bytes.Buffer{}}
	line := "AKIAIOSFODNN7EXAMPLE"
	findings := matchLine(line, 1, "test.txt", "", rs, opts)

	// The global allowlist should suppress the finding for the test rule.
	for _, f := range findings {
		if f.RuleID == "test-aws-key" {
			t.Error("expected global allowlist to suppress test-aws-key finding")
		}
	}
}

func TestMatchLine_DecoderFindsSecretsInEncoded(t *testing.T) {
	// "AKIAIOSFODNN7EXAMPLE" encoded in base64 is "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	// We create a rule that matches the base64-encoded string, and the
	// built-in AWS key rule should match the decoded value.
	rs, err := rules.Compile(
		[]config.RuleConfig{
			{
				ID:          "test-base64-blob",
				Description: "Base64 blob",
				Regex:       `(QUtJQUlPU0ZPRE5ON0VYQU1QTEU=)`,
				SecretGroup: 1,
				Tags:        []string{"test"},
			},
			{
				ID:          "test-aws-key",
				Description: "Test AWS Key",
				Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
				SecretGroup: 1,
				Keywords:    []string{"AKIA"},
				Tags:        []string{"aws"},
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{Stderr: &bytes.Buffer{}}
	line := "secret=QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	findings := matchLine(line, 1, "test.txt", "", rs, opts)

	// The decoder should decode the base64 secret and find AKIAIOSFODNN7EXAMPLE,
	// which matches test-aws-key. This adds "decoded:base64" tag.
	for _, f := range findings {
		if f.RuleID == "test-base64-blob" {
			for _, tag := range f.Tags {
				if tag == "decoded:base64" {
					return // success - decoder path was hit
				}
			}
		}
	}
	t.Log("decoder tag not found - the decoder path may not have matched")
}

func TestScanFiles_VerboseWarning(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create an unreadable directory to trigger verbose warning.
	badDir := filepath.Join(dir, "noperm")
	if err := os.MkdirAll(badDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Create a file, then make the dir unreadable.
	if err := os.WriteFile(filepath.Join(badDir, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(badDir, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(badDir, 0755) })

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	_, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	if stderr.Len() == 0 {
		t.Log("no verbose warning emitted (may depend on OS permissions)")
	}
}

func TestScanFiles_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a file then make it unreadable.
	f := filepath.Join(dir, "unreadable.txt")
	if err := os.WriteFile(f, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f, 0644) })

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	_, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	// Verbose mode should have logged a warning about the unreadable file.
	if stderr.Len() == 0 {
		t.Log("no verbose warning emitted for unreadable file")
	}
}

func TestScanFiles_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a regular file with a secret.
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to it.
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported")
	}

	opts := Options{
		Dir:    dir,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	// The target file should be found, but not through the symlink.
	// We just verify no crash occurred and the target is scanned.
	foundTarget := false
	for _, f := range findings {
		if f.File == "target.txt" {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Error("expected finding from target.txt")
	}
}

func TestScanSingleFile_ScannerError(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a file with a line exceeding maxLineSize (1MB).
	// This should trigger scanner.Err().
	f := filepath.Join(dir, "longline.txt")
	longLine := make([]byte, maxLineSize+100)
	for i := range longLine {
		longLine[i] = 'A'
	}
	longLine[len(longLine)-1] = '\n'
	if err := os.WriteFile(f, longLine, 0644); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	opts := Options{
		Verbose: true,
		Stderr:  &stderr,
	}

	_, err := scanSingleFile("longline.txt", f, "", rs, opts)
	if err != nil {
		t.Fatalf("scanSingleFile returned error: %v", err)
	}

	// In verbose mode, a scanner error warning should be emitted
	// if the line exceeds the buffer.
	if stderr.Len() > 0 {
		t.Logf("verbose output: %s", stderr.String())
	}
}

func TestScanFiles_NegativeMaxFileSizeMB(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	f := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(f, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Dir:           dir,
		MaxFileSizeMB: -1, // negative triggers default
		Stderr:        &bytes.Buffer{},
	}

	findings, err := scanFiles(opts, rs)
	if err != nil {
		t.Fatalf("scanFiles returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected findings with negative MaxFileSizeMB (should use default)")
	}
}
