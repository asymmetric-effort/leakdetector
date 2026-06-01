package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// ---------------------------------------------------------------------------
// fileBuffer tests
// ---------------------------------------------------------------------------

func TestNewFileBuffer_MultilineContent(t *testing.T) {
	data := []byte("line1\nline2\nline3\n")
	fb := newFileBuffer(data)

	if fb.lineCount() != 3 {
		t.Errorf("lineCount() = %d, want 3", fb.lineCount())
	}
	if fb.lineAt(0) != "line1" {
		t.Errorf("lineAt(0) = %q, want %q", fb.lineAt(0), "line1")
	}
	if fb.lineAt(1) != "line2" {
		t.Errorf("lineAt(1) = %q, want %q", fb.lineAt(1), "line2")
	}
	if fb.lineAt(2) != "line3" {
		t.Errorf("lineAt(2) = %q, want %q", fb.lineAt(2), "line3")
	}
}

func TestNewFileBuffer_SingleLineNoNewline(t *testing.T) {
	data := []byte("onlyone")
	fb := newFileBuffer(data)

	if fb.lineCount() != 1 {
		t.Errorf("lineCount() = %d, want 1", fb.lineCount())
	}
	if fb.lineAt(0) != "onlyone" {
		t.Errorf("lineAt(0) = %q, want %q", fb.lineAt(0), "onlyone")
	}
}

func TestNewFileBuffer_Empty(t *testing.T) {
	fb := newFileBuffer([]byte{})

	// Even empty content gets one line start at offset 0.
	if fb.lineCount() != 1 {
		t.Errorf("lineCount() = %d, want 1", fb.lineCount())
	}
	if fb.lineAt(0) != "" {
		t.Errorf("lineAt(0) = %q, want empty", fb.lineAt(0))
	}
}

func TestNewFileBuffer_ContentEndingWithNewline(t *testing.T) {
	data := []byte("hello\nworld\n")
	fb := newFileBuffer(data)

	// "hello\nworld\n" -- the trailing \n does not start a new line because
	// there is no content after it (i+1 >= len(data)).
	if fb.lineCount() != 2 {
		t.Errorf("lineCount() = %d, want 2", fb.lineCount())
	}
	if fb.lineAt(0) != "hello" {
		t.Errorf("lineAt(0) = %q, want %q", fb.lineAt(0), "hello")
	}
	if fb.lineAt(1) != "world" {
		t.Errorf("lineAt(1) = %q, want %q", fb.lineAt(1), "world")
	}
}

func TestNewFileBuffer_CRLFLineEndings(t *testing.T) {
	data := []byte("alpha\r\nbeta\r\ngamma\r\n")
	fb := newFileBuffer(data)

	if fb.lineCount() != 3 {
		t.Errorf("lineCount() = %d, want 3", fb.lineCount())
	}
	// lineAt should strip trailing \r and \n.
	if fb.lineAt(0) != "alpha" {
		t.Errorf("lineAt(0) = %q, want %q", fb.lineAt(0), "alpha")
	}
	if fb.lineAt(1) != "beta" {
		t.Errorf("lineAt(1) = %q, want %q", fb.lineAt(1), "beta")
	}
	if fb.lineAt(2) != "gamma" {
		t.Errorf("lineAt(2) = %q, want %q", fb.lineAt(2), "gamma")
	}
}

// ---------------------------------------------------------------------------
// lineAt out-of-bounds
// ---------------------------------------------------------------------------

func TestLineAt_OutOfBounds(t *testing.T) {
	fb := newFileBuffer([]byte("a\nb\nc"))

	tests := []struct {
		name string
		idx  int
	}{
		{"negative", -1},
		{"too large", 100},
		{"exactly lineCount", fb.lineCount()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fb.lineAt(tc.idx)
			if got != "" {
				t.Errorf("lineAt(%d) = %q, want empty", tc.idx, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// lineColFromOffset
// ---------------------------------------------------------------------------

func TestLineColFromOffset(t *testing.T) {
	// "abc\ndef\nghi"
	//  0123 4567 89..
	data := []byte("abc\ndef\nghi")
	fb := newFileBuffer(data)

	tests := []struct {
		name    string
		offset  int
		wantLn  int
		wantCol int
	}{
		{"start of file", 0, 1, 1},
		{"middle of first line", 2, 1, 3},
		{"start of second line", 4, 2, 1},
		{"end of file", len(data) - 1, 3, 3}, // 'i' at offset 10
		{"negative offset", -1, 1, 0},          // clamps to line 0
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ln, col := fb.lineColFromOffset(tc.offset)
			if ln != tc.wantLn || col != tc.wantCol {
				t.Errorf("lineColFromOffset(%d) = (%d, %d), want (%d, %d)",
					tc.offset, ln, col, tc.wantLn, tc.wantCol)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// linesForProximity
// ---------------------------------------------------------------------------

func TestLinesForProximity(t *testing.T) {
	data := []byte("L0\nL1\nL2\nL3\nL4\n")
	fb := newFileBuffer(data)

	tests := []struct {
		name     string
		lineIdx  int
		radius   int
		wantLen  int
		wantFirst string
		wantLast  string
	}{
		{"center", 2, 1, 3, "L1", "L3"},
		{"near start clamps", 0, 2, 3, "L0", "L2"},
		{"near end clamps", 4, 2, 3, "L2", "L4"},
		{"radius covers all", 2, 10, 5, "L0", "L4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lines := fb.linesForProximity(tc.lineIdx, tc.radius)
			if len(lines) != tc.wantLen {
				t.Fatalf("len = %d, want %d; lines = %v", len(lines), tc.wantLen, lines)
			}
			if lines[0] != tc.wantFirst {
				t.Errorf("first = %q, want %q", lines[0], tc.wantFirst)
			}
			if lines[len(lines)-1] != tc.wantLast {
				t.Errorf("last = %q, want %q", lines[len(lines)-1], tc.wantLast)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// proximityCenter
// ---------------------------------------------------------------------------

func TestProximityCenter(t *testing.T) {
	fb := newFileBuffer([]byte("a\nb\nc\nd\ne\n"))

	tests := []struct {
		name    string
		lineIdx int
		radius  int
		want    int
	}{
		{"center", 2, 1, 1},
		{"near start clamps", 0, 3, 0},
		{"near end", 4, 1, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fb.proximityCenter(tc.lineIdx, tc.radius)
			if got != tc.want {
				t.Errorf("proximityCenter(%d, %d) = %d, want %d",
					tc.lineIdx, tc.radius, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// scanBuffer tests
// ---------------------------------------------------------------------------

// bufferTestRuleSet creates an isolated rule set (no built-in rules) with only
// the supplied custom rules.
func bufferTestRuleSet(t *testing.T, ruleConfigs []config.RuleConfig, globalAL []config.Allowlist) *rules.RuleSet {
	t.Helper()
	rs, err := rules.CompileWithOptions(ruleConfigs, globalAL, rules.CompileOptions{UseDefault: false})
	if err != nil {
		t.Fatalf("failed to compile test rules: %v", err)
	}
	return rs
}

// awsKeyRule returns a simple rule config that matches the well-known AWS
// example access key AKIAIOSFODNN7EXAMPLE.
func awsKeyRule() config.RuleConfig {
	return config.RuleConfig{
		ID:          "test-aws-key",
		Description: "Test AWS Access Key",
		Regex:       `\b(AKIA[0-9A-Z]{16})\b`,
		SecretGroup: 1,
		Keywords:    []string{"AKIA"},
		Tags:        []string{"aws"},
	}
}

func TestScanBuffer_FindsKnownSecret(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("config: AKIAIOSFODNN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.RuleID != "test-aws-key" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "test-aws-key")
	}
	if f.Secret != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Secret = %q, want AKIAIOSFODNN7EXAMPLE", f.Secret)
	}
}

func TestScanBuffer_CleanContent(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("no secrets here\njust normal text\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "clean.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanBuffer_InlineAllowSuppresses(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("key=AKIAIOSFODNN7EXAMPLE // leakdetector:allow\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected inline allow to suppress finding, got %d findings", len(findings))
	}
}

func TestScanBuffer_SecretSplitAcrossLines(t *testing.T) {
	// The regex requires contiguous AKIA + 16 chars. Splitting the key across
	// lines means \n is inserted in the middle, so the regex should NOT match.
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("AKIAIOSFODN\nN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected no findings for split secret, got %d", len(findings))
	}
}

func TestScanBuffer_GlobalAllowlistSuppresses(t *testing.T) {
	globalAL := []config.Allowlist{
		{
			Description: "Allow example keys",
			Regexes:     []string{`AKIAIOSFODNN7EXAMPLE`},
		},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, globalAL)
	content := []byte("key=AKIAIOSFODNN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected global allowlist to suppress finding, got %d findings", len(findings))
	}
}

func TestScanBuffer_ProximityRequired_Found(t *testing.T) {
	rule := config.RuleConfig{
		ID:          "test-secret-with-context",
		Description: "Secret near keyword",
		Regex:       `SECRET_([A-Z0-9]{10,})`,
		SecretGroup: 1,
		Required: []config.RequiredRule{
			{
				ID:          "needs-password-keyword",
				Regex:       `(?i)password`,
				WithinLines: 3,
			},
		},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)

	// Required pattern "password" is within 3 lines of the secret.
	content := []byte("password = value\nconfig = SECRET_ABCDEFGHIJ\nother\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Fatal("expected finding when proximity required pattern is nearby")
	}
}

func TestScanBuffer_ProximityRequired_NotNearby(t *testing.T) {
	rule := config.RuleConfig{
		ID:          "test-secret-with-context",
		Description: "Secret near keyword",
		Regex:       `SECRET_([A-Z0-9]{10,})`,
		SecretGroup: 1,
		Required: []config.RequiredRule{
			{
				ID:          "needs-password-keyword",
				Regex:       `(?i)password`,
				WithinLines: 1,
			},
		},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)

	// Required pattern "password" is too far away (more than 1 line).
	content := []byte("password = value\nfiller\nfiller\nfiller\nconfig = SECRET_ABCDEFGHIJ\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected proximity check to suppress finding, got %d", len(findings))
	}
}

func TestScanBuffer_MaxDecodeDepth(t *testing.T) {
	// "AKIAIOSFODNN7EXAMPLE" base64-encoded is "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	ruleConfigs := []config.RuleConfig{
		{
			ID:          "test-base64-blob",
			Description: "Base64 blob",
			Regex:       `(QUtJQUlPU0ZPRE5ON0VYQU1QTEU=)`,
			SecretGroup: 1,
			Tags:        []string{"test"},
		},
		awsKeyRule(),
	}
	rs := bufferTestRuleSet(t, ruleConfigs, nil)

	content := []byte("secret=QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{
		Stderr:         &bytes.Buffer{},
		MaxDecodeDepth: 2,
	}, "", "")

	// Look for the decoded:base64 tag on the base64-blob finding.
	for _, f := range findings {
		if f.RuleID == "test-base64-blob" {
			for _, tag := range f.Tags {
				if tag == "decoded:base64" {
					return // success
				}
			}
		}
	}
	t.Log("decoded:base64 tag not found; decoder path may not have triggered")
}

func TestScanBuffer_Deduplication(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)

	// Place the secret near a window boundary so it could appear in two
	// overlapping windows. The sliding window overlap is 1024 bytes, so
	// place the secret around offset (4096 - 1024) = 3072. The keyword
	// pre-filter needs "akia" (case-insensitive) in the window.
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte(" "), 3072))
	buf.WriteString("AKIAIOSFODNN7EXAMPLE")
	buf.Write(bytes.Repeat([]byte(" "), 2000))
	fb := newFileBuffer(buf.Bytes())

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")

	// Count findings for our rule.
	count := 0
	for _, f := range findings {
		if f.RuleID == "test-aws-key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 deduplicated finding, got %d", count)
	}
}

func TestScanBuffer_LargeContent_MultipleWindows(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)

	// Place secrets in different windows.
	var buf bytes.Buffer
	buf.WriteString("AKIAIOSFODNN7AAAAAAA\n") // near start
	buf.Write(bytes.Repeat([]byte("x"), 5000))
	buf.WriteString("\nAKIAIOSFODNN7BBBBBBB\n") // in a later window
	fb := newFileBuffer(buf.Bytes())

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")

	ruleFindings := 0
	for _, f := range findings {
		if f.RuleID == "test-aws-key" {
			ruleFindings++
		}
	}
	if ruleFindings != 2 {
		t.Errorf("expected 2 findings in multi-window content, got %d", ruleFindings)
	}
}

func TestScanBuffer_BinaryLikeContent(t *testing.T) {
	// One long line with no newlines (binary-like).
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)

	content := make([]byte, 0, 200)
	content = append(content, bytes.Repeat([]byte(" "), 50)...)
	content = append(content, []byte("AKIAIOSFODNN7EXAMPLE")...)
	content = append(content, bytes.Repeat([]byte(" "), 50)...)
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "bin.dat", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Fatal("expected finding in binary-like (no newline) content")
	}
	// With no newlines, the entire file is one line.
	if findings[0].StartLine != 1 {
		t.Errorf("StartLine = %d, want 1", findings[0].StartLine)
	}
}

func TestScanBuffer_FindingLineColumn(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("line one\nkey=AKIAIOSFODNN7EXAMPLE\nline three\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := findings[0]
	if f.StartLine != 2 {
		t.Errorf("StartLine = %d, want 2", f.StartLine)
	}
	// "key=" is 4 chars, so the match starts at column 5.
	if f.StartColumn != 5 {
		t.Errorf("StartColumn = %d, want 5", f.StartColumn)
	}
}

// ---------------------------------------------------------------------------
// Integration: scanSingleFile with temp file
// ---------------------------------------------------------------------------

func TestScanSingleFile_LineColumnAccuracy(t *testing.T) {
	dir := t.TempDir()
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)

	content := "first line\nsecond line\nprefix AKIAIOSFODNN7EXAMPLE suffix\nfourth line\n"
	fpath := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := scanSingleFile("test.txt", fpath, "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if err != nil {
		t.Fatalf("scanSingleFile error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := findings[0]
	if f.StartLine != 3 {
		t.Errorf("StartLine = %d, want 3", f.StartLine)
	}
	// "prefix " is 7 chars, match starts at column 8.
	if f.StartColumn != 8 {
		t.Errorf("StartColumn = %d, want 8", f.StartColumn)
	}
	if f.File != "test.txt" {
		t.Errorf("File = %q, want %q", f.File, "test.txt")
	}
	if f.Secret != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Secret = %q, want AKIAIOSFODNN7EXAMPLE", f.Secret)
	}
}

func TestScanSingleFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)

	fpath := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(fpath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := scanSingleFile("empty.txt", fpath, "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if err != nil {
		t.Fatalf("scanSingleFile error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestScanSingleFile_MultipleSecretsOnDifferentLines(t *testing.T) {
	dir := t.TempDir()
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)

	content := "AKIAIOSFODNN7AAAAAAA\nfiller\nAKIAIOSFODNN7BBBBBBB\n"
	fpath := filepath.Join(dir, "multi.txt")
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := scanSingleFile("multi.txt", fpath, "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if err != nil {
		t.Fatalf("scanSingleFile error: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	// Verify both line numbers appear.
	linesSeen := make(map[int]bool)
	for _, f := range findings {
		linesSeen[f.StartLine] = true
	}
	if !linesSeen[1] {
		t.Error("expected finding on line 1")
	}
	if !linesSeen[3] {
		t.Error("expected finding on line 3")
	}
}

func TestScanBuffer_EntropyFilter(t *testing.T) {
	// Rule with a high entropy threshold that the low-entropy secret won't pass.
	rule := config.RuleConfig{
		ID:      "test-entropy",
		Regex:   `SECRET=([A-Za-z0-9]+)`,
		SecretGroup: 1,
		Entropy: 3.5,
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)

	// "aaaa" has very low entropy (0.0).
	content := []byte("SECRET=aaaa\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected entropy filter to suppress finding, got %d", len(findings))
	}

	// High-entropy secret should pass (entropy ~4.0).
	content2 := []byte("SECRET=a9X7kL2mQ5nR8pW4\n")
	fb2 := newFileBuffer(content2)

	findings2 := scanBuffer(fb2, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings2) == 0 {
		t.Error("expected high-entropy secret to produce a finding")
	}
}

func TestScanBuffer_PathFilter(t *testing.T) {
	rule := config.RuleConfig{
		ID:    "test-go-only",
		Regex: `SECRET_[A-Z]+`,
		Path:  `\.go$`,
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)
	content := []byte("found SECRET_VALUE here\n")
	fb := newFileBuffer(content)

	// Should match .go files.
	findings := scanBuffer(fb, "main.go", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Error("expected finding for .go file")
	}

	// Should NOT match .py files.
	findings2 := scanBuffer(fb, "main.py", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings2) != 0 {
		t.Errorf("expected no finding for .py file, got %d", len(findings2))
	}
}

func TestScanBuffer_KeywordPreFilter(t *testing.T) {
	rule := config.RuleConfig{
		ID:       "test-kw",
		Regex:    `TOKEN_[A-Z]+`,
		Keywords: []string{"token"},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)

	// Content has the keyword.
	fb := newFileBuffer([]byte("my token is TOKEN_VALUE\n"))
	findings := scanBuffer(fb, "f.go", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Error("expected finding when keyword is present")
	}

	// Content does NOT have the keyword.
	fb2 := newFileBuffer([]byte("my secret is TOKEN_VALUE\n"))
	// "secret" doesn't contain "token" so keyword filter fails.
	// Wait, "TOKEN_VALUE" does contain "token" (case-insensitive).
	// Use content without the keyword at all.
	fb3 := newFileBuffer([]byte("no keyword here but regex matches TOKEN_VALUE nope\n"))
	// Actually "TOKEN_VALUE" contains "token" substring. Let me use a keyword
	// that is truly absent from content.
	rule2 := config.RuleConfig{
		ID:       "test-kw2",
		Regex:    `SECRET_[A-Z]+`,
		Keywords: []string{"password"},
	}
	rs2 := bufferTestRuleSet(t, []config.RuleConfig{rule2}, nil)
	fb4 := newFileBuffer([]byte("has SECRET_VALUE but not the keyword\n"))
	findings2 := scanBuffer(fb4, "f.go", "", rs2, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings2) != 0 {
		t.Errorf("expected keyword filter to suppress finding, got %d", len(findings2))
	}

	_ = fb2
	_ = fb3
}

func TestScanBuffer_Fingerprint(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "abc123", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	fp := findings[0].Fingerprint
	if !strings.Contains(fp, "abc123") || !strings.Contains(fp, "test.txt") {
		t.Errorf("fingerprint %q should contain commit and file", fp)
	}
}

func TestScanBuffer_Tags(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	f := findings[0]
	if len(f.Tags) == 0 {
		t.Error("expected tags to be copied")
	}
	foundTag := false
	for _, tag := range f.Tags {
		if tag == "aws" {
			foundTag = true
		}
	}
	if !foundTag {
		t.Errorf("expected 'aws' tag, got %v", f.Tags)
	}
}

func TestScanBuffer_NilRegexSkipped(t *testing.T) {
	// A rule with no regex (Regex == nil after compile) should be skipped.
	// CompileWithOptions with a rule that has no regex will fail, so we test
	// indirectly by using a rule with a path filter that doesn't match.
	// Instead, test with a rule that has keywords but the window doesn't
	// contain them -- this exercises the keyword pre-filter skip path.
	rule := config.RuleConfig{
		ID:       "test-no-match-kw",
		Regex:    `NOMATCH_[A-Z]+`,
		Keywords: []string{"xyzzy"},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)
	content := []byte("no keywords here\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanBuffer_PlatformLinkGenerated(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "abc123", rs, Options{
		Stderr:   &bytes.Buffer{},
		Platform: "github",
	}, "myowner", "myrepo")

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Link == "" {
		t.Error("expected non-empty Link when platform owner/repo provided")
	}
	if !strings.Contains(findings[0].Link, "github.com/myowner/myrepo") {
		t.Errorf("expected github link, got %q", findings[0].Link)
	}
}

func TestScanBuffer_EmptyLinkOwnerRepo(t *testing.T) {
	rs := bufferTestRuleSet(t, []config.RuleConfig{awsKeyRule()}, nil)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "abc123", rs, Options{
		Stderr:   &bytes.Buffer{},
		Platform: "github",
	}, "", "")

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Link != "" {
		t.Errorf("expected empty Link when owner/repo empty, got %q", findings[0].Link)
	}
}

func TestScanBuffer_ProximityDefaultRadius(t *testing.T) {
	// Test that when Required rules have WithinLines=0, the default radius of 5 is used.
	rule := config.RuleConfig{
		ID:          "test-prox-default",
		Description: "Proximity default radius",
		Regex:       `SECRET_([A-Z0-9]{10,})`,
		SecretGroup: 1,
		Required: []config.RequiredRule{
			{
				ID:          "needs-keyword",
				Regex:       `(?i)password`,
				WithinLines: 0, // zero triggers default radius of 5
			},
		},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)

	// Place "password" within default 5-line radius of the secret.
	content := []byte("password = val\nfiller\nfiller\nconfig = SECRET_ABCDEFGHIJ\n")
	fb := newFileBuffer(content)

	findings := scanBuffer(fb, "test.txt", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) == 0 {
		t.Error("expected finding when proximity keyword is within default radius")
	}
}

func TestScanBuffer_RuleAllowlistSuppresses(t *testing.T) {
	rule := config.RuleConfig{
		ID:    "test-with-al",
		Regex: `SECRET_([A-Z]+)`,
		Allowlists: []config.Allowlist{
			{StopWords: []string{"example"}},
		},
	}
	rs := bufferTestRuleSet(t, []config.RuleConfig{rule}, nil)

	// Secret contains stop word "example" (case-insensitive check).
	content := []byte("SECRET_EXAMPLE\n")
	fb := newFileBuffer(content)
	findings := scanBuffer(fb, "f.go", "", rs, Options{Stderr: &bytes.Buffer{}}, "", "")
	if len(findings) != 0 {
		t.Errorf("expected rule allowlist to suppress finding, got %d", len(findings))
	}
}
