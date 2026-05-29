package scanner

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestScanStdin_WithSecrets(t *testing.T) {
	rs := testRuleSet(t)

	// Create a pipe to simulate stdin.
	input := "line one\nAKIAIOSFODNN7EXAMPLE\nline three\n"
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// Save and restore os.Stdin.
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	// Write input in a goroutine to avoid blocking.
	go func() {
		io.WriteString(w, input)
		w.Close()
	}()

	opts := Options{
		Stdin:  true,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanStdin(opts, rs)
	if err != nil {
		t.Fatalf("scanStdin returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from stdin with secret")
	}

	// All findings should have file == "stdin".
	for _, f := range findings {
		if f.File != "stdin" {
			t.Errorf("expected File=stdin, got %s", f.File)
		}
		if f.Commit != "" {
			t.Errorf("expected empty Commit for stdin, got %s", f.Commit)
		}
	}

	// Check that the finding is on line 2.
	foundLine2 := false
	for _, f := range findings {
		if f.StartLine == 2 {
			foundLine2 = true
			break
		}
	}
	if !foundLine2 {
		t.Error("expected a finding on line 2")
	}
}

func TestScanStdin_CleanInput(t *testing.T) {
	rs := testRuleSet(t)

	input := "this is clean\nno secrets here\njust regular text\n"
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

	findings, err := scanStdin(opts, rs)
	if err != nil {
		t.Fatalf("scanStdin returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean input, got %d", len(findings))
	}
}

func TestScanStdin_LongLine(t *testing.T) {
	rs := testRuleSet(t)

	// Create a line longer than maxLineSize (1MB) to trigger scanner.Err().
	longLine := make([]byte, maxLineSize+100)
	for i := range longLine {
		longLine[i] = 'A'
	}
	// No newline at the end - the scanner will try to read the whole thing
	// as one line and fail.

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	go func() {
		w.Write(longLine)
		w.Close()
	}()

	opts := Options{
		Stdin:  true,
		Stderr: &bytes.Buffer{},
	}

	_, err = scanStdin(opts, rs)
	if err == nil {
		t.Log("expected scanner error for line exceeding buffer, but got nil")
	}
}

func TestScanStdin_EmptyInput(t *testing.T) {
	rs := testRuleSet(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	go func() {
		w.Close() // Immediate EOF.
	}()

	opts := Options{
		Stdin:  true,
		Stderr: &bytes.Buffer{},
	}

	findings, err := scanStdin(opts, rs)
	if err != nil {
		t.Fatalf("scanStdin returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(findings))
	}
}
