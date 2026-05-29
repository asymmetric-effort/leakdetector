package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// errWriter is an io.Writer that always returns an error.
type errWriter struct{}

func (e *errWriter) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

// limitWriter fails after writing n bytes. Accepts partial writes.
type limitWriter struct {
	n int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return 0, errors.New("write limit exceeded")
	}
	if len(p) > lw.n {
		written := lw.n
		lw.n = 0
		return written, errors.New("write limit exceeded")
	}
	lw.n -= len(p)
	return len(p), nil
}

// sampleFinding returns a fully populated finding for testing.
func sampleFinding() finding.Finding {
	return finding.Finding{
		RuleID:      "api-key",
		Description: "API key detected",
		StartLine:   10,
		EndLine:     10,
		StartColumn: 5,
		EndColumn:   45,
		Match:       "AKIAIOSFODNN7EXAMPLE",
		Secret:      "AKIAIOSFODNN7EXAMPLE",
		File:        "config.yaml",
		Commit:      "abc123",
		Author:      "dev",
		Email:       "dev@example.com",
		Date:        "2025-01-01",
		Message:     "add config",
		Tags:        []string{"aws", "key"},
		Entropy:     4.5,
		Fingerprint: "abc123:config.yaml:api-key:10",
	}
}

// sampleFindings returns two different findings for multi-finding tests.
func sampleFindings() []finding.Finding {
	return []finding.Finding{
		sampleFinding(),
		{
			RuleID:      "password",
			Description: "Password detected",
			StartLine:   20,
			EndLine:     20,
			StartColumn: 1,
			EndColumn:   30,
			Match:       "password=SuperSecret99",
			Secret:      "SuperSecret99",
			File:        "app.env",
			Commit:      "def456",
			Author:      "admin",
			Email:       "admin@example.com",
			Date:        "2025-02-01",
			Message:     "add env",
			Tags:        []string{"password"},
			Entropy:     3.8,
			Fingerprint: "def456:app.env:password:20",
		},
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		format string
		redact bool
	}{
		{"json format no redact", "json", false},
		{"csv format with redact", "csv", true},
		{"junit format no redact", "junit", false},
		{"sarif format with redact", "sarif", true},
		{"empty format", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := New(tc.format, tc.redact)
			if w == nil {
				t.Fatal("New() returned nil")
			}
			if w.Format != tc.format {
				t.Errorf("Format = %q, want %q", w.Format, tc.format)
			}
			if w.Redact != tc.redact {
				t.Errorf("Redact = %v, want %v", w.Redact, tc.redact)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	w := New("json", false)
	findings := []finding.Finding{sampleFinding()}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	var parsed []finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed))
	}
	if parsed[0].RuleID != "api-key" {
		t.Errorf("RuleID = %q, want %q", parsed[0].RuleID, "api-key")
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	w := New("csv", false)
	findings := []finding.Finding{sampleFinding()}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	// header + 1 data row
	if len(records) != 2 {
		t.Fatalf("expected 2 rows (header + 1 data), got %d", len(records))
	}
}

func TestWriteJUnit(t *testing.T) {
	var buf bytes.Buffer
	w := New("junit", false)
	findings := []finding.Finding{sampleFinding()}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
	if len(suites.TestSuites) != 1 {
		t.Fatalf("expected 1 test suite, got %d", len(suites.TestSuites))
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	w := New("sarif", false)
	findings := []finding.Finding{sampleFinding()}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if report.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", report.Version, "2.1.0")
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	w := New("unknown", false)
	findings := []finding.Finding{sampleFinding()}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Unknown format should default to JSON.
	var parsed []finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unknown format did not produce valid JSON: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed))
	}
}

func TestWriteRedact(t *testing.T) {
	formats := []string{"json", "csv", "junit", "sarif"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			w := New(format, true)
			// Use a fresh copy each time since Redact mutates.
			findings := []finding.Finding{sampleFinding()}

			if err := w.Write(&buf, findings); err != nil {
				t.Fatalf("Write() error: %v", err)
			}

			// Verify the finding was redacted (mutated in place).
			if findings[0].Secret == "AKIAIOSFODNN7EXAMPLE" {
				t.Error("finding secret was not redacted")
			}
			if findings[0].Secret != "AK...LE" {
				t.Errorf("Secret = %q, want %q", findings[0].Secret, "AK...LE")
			}
		})
	}
}

func TestWriteRedactShortSecret(t *testing.T) {
	var buf bytes.Buffer
	w := New("json", true)
	findings := []finding.Finding{
		{
			RuleID:      "short",
			Description: "Short secret",
			StartLine:   1,
			EndLine:     1,
			Secret:      "abc",
			Match:       "abc",
			File:        "test.txt",
			Fingerprint: "fp1",
		},
	}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "REDACTED") {
		t.Error("short secret should be fully REDACTED")
	}
}

func TestWriteEmptyFindings(t *testing.T) {
	formats := []string{"json", "csv", "junit", "sarif"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			w := New(format, false)

			if err := w.Write(&buf, []finding.Finding{}); err != nil {
				t.Fatalf("Write() with empty findings error: %v", err)
			}

			if buf.Len() == 0 {
				t.Error("expected non-empty output even with no findings")
			}
		})
	}
}

func TestWriteNilFindings(t *testing.T) {
	formats := []string{"json", "csv", "junit", "sarif"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			w := New(format, false)

			if err := w.Write(&buf, nil); err != nil {
				t.Fatalf("Write() with nil findings error: %v", err)
			}
		})
	}
}

func TestWriteMultipleFindings(t *testing.T) {
	formats := []string{"json", "csv", "junit", "sarif"}
	findings := sampleFindings()

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			w := New(format, false)

			if err := w.Write(&buf, findings); err != nil {
				t.Fatalf("Write() error: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, "api-key") {
				t.Error("output missing first finding rule ID")
			}
			if !strings.Contains(output, "password") {
				t.Error("output missing second finding rule ID")
			}
		})
	}
}

func TestWriteRedactEmptySecret(t *testing.T) {
	var buf bytes.Buffer
	w := New("json", true)
	findings := []finding.Finding{
		{
			RuleID:      "empty-secret",
			Description: "Empty secret test",
			StartLine:   1,
			EndLine:     1,
			Secret:      "",
			Match:       "",
			File:        "test.txt",
			Fingerprint: "fp-empty",
		},
	}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	var parsed []finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Empty secret should remain empty after redact.
	if parsed[0].Secret != "" {
		t.Errorf("Secret = %q, want empty string", parsed[0].Secret)
	}
}

func TestWriteCSVErrorOnHeader(t *testing.T) {
	// errWriter causes csv.Writer's internal bufio to fail on Flush.
	// csv.Writer buffers writes, so header write itself won't fail, but
	// the error surfaces via w.Error() after Flush.
	ew := &errWriter{}
	err := writeCSV(ew, []finding.Finding{sampleFinding()})
	if err == nil {
		t.Error("expected error writing CSV to failing writer")
	}
}

func TestWriteCSVErrorOnLargeRow(t *testing.T) {
	// Create a finding with a very large field to overflow the internal
	// bufio.Writer buffer (4096 bytes), causing csv.Writer.Write to
	// hit the underlying writer's error.
	bigStr := strings.Repeat("x", 5000)
	f := sampleFinding()
	f.Description = bigStr
	// Use errWriter so the bufio flush triggered by buffer overflow fails.
	ew := &errWriter{}
	err := writeCSV(ew, []finding.Finding{f})
	if err == nil {
		t.Error("expected error writing large CSV row to failing writer")
	}
}

func TestWriteCSVErrorOnRowWrite(t *testing.T) {
	// Generate enough findings with large data to overflow the 4096
	// byte internal buffer during row writes.
	bigStr := strings.Repeat("a", 5000)
	findings := make([]finding.Finding, 3)
	for i := range findings {
		findings[i] = finding.Finding{
			RuleID:      bigStr,
			Description: bigStr,
			File:        "f.go",
			StartLine:   1,
			Secret:      "s",
			Fingerprint: "fp",
		}
	}
	ew := &errWriter{}
	err := writeCSV(ew, findings)
	if err == nil {
		t.Error("expected error writing CSV rows to failing writer")
	}
}

func TestWriteJUnitErrorOnHeader(t *testing.T) {
	ew := &errWriter{}
	err := writeJUnit(ew, []finding.Finding{sampleFinding()})
	if err == nil {
		t.Error("expected error writing JUnit XML header to failing writer")
	}
}

func TestWriteJUnitErrorOnEncode(t *testing.T) {
	// Allow the XML header to be written but fail on the body.
	lw := &limitWriter{n: len(xml.Header)}
	err := writeJUnit(lw, []finding.Finding{sampleFinding()})
	if err == nil {
		t.Error("expected error encoding JUnit XML to limited writer")
	}
}
