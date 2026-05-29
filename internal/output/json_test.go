package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

func TestWriteJSONValid(t *testing.T) {
	tests := []struct {
		name     string
		findings []finding.Finding
		wantLen  int
	}{
		{
			name:     "single finding",
			findings: []finding.Finding{sampleFinding()},
			wantLen:  1,
		},
		{
			name:     "multiple findings",
			findings: sampleFindings(),
			wantLen:  2,
		},
		{
			name:     "empty findings",
			findings: []finding.Finding{},
			wantLen:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeJSON(&buf, tc.findings); err != nil {
				t.Fatalf("writeJSON() error: %v", err)
			}

			var parsed []finding.Finding
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if len(parsed) != tc.wantLen {
				t.Errorf("got %d findings, want %d", len(parsed), tc.wantLen)
			}
		})
	}
}

func TestWriteJSONEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, []finding.Finding{}); err != nil {
		t.Fatalf("writeJSON() error: %v", err)
	}

	output := buf.String()
	// Should produce an empty JSON array.
	var parsed []finding.Finding
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if len(parsed) != 0 {
		t.Errorf("expected empty array, got %d elements", len(parsed))
	}
}

func TestWriteJSONNilFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, nil); err != nil {
		t.Fatalf("writeJSON() error: %v", err)
	}

	// nil slice encodes as JSON null.
	output := bytes.TrimSpace(buf.Bytes())
	if string(output) != "null" {
		t.Errorf("nil findings produced %q, want \"null\"", string(output))
	}
}

func TestWriteJSONAllFields(t *testing.T) {
	var buf bytes.Buffer
	f := sampleFinding()
	if err := writeJSON(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeJSON() error: %v", err)
	}

	// Parse into raw map to check all expected keys.
	var raw []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	if len(raw) != 1 {
		t.Fatalf("expected 1 element, got %d", len(raw))
	}

	requiredFields := []string{
		"rule_id", "description", "start_line", "end_line",
		"start_column", "end_column", "match", "secret",
		"file", "commit", "author", "email", "date", "message",
		"tags", "entropy", "fingerprint",
	}

	for _, field := range requiredFields {
		if _, ok := raw[0][field]; !ok {
			t.Errorf("missing field %q in JSON output", field)
		}
	}
}

func TestWriteJSONFieldValues(t *testing.T) {
	var buf bytes.Buffer
	f := sampleFinding()
	if err := writeJSON(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeJSON() error: %v", err)
	}

	var parsed []finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	got := parsed[0]
	if got.RuleID != f.RuleID {
		t.Errorf("RuleID = %q, want %q", got.RuleID, f.RuleID)
	}
	if got.Description != f.Description {
		t.Errorf("Description = %q, want %q", got.Description, f.Description)
	}
	if got.StartLine != f.StartLine {
		t.Errorf("StartLine = %d, want %d", got.StartLine, f.StartLine)
	}
	if got.EndLine != f.EndLine {
		t.Errorf("EndLine = %d, want %d", got.EndLine, f.EndLine)
	}
	if got.Secret != f.Secret {
		t.Errorf("Secret = %q, want %q", got.Secret, f.Secret)
	}
	if got.File != f.File {
		t.Errorf("File = %q, want %q", got.File, f.File)
	}
	if got.Commit != f.Commit {
		t.Errorf("Commit = %q, want %q", got.Commit, f.Commit)
	}
	if got.Fingerprint != f.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, f.Fingerprint)
	}
	if got.Entropy != f.Entropy {
		t.Errorf("Entropy = %f, want %f", got.Entropy, f.Entropy)
	}
	if len(got.Tags) != len(f.Tags) {
		t.Errorf("Tags length = %d, want %d", len(got.Tags), len(f.Tags))
	}
}

func TestWriteJSONIndented(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, []finding.Finding{sampleFinding()}); err != nil {
		t.Fatalf("writeJSON() error: %v", err)
	}

	output := buf.String()
	// Indented JSON should contain newlines and spaces.
	if !bytes.Contains([]byte(output), []byte("\n")) {
		t.Error("JSON output is not indented (no newlines)")
	}
	if !bytes.Contains([]byte(output), []byte("  ")) {
		t.Error("JSON output is not indented (no 2-space indent)")
	}
}
