package output

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

func TestWriteCSVValid(t *testing.T) {
	tests := []struct {
		name     string
		findings []finding.Finding
		wantRows int // including header
	}{
		{
			name:     "single finding",
			findings: []finding.Finding{sampleFinding()},
			wantRows: 2,
		},
		{
			name:     "multiple findings",
			findings: sampleFindings(),
			wantRows: 3,
		},
		{
			name:     "empty findings",
			findings: []finding.Finding{},
			wantRows: 1, // header only
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeCSV(&buf, tc.findings); err != nil {
				t.Fatalf("writeCSV() error: %v", err)
			}

			r := csv.NewReader(strings.NewReader(buf.String()))
			records, err := r.ReadAll()
			if err != nil {
				t.Fatalf("output is not valid CSV: %v", err)
			}
			if len(records) != tc.wantRows {
				t.Errorf("got %d rows, want %d", len(records), tc.wantRows)
			}
		})
	}
}

func TestWriteCSVHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCSV(&buf, []finding.Finding{}); err != nil {
		t.Fatalf("writeCSV() error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}

	if len(records) < 1 {
		t.Fatal("expected at least a header row")
	}

	expectedHeaders := []string{
		"RuleID", "Description", "File", "StartLine",
		"Secret", "Commit", "Author", "Fingerprint",
	}

	header := records[0]
	if len(header) != len(expectedHeaders) {
		t.Fatalf("header has %d columns, want %d", len(header), len(expectedHeaders))
	}

	for i, want := range expectedHeaders {
		if header[i] != want {
			t.Errorf("header[%d] = %q, want %q", i, header[i], want)
		}
	}
}

func TestWriteCSVColumnCount(t *testing.T) {
	var buf bytes.Buffer
	findings := sampleFindings()
	if err := writeCSV(&buf, findings); err != nil {
		t.Fatalf("writeCSV() error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}

	expectedCols := 8
	for i, row := range records {
		if len(row) != expectedCols {
			t.Errorf("row %d has %d columns, want %d", i, len(row), expectedCols)
		}
	}
}

func TestWriteCSVDataValues(t *testing.T) {
	var buf bytes.Buffer
	f := sampleFinding()
	if err := writeCSV(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeCSV() error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}

	if len(records) < 2 {
		t.Fatal("expected header + data row")
	}

	data := records[1]
	checks := []struct {
		col  int
		name string
		want string
	}{
		{0, "RuleID", f.RuleID},
		{1, "Description", f.Description},
		{2, "File", f.File},
		{3, "StartLine", "10"},
		{4, "Secret", f.Secret},
		{5, "Commit", f.Commit},
		{6, "Author", f.Author},
		{7, "Fingerprint", f.Fingerprint},
	}

	for _, c := range checks {
		if data[c.col] != c.want {
			t.Errorf("%s = %q, want %q", c.name, data[c.col], c.want)
		}
	}
}

func TestWriteCSVNilFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCSV(&buf, nil); err != nil {
		t.Fatalf("writeCSV() error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v", err)
	}

	// Should have header only.
	if len(records) != 1 {
		t.Errorf("expected 1 row (header), got %d", len(records))
	}
}

func TestWriteCSVSpecialCharacters(t *testing.T) {
	var buf bytes.Buffer
	f := sampleFinding()
	f.Description = "contains, commas and \"quotes\""
	f.Secret = "line1\nline2"

	if err := writeCSV(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeCSV() error: %v", err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV with special chars not valid: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(records))
	}

	if records[1][1] != f.Description {
		t.Errorf("Description = %q, want %q", records[1][1], f.Description)
	}
}
