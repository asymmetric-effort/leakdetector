package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

func TestWriteSARIFValid(t *testing.T) {
	tests := []struct {
		name     string
		findings []finding.Finding
	}{
		{"single finding", []finding.Finding{sampleFinding()}},
		{"multiple findings", sampleFindings()},
		{"empty findings", []finding.Finding{}},
		{"nil findings", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeSARIF(&buf, tc.findings); err != nil {
				t.Fatalf("writeSARIF() error: %v", err)
			}

			var report sarifReport
			if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
		})
	}
}

func TestWriteSARIFSchemaAndVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{sampleFinding()}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	expectedSchema := "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	if report.Schema != expectedSchema {
		t.Errorf("Schema = %q, want %q", report.Schema, expectedSchema)
	}
	if report.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", report.Version, "2.1.0")
	}
}

func TestWriteSARIFRunStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{sampleFinding()}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "leakdetector" {
		t.Errorf("driver name = %q, want %q", run.Tool.Driver.Name, "leakdetector")
	}
	if run.Tool.Driver.SemanticVersion != "1.0.0" {
		t.Errorf("semantic version = %q, want %q", run.Tool.Driver.SemanticVersion, "1.0.0")
	}
}

func TestWriteSARIFRulesPopulated(t *testing.T) {
	findings := sampleFindings()
	var buf bytes.Buffer
	if err := writeSARIF(&buf, findings); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	rules := report.Runs[0].Tool.Driver.Rules
	// Two different rule IDs in sampleFindings.
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].ID != "api-key" {
		t.Errorf("rules[0].ID = %q, want %q", rules[0].ID, "api-key")
	}
	if rules[0].ShortDescription.Text != "API key detected" {
		t.Errorf("rules[0] description = %q, want %q", rules[0].ShortDescription.Text, "API key detected")
	}
	if rules[1].ID != "password" {
		t.Errorf("rules[1].ID = %q, want %q", rules[1].ID, "password")
	}
}

func TestWriteSARIFUniqueRules(t *testing.T) {
	// Multiple findings with the same rule ID should produce one rule.
	findings := []finding.Finding{
		{RuleID: "same-rule", Description: "desc", File: "a.go", StartLine: 1, Fingerprint: "fp1"},
		{RuleID: "same-rule", Description: "desc", File: "b.go", StartLine: 2, Fingerprint: "fp2"},
	}

	var buf bytes.Buffer
	if err := writeSARIF(&buf, findings); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Errorf("expected 1 unique rule, got %d", len(rules))
	}
}

func TestWriteSARIFResults(t *testing.T) {
	f := sampleFinding()
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	results := report.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.RuleID != f.RuleID {
		t.Errorf("ruleId = %q, want %q", result.RuleID, f.RuleID)
	}
	if result.Message.Text != f.Description {
		t.Errorf("message = %q, want %q", result.Message.Text, f.Description)
	}
}

func TestWriteSARIFResultLocations(t *testing.T) {
	f := sampleFinding()
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	result := report.Runs[0].Results[0]
	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}

	loc := result.Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != f.File {
		t.Errorf("URI = %q, want %q", loc.PhysicalLocation.ArtifactLocation.URI, f.File)
	}

	region := loc.PhysicalLocation.Region
	if region.StartLine != f.StartLine {
		t.Errorf("StartLine = %d, want %d", region.StartLine, f.StartLine)
	}
	if region.EndLine != f.EndLine {
		t.Errorf("EndLine = %d, want %d", region.EndLine, f.EndLine)
	}
	if region.StartColumn != f.StartColumn {
		t.Errorf("StartColumn = %d, want %d", region.StartColumn, f.StartColumn)
	}
	if region.EndColumn != f.EndColumn {
		t.Errorf("EndColumn = %d, want %d", region.EndColumn, f.EndColumn)
	}
}

func TestWriteSARIFFingerprints(t *testing.T) {
	f := sampleFinding()
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	result := report.Runs[0].Results[0]
	fp, ok := result.Fingerprints["leakdetector"]
	if !ok {
		t.Fatal("fingerprints missing 'leakdetector' key")
	}
	if fp != f.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", fp, f.Fingerprint)
	}
}

func TestWriteSARIFEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
	}

	if len(report.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
}

func TestWriteSARIFMultipleResults(t *testing.T) {
	findings := sampleFindings()
	var buf bytes.Buffer
	if err := writeSARIF(&buf, findings); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	var report sarifReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	results := report.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].RuleID != "api-key" {
		t.Errorf("results[0].ruleId = %q, want %q", results[0].RuleID, "api-key")
	}
	if results[1].RuleID != "password" {
		t.Errorf("results[1].ruleId = %q, want %q", results[1].RuleID, "password")
	}
}

func TestWriteSARIFIndented(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSARIF(&buf, []finding.Finding{sampleFinding()}); err != nil {
		t.Fatalf("writeSARIF() error: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("\n")) {
		t.Error("SARIF output is not indented")
	}
}
