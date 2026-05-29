package output

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

func TestWriteJUnitValid(t *testing.T) {
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
			if err := writeJUnit(&buf, tc.findings); err != nil {
				t.Fatalf("writeJUnit() error: %v", err)
			}

			output := buf.String()
			// Should start with XML header.
			if !strings.HasPrefix(output, xml.Header) {
				t.Error("output does not start with XML header")
			}

			var suites junitTestSuites
			if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
				t.Fatalf("output is not valid XML: %v", err)
			}
		})
	}
}

func TestWriteJUnitGroupedByRuleID(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID:      "rule-a",
			Description: "Rule A",
			StartLine:   1,
			File:        "file1.go",
			Secret:      "secret1",
			Fingerprint: "fp1",
		},
		{
			RuleID:      "rule-b",
			Description: "Rule B",
			StartLine:   5,
			File:        "file2.go",
			Secret:      "secret2",
			Fingerprint: "fp2",
		},
		{
			RuleID:      "rule-a",
			Description: "Rule A",
			StartLine:   10,
			File:        "file3.go",
			Secret:      "secret3",
			Fingerprint: "fp3",
		},
	}

	var buf bytes.Buffer
	if err := writeJUnit(&buf, findings); err != nil {
		t.Fatalf("writeJUnit() error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("not valid XML: %v", err)
	}

	// Two unique rule IDs => two test suites.
	if len(suites.TestSuites) != 2 {
		t.Fatalf("expected 2 test suites, got %d", len(suites.TestSuites))
	}

	// First suite should be rule-a with 2 test cases.
	if suites.TestSuites[0].Name != "rule-a" {
		t.Errorf("first suite name = %q, want %q", suites.TestSuites[0].Name, "rule-a")
	}
	if suites.TestSuites[0].Tests != 2 {
		t.Errorf("first suite tests = %d, want 2", suites.TestSuites[0].Tests)
	}
	if suites.TestSuites[0].Failures != 2 {
		t.Errorf("first suite failures = %d, want 2", suites.TestSuites[0].Failures)
	}
	if len(suites.TestSuites[0].TestCases) != 2 {
		t.Errorf("first suite test cases = %d, want 2", len(suites.TestSuites[0].TestCases))
	}

	// Second suite should be rule-b with 1 test case.
	if suites.TestSuites[1].Name != "rule-b" {
		t.Errorf("second suite name = %q, want %q", suites.TestSuites[1].Name, "rule-b")
	}
	if suites.TestSuites[1].Tests != 1 {
		t.Errorf("second suite tests = %d, want 1", suites.TestSuites[1].Tests)
	}
	if len(suites.TestSuites[1].TestCases) != 1 {
		t.Errorf("second suite test cases = %d, want 1", len(suites.TestSuites[1].TestCases))
	}
}

func TestWriteJUnitTestCaseStructure(t *testing.T) {
	f := sampleFinding()
	var buf bytes.Buffer
	if err := writeJUnit(&buf, []finding.Finding{f}); err != nil {
		t.Fatalf("writeJUnit() error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("not valid XML: %v", err)
	}

	if len(suites.TestSuites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.TestSuites))
	}

	suite := suites.TestSuites[0]
	if suite.Name != f.RuleID {
		t.Errorf("suite name = %q, want %q", suite.Name, f.RuleID)
	}

	if len(suite.TestCases) != 1 {
		t.Fatalf("expected 1 test case, got %d", len(suite.TestCases))
	}

	tc := suite.TestCases[0]
	expectedName := fmt.Sprintf("%s:%d", f.File, f.StartLine)
	if tc.Name != expectedName {
		t.Errorf("test case name = %q, want %q", tc.Name, expectedName)
	}
	if tc.ClassName != f.RuleID {
		t.Errorf("test case classname = %q, want %q", tc.ClassName, f.RuleID)
	}

	if tc.Failure == nil {
		t.Fatal("test case failure is nil")
	}
	if tc.Failure.Message != f.Description {
		t.Errorf("failure message = %q, want %q", tc.Failure.Message, f.Description)
	}
	if tc.Failure.Type != f.RuleID {
		t.Errorf("failure type = %q, want %q", tc.Failure.Type, f.RuleID)
	}

	expectedText := fmt.Sprintf("Secret detected in %s at line %d: %s", f.File, f.StartLine, f.Secret)
	if tc.Failure.Text != expectedText {
		t.Errorf("failure text = %q, want %q", tc.Failure.Text, expectedText)
	}
}

func TestWriteJUnitEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJUnit(&buf, []finding.Finding{}); err != nil {
		t.Fatalf("writeJUnit() error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("not valid XML: %v", err)
	}

	if len(suites.TestSuites) != 0 {
		t.Errorf("expected 0 test suites for empty findings, got %d", len(suites.TestSuites))
	}
}

func TestWriteJUnitPreservesOrder(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "z-rule", File: "a.go", StartLine: 1, Secret: "s1", Fingerprint: "fp1"},
		{RuleID: "a-rule", File: "b.go", StartLine: 2, Secret: "s2", Fingerprint: "fp2"},
		{RuleID: "m-rule", File: "c.go", StartLine: 3, Secret: "s3", Fingerprint: "fp3"},
	}

	var buf bytes.Buffer
	if err := writeJUnit(&buf, findings); err != nil {
		t.Fatalf("writeJUnit() error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("not valid XML: %v", err)
	}

	// Order should match insertion order, not alphabetical.
	expectedOrder := []string{"z-rule", "a-rule", "m-rule"}
	for i, suite := range suites.TestSuites {
		if suite.Name != expectedOrder[i] {
			t.Errorf("suite[%d] = %q, want %q", i, suite.Name, expectedOrder[i])
		}
	}
}

func TestWriteJUnitSingleRuleMultipleFindings(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "same-rule", File: "a.go", StartLine: 1, Secret: "s1", Fingerprint: "fp1", Description: "desc"},
		{RuleID: "same-rule", File: "b.go", StartLine: 5, Secret: "s2", Fingerprint: "fp2", Description: "desc"},
		{RuleID: "same-rule", File: "c.go", StartLine: 9, Secret: "s3", Fingerprint: "fp3", Description: "desc"},
	}

	var buf bytes.Buffer
	if err := writeJUnit(&buf, findings); err != nil {
		t.Fatalf("writeJUnit() error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("not valid XML: %v", err)
	}

	if len(suites.TestSuites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.TestSuites))
	}

	suite := suites.TestSuites[0]
	if suite.Tests != 3 {
		t.Errorf("Tests = %d, want 3", suite.Tests)
	}
	if suite.Failures != 3 {
		t.Errorf("Failures = %d, want 3", suite.Failures)
	}
	if len(suite.TestCases) != 3 {
		t.Errorf("TestCases = %d, want 3", len(suite.TestCases))
	}
}
