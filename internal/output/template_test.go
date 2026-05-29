package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

func TestWriteTemplate_ValidTemplate(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "report.tmpl")
	tmplContent := `Found {{len .}} findings:
{{range .}}- {{.RuleID}}: {{.File}}:{{.StartLine}}
{{end}}`
	if err := os.WriteFile(tmplPath, []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	findings := []finding.Finding{sampleFinding()}

	if err := writeTemplate(&buf, findings, tmplPath); err != nil {
		t.Fatalf("writeTemplate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Found 1 findings") {
		t.Errorf("output missing count, got: %s", output)
	}
	if !strings.Contains(output, "api-key: config.yaml:10") {
		t.Errorf("output missing finding detail, got: %s", output)
	}
}

func TestWriteTemplate_EmptyTemplatePath(t *testing.T) {
	var buf bytes.Buffer
	err := writeTemplate(&buf, []finding.Finding{}, "")
	if err == nil {
		t.Fatal("expected error for empty template path")
	}
	if !strings.Contains(err.Error(), "template path is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestWriteTemplate_MissingFile(t *testing.T) {
	var buf bytes.Buffer
	err := writeTemplate(&buf, []finding.Finding{}, "/nonexistent/template.tmpl")
	if err == nil {
		t.Fatal("expected error for missing template file")
	}
	if !strings.Contains(err.Error(), "read template file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestWriteTemplate_InvalidSyntax(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "bad.tmpl")
	if err := os.WriteFile(tmplPath, []byte("{{ .Invalid {{"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := writeTemplate(&buf, []finding.Finding{}, tmplPath)
	if err == nil {
		t.Fatal("expected error for invalid template syntax")
	}
	if !strings.Contains(err.Error(), "parse template") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestWriteTemplate_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "empty.tmpl")
	tmplContent := `Count: {{len .}}`
	if err := os.WriteFile(tmplPath, []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := writeTemplate(&buf, []finding.Finding{}, tmplPath); err != nil {
		t.Fatalf("writeTemplate() error: %v", err)
	}

	if buf.String() != "Count: 0" {
		t.Errorf("unexpected output: %q", buf.String())
	}
}

func TestWriteTemplate_ExecuteError(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "execerr.tmpl")
	// Call a method that does not exist to trigger an execute error.
	tmplContent := `{{.NonExistentMethod}}`
	if err := os.WriteFile(tmplPath, []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := writeTemplate(&buf, []finding.Finding{sampleFinding()}, tmplPath)
	if err == nil {
		t.Fatal("expected error for template execution failure")
	}
	if !strings.Contains(err.Error(), "execute template") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestWrite_TemplateFormat(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "report.tmpl")
	tmplContent := `{{range .}}{{.RuleID}}{{end}}`
	if err := os.WriteFile(tmplPath, []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := New("template", 0, tmplPath)
	findings := []finding.Finding{sampleFinding()}

	if err := w.Write(&buf, findings); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	if buf.String() != "api-key" {
		t.Errorf("output = %q, want %q", buf.String(), "api-key")
	}
}

func TestWrite_TemplateFormatMissingPath(t *testing.T) {
	var buf bytes.Buffer
	w := New("template", 0, "")
	err := w.Write(&buf, []finding.Finding{})
	if err == nil {
		t.Fatal("expected error for template format without path")
	}
}
