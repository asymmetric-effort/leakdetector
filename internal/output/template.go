package output

import (
	"fmt"
	"io"
	"text/template"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/safefile"
)

// writeTemplate loads a Go text/template from templatePath and executes it
// with the given findings slice, writing the result to w.
func writeTemplate(w io.Writer, findings []finding.Finding, templatePath string) error {
	if templatePath == "" {
		return fmt.Errorf("template path is required for template format")
	}

	data, err := safefile.Read(templatePath)
	if err != nil {
		return fmt.Errorf("read template file: %w", err)
	}

	tmpl, err := template.New("report").Parse(string(data))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	if err := tmpl.Execute(w, findings); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}
