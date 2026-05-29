package output

import (
	"io"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// Writer formats findings for output in the configured format.
type Writer struct {
	Format        string
	RedactPercent int
	TemplatePath  string
}

// New creates a new Writer with the specified format, redaction percentage, and
// optional template path (used when format is "template").
//
// RedactPercent semantics:
//
//	0  = no redaction (default / disabled)
//	100 = fully redact (replace with "REDACTED")
//	1-99 = show (100 - RedactPercent)% of the secret, i.e. redact that percentage
func New(format string, redactPercent int, templatePath string) *Writer {
	return &Writer{
		Format:        format,
		RedactPercent: redactPercent,
		TemplatePath:  templatePath,
	}
}

// Write formats findings and writes them to dest. If RedactPercent > 0,
// each finding is redacted before writing. Supported formats: json, csv,
// junit, sarif, template. Unknown formats default to JSON.
func (w *Writer) Write(dest io.Writer, findings []finding.Finding) error {
	if w.RedactPercent > 0 {
		// Convert: RedactPercent of 100 means fully redact (pct=0 to RedactPercent method),
		// RedactPercent of 50 means redact 50% (show 50%), etc.
		pct := 100 - w.RedactPercent
		for i := range findings {
			findings[i].RedactPercent(pct)
		}
	}

	switch w.Format {
	case "csv":
		return writeCSV(dest, findings)
	case "junit":
		return writeJUnit(dest, findings)
	case "sarif":
		return writeSARIF(dest, findings)
	case "template":
		return writeTemplate(dest, findings, w.TemplatePath)
	default:
		return writeJSON(dest, findings)
	}
}
