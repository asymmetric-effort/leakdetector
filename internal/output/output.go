package output

import (
	"io"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// Writer formats findings for output in the configured format.
type Writer struct {
	Format string
	Redact bool
}

// New creates a new Writer with the specified format and redaction setting.
func New(format string, redact bool) *Writer {
	return &Writer{
		Format: format,
		Redact: redact,
	}
}

// Write formats findings and writes them to dest. If Redact is true,
// each finding is redacted before writing. Supported formats: json, csv,
// junit, sarif. Unknown formats default to JSON.
func (w *Writer) Write(dest io.Writer, findings []finding.Finding) error {
	if w.Redact {
		for i := range findings {
			findings[i].Redact()
		}
	}

	switch w.Format {
	case "csv":
		return writeCSV(dest, findings)
	case "junit":
		return writeJUnit(dest, findings)
	case "sarif":
		return writeSARIF(dest, findings)
	default:
		return writeJSON(dest, findings)
	}
}
