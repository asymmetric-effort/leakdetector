package output

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// writeCSV writes findings in CSV format with a header row.
func writeCSV(dest io.Writer, findings []finding.Finding) error {
	w := csv.NewWriter(dest)

	// Write header row.
	if err := w.Write([]string{
		"RuleID", "Description", "File", "StartLine",
		"Secret", "Commit", "Author", "Fingerprint",
	}); err != nil {
		return err
	}

	// Write one row per finding.
	for i := range findings {
		f := &findings[i]
		record := []string{
			f.RuleID,
			f.Description,
			f.File,
			strconv.Itoa(f.StartLine),
			f.Secret,
			f.Commit,
			f.Author,
			f.Fingerprint,
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
