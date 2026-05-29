package output

import (
	"encoding/json"
	"io"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
)

// writeJSON writes findings as an indented JSON array.
func writeJSON(dest io.Writer, findings []finding.Finding) error {
	encoder := json.NewEncoder(dest)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}
