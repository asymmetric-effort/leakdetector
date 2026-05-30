package scanner

import (
	"bufio"
	"os"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// scanStdin reads lines from os.Stdin and scans each against all rules.
func scanStdin(opts Options, rs *rules.RuleSet) ([]finding.Finding, error) {
	var findings []finding.Finding

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		lineFindings := matchLine(line, lineNum, "stdin", "", rs, opts, nil, 0)
		findings = append(findings, lineFindings...)
	}

	if err := scanner.Err(); err != nil {
		return findings, err
	}

	return findings, nil
}
