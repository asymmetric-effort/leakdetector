package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// scanStaged runs git diff --staged and scans added lines against all rules.
func scanStaged(opts Options, rs *rules.RuleSet) ([]finding.Finding, error) {
	cmd := exec.Command("git", "diff", "--staged")
	cmd.Dir = opts.Dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git diff stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git diff start: %w", err)
	}

	var findings []finding.Finding

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	var (
		filePath string
		lineNum  int
		inDiff   bool
	)

	for scanner.Scan() {
		line := scanner.Text()

		// Parse diff headers.
		if strings.HasPrefix(line, "diff --git ") {
			inDiff = true
			lineNum = 0
			continue
		}

		if inDiff && strings.HasPrefix(line, "+++ b/") {
			filePath = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
			continue
		}

		if inDiff && strings.HasPrefix(line, "--- ") {
			continue
		}

		// Parse hunk headers to track line numbers.
		if inDiff && strings.HasPrefix(line, "@@ ") {
			lineNum = parseHunkLineNumber(line)
			continue
		}

		// Only process added lines (start with +).
		if inDiff && strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := line[1:] // Strip the leading +.

			if filePath != "" && isExcludedPath(filePath, opts.ExcludePaths) {
				lineNum++
				continue
			}

			lineFindings := matchLine(content, lineNum, filePath, "", rs, opts)
			findings = append(findings, lineFindings...)
			lineNum++
			continue
		}

		// Context lines advance line counter.
		if inDiff && len(line) > 0 && line[0] == ' ' {
			lineNum++
			continue
		}

		// Lines starting with - are removed lines; don't advance new-file line counter.
	}

	if err := scanner.Err(); err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: git diff scanner error: %v\n", err)
		}
	}

	if err := cmd.Wait(); err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: git diff exited with: %v\n", err)
		}
	}

	return findings, nil
}
