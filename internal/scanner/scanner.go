package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// Scan orchestrates scanning based on the provided options and rule set.
// If Stdin mode is set, it reads from os.Stdin. Otherwise it scans files
// in Dir, then (if .git exists and SkipHistory is false) scans git history.
func Scan(opts Options, rs *rules.RuleSet) ([]finding.Finding, error) {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	if opts.Stdin {
		return scanStdin(opts, rs)
	}

	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve dir: %w", err)
	}
	opts.Dir = dir

	var findings []finding.Finding

	// Scan files on disk.
	fileFindings, err := scanFiles(opts, rs)
	if err != nil {
		return nil, fmt.Errorf("file scan: %w", err)
	}
	findings = append(findings, fileFindings...)

	// Scan git history if .git directory exists and history is not skipped.
	if !opts.SkipHistory {
		gitDir := filepath.Join(dir, ".git")
		info, statErr := os.Stat(gitDir)
		if statErr == nil && info.IsDir() {
			gitFindings, gitErr := scanGit(opts, rs)
			if gitErr != nil {
				return findings, fmt.Errorf("git scan: %w", gitErr)
			}
			findings = append(findings, gitFindings...)
		}
	}

	return findings, nil
}
