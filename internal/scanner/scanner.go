package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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

	// Create context with optional timeout.
	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	var findings []finding.Finding

	// Scan files on disk.
	fileFindings, err := scanFiles(ctx, opts, rs)
	if err != nil {
		return nil, fmt.Errorf("file scan: %w", err)
	}
	findings = append(findings, fileFindings...)

	// Scan staged changes if requested.
	if opts.Staged {
		stagedFindings, stagedErr := scanStaged(opts, rs)
		if stagedErr != nil {
			return findings, fmt.Errorf("staged scan: %w", stagedErr)
		}
		findings = append(findings, stagedFindings...)
	} else if !opts.SkipHistory {
		// Scan git history if .git directory exists and history is not skipped.
		gitDir := filepath.Join(dir, ".git")
		info, statErr := os.Stat(gitDir)
		if statErr == nil && info.IsDir() {
			gitFindings, gitErr := scanGit(ctx, opts, rs)
			if gitErr != nil {
				return findings, fmt.Errorf("git scan: %w", gitErr)
			}
			findings = append(findings, gitFindings...)
		}
	}

	return findings, nil
}
