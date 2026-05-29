package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/decoder"
	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

const (
	maxLineSize    = 1024 * 1024 // 1 MB
	maxQueueSize   = 10000
	defaultMaxMB   = 10
)

// scanFiles walks the directory tree iteratively using a bounded stack and
// scans each eligible file line-by-line against all rules.
func scanFiles(opts Options, rs *rules.RuleSet) ([]finding.Finding, error) {
	maxBytes := int64(opts.MaxFileSizeMB) * 1024 * 1024
	if opts.MaxFileSizeMB <= 0 {
		maxBytes = int64(defaultMaxMB) * 1024 * 1024
	}

	var findings []finding.Finding

	// Iterative directory walk using a bounded stack.
	stack := make([]string, 0, 128)
	stack = append(stack, opts.Dir)

	for len(stack) > 0 {
		// Pop from stack.
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(current)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintf(opts.Stderr, "warning: cannot read directory %s: %v\n", current, err)
			}
			continue
		}

		for _, entry := range entries {
			fullPath := filepath.Join(current, entry.Name())
			relPath, _ := filepath.Rel(opts.Dir, fullPath)

			if entry.IsDir() {
				// Skip .git directory.
				if entry.Name() == ".git" {
					continue
				}
				if isExcludedPath(relPath, opts.ExcludePaths) {
					continue
				}
				if len(stack) < maxQueueSize {
					stack = append(stack, fullPath)
				}
				continue
			}

			// Skip excluded paths.
			if isExcludedPath(relPath, opts.ExcludePaths) {
				continue
			}

			// Skip files exceeding size limit.
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Size() > maxBytes {
				if opts.Verbose {
					fmt.Fprintf(opts.Stderr, "skipping large file: %s (%d bytes)\n", relPath, info.Size())
				}
				continue
			}

			// Skip symlinks.
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}

			fileFindings, err := scanSingleFile(relPath, fullPath, "", rs, opts)
			if err != nil {
				if opts.Verbose {
					fmt.Fprintf(opts.Stderr, "warning: error scanning %s: %v\n", relPath, err)
				}
				continue
			}
			findings = append(findings, fileFindings...)
		}
	}

	return findings, nil
}

// scanSingleFile reads a file line-by-line and checks each line against all rules.
func scanSingleFile(relPath, fullPath, commit string, rs *rules.RuleSet, opts Options) ([]finding.Finding, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []finding.Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		lineFindings := matchLine(line, lineNum, relPath, commit, rs, opts)
		findings = append(findings, lineFindings...)
	}

	if err := scanner.Err(); err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: scanner error in %s: %v\n", relPath, err)
		}
	}

	return findings, nil
}

// matchLine checks a single line against all rules and returns any findings.
func matchLine(line string, lineNum int, filePath, commit string, rs *rules.RuleSet, opts Options) []finding.Finding {
	if hasInlineAllow(line) {
		return nil
	}

	var findings []finding.Finding

	for i := range rs.Rules {
		rule := &rs.Rules[i]

		fullMatch, secret, found := rule.Match(line, filePath, commit)
		if !found {
			continue
		}

		// Check global allowlists.
		if isGlobalAllowed(rs.Allowlists, secret, fullMatch, line, filePath, commit) {
			continue
		}

		f := finding.Finding{
			RuleID:      rule.ID,
			Description: rule.Description,
			StartLine:   lineNum,
			EndLine:     lineNum,
			StartColumn: strings.Index(line, fullMatch) + 1,
			EndColumn:   strings.Index(line, fullMatch) + len(fullMatch),
			Match:       fullMatch,
			Secret:      secret,
			File:        filePath,
			Commit:      commit,
			Tags:        copyTags(rule.Tags),
			Fingerprint: finding.ComputeFingerprint(commit, filePath, rule.ID, lineNum),
		}

		// Attempt decoding to find additional secrets.
		decoded := decoder.Decode(secret, 2)
		for _, d := range decoded {
			for j := range rs.Rules {
				dm, ds, df := rs.Rules[j].Match(d.Value, filePath, commit)
				if df && !isGlobalAllowed(rs.Allowlists, ds, dm, d.Value, filePath, commit) {
					f.Tags = append(f.Tags, "decoded:"+d.Encoding)
					break
				}
			}
		}

		findings = append(findings, f)
	}

	return findings
}

// copyTags returns a copy of the tags slice.
func copyTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, len(tags))
	copy(out, tags)
	return out
}
