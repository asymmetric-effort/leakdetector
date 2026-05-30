package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/decoder"
	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

const (
	maxLineSize  = 1024 * 1024 // 1 MB
	maxQueueSize = 10000
	defaultMaxMB = 10
)

// scanFiles walks the directory tree iteratively using a bounded stack and
// scans each eligible file line-by-line against all rules.
func scanFiles(ctx context.Context, opts Options, rs *rules.RuleSet) ([]finding.Finding, error) {
	maxBytes := int64(opts.MaxFileSizeMB) * 1024 * 1024
	if opts.MaxFileSizeMB <= 0 {
		maxBytes = int64(defaultMaxMB) * 1024 * 1024
	}

	var findings []finding.Finding

	// Track visited real paths when following symlinks to guard against loops.
	var visited map[string]struct{}
	if opts.FollowSymlinks {
		visited = make(map[string]struct{})
	}

	// Iterative directory walk using a bounded stack.
	stack := make([]string, 0, 128)
	stack = append(stack, opts.Dir)

	for len(stack) > 0 {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Pop from stack.
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// If following symlinks, resolve and check for loops on directories.
		if opts.FollowSymlinks {
			realPath, err := filepath.EvalSymlinks(current)
			if err != nil { // Defensive: only fails if path deleted or broken
				continue
			}
			if _, seen := visited[realPath]; seen {
				continue
			}
			visited[realPath] = struct{}{}
			current = realPath
		}

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

			// Handle symlinks.
			if entry.Type()&os.ModeSymlink != 0 {
				if !opts.FollowSymlinks {
					continue
				}
				// Resolve the symlink target.
				realPath, err := filepath.EvalSymlinks(fullPath)
				if err != nil {
					if opts.Verbose {
						fmt.Fprintf(opts.Stderr, "warning: cannot resolve symlink %s: %v\n", fullPath, err)
					}
					continue
				}
				if _, seen := visited[realPath]; seen {
					continue
				}
				visited[realPath] = struct{}{}

				info, err := os.Stat(realPath)
				if err != nil {
					continue
				}
				if info.IsDir() {
					if entry.Name() == ".git" {
						continue
					}
					if isExcludedPath(relPath, opts.ExcludePaths) {
						continue
					}
					if len(stack) < maxQueueSize {
						stack = append(stack, realPath)
					}
					continue
				}
				// It's a file symlink - scan it.
				if isExcludedPath(relPath, opts.ExcludePaths) {
					continue
				}
				if info.Size() > maxBytes {
					if opts.Verbose {
						fmt.Fprintf(opts.Stderr, "skipping large file: %s (%d bytes)\n", relPath, info.Size())
					}
					continue
				}
				fileFindings, err := scanSingleFile(relPath, realPath, "", rs, opts)
				if err != nil {
					if opts.Verbose {
						fmt.Fprintf(opts.Stderr, "warning: error scanning %s: %v\n", relPath, err)
					}
					continue
				}
				findings = append(findings, fileFindings...)
				continue
			}

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

			fileFindings, err := scanSingleFile(relPath, fullPath, "", rs, opts)
			if err != nil {
				if opts.Verbose {
					fmt.Fprintf(opts.Stderr, "warning: error scanning %s: %v\n", relPath, err)
				}
				continue
			}
			findings = append(findings, fileFindings...)

			// Scan archive contents if enabled.
			if opts.MaxArchiveDepth > 0 && isArchive(fullPath) {
				archiveFindings := scanArchive(fullPath, relPath, 1, opts.MaxArchiveDepth, rs, opts)
				findings = append(findings, archiveFindings...)
			}
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

	// Collect all lines for proximity checking.
	var allLines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineSize), maxLineSize)
	for sc.Scan() {
		allLines = append(allLines, sc.Text())
	}

	if err := sc.Err(); err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: scanner error in %s: %v\n", relPath, err)
		}
	}

	var findings []finding.Finding
	for lineIdx, line := range allLines {
		lineNum := lineIdx + 1
		lineFindings := matchLine(line, lineNum, relPath, commit, rs, opts, allLines, lineIdx)
		findings = append(findings, lineFindings...)
	}

	return findings, nil
}

// matchLine checks a single line against all rules and returns any findings.
// allLines and lineIdx are optional (can be nil/0) and used for proximity rule checking.
func matchLine(line string, lineNum int, filePath, commit string, rs *rules.RuleSet, opts Options, allLines []string, lineIdx int) []finding.Finding {
	if hasInlineAllow(line) {
		return nil
	}

	var findings []finding.Finding

	for i := range rs.Rules {
		rule := &rs.Rules[i]

		mr := rule.Match(line, filePath, commit)
		if !mr.Found {
			continue
		}

		// Check global allowlists.
		if isGlobalAllowed(rs.Allowlists, mr.Secret, mr.FullMatch, line, filePath, commit) {
			continue
		}

		// Check proximity/composite rules.
		if len(rule.Required) > 0 && allLines != nil {
			matchCol := strings.Index(line, mr.FullMatch)
			if !rule.CheckProximity(allLines, lineIdx, matchCol) {
				continue
			}
		}

		f := finding.Finding{
			RuleID:      rule.ID,
			Description: rule.Description,
			StartLine:   lineNum,
			EndLine:     lineNum,
			StartColumn: strings.Index(line, mr.FullMatch) + 1,
			EndColumn:   strings.Index(line, mr.FullMatch) + len(mr.FullMatch),
			Match:       mr.FullMatch,
			Secret:      mr.Secret,
			File:        filePath,
			Commit:      commit,
			Tags:        copyTags(rule.Tags),
			Entropy:     mr.Entropy,
			Fingerprint: finding.ComputeFingerprint(commit, filePath, rule.ID, lineNum),
		}

		// Generate platform link for file findings if platform is set.
		if opts.Platform != "" && commit == "" {
			link := generateFileLink(opts, filePath, lineNum)
			if link != "" {
				f.Link = link
			}
		}

		// Attempt decoding to find additional secrets.
		maxDepth := opts.MaxDecodeDepth
		if opts.MaxDecodeDepth == 0 {
			maxDepth = 0
		} else if opts.MaxDecodeDepth > 0 {
			maxDepth = opts.MaxDecodeDepth
		}
		decoded := decoder.Decode(mr.Secret, maxDepth)
		for _, d := range decoded {
			for j := range rs.Rules {
				dmr := rs.Rules[j].Match(d.Value, filePath, commit)
				if dmr.Found && !isGlobalAllowed(rs.Allowlists, dmr.Secret, dmr.FullMatch, d.Value, filePath, commit) {
					f.Tags = append(f.Tags, "decoded:"+d.Encoding)
					break
				}
			}
		}

		findings = append(findings, f)
	}

	return findings
}

// generateFileLink creates a platform-specific link for file scan findings.
func generateFileLink(opts Options, filePath string, lineNum int) string {
	remoteURL := getRemoteURL(opts.Dir)
	if remoteURL == "" {
		return ""
	}
	owner, repo := parseRemoteURL(remoteURL)
	if owner == "" || repo == "" {
		return ""
	}

	switch strings.ToLower(opts.Platform) {
	case "github":
		return fmt.Sprintf("https://github.com/%s/%s/blob/HEAD/%s#L%d", owner, repo, filePath, lineNum)
	case "gitlab":
		return fmt.Sprintf("https://gitlab.com/%s/%s/-/blob/HEAD/%s#L%d", owner, repo, filePath, lineNum)
	}
	return ""
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
