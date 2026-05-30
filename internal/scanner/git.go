package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// scanGit runs git log -p and parses the unified diff output to scan
// added lines against all rules.
func scanGit(ctx context.Context, opts Options, rs *rules.RuleSet) ([]finding.Finding, error) {
	args := []string{"log", "-p", "--full-history"}
	if opts.Branch != "" {
		args = append(args, opts.Branch)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = opts.Dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git start: %w", err)
	}

	// Resolve remote URL and owner/repo for platform link generation.
	var linkOwner, linkRepo string
	if opts.Platform != "" {
		remoteURL := getRemoteURL(opts.Dir)
		if remoteURL != "" {
			linkOwner, linkRepo = parseRemoteURL(remoteURL)
		}
	}

	var findings []finding.Finding

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	var (
		commitSHA string
		author    string
		email     string
		date      string
		message   strings.Builder
		filePath  string
		lineNum   int
		inMessage bool
		inDiff    bool
	)

	for scanner.Scan() {
		line := scanner.Text()

		// Parse commit header.
		if strings.HasPrefix(line, "commit ") && len(line) >= 47 {
			// Save any pending state (commit boundary).
			commitSHA = strings.TrimPrefix(line, "commit ")
			// Handle merge commits: "commit abc123 (merge ...)"
			if idx := strings.IndexByte(commitSHA, ' '); idx > 0 {
				commitSHA = commitSHA[:idx]
			}
			author = ""
			email = ""
			date = ""
			message.Reset()
			filePath = ""
			lineNum = 0
			inMessage = false
			inDiff = false
			continue
		}

		if strings.HasPrefix(line, "Author: ") {
			raw := strings.TrimPrefix(line, "Author: ")
			author, email = parseAuthor(raw)
			continue
		}

		if strings.HasPrefix(line, "Date: ") {
			date = strings.TrimSpace(strings.TrimPrefix(line, "Date: "))
			inMessage = true
			continue
		}

		// Commit message lines (indented with spaces after Date).
		if inMessage && !inDiff {
			if strings.HasPrefix(line, "diff --git ") {
				inMessage = false
				inDiff = true
				// Fall through to diff processing below.
			} else {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					if message.Len() > 0 {
						message.WriteByte(' ')
					}
					message.WriteString(trimmed)
				}
				continue
			}
		}

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

			if isExcludedCommit(commitSHA, opts.ExcludeCommits) {
				lineNum++
				continue
			}

			if filePath != "" && isExcludedPath(filePath, opts.ExcludePaths) {
				lineNum++
				continue
			}

			lineFindings := matchLine(content, lineNum, filePath, commitSHA, rs, opts, nil, 0)
			for i := range lineFindings {
				lineFindings[i].Author = author
				lineFindings[i].Email = email
				lineFindings[i].Date = date
				lineFindings[i].Message = message.String()

				// Generate platform link if configured.
				if linkOwner != "" && linkRepo != "" {
					lineFindings[i].Link = generateGitLink(opts.Platform, linkOwner, linkRepo, commitSHA, filePath, lineFindings[i].StartLine)
				}
			}
			findings = append(findings, lineFindings...)
			lineNum++
			continue
		}

		// Context lines (no prefix or space prefix) also advance line counter.
		if inDiff && len(line) > 0 && line[0] == ' ' {
			lineNum++
			continue
		}

		// Lines starting with - are removed lines; don't advance new-file line counter.
	}

	if err := scanner.Err(); err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: git log scanner error: %v\n", err)
		}
	}

	// Wait for the git process to finish.
	if err := cmd.Wait(); err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: git log exited with: %v\n", err)
		}
	}

	return findings, nil
}

// parseAuthor splits "Name <email>" into name and email components.
func parseAuthor(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	ltIdx := strings.LastIndex(raw, "<")
	gtIdx := strings.LastIndex(raw, ">")
	if ltIdx >= 0 && gtIdx > ltIdx {
		name := strings.TrimSpace(raw[:ltIdx])
		addr := raw[ltIdx+1 : gtIdx]
		return name, addr
	}
	return raw, ""
}

// parseHunkLineNumber extracts the starting line number of the new file
// from a unified diff hunk header like "@@ -a,b +c,d @@".
func parseHunkLineNumber(hunk string) int {
	// Find the +N part.
	plusIdx := strings.Index(hunk, "+")
	if plusIdx < 0 {
		return 0
	}
	rest := hunk[plusIdx+1:]
	// Read digits until comma or space.
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	num := 0
	for _, c := range rest[:end] {
		num = num*10 + int(c-'0')
	}
	return num
}

// getRemoteURL runs git remote get-url origin and returns the result.
func getRemoteURL(dir string) string {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// parseRemoteURL extracts owner and repo from a git remote URL.
// Supports SSH (git@host:owner/repo.git) and HTTPS (https://host/owner/repo.git).
func parseRemoteURL(rawURL string) (string, string) {
	// SSH format: git@github.com:owner/repo.git
	if strings.HasPrefix(rawURL, "git@") {
		colonIdx := strings.Index(rawURL, ":")
		if colonIdx < 0 {
			return "", ""
		}
		path := rawURL[colonIdx+1:]
		path = strings.TrimSuffix(path, ".git")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			return "", ""
		}
		return parts[0], parts[1]
	}

	// HTTPS format: https://github.com/owner/repo.git
	if strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://") {
		// Remove scheme and host.
		idx := strings.Index(rawURL, "://")
		path := rawURL[idx+3:]
		// Remove host.
		slashIdx := strings.Index(path, "/")
		if slashIdx < 0 {
			return "", ""
		}
		path = path[slashIdx+1:]
		path = strings.TrimSuffix(path, ".git")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			return "", ""
		}
		return parts[0], parts[1]
	}

	return "", ""
}

// generateGitLink creates a platform-specific link for a finding in git history.
func generateGitLink(platform, owner, repo, commit, filePath string, lineNum int) string {
	switch strings.ToLower(platform) {
	case "github":
		return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s#L%d", owner, repo, commit, filePath, lineNum)
	case "gitlab":
		return fmt.Sprintf("https://gitlab.com/%s/%s/-/blob/%s/%s#L%d", owner, repo, commit, filePath, lineNum)
	}
	return ""
}
