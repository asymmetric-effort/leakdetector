package scanner

import (
	"path/filepath"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

// isExcludedPath returns true if the given path should be skipped based on
// the exclude patterns. Patterns are matched as glob-style or as a prefix.
func isExcludedPath(relPath string, excludePaths []string) bool {
	for _, pattern := range excludePaths {
		// Try glob match first.
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}
		// Try matching against just the base name.
		if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
			return true
		}
		// Prefix match (directory prefix).
		if strings.HasPrefix(relPath, pattern) {
			return true
		}
	}
	return false
}

// isExcludedCommit returns true if the given commit SHA should be skipped.
func isExcludedCommit(commit string, excludeCommits []string) bool {
	for _, exc := range excludeCommits {
		if commit == exc {
			return true
		}
		// Allow short-hash matching.
		if len(commit) >= len(exc) && strings.HasPrefix(commit, exc) {
			return true
		}
		if len(exc) >= len(commit) && strings.HasPrefix(exc, commit) {
			return true
		}
	}
	return false
}

// hasInlineAllow returns true if the line contains a leakdetector:allow comment.
func hasInlineAllow(line string) bool {
	return strings.Contains(line, "leakdetector:allow")
}

// isGlobalAllowed returns true if a finding is suppressed by a global allowlist entry.
func isGlobalAllowed(allowlists []rules.CompiledAllowlist, secret, match, line, filePath, commit string) bool {
	for i := range allowlists {
		if allowlists[i].IsAllowed(secret, match, line, filePath, commit) {
			return true
		}
	}
	return false
}
