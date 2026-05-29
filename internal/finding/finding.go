package finding

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Finding represents a single detected secret or sensitive information.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	StartColumn int      `json:"start_column"`
	EndColumn   int      `json:"end_column"`
	Match       string   `json:"match"`
	Secret      string   `json:"secret"`
	File        string   `json:"file"`
	Commit      string   `json:"commit,omitempty"`
	Author      string   `json:"author,omitempty"`
	Email       string   `json:"email,omitempty"`
	Date        string   `json:"date,omitempty"`
	Message     string   `json:"message,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Entropy     float64  `json:"entropy"`
	Fingerprint string   `json:"fingerprint"`
	Link        string   `json:"link,omitempty"`
}

// ComputeFingerprint generates a unique fingerprint for a finding.
// Format: {commit}:{file}:{rule_id}:{line}
func ComputeFingerprint(commit, file, ruleID string, line int) string {
	if commit == "" {
		commit = "0000000"
	}
	return fmt.Sprintf("%s:%s:%s:%d", commit, file, ruleID, line)
}

// Redact replaces the secret value with a redacted placeholder.
// It preserves the first 2 and last 2 characters for secrets longer than 4 chars.
func (f *Finding) Redact() {
	if len(f.Secret) == 0 {
		return
	}
	if len(f.Secret) <= 4 {
		f.Secret = "REDACTED"
		f.Match = "REDACTED"
		return
	}
	f.Secret = f.Secret[:2] + "..." + f.Secret[len(f.Secret)-2:]
	f.Match = f.Secret
}

// RedactPercent redacts the secret based on a percentage value.
// pct <= 0: fully replace secret with "REDACTED".
// pct >= 100: do nothing (no redaction).
// 1-99: show the first pct% of characters followed by "...".
func (f *Finding) RedactPercent(pct int) {
	if len(f.Secret) == 0 {
		return
	}
	if pct >= 100 {
		return
	}
	if pct <= 0 {
		f.Secret = "REDACTED"
		f.Match = "REDACTED"
		return
	}
	show := len(f.Secret) * pct / 100
	if show <= 0 {
		show = 1
	}
	f.Secret = f.Secret[:show] + "..."
	f.Match = f.Secret
}

// LoadIgnoreFile reads a .leakdetectorignore file containing one fingerprint
// per line. Lines starting with # are comments and blank lines are ignored.
// Returns nil if the file does not exist.
func LoadIgnoreFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var fingerprints []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fingerprints = append(fingerprints, line)
	}
	return fingerprints
}

// FilterFingerprints removes findings whose fingerprints appear in the given list.
func FilterFingerprints(findings []Finding, fingerprints []string) []Finding {
	if len(fingerprints) == 0 {
		return findings
	}
	ignore := make(map[string]struct{}, len(fingerprints))
	for _, fp := range fingerprints {
		ignore[fp] = struct{}{}
	}
	var filtered []Finding
	for i := range findings {
		if _, ok := ignore[findings[i].Fingerprint]; !ok {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}

// LoadBaseline reads a JSON baseline file and returns the findings.
func LoadBaseline(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return findings, nil
}

// FilterBaseline removes findings whose fingerprints appear in the baseline.
func FilterBaseline(findings, baseline []Finding) []Finding {
	known := make(map[string]struct{}, len(baseline))
	for i := range baseline {
		known[baseline[i].Fingerprint] = struct{}{}
	}

	var filtered []Finding
	for i := range findings {
		if _, ok := known[findings[i].Fingerprint]; !ok {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}
