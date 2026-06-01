package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseDefaults(t *testing.T) {
	var buf bytes.Buffer
	opts, err := Parse([]string{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.SkipHistory {
		t.Error("expected SkipHistory to default to false")
	}
	if opts.Branch != "" {
		t.Errorf("expected Branch to default to empty, got %q", opts.Branch)
	}
	if opts.ConfigPath != "" {
		t.Errorf("expected ConfigPath to default to empty, got %q", opts.ConfigPath)
	}
	if opts.ReportPath != "" {
		t.Errorf("expected ReportPath to default to empty, got %q", opts.ReportPath)
	}
	if opts.ReportFormat != "json" {
		t.Errorf("expected ReportFormat to default to 'json', got %q", opts.ReportFormat)
	}
	if opts.RedactPercent != 0 {
		t.Errorf("expected RedactPercent to default to 0, got %d", opts.RedactPercent)
	}
	if opts.Verbose {
		t.Error("expected Verbose to default to false")
	}
	if opts.NoColor {
		t.Error("expected NoColor to default to false")
	}
	if opts.ShowVersion {
		t.Error("expected ShowVersion to default to false")
	}
	if opts.ShowHelp {
		t.Error("expected ShowHelp to default to false")
	}
	if opts.ExitCode != 1 {
		t.Errorf("expected ExitCode to default to 1, got %d", opts.ExitCode)
	}
	if opts.MaxFileSizeMB != 0 {
		t.Errorf("expected MaxFileSizeMB to default to 0, got %d", opts.MaxFileSizeMB)
	}
	if opts.Stdin {
		t.Error("expected Stdin to default to false")
	}
	if opts.BaselinePath != "" {
		t.Errorf("expected BaselinePath to default to empty, got %q", opts.BaselinePath)
	}
}

func TestParseBoolFlags(t *testing.T) {
	tests := []struct {
		name string
		flag string
		check func(Options) bool
	}{
		{"version", "--version", func(o Options) bool { return o.ShowVersion }},
		{"skip-history", "--skip-history", func(o Options) bool { return o.SkipHistory }},
		{"redact", "--redact=100", func(o Options) bool { return o.RedactPercent == 100 }},
		{"verbose", "--verbose", func(o Options) bool { return o.Verbose }},
		{"no-color", "--no-color", func(o Options) bool { return o.NoColor }},
		{"stdin", "--stdin", func(o Options) bool { return o.Stdin }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			opts, err := Parse([]string{tc.flag}, &buf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.check(opts) {
				t.Errorf("expected %s to be set", tc.flag)
			}
		})
	}
}

func TestParseStringFlags(t *testing.T) {
	tests := []struct {
		name  string
		flag  string
		value string
		check func(Options) string
	}{
		{"branch", "--branch", "foo", func(o Options) string { return o.Branch }},
		{"config", "--config", "/path/to/config.yml", func(o Options) string { return o.ConfigPath }},
		{"report", "--report", "/path/to/report.json", func(o Options) string { return o.ReportPath }},
		{"format", "--format", "sarif", func(o Options) string { return o.ReportFormat }},
		{"baseline", "--baseline", "/path/to/baseline.json", func(o Options) string { return o.BaselinePath }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			opts, err := Parse([]string{tc.flag, tc.value}, &buf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := tc.check(opts)
			if got != tc.value {
				t.Errorf("expected %q, got %q", tc.value, got)
			}
		})
	}
}

func TestParseIntFlags(t *testing.T) {
	tests := []struct {
		name  string
		flag  string
		value string
		want  int
		check func(Options) int
	}{
		{"exit-code", "--exit-code", "2", 2, func(o Options) int { return o.ExitCode }},
		{"max-file-size", "--max-file-size", "10", 10, func(o Options) int { return o.MaxFileSizeMB }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			opts, err := Parse([]string{tc.flag, tc.value}, &buf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := tc.check(opts)
			if got != tc.want {
				t.Errorf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

func TestParseHelpFlag(t *testing.T) {
	var buf bytes.Buffer
	opts, err := Parse([]string{"--help"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.ShowHelp {
		t.Error("expected ShowHelp to be true")
	}
}

func TestParseInvalidFlag(t *testing.T) {
	var buf bytes.Buffer
	_, err := Parse([]string{"--nonexistent-flag"}, &buf)
	if err == nil {
		t.Error("expected error for invalid flag, got nil")
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "leakdetector") {
		t.Errorf("expected version output to contain 'leakdetector', got %q", out)
	}
	if !strings.Contains(out, Version) {
		t.Errorf("expected version output to contain version %q, got %q", Version, out)
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunInvalidFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--nonexistent-flag"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "error") {
		t.Errorf("expected stderr to contain 'error', got %q", errOut)
	}
}

func TestStringSliceFlagString(t *testing.T) {
	// Test with nil values pointer.
	s := &stringSliceFlag{values: nil}
	if got := s.String(); got != "" {
		t.Errorf("expected empty string for nil values, got %q", got)
	}

	// Test with populated values.
	vals := []string{"rule1", "rule2", "rule3"}
	s = &stringSliceFlag{values: &vals}
	if got := s.String(); got != "rule1,rule2,rule3" {
		t.Errorf("expected 'rule1,rule2,rule3', got %q", got)
	}

	// Test with empty slice.
	empty := []string{}
	s = &stringSliceFlag{values: &empty}
	if got := s.String(); got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestStringSliceFlagSet(t *testing.T) {
	var vals []string
	s := &stringSliceFlag{values: &vals}

	if err := s.Set("rule1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.Set("rule2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vals) != 2 || vals[0] != "rule1" || vals[1] != "rule2" {
		t.Errorf("expected [rule1, rule2], got %v", vals)
	}
}

func TestParseNewFlags(t *testing.T) {
	var buf bytes.Buffer

	// Test --staged
	opts, err := Parse([]string{"--staged"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Staged {
		t.Error("expected Staged to be true")
	}

	// Test --max-decode-depth
	opts, err = Parse([]string{"--max-decode-depth", "5"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.MaxDecodeDepth != 5 {
		t.Errorf("expected MaxDecodeDepth 5, got %d", opts.MaxDecodeDepth)
	}

	// Test --follow-symlinks
	opts, err = Parse([]string{"--follow-symlinks"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.FollowSymlinks {
		t.Error("expected FollowSymlinks to be true")
	}

	// Test --timeout
	opts, err = Parse([]string{"--timeout", "30"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Timeout != 30 {
		t.Errorf("expected Timeout 30, got %d", opts.Timeout)
	}

	// Test --platform
	opts, err = Parse([]string{"--platform", "github"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Platform != "github" {
		t.Errorf("expected Platform 'github', got %q", opts.Platform)
	}

	// Test --report-template
	opts, err = Parse([]string{"--report-template", "/tmp/tmpl.txt"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TemplatePath != "/tmp/tmpl.txt" {
		t.Errorf("expected TemplatePath '/tmp/tmpl.txt', got %q", opts.TemplatePath)
	}
}

func TestParseEnableRuleRepeated(t *testing.T) {
	var buf bytes.Buffer
	opts, err := Parse([]string{"--enable-rule", "rule1", "--enable-rule", "rule2"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.EnableRules) != 2 {
		t.Fatalf("expected 2 enable rules, got %d", len(opts.EnableRules))
	}
	if opts.EnableRules[0] != "rule1" || opts.EnableRules[1] != "rule2" {
		t.Errorf("expected [rule1, rule2], got %v", opts.EnableRules)
	}
}

func TestParseRedactIntValue(t *testing.T) {
	var buf bytes.Buffer
	opts, err := Parse([]string{"--redact", "50"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.RedactPercent != 50 {
		t.Errorf("expected RedactPercent 50, got %d", opts.RedactPercent)
	}
}

func TestParseDefaultsNewFields(t *testing.T) {
	var buf bytes.Buffer
	opts, err := Parse([]string{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Staged {
		t.Error("expected Staged to default to false")
	}
	if opts.MaxDecodeDepth != 0 {
		t.Errorf("expected MaxDecodeDepth to default to 0, got %d", opts.MaxDecodeDepth)
	}
	if opts.FollowSymlinks {
		t.Error("expected FollowSymlinks to default to false")
	}
	if opts.Timeout != 0 {
		t.Errorf("expected Timeout to default to 0, got %d", opts.Timeout)
	}
	if opts.Platform != "" {
		t.Errorf("expected Platform to default to empty, got %q", opts.Platform)
	}
	if opts.TemplatePath != "" {
		t.Errorf("expected TemplatePath to default to empty, got %q", opts.TemplatePath)
	}
	if len(opts.EnableRules) != 0 {
		t.Errorf("expected EnableRules to default to empty, got %v", opts.EnableRules)
	}
}

func TestValidateBranchName(t *testing.T) {
	tests := []struct {
		name    string
		branch  string
		wantErr bool
	}{
		{"valid simple", "main", false},
		{"valid with slash", "feature/auth", false},
		{"valid with dash", "fix-bug", false},
		{"valid with underscore", "my_branch", false},
		{"valid with dot", "release.1.0", false},
		{"valid with numbers", "v2", false},
		{"starts with dash", "-bad", true},
		{"contains dotdot", "a..b", true},
		{"ends with .lock", "branch.lock", true},
		{"contains space", "has space", true},
		{"contains tilde", "bad~1", true},
		{"contains caret", "bad^2", true},
		{"contains colon", "bad:ref", true},
		{"contains backslash", "bad\\path", true},
		{"contains question", "bad?", true},
		{"contains asterisk", "bad*", true},
		{"contains bracket", "bad[0]", true},
		{"empty string", "", true},
		{"git flag injection", "--exec=evil", true},
		{"git option", "-c", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBranchName(tc.branch)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for branch %q, got nil", tc.branch)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for branch %q: %v", tc.branch, err)
			}
		})
	}
}

func TestContainsDotDot(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"normal/path", false},
		{"../escape", true},
		{"dir/../../etc", true},
		{"dir/../sibling", true},
		{"...", false},
		{"dir/..file", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := containsDotDot(tc.path)
			if got != tc.want {
				t.Errorf("containsDotDot(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseBranchValidation(t *testing.T) {
	var buf bytes.Buffer

	// Valid branch should parse.
	_, err := Parse([]string{"--branch", "main"}, &buf)
	if err != nil {
		t.Errorf("expected valid branch to parse, got: %v", err)
	}

	// Invalid branch should fail.
	_, err = Parse([]string{"--branch", "--exec=evil"}, &buf)
	if err == nil {
		t.Error("expected error for malicious branch name")
	}
}

func TestParseCombinedFlags(t *testing.T) {
	var buf bytes.Buffer
	opts, err := Parse([]string{
		"--staged",
		"--max-decode-depth", "3",
		"--follow-symlinks",
		"--timeout", "60",
		"--platform", "gitlab",
		"--report-template", "/tmp/t.tmpl",
		"--enable-rule", "aws-access-key-id",
		"--redact", "25",
		"--verbose",
	}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Staged {
		t.Error("expected Staged true")
	}
	if opts.MaxDecodeDepth != 3 {
		t.Errorf("expected MaxDecodeDepth 3, got %d", opts.MaxDecodeDepth)
	}
	if !opts.FollowSymlinks {
		t.Error("expected FollowSymlinks true")
	}
	if opts.Timeout != 60 {
		t.Errorf("expected Timeout 60, got %d", opts.Timeout)
	}
	if opts.Platform != "gitlab" {
		t.Errorf("expected Platform 'gitlab', got %q", opts.Platform)
	}
	if opts.TemplatePath != "/tmp/t.tmpl" {
		t.Errorf("expected TemplatePath '/tmp/t.tmpl', got %q", opts.TemplatePath)
	}
	if len(opts.EnableRules) != 1 || opts.EnableRules[0] != "aws-access-key-id" {
		t.Errorf("expected [aws-access-key-id], got %v", opts.EnableRules)
	}
	if opts.RedactPercent != 25 {
		t.Errorf("expected RedactPercent 25, got %d", opts.RedactPercent)
	}
	if !opts.Verbose {
		t.Error("expected Verbose true")
	}
}

func TestParseValidation_Redact(t *testing.T) {
	var buf bytes.Buffer
	_, err := Parse([]string{"--redact", "-1"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "--redact must be between") {
		t.Errorf("expected redact range error, got: %v", err)
	}

	_, err = Parse([]string{"--redact", "101"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "--redact must be between") {
		t.Errorf("expected redact range error, got: %v", err)
	}

	// Valid values should pass.
	_, err = Parse([]string{"--redact", "0"}, &buf)
	if err != nil {
		t.Errorf("redact 0 should be valid: %v", err)
	}
	_, err = Parse([]string{"--redact", "100"}, &buf)
	if err != nil {
		t.Errorf("redact 100 should be valid: %v", err)
	}
}

func TestParseValidation_Format(t *testing.T) {
	var buf bytes.Buffer
	_, err := Parse([]string{"--format", "jsson"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "--format must be one of") {
		t.Errorf("expected format error, got: %v", err)
	}

	for _, f := range []string{"json", "csv", "junit", "sarif", "template"} {
		_, err := Parse([]string{"--format", f}, &buf)
		if err != nil {
			t.Errorf("format %q should be valid: %v", f, err)
		}
	}
}

func TestParseValidation_Platform(t *testing.T) {
	var buf bytes.Buffer
	_, err := Parse([]string{"--platform", "bitbucket"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "--platform must be") {
		t.Errorf("expected platform error, got: %v", err)
	}

	_, err = Parse([]string{"--platform", "github"}, &buf)
	if err != nil {
		t.Errorf("platform github should be valid: %v", err)
	}
	_, err = Parse([]string{"--platform", "gitlab"}, &buf)
	if err != nil {
		t.Errorf("platform gitlab should be valid: %v", err)
	}

	// Empty platform (not specified) is valid.
	_, err = Parse([]string{}, &buf)
	if err != nil {
		t.Errorf("no platform should be valid: %v", err)
	}
}

func TestParseValidation_ExitCode(t *testing.T) {
	var buf bytes.Buffer
	_, err := Parse([]string{"--exit-code", "-1"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "--exit-code must be between") {
		t.Errorf("expected exit-code range error, got: %v", err)
	}

	_, err = Parse([]string{"--exit-code", "256"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "--exit-code must be between") {
		t.Errorf("expected exit-code range error, got: %v", err)
	}

	_, err = Parse([]string{"--exit-code", "0"}, &buf)
	if err != nil {
		t.Errorf("exit-code 0 should be valid: %v", err)
	}
	_, err = Parse([]string{"--exit-code", "255"}, &buf)
	if err != nil {
		t.Errorf("exit-code 255 should be valid: %v", err)
	}
}
