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
	if opts.Redact {
		t.Error("expected Redact to default to false")
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
		{"redact", "--redact", func(o Options) bool { return o.Redact }},
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
