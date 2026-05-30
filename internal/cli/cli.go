package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Options holds the parsed command-line options.
type Options struct {
	SkipHistory    bool
	Branch         string
	ConfigPath     string
	ReportPath     string
	ReportFormat   string
	TemplatePath   string
	RedactPercent  int
	Verbose        bool
	NoColor        bool
	ShowVersion    bool
	ShowHelp       bool
	ExitCode       int
	MaxFileSizeMB  int
	MaxDecodeDepth  int
	MaxArchiveDepth int
	Stdin           bool
	Staged         bool
	BaselinePath   string
	EnableRules    []string
	FollowSymlinks bool
	Timeout        int
	Platform       string
}

// stringSliceFlag implements flag.Value for repeated string flags.
type stringSliceFlag struct {
	values *[]string
}

func (s *stringSliceFlag) String() string {
	if s.values == nil {
		return ""
	}
	return strings.Join(*s.values, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	*s.values = append(*s.values, val)
	return nil
}

// Parse parses command-line arguments and returns Options.
// It writes usage/version output to the provided writer.
func Parse(args []string, w io.Writer) (Options, error) {
	var opts Options

	fs := flag.NewFlagSet("leakdetector", flag.ContinueOnError)
	fs.SetOutput(w)

	fs.BoolVar(&opts.SkipHistory, "skip-history", false, "skip scanning git history")
	fs.StringVar(&opts.Branch, "branch", "", "scan a specific branch")
	fs.StringVar(&opts.ConfigPath, "config", "", "path to configuration file (default: .leakdetector.yml)")
	fs.StringVar(&opts.ReportPath, "report", "", "path to write report output; file is created or overwritten (default: stdout)")
	fs.StringVar(&opts.ReportFormat, "format", "json", "output format: json, csv, junit, sarif, template")
	fs.StringVar(&opts.TemplatePath, "report-template", "", "path to Go template file (used with --format template)")
	fs.IntVar(&opts.RedactPercent, "redact", 0, "redact secrets: percentage to show (0=full redact, 100=no redact)")
	fs.BoolVar(&opts.Verbose, "verbose", false, "enable verbose output")
	fs.BoolVar(&opts.NoColor, "no-color", false, "disable colored output")
	fs.BoolVar(&opts.ShowVersion, "version", false, "print version and exit")
	fs.IntVar(&opts.ExitCode, "exit-code", 1, "exit code when leaks are found")
	fs.IntVar(&opts.MaxFileSizeMB, "max-file-size", 0, "skip files larger than this size in MB (0=no limit)")
	fs.IntVar(&opts.MaxDecodeDepth, "max-decode-depth", 0, "recursive decode depth for base64/hex/percent (0=disabled)")
	fs.IntVar(&opts.MaxArchiveDepth, "max-archive-depth", 0, "nested archive extraction depth (0=disabled)")
	fs.BoolVar(&opts.Stdin, "stdin", false, "read input from stdin")
	fs.BoolVar(&opts.Staged, "staged", false, "scan only staged changes (for pre-commit hooks)")
	fs.StringVar(&opts.BaselinePath, "baseline", "", "path to baseline report to ignore known findings")
	fs.Var(&stringSliceFlag{values: &opts.EnableRules}, "enable-rule", "only enable specific rules by ID (can be repeated)")
	fs.BoolVar(&opts.FollowSymlinks, "follow-symlinks", false, "follow symbolic links during file scanning")
	fs.IntVar(&opts.Timeout, "timeout", 0, "scan timeout in seconds (0=no timeout)")
	fs.StringVar(&opts.Platform, "platform", "", "platform for link generation: github, gitlab")

	fs.Usage = func() {
		fmt.Fprintf(w, "Usage: leakdetector [options]\n\n")
		fmt.Fprintf(w, "Scan git repositories for leaked secrets and sensitive information.\n\n")
		fmt.Fprintf(w, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(w, "\nExamples:\n")
		fmt.Fprintf(w, "  leakdetector                    Scan current directory with full git history\n")
		fmt.Fprintf(w, "  leakdetector --skip-history      Scan current directory without git history\n")
		fmt.Fprintf(w, "  leakdetector --branch main       Scan a specific branch\n")
		fmt.Fprintf(w, "  leakdetector --staged            Scan only staged changes (pre-commit)\n")
		fmt.Fprintf(w, "  leakdetector --format sarif       Output in SARIF format\n")
		fmt.Fprintf(w, "  leakdetector --stdin             Read from stdin\n")
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	// Validate branch name.
	if opts.Branch != "" {
		if err := validateBranchName(opts.Branch); err != nil {
			return opts, err
		}
	}

	return opts, nil
}

// validateBranchName checks that a branch name contains only characters
// valid in git ref names: alphanumeric, hyphen, underscore, dot, and slash.
func validateBranchName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("branch name must not be empty")
	}
	if name[0] == '-' {
		return fmt.Errorf("invalid branch name %q: must not start with '-'", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid branch name %q: must not contain '..'", name)
	}
	if strings.HasSuffix(name, ".lock") {
		return fmt.Errorf("invalid branch name %q: must not end with '.lock'", name)
	}
	for _, c := range name {
		if !isValidBranchChar(c) {
			return fmt.Errorf("invalid branch name %q: contains invalid character %q", name, c)
		}
	}
	return nil
}

func isValidBranchChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '/'
}

// Run executes leakdetector with the given options.
// It returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	opts, err := Parse(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if opts.ShowVersion {
		fmt.Fprintf(stdout, "leakdetector %s\n", Version)
		return 0
	}

	if opts.ShowHelp {
		return 0
	}

	// Determine working directory
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "error: failed to get working directory: %v\n", err)
		return 2
	}

	return execute(opts, dir, stdout, stderr)
}
