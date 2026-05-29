package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Options holds the parsed command-line options.
type Options struct {
	SkipHistory bool
	Branch      string
	ConfigPath  string
	ReportPath  string
	ReportFormat string
	Redact      bool
	Verbose     bool
	NoColor     bool
	ShowVersion bool
	ShowHelp    bool
	ExitCode    int
	MaxFileSizeMB int
	Stdin       bool
	BaselinePath string
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
	fs.StringVar(&opts.ReportPath, "report", "", "path to write report output (default: stdout)")
	fs.StringVar(&opts.ReportFormat, "format", "json", "output format: json, csv, junit, sarif")
	fs.BoolVar(&opts.Redact, "redact", false, "redact secrets from output")
	fs.BoolVar(&opts.Verbose, "verbose", false, "enable verbose output")
	fs.BoolVar(&opts.NoColor, "no-color", false, "disable colored output")
	fs.BoolVar(&opts.ShowVersion, "version", false, "print version and exit")
	fs.IntVar(&opts.ExitCode, "exit-code", 1, "exit code when leaks are found")
	fs.IntVar(&opts.MaxFileSizeMB, "max-file-size", 0, "skip files larger than this size in MB (0=no limit)")
	fs.BoolVar(&opts.Stdin, "stdin", false, "read input from stdin")
	fs.StringVar(&opts.BaselinePath, "baseline", "", "path to baseline report to ignore known findings")

	fs.Usage = func() {
		fmt.Fprintf(w, "Usage: leakdetector [options]\n\n")
		fmt.Fprintf(w, "Scan git repositories for leaked secrets and sensitive information.\n\n")
		fmt.Fprintf(w, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(w, "\nExamples:\n")
		fmt.Fprintf(w, "  leakdetector                    Scan current directory with full git history\n")
		fmt.Fprintf(w, "  leakdetector --skip-history      Scan current directory without git history\n")
		fmt.Fprintf(w, "  leakdetector --branch main       Scan a specific branch\n")
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

	return opts, nil
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
