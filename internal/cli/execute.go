package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/asymmetric-effort/leakdetector/internal/config"
	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/output"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
	"github.com/asymmetric-effort/leakdetector/internal/scanner"
)

func execute(opts Options, dir string, stdout, stderr io.Writer) int {
	// Load configuration
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = filepath.Join(dir, ".leakdetector.yml")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(stderr, "error: failed to load config: %v\n", err)
		return 2
	}
	if cfg == nil {
		cfg = config.Default()
	}

	// Build ruleset
	rs, err := rules.Compile(cfg.Rules, cfg.Allowlists)
	if err != nil {
		fmt.Fprintf(stderr, "error: failed to compile rules: %v\n", err)
		return 2
	}

	// Load baseline if provided
	var baseline []finding.Finding
	if opts.BaselinePath != "" {
		baseline, err = finding.LoadBaseline(opts.BaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "error: failed to load baseline: %v\n", err)
			return 2
		}
	}

	// Build scanner options
	scanOpts := scanner.Options{
		Dir:            dir,
		SkipHistory:    opts.SkipHistory,
		Branch:         opts.Branch,
		Stdin:          opts.Stdin,
		ExcludeCommits: cfg.ExcludeCommits,
		ExcludePaths:   cfg.ExcludePaths,
		MaxFileSizeMB:  opts.MaxFileSizeMB,
		Verbose:        opts.Verbose,
		Stderr:         stderr,
	}

	// Run scanner
	findings, err := scanner.Scan(scanOpts, rs)
	if err != nil {
		fmt.Fprintf(stderr, "error: scan failed: %v\n", err)
		return 2
	}

	// Filter against baseline
	if len(baseline) > 0 {
		findings = finding.FilterBaseline(findings, baseline)
	}

	// Write output
	writer := output.New(opts.ReportFormat, opts.Redact)
	var dest io.Writer = stdout
	if opts.ReportPath != "" {
		f, err := os.Create(opts.ReportPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: failed to create report file: %v\n", err)
			return 2
		}
		defer f.Close()
		dest = f
	}

	if err := writer.Write(dest, findings); err != nil {
		fmt.Fprintf(stderr, "error: failed to write report: %v\n", err)
		return 2
	}

	if opts.Verbose {
		fmt.Fprintf(stderr, "scan complete: %d findings\n", len(findings))
	}

	if len(findings) > 0 {
		return opts.ExitCode
	}

	return 0
}
