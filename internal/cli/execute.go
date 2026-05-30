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

	// Load extended config if specified.
	if cfg.Extend != nil && cfg.Extend.Path != "" {
		extCfg, extErr := config.Load(cfg.Extend.Path)
		if extErr != nil && !os.IsNotExist(extErr) {
			fmt.Fprintf(stderr, "error: failed to load extended config %s: %v\n", cfg.Extend.Path, extErr)
			return 2
		}
		if extCfg != nil {
			cfg.Rules = append(extCfg.Rules, cfg.Rules...)
			cfg.Allowlists = append(extCfg.Allowlists, cfg.Allowlists...)
			cfg.ExcludeCommits = append(extCfg.ExcludeCommits, cfg.ExcludeCommits...)
			cfg.ExcludePaths = append(extCfg.ExcludePaths, cfg.ExcludePaths...)
		}
	}

	// Build compile options from extend config.
	compileOpts := rules.CompileOptions{
		UseDefault: true,
	}
	if cfg.Extend != nil {
		compileOpts.UseDefault = cfg.Extend.UseDefault
		compileOpts.DisabledRules = cfg.Extend.DisabledRules
	}
	if len(opts.EnableRules) > 0 {
		compileOpts.EnabledRules = opts.EnableRules
	}

	// Build ruleset
	rs, err := rules.CompileWithOptions(cfg.Rules, cfg.Allowlists, compileOpts)
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
		Staged:         opts.Staged,
		ExcludeCommits: cfg.ExcludeCommits,
		ExcludePaths:   cfg.ExcludePaths,
		MaxFileSizeMB:  opts.MaxFileSizeMB,
		MaxDecodeDepth:  opts.MaxDecodeDepth,
		MaxArchiveDepth: opts.MaxArchiveDepth,
		FollowSymlinks:  opts.FollowSymlinks,
		Timeout:        opts.Timeout,
		Platform:       opts.Platform,
		Verbose:        opts.Verbose,
		Stderr:         stderr,
	}

	// Load .leakdetectorignore
	ignorePath := filepath.Join(dir, ".leakdetectorignore")
	ignoreFingerprints := finding.LoadIgnoreFile(ignorePath)

	// Run scanner
	findings, err := scanner.Scan(scanOpts, rs)
	if err != nil {
		fmt.Fprintf(stderr, "error: scan failed: %v\n", err)
		return 2
	}

	// Filter against .leakdetectorignore
	if len(ignoreFingerprints) > 0 {
		findings = finding.FilterFingerprints(findings, ignoreFingerprints)
	}

	// Filter against baseline
	if len(baseline) > 0 {
		findings = finding.FilterBaseline(findings, baseline)
	}

	// Write output
	writer := output.New(opts.ReportFormat, opts.RedactPercent, opts.TemplatePath)
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
