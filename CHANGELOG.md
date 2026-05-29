# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure and scaffolding.
- CLI with `--skip-history`, `--branch`, `--version`, `--help` flags.
- YAML configuration via `.leakdetector.yml`.
- 222+ built-in secret detection rules.
- Shannon entropy-based filtering.
- Git history scanning (full history, specific branch, current HEAD).
- File/directory scanning.
- Stdin scanning.
- Output formats: JSON, CSV, JUnit, SARIF, custom Go templates.
- Allowlists (global, per-rule, inline comments).
- Baseline/fingerprinting for incremental scanning.
- Commit and path exclusion lists in configuration.
- Secret redaction in output.
- Cross-platform builds (linux, darwin, windows; amd64, arm64).
