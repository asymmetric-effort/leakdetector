# Usage

## Basic Usage

Run leakdetector in any git repository directory:

```bash
# Scan current directory with full git history
leakdetector

# Scan current directory without git history
leakdetector --skip-history

# Scan a specific branch
leakdetector --branch main

# Print version
leakdetector --version

# Show help
leakdetector --help
```

## Scanning Modes

### Full History Scan (Default)

When run without flags, leakdetector scans both the current working tree and
the full git history (all branches). This is the most thorough scanning mode.

```bash
leakdetector
```

### Current HEAD Only

Use `--skip-history` to scan only the current state of files on disk, skipping
all git history analysis.

```bash
leakdetector --skip-history
```

### Branch Scan

Use `--branch` to scan a specific branch's history.

```bash
leakdetector --branch feature/auth
```

### Stdin

Use `--stdin` to pipe content into leakdetector for scanning.

```bash
cat secrets.txt | leakdetector --stdin
echo "AKIAIOSFODNN7EXAMPLE" | leakdetector --stdin
```

## Output Options

### Output Format

Specify the output format with `--format`:

```bash
leakdetector --format json     # JSON (default)
leakdetector --format csv      # CSV
leakdetector --format junit    # JUnit XML
leakdetector --format sarif    # SARIF 2.1.0
```

### Report File

Write output to a file instead of stdout:

```bash
leakdetector --report findings.json
leakdetector --format sarif --report findings.sarif
```

### Redaction

Redact secrets from the output:

```bash
leakdetector --redact
```

## Filtering Options

### Configuration File

Specify a custom configuration file:

```bash
leakdetector --config /path/to/.leakdetector.yml
```

By default, leakdetector looks for `.leakdetector.yml` in the current directory.

### Baseline

Compare against a previous scan to only report new findings:

```bash
# First scan - establish baseline
leakdetector --report baseline.json

# Later scan - only report new findings
leakdetector --baseline baseline.json
```

### File Size Limit

Skip files larger than a given size in MB:

```bash
leakdetector --max-file-size 10
```

## Verbose Output

Enable verbose output to stderr:

```bash
leakdetector --verbose
```

## Exit Codes

| Code | Meaning                          |
|------|----------------------------------|
| 0    | No leaks detected                |
| 1    | Leaks detected (default)         |
| 2    | Error (invalid config, I/O, etc) |

Customize the exit code for detected leaks:

```bash
leakdetector --exit-code 0  # Don't fail on leaks
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    leakdetector --format sarif --report results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
leakdetector --skip-history
```

Or use with the pre-commit framework in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/asymmetric-effort/leakdetector
    rev: v0.1.0
    hooks:
      - id: leakdetector
        args: ["--skip-history"]
```
