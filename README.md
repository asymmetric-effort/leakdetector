# leakdetector

A fast, zero-dependency CLI tool for detecting leaked secrets and sensitive
information in git repositories.

## Features

- **250+ built-in detection rules** covering AWS, Azure, GCP, GitHub, GitLab,
  Slack, Stripe, OpenAI, Anthropic, and dozens more platforms.
- **Git history scanning** with full history, branch-specific, or current HEAD
  modes.
- **Shannon entropy filtering** to reduce false positives.
- **Multiple output formats**: JSON, CSV, JUnit XML, SARIF 2.1.0.
- **Flexible allowlists**: global, per-rule, inline comments, baseline files.
- **Zero runtime dependencies**: built entirely on the Go standard library to
  minimize supply chain attack surface.
- **Cross-platform**: Linux, macOS, and Windows on amd64 and arm64.
- **YAML configuration** via `.leakdetector.yml`.

## Quick Start

```bash
# Build from source (requires Go 1.26+)
git clone https://github.com/asymmetric-effort/leakdetector.git
cd leakdetector
make build

# Scan current directory with full git history
./build/linux/amd64/leakdetector

# Scan without git history
./build/linux/amd64/leakdetector --skip-history

# Scan a specific branch
./build/linux/amd64/leakdetector --branch main

# Output as SARIF for GitHub Security integration
./build/linux/amd64/leakdetector --format sarif --report findings.sarif
```

## Installation

### From Source

```bash
git clone https://github.com/asymmetric-effort/leakdetector.git
cd leakdetector
make build
```

Binaries are output to `./build/<os>/<arch>/leakdetector`.

### From Release

Download the latest binary from
[GitHub Releases](https://github.com/asymmetric-effort/leakdetector/releases).

## Usage

```
Usage: leakdetector [options]

Scan git repositories for leaked secrets and sensitive information.

Options:
  --skip-history       Skip scanning git history
  --branch string      Scan a specific branch
  --config string      Path to configuration file (default: .leakdetector.yml)
  --report string      Path to write report output (default: stdout)
  --format string      Output format: json, csv, junit, sarif (default: json)
  --redact             Redact secrets from output
  --verbose            Enable verbose output
  --no-color           Disable colored output
  --version            Print version and exit
  --exit-code int      Exit code when leaks are found (default: 1)
  --max-file-size int  Skip files larger than this size in MB (0=no limit)
  --stdin              Read input from stdin
  --baseline string    Path to baseline report to ignore known findings

Examples:
  leakdetector                        Scan current directory with full git history
  leakdetector --skip-history         Scan current directory without git history
  leakdetector --branch main          Scan a specific branch
  leakdetector --format sarif         Output in SARIF format
  leakdetector --stdin                Read from stdin
```

## Scanning Modes

| Command | Behavior |
|---------|----------|
| `leakdetector` | Scan cwd + full git history (if `.git` exists) |
| `leakdetector --skip-history` | Scan cwd files only, skip git history |
| `leakdetector --branch foo` | Scan branch `foo` history |
| `leakdetector --stdin` | Scan content piped to stdin |

## Configuration

Create a `.leakdetector.yml` in your repository root:

```yaml
# Exclude specific commits from scanning
exclude_commits:
  - "abc1234"

# Exclude paths from scanning
exclude_paths:
  - "vendor/"
  - "node_modules/"
  - "*.min.js"

# Custom rules (added to built-in rules)
rules:
  - id: "internal-token"
    description: "Internal service token"
    regex: "INT_[A-Za-z0-9]{32}"
    keywords:
      - "INT_"

# Global allowlists
allowlists:
  - description: "Ignore test files"
    paths:
      - ".*_test\\.go$"
  - description: "Ignore example values"
    stop_words:
      - "example"
      - "CHANGE_ME"
```

See [docs/configuration.md](docs/configuration.md) for the full reference.

## Inline Suppression

Add `leakdetector:allow` as a comment to suppress a finding on a specific line:

```python
API_KEY = "sk_test_example"  # leakdetector:allow
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| JSON   | `--format json` | Default, machine-readable |
| CSV    | `--format csv` | Spreadsheet import |
| JUnit  | `--format junit` | CI/CD test reporting |
| SARIF  | `--format sarif` | GitHub Security tab |

## Baseline Scanning

Compare against a previous scan to only report new findings:

```bash
# Create baseline
leakdetector --report baseline.json

# Report only new findings
leakdetector --baseline baseline.json
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: leakdetector --format sarif --report results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/bash
leakdetector --skip-history
```

## Built-in Rules

leakdetector ships with 250+ detection rules covering:

- **Cloud**: AWS, Azure, GCP, Alibaba, DigitalOcean, Heroku, Linode
- **VCS**: GitHub, GitLab, Bitbucket, Gitea
- **CI/CD**: Travis CI, Drone CI, CircleCI, Jenkins, Buildkite
- **Payment**: Stripe, Square, Shopify, Braintree
- **Messaging**: Slack, Discord, Telegram, Mattermost
- **AI/ML**: OpenAI, Anthropic, Hugging Face, Cohere, Replicate
- **Infrastructure**: Vault, Terraform, Pulumi, Kubernetes, Docker
- **Databases**: MongoDB, MySQL, PostgreSQL, Redis, Databricks
- **Crypto**: RSA/EC/DSA/SSH/PGP private keys, JWT, Age
- **Generic**: API keys, passwords, secrets, bearer tokens, basic auth URLs

See [docs/rules.md](docs/rules.md) for the complete list.

## Development

```bash
make clean       # Delete and recreate ./build
make lint        # Run govulncheck, go vet, staticcheck
make test        # Run unit, integration, e2e, and PDV tests
make cover       # Verify 98%+ test coverage
make build       # Cross-compile for all platforms
make release     # Bump patch version and tag
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | No leaks detected |
| 1    | Leaks detected (configurable via `--exit-code`) |
| 2    | Error |

## Documentation

- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Configuration](docs/configuration.md)
- [Rules](docs/rules.md)
- [Output Formats](docs/output-formats.md)
- [Allowlists](docs/allowlists.md)
- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

[MIT License](LICENSE.txt) - Copyright (c) 2026 Asymmetric Effort, LLC.
