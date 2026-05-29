# Architecture

This document describes the internal architecture of leakdetector.

## Design Principles

1. **Minimal Dependencies**: leakdetector uses only the Go standard library.
   No third-party dependencies are used at runtime, minimizing supply chain
   attack surface.

2. **No Recursion**: All directory traversal and data processing uses iterative
   approaches with bounded data structures.

3. **Bounded Buffers**: All queues and buffers have explicit size limits to
   prevent unbounded memory growth.

4. **Pure Functions**: Where possible, functions are pure — they take inputs
   and return outputs without side effects.

## Package Structure

```
cmd/
  leakdetector/       Entry point (main.go)

internal/
  cli/                CLI flag parsing and execution orchestration
  config/             YAML configuration loading and parsing
  decoder/            Base64, hex, and percent-encoding decoders
  entropy/            Shannon entropy calculation
  finding/            Finding data structure, fingerprinting, baseline
  git/                Git repository helpers (branch detection, log args)
  output/             Output formatters (JSON, CSV, JUnit, SARIF)
  rules/              Rule compilation, matching, built-in rules
  scanner/            File, git history, and stdin scanning

test/
  e2e/                End-to-end tests (run the built binary)
  integration/        Integration tests (multi-package)
  testdata/           Test fixture files
```

## Data Flow

```
CLI (args)
  |
  v
Config (load .leakdetector.yml)
  |
  v
Rules (compile built-in + custom rules)
  |
  v
Scanner (scan files / git history / stdin)
  |  |
  |  +-- File Scanner (walk directory, read files line by line)
  |  +-- Git Scanner (git log -p, parse diff output)
  |  +-- Stdin Scanner (read stdin line by line)
  |
  v
Findings (match, fingerprint, filter)
  |
  +-- Baseline Filter (remove known findings)
  +-- Allowlist Filter (remove allowed findings)
  |
  v
Output (format and write results)
```

## Rule Matching Pipeline

For each line of content, the matching pipeline runs:

1. **Path filter**: Skip if file path doesn't match rule's path regex.
2. **Keyword pre-filter**: Skip if none of the rule's keywords appear in the
   line (case-insensitive). This is a fast O(n) string search that avoids
   expensive regex evaluation on most lines.
3. **Regex match**: Apply the compiled regex to the line.
4. **Secret extraction**: Extract the secret from the specified capture group.
5. **Entropy check**: Calculate Shannon entropy and compare against threshold.
6. **Allowlist check**: Check rule-level allowlists, then global allowlists.
7. **Inline comment check**: Check for `leakdetector:allow` in the line.
8. **Decoder**: Optionally decode base64/hex/percent-encoded secrets and
   re-scan decoded values.

## Git History Scanning

The git scanner runs `git log -p` and parses the unified diff output:

1. Parse commit headers (SHA, author, email, date, message).
2. Parse diff headers (`diff --git`, `--- a/`, `+++ b/`).
3. Parse hunks (`@@ -start,count +start,count @@`).
4. Scan only added lines (lines starting with `+`).
5. Track line numbers within hunks for accurate positioning.

## Configuration Parsing

leakdetector includes a hand-written YAML parser that handles the subset of
YAML used in configuration files. This avoids depending on a third-party YAML
library.

Supported YAML features:
- Key-value pairs
- Block-style lists (with `- ` prefix)
- Inline lists (`[a, b, c]`)
- Single and double-quoted strings
- Comments (`#`)
- Nested objects (indent-based)

## Output Formats

Each output format implements the same interface, receiving a slice of findings
and writing formatted output to an `io.Writer`:

- **JSON**: `encoding/json` with indentation.
- **CSV**: `encoding/csv` with header row.
- **JUnit**: `encoding/xml` with test suite/case structure.
- **SARIF**: `encoding/json` with SARIF 2.1.0 schema.
