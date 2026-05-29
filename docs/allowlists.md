# Allowlists

Allowlists let you suppress known false positives or intentionally ignore
certain findings.

## Methods of Suppression

leakdetector supports several ways to suppress findings:

1. **Inline comments** (`leakdetector:allow`)
2. **Configuration allowlists** (global and per-rule)
3. **Baseline files** (for incremental scanning)
4. **Path exclusions** (`exclude_paths`)
5. **Commit exclusions** (`exclude_commits`)

## Inline Comments

Add `leakdetector:allow` as a comment on any line to suppress findings on that
line:

```python
# This is a test key, not a real secret
API_KEY = "sk_test_1234567890"  # leakdetector:allow
```

```go
const testToken = "ghp_test1234567890" // leakdetector:allow
```

```yaml
api_key: "AKIAIOSFODNN7EXAMPLE"  # leakdetector:allow
```

## Configuration Allowlists

### Global Allowlists

Apply to all rules. Defined at the top level of `.leakdetector.yml`:

```yaml
allowlists:
  - description: "Ignore test files"
    paths:
      - ".*_test\\.go$"
      - "test/.*"

  - description: "Ignore known example values"
    stop_words:
      - "example"
      - "placeholder"
      - "CHANGE_ME"
      - "xxxx"
```

### Per-Rule Allowlists

Apply only to a specific rule:

```yaml
rules:
  - id: "aws-access-key-id"
    description: "AWS Access Key ID"
    regex: "AKIA[0-9A-Z]{16}"
    allowlists:
      - description: "AWS example key"
        regexes:
          - "AKIAIOSFODNN7EXAMPLE"
        regex_target: "secret"
```

## Allowlist Fields

### `paths`

List of regex patterns matched against file paths:

```yaml
allowlists:
  - paths:
      - "vendor/.*"
      - ".*\\.generated\\.go$"
```

### `regexes`

List of regex patterns matched against the finding. The `regex_target` field
controls what is matched:

| `regex_target` | Matches against |
|---------------|-----------------|
| `secret`      | Extracted secret value (default) |
| `match`       | Full regex match |
| `line`        | Entire source line |

```yaml
allowlists:
  - regexes:
      - "AKIAIOSFODNN7EXAMPLE"
    regex_target: "secret"
```

### `commits`

List of commit hashes to ignore. Supports full and short hashes:

```yaml
allowlists:
  - commits:
      - "abc1234"
      - "def5678901234567890123456789012345678901"
```

### `stop_words`

List of substrings that indicate a false positive. Matched case-insensitively
against the extracted secret:

```yaml
allowlists:
  - stop_words:
      - "example"
      - "test"
      - "fake"
      - "dummy"
      - "placeholder"
```

### `condition`

Controls how multiple criteria are combined:

- `OR` (default): Finding is allowed if **any** criterion matches.
- `AND`: Finding is allowed only if **all** criteria match.

```yaml
allowlists:
  - description: "Only ignore test files with example values"
    condition: "AND"
    paths:
      - ".*_test\\.go$"
    stop_words:
      - "example"
```

## Baseline Files

Use `--baseline` to compare against a previous scan and only report new
findings:

```bash
# Create initial baseline
leakdetector --report baseline.json

# Only report findings not in the baseline
leakdetector --baseline baseline.json
```

Baseline matching uses the `fingerprint` field, which is computed as:
`{commit}:{file}:{rule_id}:{line}`.

## Path Exclusions

Exclude entire directories or file patterns from scanning:

```yaml
exclude_paths:
  - "vendor/"
  - "node_modules/"
  - "*.min.js"
  - ".git/"
```

## Commit Exclusions

Exclude specific commits from git history scanning:

```yaml
exclude_commits:
  - "abc1234"
```

This is useful for commits that are known to contain false positives or
intentional test data.
