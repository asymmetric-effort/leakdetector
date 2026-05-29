# Configuration

leakdetector is configured via a `.leakdetector.yml` file in the root of your
repository. If no configuration file is found, built-in defaults are used.

## Configuration File Location

leakdetector searches for configuration in this order:

1. Path specified by `--config` flag.
2. `.leakdetector.yml` in the current working directory.
3. Built-in defaults (all 250 built-in rules enabled).

## Full Configuration Reference

```yaml
# Exclude specific commits from scanning.
# Accepts full or short commit hashes.
exclude_commits:
  - "abc1234"
  - "def5678901234567890123456789012345678901"

# Exclude file paths from scanning.
# Supports exact paths and prefix matching.
exclude_paths:
  - "vendor/"
  - "node_modules/"
  - "testdata/"
  - "*.min.js"

# Configuration inheritance.
extend:
  # Use built-in default rules as a base (default: true).
  use_default: true

  # Extend from another config file.
  # path: "shared/.leakdetector.yml"

  # Disable specific built-in rules.
  disabled_rules:
    - "generic-api-key"
    - "generic-password"

# Custom detection rules.
# These are added to (or override) built-in rules.
rules:
  - id: "custom-internal-token"
    description: "Internal service token"
    regex: "INT_TOKEN_[A-Za-z0-9]{32}"
    keywords:
      - "INT_TOKEN_"
    tags:
      - "internal"

  - id: "high-entropy-secret"
    description: "High entropy string in assignment"
    regex: '(?:secret|token|key)\s*[=:]\s*["\x27]([A-Za-z0-9+/=]{32,})["\x27]'
    secret_group: 1
    entropy: 4.0
    keywords:
      - "secret"
      - "token"
      - "key"

# Global allowlists.
# Findings matching these criteria are ignored.
allowlists:
  - description: "Ignore test fixtures"
    paths:
      - ".*_test\\.go"
      - "testdata/.*"

  - description: "Ignore example values"
    stop_words:
      - "example"
      - "placeholder"
      - "CHANGE_ME"
      - "your-api-key"

  - description: "Ignore specific false positives"
    regexes:
      - "AKIAIOSFODNN7EXAMPLE"
    regex_target: "secret"
```

## Configuration Fields

### `exclude_commits`

A list of commit hashes to exclude from git history scanning. Both full (40
character) and short (7+ character) hashes are supported.

```yaml
exclude_commits:
  - "abc1234"
  - "def5678901234567890123456789012345678901"
```

### `exclude_paths`

A list of file path patterns to exclude from scanning. Supports prefix
matching and glob-style patterns.

```yaml
exclude_paths:
  - "vendor/"
  - "third_party/"
  - "*.generated.go"
```

### `extend`

Controls how the configuration inherits from other sources.

| Field            | Type     | Description                              |
|-----------------|----------|------------------------------------------|
| `use_default`   | bool     | Include built-in rules (default: true)   |
| `path`          | string   | Path to parent config file               |
| `disabled_rules`| []string | Rule IDs to disable from inherited rules |

### `rules`

Custom detection rules. Each rule supports:

| Field          | Type     | Required | Description                                     |
|---------------|----------|----------|-------------------------------------------------|
| `id`          | string   | Yes      | Unique rule identifier                          |
| `description` | string   | Yes      | Human-readable description                      |
| `regex`       | string   | Yes      | Go regex pattern for detection                  |
| `secret_group`| int      | No       | Capture group index containing the secret (0=full match) |
| `entropy`     | float64  | No       | Minimum Shannon entropy threshold (0-8.0)       |
| `path`        | string   | No       | Regex to filter by file path                    |
| `keywords`    | []string | No       | Keywords for fast pre-filtering                 |
| `tags`        | []string | No       | Metadata tags for categorization                |
| `allowlists`  | []object | No       | Rule-specific allowlists                        |

### `allowlists`

Global allowlists that apply to all rules. Each allowlist supports:

| Field          | Type     | Description                                       |
|---------------|----------|---------------------------------------------------|
| `description` | string   | Human-readable description                        |
| `paths`       | []string | Regex patterns to match file paths                |
| `regexes`     | []string | Regex patterns to match against the target        |
| `commits`     | []string | Commit hashes to allow                            |
| `stop_words`  | []string | Substrings that indicate false positives          |
| `regex_target`| string   | What regexes match against: `secret`, `match`, or `line` |
| `condition`   | string   | `OR` (default) or `AND` for combining criteria    |

## Inline Suppression

Add a comment containing `leakdetector:allow` to suppress a finding on a
specific line:

```python
API_KEY = "sk_test_example_key"  # leakdetector:allow
```

```go
const token = "ghp_test1234567890" // leakdetector:allow
```

## Environment Variables

| Variable              | Description                     |
|----------------------|----------------------------------|
| `LEAKDETECTOR_CONFIG` | Path to configuration file       |
