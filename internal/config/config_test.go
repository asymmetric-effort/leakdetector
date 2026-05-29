package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if cfg.Extend == nil {
		t.Fatal("Default().Extend is nil")
	}
	if !cfg.Extend.UseDefault {
		t.Error("Default().Extend.UseDefault should be true")
	}
	if cfg.Extend.Path != "" {
		t.Errorf("Default().Extend.Path should be empty, got %q", cfg.Extend.Path)
	}
	if len(cfg.Extend.DisabledRules) != 0 {
		t.Errorf("Default().Extend.DisabledRules should be empty, got %v", cfg.Extend.DisabledRules)
	}
	if len(cfg.ExcludeCommits) != 0 {
		t.Error("Default().ExcludeCommits should be empty")
	}
	if len(cfg.ExcludePaths) != 0 {
		t.Error("Default().ExcludePaths should be empty")
	}
	if len(cfg.Rules) != 0 {
		t.Error("Default().Rules should be empty")
	}
	if len(cfg.Allowlists) != 0 {
		t.Error("Default().Allowlists should be empty")
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/to/config.yml")
	if err == nil {
		t.Fatal("Load should return error for non-existent file")
	}
}

func TestLoadValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := `exclude_commits:
  - abc123
  - def456
exclude_paths:
  - vendor/
  - node_modules/
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.ExcludeCommits) != 2 {
		t.Fatalf("expected 2 exclude_commits, got %d", len(cfg.ExcludeCommits))
	}
	if cfg.ExcludeCommits[0] != "abc123" || cfg.ExcludeCommits[1] != "def456" {
		t.Errorf("unexpected exclude_commits: %v", cfg.ExcludeCommits)
	}
	if len(cfg.ExcludePaths) != 2 {
		t.Fatalf("expected 2 exclude_paths, got %d", len(cfg.ExcludePaths))
	}
	if cfg.ExcludePaths[0] != "vendor/" || cfg.ExcludePaths[1] != "node_modules/" {
		t.Errorf("unexpected exclude_paths: %v", cfg.ExcludePaths)
	}
}

func TestLoadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error for empty file: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config for empty file")
	}
	if len(cfg.Rules) != 0 || len(cfg.ExcludeCommits) != 0 {
		t.Error("empty file should produce empty config")
	}
}

func TestLoadCommentsOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comments.yml")
	content := `# This is a comment
# Another comment

# More comments
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil")
	}
}

func TestLoadFullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.yml")
	content := `exclude_commits:
  - aaaa
exclude_paths:
  - "test/"
  - 'vendor/'
rules:
  - id: rule-1
    description: "Test rule"
    regex: "password\\s*=\\s*['\"]\\w+"
    secret_group: 1
    entropy: 3.5
    path: ".*\\.go"
    keywords:
      - password
      - secret
    tags:
      - security
      - credential
    allowlists:
      - description: "Test allow"
        paths:
          - test/
        regexes:
          - "example"
        commits:
          - deadbeef
        stop_words:
          - fake
        regex_target: match
        condition: AND
  - id: rule-2
    description: Second rule
    regex: "api_key"
allowlists:
  - description: Global allowlist
    paths:
      - docs/
    regexes:
      - placeholder
    commits:
      - abcdef12
    stop_words:
      - test
    regex_target: line
    condition: OR
extend:
  use_default: true
  path: "/etc/leakdetector.yml"
  disabled_rules:
    - generic-api-key
    - generic-password
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// exclude_commits
	if len(cfg.ExcludeCommits) != 1 || cfg.ExcludeCommits[0] != "aaaa" {
		t.Errorf("unexpected exclude_commits: %v", cfg.ExcludeCommits)
	}

	// exclude_paths (quoted strings)
	if len(cfg.ExcludePaths) != 2 {
		t.Fatalf("expected 2 exclude_paths, got %d", len(cfg.ExcludePaths))
	}
	if cfg.ExcludePaths[0] != "test/" {
		t.Errorf("expected exclude_paths[0]='test/', got %q", cfg.ExcludePaths[0])
	}
	if cfg.ExcludePaths[1] != "vendor/" {
		t.Errorf("expected exclude_paths[1]='vendor/', got %q", cfg.ExcludePaths[1])
	}

	// rules
	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if r.ID != "rule-1" {
		t.Errorf("rule[0].ID = %q, want rule-1", r.ID)
	}
	if r.Description != "Test rule" {
		t.Errorf("rule[0].Description = %q, want 'Test rule'", r.Description)
	}
	if r.Regex != "password\\s*=\\s*['\"]\\w+" {
		t.Errorf("rule[0].Regex = %q", r.Regex)
	}
	if r.SecretGroup != 1 {
		t.Errorf("rule[0].SecretGroup = %d, want 1", r.SecretGroup)
	}
	if r.Entropy != 3.5 {
		t.Errorf("rule[0].Entropy = %f, want 3.5", r.Entropy)
	}
	if r.Path != ".*\\.go" {
		t.Errorf("rule[0].Path = %q", r.Path)
	}
	if len(r.Keywords) != 2 || r.Keywords[0] != "password" || r.Keywords[1] != "secret" {
		t.Errorf("rule[0].Keywords = %v", r.Keywords)
	}
	if len(r.Tags) != 2 || r.Tags[0] != "security" || r.Tags[1] != "credential" {
		t.Errorf("rule[0].Tags = %v", r.Tags)
	}

	// Rule-level allowlist
	if len(r.Allowlists) != 1 {
		t.Fatalf("rule[0].Allowlists length = %d, want 1", len(r.Allowlists))
	}
	ra := r.Allowlists[0]
	if ra.Description != "Test allow" {
		t.Errorf("rule allowlist description = %q", ra.Description)
	}
	if len(ra.Paths) != 1 || ra.Paths[0] != "test/" {
		t.Errorf("rule allowlist paths = %v", ra.Paths)
	}
	if len(ra.Regexes) != 1 || ra.Regexes[0] != "example" {
		t.Errorf("rule allowlist regexes = %v", ra.Regexes)
	}
	if len(ra.Commits) != 1 || ra.Commits[0] != "deadbeef" {
		t.Errorf("rule allowlist commits = %v", ra.Commits)
	}
	if len(ra.StopWords) != 1 || ra.StopWords[0] != "fake" {
		t.Errorf("rule allowlist stop_words = %v", ra.StopWords)
	}
	if ra.RegexTarget != "match" {
		t.Errorf("rule allowlist regex_target = %q", ra.RegexTarget)
	}
	if ra.Condition != "AND" {
		t.Errorf("rule allowlist condition = %q", ra.Condition)
	}

	// Second rule
	r2 := cfg.Rules[1]
	if r2.ID != "rule-2" {
		t.Errorf("rule[1].ID = %q", r2.ID)
	}
	if r2.Description != "Second rule" {
		t.Errorf("rule[1].Description = %q", r2.Description)
	}

	// Global allowlists
	if len(cfg.Allowlists) != 1 {
		t.Fatalf("expected 1 global allowlist, got %d", len(cfg.Allowlists))
	}
	ga := cfg.Allowlists[0]
	if ga.Description != "Global allowlist" {
		t.Errorf("global allowlist description = %q", ga.Description)
	}
	if len(ga.Paths) != 1 || ga.Paths[0] != "docs/" {
		t.Errorf("global allowlist paths = %v", ga.Paths)
	}
	if len(ga.Regexes) != 1 || ga.Regexes[0] != "placeholder" {
		t.Errorf("global allowlist regexes = %v", ga.Regexes)
	}
	if len(ga.Commits) != 1 || ga.Commits[0] != "abcdef12" {
		t.Errorf("global allowlist commits = %v", ga.Commits)
	}
	if len(ga.StopWords) != 1 || ga.StopWords[0] != "test" {
		t.Errorf("global allowlist stop_words = %v", ga.StopWords)
	}
	if ga.RegexTarget != "line" {
		t.Errorf("global allowlist regex_target = %q", ga.RegexTarget)
	}
	if ga.Condition != "OR" {
		t.Errorf("global allowlist condition = %q", ga.Condition)
	}

	// Extend
	if cfg.Extend == nil {
		t.Fatal("Extend is nil")
	}
	if !cfg.Extend.UseDefault {
		t.Error("Extend.UseDefault should be true")
	}
	if cfg.Extend.Path != "/etc/leakdetector.yml" {
		t.Errorf("Extend.Path = %q", cfg.Extend.Path)
	}
	if len(cfg.Extend.DisabledRules) != 2 {
		t.Fatalf("Extend.DisabledRules length = %d, want 2", len(cfg.Extend.DisabledRules))
	}
	if cfg.Extend.DisabledRules[0] != "generic-api-key" || cfg.Extend.DisabledRules[1] != "generic-password" {
		t.Errorf("Extend.DisabledRules = %v", cfg.Extend.DisabledRules)
	}
}

func TestLoadInlineStringLists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inline.yml")
	content := `rules:
  - id: inline-rule
    keywords: [password, secret, key]
    tags: [tag1, tag2]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	r := cfg.Rules[0]
	if len(r.Keywords) != 3 || r.Keywords[0] != "password" || r.Keywords[1] != "secret" || r.Keywords[2] != "key" {
		t.Errorf("inline keywords = %v", r.Keywords)
	}
	if len(r.Tags) != 2 || r.Tags[0] != "tag1" || r.Tags[1] != "tag2" {
		t.Errorf("inline tags = %v", r.Tags)
	}
}

func TestLoadExtendUseFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.yml")
	content := `extend:
  use_default: false
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Extend == nil {
		t.Fatal("Extend is nil")
	}
	if cfg.Extend.UseDefault {
		t.Error("Extend.UseDefault should be false")
	}
}

func TestLoadExtendInlineDisabledRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.yml")
	content := `extend:
  disabled_rules: [rule-a, rule-b]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Extend == nil {
		t.Fatal("Extend is nil")
	}
	if len(cfg.Extend.DisabledRules) != 2 || cfg.Extend.DisabledRules[0] != "rule-a" {
		t.Errorf("Extend.DisabledRules = %v", cfg.Extend.DisabledRules)
	}
}

func TestLoadUnknownTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown.yml")
	content := `unknown_key: some_value
another_unknown:
  nested: value
exclude_commits:
  - abc
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	// Unknown keys should be ignored, known keys parsed
	if len(cfg.ExcludeCommits) != 1 || cfg.ExcludeCommits[0] != "abc" {
		t.Errorf("exclude_commits = %v", cfg.ExcludeCommits)
	}
}

func TestLoadAllowlistInlineListFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "al.yml")
	content := `allowlists:
  - description: inline test
    paths: [p1, p2]
    regexes: [r1]
    commits: [c1, c2, c3]
    stop_words: [sw1]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Allowlists) != 1 {
		t.Fatalf("expected 1 allowlist, got %d", len(cfg.Allowlists))
	}
	al := cfg.Allowlists[0]
	if len(al.Paths) != 2 {
		t.Errorf("paths = %v", al.Paths)
	}
	if len(al.Regexes) != 1 {
		t.Errorf("regexes = %v", al.Regexes)
	}
	if len(al.Commits) != 3 {
		t.Errorf("commits = %v", al.Commits)
	}
	if len(al.StopWords) != 1 {
		t.Errorf("stop_words = %v", al.StopWords)
	}
}

func TestLoadSingleValueKeywordsTags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.yml")
	content := `rules:
  - id: r1
    keywords: onlyone
    tags: singletag
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	r := cfg.Rules[0]
	if len(r.Keywords) != 1 || r.Keywords[0] != "onlyone" {
		t.Errorf("keywords = %v", r.Keywords)
	}
	if len(r.Tags) != 1 || r.Tags[0] != "singletag" {
		t.Errorf("tags = %v", r.Tags)
	}
}

func TestLoadExtendQuotedPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.yml")
	content := `extend:
  path: "/some/path/config.yml"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Extend.Path != "/some/path/config.yml" {
		t.Errorf("Extend.Path = %q", cfg.Extend.Path)
	}
}

func TestLoadExtendSingleQuotedPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.yml")
	content := `extend:
  path: '/some/path/config.yml'
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Extend.Path != "/some/path/config.yml" {
		t.Errorf("Extend.Path = %q", cfg.Extend.Path)
	}
}

func TestLoadMultipleRulesWithComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "comments.yml")
	content := `# Top level comment
rules:
  # Comment before rule
  - id: r1
    description: first
  # Another comment
  - id: r2
    description: second
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].ID != "r1" || cfg.Rules[1].ID != "r2" {
		t.Errorf("rules = %v, %v", cfg.Rules[0].ID, cfg.Rules[1].ID)
	}
}

func TestLoadRuleWithZeroSecretGroupAndEntropy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zero.yml")
	content := `rules:
  - id: r1
    secret_group: 0
    entropy: 0.0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	r := cfg.Rules[0]
	if r.SecretGroup != 0 {
		t.Errorf("SecretGroup = %d, want 0", r.SecretGroup)
	}
	if r.Entropy != 0.0 {
		t.Errorf("Entropy = %f, want 0.0", r.Entropy)
	}
}

func TestLoadMultipleAllowlists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi_al.yml")
	content := `allowlists:
  - description: first
    condition: AND
  - description: second
    condition: OR
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Allowlists) != 2 {
		t.Fatalf("expected 2 allowlists, got %d", len(cfg.Allowlists))
	}
	if cfg.Allowlists[0].Description != "first" || cfg.Allowlists[0].Condition != "AND" {
		t.Errorf("allowlist[0] = %+v", cfg.Allowlists[0])
	}
	if cfg.Allowlists[1].Description != "second" || cfg.Allowlists[1].Condition != "OR" {
		t.Errorf("allowlist[1] = %+v", cfg.Allowlists[1])
	}
}

func TestLoadNonListLineInRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonlist.yml")
	// A line inside rules block that doesn't start with "- " should be skipped
	content := `rules:
  someorphanline
  - id: r1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].ID != "r1" {
		t.Errorf("rules = %v", cfg.Rules)
	}
}

func TestLoadNonListLineInAllowlists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonlist_al.yml")
	content := `allowlists:
  orphan_line
  - description: al1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Allowlists) != 1 || cfg.Allowlists[0].Description != "al1" {
		t.Errorf("allowlists = %v", cfg.Allowlists)
	}
}
