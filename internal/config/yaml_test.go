package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCountIndent(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{"no indent", "hello", 0},
		{"two spaces", "  hello", 2},
		{"four spaces", "    hello", 4},
		{"tab", "\thello", 2},
		{"two tabs", "\t\thello", 4},
		{"mixed space tab", "  \thello", 4},
		{"empty", "", 0},
		{"only spaces", "   ", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countIndent(tt.line)
			if got != tt.want {
				t.Errorf("countIndent(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}

func TestSplitKeyValue(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
	}{
		{"simple", "key: value", "key", "value"},
		{"no value", "key:", "key", ""},
		{"no colon", "justkey", "justkey", ""},
		{"value with spaces", "key: some value here", "key", "some value here"},
		{"colon in value", "key: val:ue", "key", "val:ue"},
		{"empty", "", "", ""},
		{"spaces around key", "  key  :  value  ", "key", "value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, val := splitKeyValue(tt.input)
			if key != tt.wantKey {
				t.Errorf("splitKeyValue(%q) key = %q, want %q", tt.input, key, tt.wantKey)
			}
			if val != tt.wantVal {
				t.Errorf("splitKeyValue(%q) val = %q, want %q", tt.input, val, tt.wantVal)
			}
		})
	}
}

func TestUnquoteYAML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no quotes", "hello", "hello"},
		{"double quoted", `"hello"`, "hello"},
		{"single quoted", `'hello'`, "hello"},
		{"double with escape", `"hello\nworld"`, "hello\nworld"},
		{"single with backslash", `'hello\nworld'`, `hello\nworld`},
		{"empty", "", ""},
		{"single char", "x", "x"},
		{"only quotes double", `""`, ""},
		{"only quotes single", `''`, ""},
		{"spaces around", "  hello  ", "hello"},
		{"quoted with spaces", `"  hello  "`, "  hello  "},
		{"mismatched quotes", `"hello'`, `"hello'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unquoteYAML(tt.input)
			if got != tt.want {
				t.Errorf("unquoteYAML(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSetRuleFieldChecked(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		val       string
		check     func(*RuleConfig) bool
		wantErr   bool
		wantWarn  bool
	}{
		{"id", "id", "test-id", func(r *RuleConfig) bool { return r.ID == "test-id" }, false, false},
		{"description", "description", "test desc", func(r *RuleConfig) bool { return r.Description == "test desc" }, false, false},
		{"regex", "regex", ".*", func(r *RuleConfig) bool { return r.Regex == ".*" }, false, false},
		{"secret_group", "secret_group", "3", func(r *RuleConfig) bool { return r.SecretGroup == 3 }, false, false},
		{"entropy", "entropy", "4.2", func(r *RuleConfig) bool { return r.Entropy == 4.2 }, false, false},
		{"path", "path", "src/", func(r *RuleConfig) bool { return r.Path == "src/" }, false, false},
		{"invalid secret_group", "secret_group", "notanint", func(r *RuleConfig) bool { return r.SecretGroup == 0 }, true, false},
		{"invalid entropy", "entropy", "notafloat", func(r *RuleConfig) bool { return r.Entropy == 0.0 }, true, false},
		{"unknown key", "unknown", "val", func(r *RuleConfig) bool { return r.ID == "" }, false, true},
		{"quoted id", "id", `"quoted-id"`, func(r *RuleConfig) bool { return r.ID == "quoted-id" }, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &parser{lines: []string{"dummy"}, pos: 0}
			var rule RuleConfig
			p.setRuleFieldChecked(&rule, tt.key, tt.val)
			if !tt.check(&rule) {
				t.Errorf("setRuleFieldChecked(%q, %q) did not produce expected result: %+v", tt.key, tt.val, rule)
			}
			if tt.wantErr && len(p.errors) == 0 {
				t.Error("expected error, got none")
			}
			if tt.wantWarn && len(p.warnings) == 0 {
				t.Error("expected warning, got none")
			}
		})
	}
}

func TestSetAllowlistFieldChecked(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		val      string
		check    func(*Allowlist) bool
		wantErr  bool
		wantWarn bool
	}{
		{"description", "description", "test", func(a *Allowlist) bool { return a.Description == "test" }, false, false},
		{"regex_target", "regex_target", "match", func(a *Allowlist) bool { return a.RegexTarget == "match" }, false, false},
		{"condition", "condition", "AND", func(a *Allowlist) bool { return a.Condition == "AND" }, false, false},
		{"unknown", "unknown", "val", func(a *Allowlist) bool { return a.Description == "" }, false, true},
		{"quoted description", "description", `"quoted"`, func(a *Allowlist) bool { return a.Description == "quoted" }, false, false},
		{"invalid regex_target", "regex_target", "bogus", func(a *Allowlist) bool { return a.RegexTarget == "" }, true, false},
		{"invalid condition", "condition", "MAYBE", func(a *Allowlist) bool { return a.Condition == "" }, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &parser{lines: []string{"dummy"}, pos: 0}
			var al Allowlist
			p.setAllowlistFieldChecked(&al, tt.key, tt.val)
			if !tt.check(&al) {
				t.Errorf("setAllowlistFieldChecked(%q, %q) did not produce expected result: %+v", tt.key, tt.val, al)
			}
			if tt.wantErr && len(p.errors) == 0 {
				t.Error("expected error, got none")
			}
			if tt.wantWarn && len(p.warnings) == 0 {
				t.Error("expected warning, got none")
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	// Rule missing id.
	_, err := parse([]byte("rules:\n  - regex: \".*\"\n"))
	if err == nil {
		t.Error("expected error for rule missing id")
	}

	// Rule missing regex.
	_, err = parse([]byte("rules:\n  - id: test\n"))
	if err == nil {
		t.Error("expected error for rule missing regex")
	}

	// Invalid secret_group.
	_, err = parse([]byte("rules:\n  - id: test\n    regex: \".*\"\n    secret_group: abc\n"))
	if err == nil {
		t.Error("expected error for invalid secret_group")
	}

	// Invalid extend.use_default.
	_, err = parse([]byte("extend:\n  use_default: maybe\n"))
	if err == nil {
		t.Error("expected error for invalid use_default")
	}

	// Invalid allowlist condition.
	_, err = parse([]byte("allowlists:\n  - condition: MAYBE\n"))
	if err == nil {
		t.Error("expected error for invalid allowlist condition")
	}
}

func TestParseWarnings(t *testing.T) {
	// Unknown top-level key.
	cfg, err := parse([]byte("bogus_key: value\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for unknown top-level key")
	}

	// Unknown rule field.
	cfg, err = parse([]byte("rules:\n  - id: test\n    regex: \".*\"\n    bogus: value\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for unknown rule field")
	}

	// Unknown extend field.
	cfg, err = parse([]byte("extend:\n  use_default: true\n  bogus: value\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for unknown extend field")
	}
}

func TestParseEmptyData(t *testing.T) {
	cfg, err := parse([]byte(""))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if cfg == nil {
		t.Fatal("parse empty returned nil")
	}
}

func TestParseCommentsOnly(t *testing.T) {
	cfg, err := parse([]byte("# comment\n# another\n"))
	if err != nil {
		t.Fatalf("parse comments: %v", err)
	}
	if len(cfg.Rules) != 0 {
		t.Error("comments-only should have no rules")
	}
}

func TestParseStringListWithComments(t *testing.T) {
	data := `exclude_commits:
  - abc
  # comment in list
  - def
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ExcludeCommits) != 2 {
		t.Errorf("expected 2 items, got %d: %v", len(cfg.ExcludeCommits), cfg.ExcludeCommits)
	}
}

func TestParseStringListWithEmptyLines(t *testing.T) {
	data := `exclude_paths:
  - path1

  - path2
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ExcludePaths) != 2 {
		t.Errorf("expected 2 items, got %d: %v", len(cfg.ExcludePaths), cfg.ExcludePaths)
	}
}

func TestParseInlineListWithQuotes(t *testing.T) {
	data := `rules:
  - id: r1
    regex: ".*"
    keywords: ["quoted", 'single']
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules) == 0 {
		t.Fatal("no rules parsed")
	}
	kw := cfg.Rules[0].Keywords
	if len(kw) != 2 || kw[0] != "quoted" || kw[1] != "single" {
		t.Errorf("keywords = %v", kw)
	}
}

func TestParseInlineListEmpty(t *testing.T) {
	data := `rules:
  - id: r1
    regex: ".*"
    keywords: []
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules[0].Keywords) != 0 {
		t.Errorf("expected empty keywords, got %v", cfg.Rules[0].Keywords)
	}
}

func TestParseExtendWithComments(t *testing.T) {
	data := `extend:
  # comment
  use_default: true
  # another comment
  path: mypath
  disabled_rules:
    - rule1
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Extend == nil {
		t.Fatal("Extend is nil")
	}
	if !cfg.Extend.UseDefault {
		t.Error("UseDefault should be true")
	}
	if cfg.Extend.Path != "mypath" {
		t.Errorf("Path = %q", cfg.Extend.Path)
	}
	if len(cfg.Extend.DisabledRules) != 1 || cfg.Extend.DisabledRules[0] != "rule1" {
		t.Errorf("DisabledRules = %v", cfg.Extend.DisabledRules)
	}
}

func TestParseRuleWithAllowlistBlockLists(t *testing.T) {
	data := `rules:
  - id: r1
    regex: ".*"
    allowlists:
      - description: al1
        paths:
          - p1
          - p2
        regexes:
          - r1
        commits:
          - c1
        stop_words:
          - sw1
          - sw2
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if len(cfg.Rules[0].Allowlists) != 1 {
		t.Fatalf("expected 1 allowlist, got %d", len(cfg.Rules[0].Allowlists))
	}
	al := cfg.Rules[0].Allowlists[0]
	if len(al.Paths) != 2 {
		t.Errorf("paths = %v", al.Paths)
	}
	if len(al.Regexes) != 1 {
		t.Errorf("regexes = %v", al.Regexes)
	}
	if len(al.Commits) != 1 {
		t.Errorf("commits = %v", al.Commits)
	}
	if len(al.StopWords) != 2 {
		t.Errorf("stop_words = %v", al.StopWords)
	}
}

func TestParseStringList2WithComments(t *testing.T) {
	// Exercises parseStringList2 directly via block-style keywords in a rule
	data := `rules:
  - id: r1
    regex: ".*"
    keywords:
      # a comment
      - kw1

      - kw2
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	kw := cfg.Rules[0].Keywords
	if len(kw) != 2 || kw[0] != "kw1" || kw[1] != "kw2" {
		t.Errorf("keywords = %v", kw)
	}
}

func TestParseTopLevelWithValue(t *testing.T) {
	// Unknown top-level key with a value on same line
	data := `some_key: some_value
exclude_commits:
  - c1
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ExcludeCommits) != 1 {
		t.Errorf("exclude_commits = %v", cfg.ExcludeCommits)
	}
}

func TestParseTopLevelWithoutValue(t *testing.T) {
	// Unknown top-level key without a value (followed by children)
	data := `unknown_section:
  child: val
exclude_commits:
  - c1
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ExcludeCommits) != 1 {
		t.Errorf("exclude_commits = %v", cfg.ExcludeCommits)
	}
}

func TestParseAllFieldsRoundTrip(t *testing.T) {
	// A comprehensive test with every possible field populated
	data := `exclude_commits:
  - commit1
  - commit2
exclude_paths:
  - path1
  - path2
rules:
  - id: rule1
    regex: ".*"
    description: "Rule one"
    regex: "pattern"
    secret_group: 2
    entropy: 3.14
    path: "src/.*"
    keywords:
      - kw1
    tags: [t1, t2]
    allowlists:
      - description: "inner allow"
        paths: [ip1]
        regexes: [ir1]
        commits: [ic1]
        stop_words: [isw1]
        regex_target: match
        condition: AND
allowlists:
  - description: "global allow"
    paths:
      - gp1
    regexes:
      - gr1
    commits:
      - gc1
    stop_words:
      - gsw1
    regex_target: line
    condition: OR
extend:
  use_default: true
  path: "/ext/path"
  disabled_rules:
    - dr1
    - dr2
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Verify everything was parsed
	if len(cfg.ExcludeCommits) != 2 {
		t.Errorf("exclude_commits len = %d", len(cfg.ExcludeCommits))
	}
	if len(cfg.ExcludePaths) != 2 {
		t.Errorf("exclude_paths len = %d", len(cfg.ExcludePaths))
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("rules len = %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if r.ID != "rule1" || r.Description != "Rule one" || r.Regex != "pattern" {
		t.Errorf("rule basic fields: %+v", r)
	}
	if r.SecretGroup != 2 || r.Entropy != 3.14 || r.Path != "src/.*" {
		t.Errorf("rule numeric/path fields: sg=%d, ent=%f, path=%q", r.SecretGroup, r.Entropy, r.Path)
	}
	if len(r.Keywords) != 1 || r.Keywords[0] != "kw1" {
		t.Errorf("keywords = %v", r.Keywords)
	}
	if len(r.Tags) != 2 {
		t.Errorf("tags = %v", r.Tags)
	}
	if len(r.Allowlists) != 1 {
		t.Fatalf("rule allowlists len = %d", len(r.Allowlists))
	}

	ral := r.Allowlists[0]
	if ral.Description != "inner allow" {
		t.Errorf("rule allowlist desc = %q", ral.Description)
	}
	if ral.RegexTarget != "match" || ral.Condition != "AND" {
		t.Errorf("rule allowlist regex_target=%q, condition=%q", ral.RegexTarget, ral.Condition)
	}

	if len(cfg.Allowlists) != 1 {
		t.Fatalf("global allowlists len = %d", len(cfg.Allowlists))
	}
	gal := cfg.Allowlists[0]
	if gal.Description != "global allow" || gal.RegexTarget != "line" || gal.Condition != "OR" {
		t.Errorf("global allowlist: %+v", gal)
	}

	if cfg.Extend == nil {
		t.Fatal("extend is nil")
	}
	if !cfg.Extend.UseDefault || cfg.Extend.Path != "/ext/path" || len(cfg.Extend.DisabledRules) != 2 {
		t.Errorf("extend: %+v", cfg.Extend)
	}
}

func TestLoadFilePermissionError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noperm.yml")
	if err := os.WriteFile(path, []byte("key: val"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for unreadable file")
	}
}

func TestParseTabIndentation(t *testing.T) {
	data := "exclude_commits:\n\t- tab1\n\t- tab2\n"
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ExcludeCommits) != 2 {
		t.Errorf("expected 2, got %d: %v", len(cfg.ExcludeCommits), cfg.ExcludeCommits)
	}
}

func TestParseRuleEmptyAllowlists(t *testing.T) {
	data := `rules:
  - id: r1
    regex: ".*"
    allowlists:
  - id: r2
    regex: ".*"
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// r1 has empty allowlists, r2 should still be parsed
	if len(cfg.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(cfg.Rules))
	}
}

func TestParseAllowlistSingleValueFields(t *testing.T) {
	// Test allowlist list fields given as single inline value (not [] syntax)
	data := `allowlists:
  - description: test
    paths: single_path
    regexes: single_regex
    commits: single_commit
    stop_words: single_word
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	al := cfg.Allowlists[0]
	if len(al.Paths) != 1 || al.Paths[0] != "single_path" {
		t.Errorf("paths = %v", al.Paths)
	}
	if len(al.Regexes) != 1 || al.Regexes[0] != "single_regex" {
		t.Errorf("regexes = %v", al.Regexes)
	}
	if len(al.Commits) != 1 || al.Commits[0] != "single_commit" {
		t.Errorf("commits = %v", al.Commits)
	}
	if len(al.StopWords) != 1 || al.StopWords[0] != "single_word" {
		t.Errorf("stop_words = %v", al.StopWords)
	}
}

func TestParseExtendEmptyDisabledRules(t *testing.T) {
	data := `extend:
  use_default: true
  disabled_rules:
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Extend == nil {
		t.Fatal("extend is nil")
	}
	if len(cfg.Extend.DisabledRules) != 0 {
		t.Errorf("expected empty disabled_rules, got %v", cfg.Extend.DisabledRules)
	}
}

func TestParseRuleBreaksOnNewListItem(t *testing.T) {
	// Tests that parseRule breaks when encountering a new "- " item at same indent
	data := `rules:
  - id: r1
    regex: ".*"
    description: first
  - id: r2
    regex: ".*"
    description: second
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Description != "first" || cfg.Rules[1].Description != "second" {
		t.Errorf("rules: %+v, %+v", cfg.Rules[0], cfg.Rules[1])
	}
}

func TestParseAllowlistBreaksOnNewItem(t *testing.T) {
	data := `allowlists:
  - description: a1
    condition: AND
  - description: a2
    condition: OR
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Allowlists) != 2 {
		t.Fatalf("expected 2 allowlists, got %d", len(cfg.Allowlists))
	}
}

func TestParseAllowlistWithCommentsAndEmptyLines(t *testing.T) {
	data := `allowlists:
  - description: a1
    # comment inside allowlist

    condition: AND
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Allowlists) != 1 {
		t.Fatalf("expected 1, got %d", len(cfg.Allowlists))
	}
	if cfg.Allowlists[0].Condition != "AND" {
		t.Errorf("condition = %q", cfg.Allowlists[0].Condition)
	}
}

func TestParseAllowlistBreaksOnBareDashItem(t *testing.T) {
	// This tests the branch: strings.HasPrefix(trimmed, "- ") && !strings.Contains(trimmed, ":")
	// A bare "- value" line (no colon) inside an allowlist should break
	data := `allowlists:
  - description: a1
    paths:
      - p1
  - description: a2
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Allowlists) != 2 {
		t.Fatalf("expected 2, got %d", len(cfg.Allowlists))
	}
}

func TestParseRuleBreaksOnDashWithoutColon(t *testing.T) {
	// In parseRule, a line starting with "- " at rule indent level should trigger break
	data := `rules:
  - id: r1
    regex: ".*"
    description: first
  - id: r2
    regex: ".*"
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.Rules))
	}
}

func TestParseRuleCommentsAndEmptyInBody(t *testing.T) {
	data := `rules:
  - id: r1
    regex: ".*"
    # comment in rule body

    description: desc1
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Description != "desc1" {
		t.Errorf("description = %q", cfg.Rules[0].Description)
	}
}

func TestParseRuleListCommentsAndEmpty(t *testing.T) {
	data := `rules:
  # comment before first rule

  - id: r1
    regex: ".*"
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
}

func TestParseAllowlistListCommentsAndEmpty(t *testing.T) {
	data := `allowlists:
  # comment

  - description: a1
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Allowlists) != 1 {
		t.Fatalf("expected 1, got %d", len(cfg.Allowlists))
	}
}

func TestParseExtendEmptyWithComments(t *testing.T) {
	data := `extend:
  # just a comment

  use_default: false
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Extend == nil {
		t.Fatal("extend is nil")
	}
}

func TestParseStringListNonListItemWarning(t *testing.T) {
	// Test that parseStringList emits a warning for non-list items.
	data := `exclude_commits:
  notalist
  - valid_item
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for non-list item in parseStringList")
	}
	foundWarning := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "expected list item starting with '- '") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("expected list item warning, got warnings: %v", cfg.Warnings)
	}
	// The valid item should still be parsed.
	if len(cfg.ExcludeCommits) != 1 || cfg.ExcludeCommits[0] != "valid_item" {
		t.Errorf("expected [valid_item], got %v", cfg.ExcludeCommits)
	}
}

func TestParseStringList2NonListItemWarning(t *testing.T) {
	// Test that parseStringList2 emits a warning for non-list items.
	// parseStringList2 is called when a block-style list is used for keywords/tags
	// in rules.
	data := `rules:
  - id: r1
    regex: ".*"
    keywords:
      notalist
      - valid_kw
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for non-list item in parseStringList2")
	}
	foundWarning := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "expected list item starting with '- '") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("expected list item warning, got warnings: %v", cfg.Warnings)
	}
	if len(cfg.Rules[0].Keywords) != 1 || cfg.Rules[0].Keywords[0] != "valid_kw" {
		t.Errorf("expected [valid_kw], got %v", cfg.Rules[0].Keywords)
	}
}

func TestParseRuleBodyDashLineBreaks(t *testing.T) {
	// A stray "- item" inside a rule body is malformed YAML.
	// The parser should report an error since it gets treated as a new
	// rule without required id/regex fields.
	data := `rules:
  - id: r1
    regex: ".*"
    description: first
    - stray_item
  - id: r2
    regex: ".*"
`
	_, err := parse([]byte(data))
	if err == nil {
		t.Error("expected error for stray list item in rule body")
	}
}

func TestParseAllowlistBodyBareDashBreaks(t *testing.T) {
	// Test that a bare "- value" (no colon) at deeper indent inside allowlist body triggers break
	// This exercises: if strings.HasPrefix(trimmed, "- ") && !strings.Contains(trimmed, ":") { break }
	data := `allowlists:
  - description: a1
    condition: AND
    - bareitem
  - description: a2
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Allowlists) < 1 {
		t.Fatal("expected at least 1 allowlist")
	}
	if cfg.Allowlists[0].Condition != "AND" {
		t.Errorf("condition = %q", cfg.Allowlists[0].Condition)
	}
}

func TestParseExtendBreaksAtTopLevel(t *testing.T) {
	data := `extend:
  use_default: true
exclude_commits:
  - c1
`
	cfg, err := parse([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Extend == nil || !cfg.Extend.UseDefault {
		t.Error("extend not parsed correctly")
	}
	if len(cfg.ExcludeCommits) != 1 {
		t.Errorf("exclude_commits = %v", cfg.ExcludeCommits)
	}
}
