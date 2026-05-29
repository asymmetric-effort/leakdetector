package rules

import (
	"errors"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
)

// ---------------------------------------------------------------------------
// Compile tests
// ---------------------------------------------------------------------------

func TestCompile_EmptyInputs(t *testing.T) {
	rs, err := Compile(nil, nil)
	if err != nil {
		t.Fatalf("Compile(nil, nil) error: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Error("expected built-in rules even with nil user rules")
	}
	if len(rs.Allowlists) != 0 {
		t.Error("expected no global allowlists with nil input")
	}
}

func TestCompile_EmptySlices(t *testing.T) {
	rs, err := Compile([]config.RuleConfig{}, []config.Allowlist{})
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Error("expected built-in rules with empty user rules slice")
	}
	if len(rs.Allowlists) != 0 {
		t.Error("expected no global allowlists with empty slice")
	}
}

func TestCompile_UserRuleOverridesBuiltin(t *testing.T) {
	override := config.RuleConfig{
		ID:          "aws-access-key-id", // same as builtin
		Description: "Custom AWS Key Rule",
		Regex:       `CUSTOM_AWS_[A-Z]{10}`,
		Keywords:    []string{"CUSTOM_AWS_"},
	}

	rs, err := Compile([]config.RuleConfig{override}, nil)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	// Find the rule
	var found *CompiledRule
	for i := range rs.Rules {
		if rs.Rules[i].ID == "aws-access-key-id" {
			found = &rs.Rules[i]
			break
		}
	}
	if found == nil {
		t.Fatal("aws-access-key-id rule not found")
	}
	if found.Description != "Custom AWS Key Rule" {
		t.Errorf("expected overridden description, got %q", found.Description)
	}

	// Verify original builtin regex no longer matches
	_, _, matched := found.Match("AKIAIOSFODNN7EXAMPLE", "f.go", "")
	if matched {
		t.Error("overridden rule should NOT match old pattern")
	}

	// Verify custom regex matches
	_, _, matched = found.Match("CUSTOM_AWS_ABCDEFGHIJ", "f.go", "")
	if matched != true {
		t.Error("overridden rule should match new pattern")
	}
}

func TestCompile_UserRuleAddsNew(t *testing.T) {
	custom := config.RuleConfig{
		ID:    "custom-new-rule",
		Regex: `CUSTOM_SECRET_[0-9]+`,
	}

	rs, err := Compile([]config.RuleConfig{custom}, nil)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	var found bool
	for _, r := range rs.Rules {
		if r.ID == "custom-new-rule" {
			found = true
			break
		}
	}
	if !found {
		t.Error("custom-new-rule not found in compiled rules")
	}
}

func TestCompile_InvalidRegex(t *testing.T) {
	bad := config.RuleConfig{
		ID:    "bad-regex",
		Regex: `[invalid`,
	}

	_, err := Compile([]config.RuleConfig{bad}, nil)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}

	var rce *RuleCompileError
	if !errors.As(err, &rce) {
		t.Fatalf("expected RuleCompileError, got %T", err)
	}
	if rce.Field != "regex" {
		t.Errorf("expected field 'regex', got %q", rce.Field)
	}
	if rce.RuleID != "bad-regex" {
		t.Errorf("expected RuleID 'bad-regex', got %q", rce.RuleID)
	}
}

func TestCompile_InvalidPathRegex(t *testing.T) {
	bad := config.RuleConfig{
		ID:    "bad-path",
		Regex: `ok`,
		Path:  `(unclosed`,
	}

	_, err := Compile([]config.RuleConfig{bad}, nil)
	if err == nil {
		t.Fatal("expected error for invalid path regex")
	}

	var rce *RuleCompileError
	if !errors.As(err, &rce) {
		t.Fatalf("expected RuleCompileError, got %T", err)
	}
	if rce.Field != "path" {
		t.Errorf("expected field 'path', got %q", rce.Field)
	}
}

func TestCompile_InvalidAllowlistPathRegex(t *testing.T) {
	rule := config.RuleConfig{
		ID:    "with-bad-al",
		Regex: `secret`,
		Allowlists: []config.Allowlist{
			{Paths: []string{`[broken`}},
		},
	}

	_, err := Compile([]config.RuleConfig{rule}, nil)
	if err == nil {
		t.Fatal("expected error for invalid allowlist path regex")
	}

	var ace *AllowlistCompileError
	if !errors.As(err, &ace) {
		t.Fatalf("expected AllowlistCompileError, got %T", err)
	}
	if ace.Field != "path" {
		t.Errorf("expected field 'path', got %q", ace.Field)
	}
}

func TestCompile_InvalidAllowlistRegex(t *testing.T) {
	rule := config.RuleConfig{
		ID:    "with-bad-al-regex",
		Regex: `secret`,
		Allowlists: []config.Allowlist{
			{Regexes: []string{`(broken`}},
		},
	}

	_, err := Compile([]config.RuleConfig{rule}, nil)
	if err == nil {
		t.Fatal("expected error for invalid allowlist regex")
	}

	var ace *AllowlistCompileError
	if !errors.As(err, &ace) {
		t.Fatalf("expected AllowlistCompileError, got %T", err)
	}
	if ace.Field != "regex" {
		t.Errorf("expected field 'regex', got %q", ace.Field)
	}
}

func TestCompile_InvalidGlobalAllowlistPath(t *testing.T) {
	al := []config.Allowlist{
		{Paths: []string{`[bad`}},
	}

	_, err := Compile(nil, al)
	if err == nil {
		t.Fatal("expected error for invalid global allowlist path")
	}

	var ace *AllowlistCompileError
	if !errors.As(err, &ace) {
		t.Fatalf("expected AllowlistCompileError, got %T", err)
	}
}

func TestCompile_InvalidGlobalAllowlistRegex(t *testing.T) {
	al := []config.Allowlist{
		{Regexes: []string{`(bad`}},
	}

	_, err := Compile(nil, al)
	if err == nil {
		t.Fatal("expected error for invalid global allowlist regex")
	}
}

func TestCompile_GlobalAllowlists(t *testing.T) {
	al := []config.Allowlist{
		{
			Description: "test allowlist",
			Paths:       []string{`\.test$`},
			Commits:     []string{"abc1234"},
			StopWords:   []string{"example"},
			RegexTarget: "line",
			Condition:   "AND",
		},
	}

	rs, err := Compile(nil, al)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	if len(rs.Allowlists) != 1 {
		t.Fatalf("expected 1 global allowlist, got %d", len(rs.Allowlists))
	}
	cal := rs.Allowlists[0]
	if cal.Description != "test allowlist" {
		t.Error("description mismatch")
	}
	if cal.Condition != "AND" {
		t.Errorf("expected condition AND, got %q", cal.Condition)
	}
	if cal.RegexTarget != "line" {
		t.Errorf("expected regex target 'line', got %q", cal.RegexTarget)
	}
	if len(cal.Commits) != 1 {
		t.Error("expected 1 commit in allowlist")
	}
	if _, ok := cal.Commits["abc1234"]; !ok {
		t.Error("commit abc1234 not found in allowlist")
	}
}

// ---------------------------------------------------------------------------
// CompiledRule.Match tests
// ---------------------------------------------------------------------------

func TestMatch_BasicMatch(t *testing.T) {
	rs, err := Compile([]config.RuleConfig{
		{ID: "test", Regex: `SECRET_([A-Z]+)`, SecretGroup: 1},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := findRule(rs, "test")
	fullMatch, secret, ok := rule.Match("found SECRET_HELLO here", "file.go", "")
	if !ok {
		t.Fatal("expected match")
	}
	if fullMatch != "SECRET_HELLO" {
		t.Errorf("fullMatch = %q, want SECRET_HELLO", fullMatch)
	}
	if secret != "HELLO" {
		t.Errorf("secret = %q, want HELLO", secret)
	}
}

func TestMatch_NoMatch(t *testing.T) {
	rs, err := Compile([]config.RuleConfig{
		{ID: "test", Regex: `SECRET_[A-Z]+`},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := findRule(rs, "test")
	_, _, ok := rule.Match("nothing here", "file.go", "")
	if ok {
		t.Error("expected no match")
	}
}

func TestMatch_NilRegex(t *testing.T) {
	// Rule with no regex should never match
	rs, err := Compile([]config.RuleConfig{
		{ID: "empty-regex", Regex: ""},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := findRule(rs, "empty-regex")
	_, _, ok := rule.Match("anything", "file.go", "")
	if ok {
		t.Error("expected no match for nil regex")
	}
}

func TestMatch_SecretGroupZero(t *testing.T) {
	rs, err := Compile([]config.RuleConfig{
		{ID: "test", Regex: `(SECRET)_([A-Z]+)`, SecretGroup: 0},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := findRule(rs, "test")
	fullMatch, secret, ok := rule.Match("found SECRET_HELLO", "f.go", "")
	if !ok {
		t.Fatal("expected match")
	}
	// SecretGroup 0 means secret == fullMatch
	if secret != fullMatch {
		t.Errorf("with SecretGroup=0, secret (%q) should equal fullMatch (%q)", secret, fullMatch)
	}
}

func TestMatch_SecretGroupOutOfRange(t *testing.T) {
	rs, err := Compile([]config.RuleConfig{
		{ID: "test", Regex: `SECRET_([A-Z]+)`, SecretGroup: 5},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := findRule(rs, "test")
	fullMatch, secret, ok := rule.Match("SECRET_HELLO", "f.go", "")
	if !ok {
		t.Fatal("expected match")
	}
	// Out of range group: secret falls back to fullMatch
	if secret != fullMatch {
		t.Errorf("out-of-range SecretGroup: secret (%q) should equal fullMatch (%q)", secret, fullMatch)
	}
}

func TestMatch_KeywordFiltering(t *testing.T) {
	tests := []struct {
		name      string
		keywords  []string
		line      string
		wantMatch bool
	}{
		{
			name:      "keyword present (exact case)",
			keywords:  []string{"password"},
			line:      "password=SECRET_VALUE",
			wantMatch: true,
		},
		{
			name:      "keyword present (case insensitive)",
			keywords:  []string{"PASSWORD"},
			line:      "password=SECRET_VALUE",
			wantMatch: true,
		},
		{
			name:      "keyword absent",
			keywords:  []string{"token"},
			line:      "password=SECRET_VALUE",
			wantMatch: false,
		},
		{
			name:      "multiple keywords one matches",
			keywords:  []string{"token", "password"},
			line:      "password=SECRET_VALUE",
			wantMatch: true,
		},
		{
			name:      "no keywords - always passes filter",
			keywords:  nil,
			line:      "SECRET_VALUE",
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := Compile([]config.RuleConfig{
				{ID: "test-kw", Regex: `SECRET_[A-Z]+`, Keywords: tc.keywords},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rule := findRule(rs, "test-kw")
			_, _, ok := rule.Match(tc.line, "f.go", "")
			if ok != tc.wantMatch {
				t.Errorf("Match() = %v, want %v", ok, tc.wantMatch)
			}
		})
	}
}

func TestMatch_PathFiltering(t *testing.T) {
	tests := []struct {
		name      string
		pathRegex string
		filePath  string
		wantMatch bool
	}{
		{
			name:      "path matches filter",
			pathRegex: `\.go$`,
			filePath:  "main.go",
			wantMatch: true,
		},
		{
			name:      "path does not match filter",
			pathRegex: `\.py$`,
			filePath:  "main.go",
			wantMatch: false,
		},
		{
			name:      "no path filter - always passes",
			pathRegex: "",
			filePath:  "anything.txt",
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := Compile([]config.RuleConfig{
				{ID: "test-path", Regex: `SECRET`, Path: tc.pathRegex},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rule := findRule(rs, "test-path")
			_, _, ok := rule.Match("SECRET", tc.filePath, "")
			if ok != tc.wantMatch {
				t.Errorf("Match() = %v, want %v", ok, tc.wantMatch)
			}
		})
	}
}

func TestMatch_EntropyFiltering(t *testing.T) {
	tests := []struct {
		name      string
		entropy   float64
		secret    string
		wantMatch bool
	}{
		{
			name:      "high entropy secret passes",
			entropy:   3.0,
			secret:    "a9X7kL2mQ5nR8pW4", // high entropy
			wantMatch: true,
		},
		{
			name:      "low entropy secret filtered out",
			entropy:   4.0,
			secret:    "aaaa", // very low entropy
			wantMatch: false,
		},
		{
			name:      "no entropy threshold - always passes",
			entropy:   0,
			secret:    "aaaa",
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use a regex that captures the secret
			rs, err := Compile([]config.RuleConfig{
				{ID: "test-ent", Regex: `KEY=([A-Za-z0-9]+)`, SecretGroup: 1, Entropy: tc.entropy},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			rule := findRule(rs, "test-ent")
			_, _, ok := rule.Match("KEY="+tc.secret, "f.go", "")
			if ok != tc.wantMatch {
				t.Errorf("Match() = %v, want %v", ok, tc.wantMatch)
			}
		})
	}
}

func TestMatch_AllowlistFiltering(t *testing.T) {
	rs, err := Compile([]config.RuleConfig{
		{
			ID:    "test-al",
			Regex: `SECRET_([A-Z]+)`,
			Allowlists: []config.Allowlist{
				{
					StopWords: []string{"example"},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := findRule(rs, "test-al")

	// Secret contains stop word -> filtered
	_, _, ok := rule.Match("SECRET_EXAMPLE", "f.go", "")
	if ok {
		t.Error("expected allowlist to filter out SECRET_EXAMPLE")
	}

	// Secret does not contain stop word -> not filtered
	_, _, ok = rule.Match("SECRET_REAL", "f.go", "")
	if !ok {
		t.Error("expected SECRET_REAL to match (not filtered)")
	}
}

// ---------------------------------------------------------------------------
// CompiledAllowlist.IsAllowed tests
// ---------------------------------------------------------------------------

func TestIsAllowed_EmptyAllowlist(t *testing.T) {
	al := CompiledAllowlist{}
	if al.IsAllowed("secret", "match", "line", "path", "commit") {
		t.Error("empty allowlist should not allow anything")
	}
}

func TestIsAllowed_ORCondition(t *testing.T) {
	// Default condition is OR: any single check passing means allowed
	rs, err := Compile(nil, []config.Allowlist{
		{
			Paths:     []string{`\.test$`},
			StopWords: []string{"dummy"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	tests := []struct {
		name     string
		secret   string
		filePath string
		want     bool
	}{
		{"path matches", "realSecret", "foo.test", true},
		{"stopword matches", "dummy_value", "foo.go", true},
		{"nothing matches", "realSecret", "foo.go", false},
		{"both match", "dummy", "foo.test", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := al.IsAllowed(tc.secret, tc.secret, tc.secret, tc.filePath, "")
			if got != tc.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsAllowed_ANDCondition(t *testing.T) {
	rs, err := Compile(nil, []config.Allowlist{
		{
			Paths:     []string{`\.test$`},
			StopWords: []string{"dummy"},
			Condition: "AND",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	tests := []struct {
		name     string
		secret   string
		filePath string
		want     bool
	}{
		{"both match", "dummy_value", "foo.test", true},
		{"only path matches", "realSecret", "foo.test", false},
		{"only stopword matches", "dummy_value", "foo.go", false},
		{"nothing matches", "realSecret", "foo.go", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := al.IsAllowed(tc.secret, tc.secret, tc.secret, tc.filePath, "")
			if got != tc.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsAllowed_CommitMatching(t *testing.T) {
	fullHash := "abc1234567890abcdef1234567890abcdef123456"
	shortHash := fullHash[:7]

	rs, err := Compile(nil, []config.Allowlist{
		{
			Description: "full hash allowlist",
			Commits:     []string{fullHash},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	tests := []struct {
		name   string
		commit string
		want   bool
	}{
		{"full hash matches", fullHash, true},
		{"different commit", "0000000000000000000000000000000000000000", false},
		{"empty commit", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := al.IsAllowed("s", "m", "l", "p", tc.commit)
			if got != tc.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tc.want)
			}
		})
	}

	// Test short hash matching
	rs2, err := Compile(nil, []config.Allowlist{
		{Commits: []string{shortHash}},
	})
	if err != nil {
		t.Fatal(err)
	}
	al2 := &rs2.Allowlists[0]

	// Providing a full hash should match against the short hash in the allowlist
	if !al2.IsAllowed("s", "m", "l", "p", fullHash) {
		t.Error("full commit hash should match short hash allowlist entry")
	}
	// Short hash directly
	if !al2.IsAllowed("s", "m", "l", "p", shortHash) {
		t.Error("short commit hash should match directly")
	}
	// Too short commit (< 7 chars) should not crash
	if al2.IsAllowed("s", "m", "l", "p", "abc") {
		t.Error("short string should not match")
	}
}

func TestIsAllowed_PathMatching(t *testing.T) {
	rs, err := Compile(nil, []config.Allowlist{
		{Paths: []string{`vendor/`, `\.test\.go$`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{"matches first path regex", "vendor/lib/file.go", true},
		{"matches second path regex", "pkg/foo.test.go", true},
		{"no path match", "src/main.go", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := al.IsAllowed("s", "m", "l", tc.filePath, "")
			if got != tc.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsAllowed_RegexTarget(t *testing.T) {
	tests := []struct {
		name        string
		regexTarget string
		secret      string
		match       string
		line        string
		wantAllowed bool
	}{
		{
			name:        "default target is secret",
			regexTarget: "",
			secret:      "ALLOW_ME",
			match:       "other",
			line:        "other line",
			wantAllowed: true,
		},
		{
			name:        "target match",
			regexTarget: "match",
			secret:      "other",
			match:       "ALLOW_ME",
			line:        "other line",
			wantAllowed: true,
		},
		{
			name:        "target line",
			regexTarget: "line",
			secret:      "other",
			match:       "other",
			line:        "ALLOW_ME in the line",
			wantAllowed: true,
		},
		{
			name:        "target secret does not contain pattern",
			regexTarget: "",
			secret:      "NOPE",
			match:       "ALLOW_ME",
			line:        "ALLOW_ME",
			wantAllowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := Compile(nil, []config.Allowlist{
				{
					Regexes:     []string{`ALLOW_ME`},
					RegexTarget: tc.regexTarget,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			al := &rs.Allowlists[0]
			got := al.IsAllowed(tc.secret, tc.match, tc.line, "", "")
			if got != tc.wantAllowed {
				t.Errorf("IsAllowed() = %v, want %v", got, tc.wantAllowed)
			}
		})
	}
}

func TestIsAllowed_StopWords(t *testing.T) {
	rs, err := Compile(nil, []config.Allowlist{
		{StopWords: []string{"example", "test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	tests := []struct {
		name   string
		secret string
		want   bool
	}{
		{"contains example", "my_example_key", true},
		{"contains test (case insensitive)", "MY_TEST_KEY", true},
		{"no stop word", "my_real_key", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := al.IsAllowed(tc.secret, "", "", "", "")
			if got != tc.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsAllowed_ANDConditionAllChecks(t *testing.T) {
	// Test AND with all four check types
	rs, err := Compile(nil, []config.Allowlist{
		{
			Commits:     []string{"abc1234"},
			Paths:       []string{`test/`},
			Regexes:     []string{`FAKE`},
			StopWords:   []string{"dummy"},
			Condition:   "AND",
			RegexTarget: "secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	// All pass
	if !al.IsAllowed("FAKE_dummy", "FAKE_dummy", "line", "test/file.go", "abc1234") {
		t.Error("all checks pass -> should be allowed under AND")
	}

	// Missing commit
	if al.IsAllowed("FAKE_dummy", "FAKE_dummy", "line", "test/file.go", "other") {
		t.Error("commit fails -> should not be allowed under AND")
	}

	// Missing path
	if al.IsAllowed("FAKE_dummy", "FAKE_dummy", "line", "src/file.go", "abc1234") {
		t.Error("path fails -> should not be allowed under AND")
	}

	// Missing regex
	if al.IsAllowed("NOPE_dummy", "NOPE_dummy", "line", "test/file.go", "abc1234") {
		t.Error("regex fails -> should not be allowed under AND")
	}

	// Missing stopword
	if al.IsAllowed("FAKE_real", "FAKE_real", "line", "test/file.go", "abc1234") {
		t.Error("stopword fails -> should not be allowed under AND")
	}
}

func TestIsAllowed_ANDConditionCaseInsensitive(t *testing.T) {
	// Verify "and" (lowercase) works the same as "AND"
	rs, err := Compile(nil, []config.Allowlist{
		{
			Paths:     []string{`\.test$`},
			StopWords: []string{"dummy"},
			Condition: "and",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	al := &rs.Allowlists[0]

	if !al.IsAllowed("dummy_val", "m", "l", "foo.test", "") {
		t.Error("lowercase 'and' condition should work like AND")
	}
	if al.IsAllowed("real_val", "m", "l", "foo.test", "") {
		t.Error("only path passes -> AND should reject")
	}
}

func TestCompile_RuleWithAllowlists(t *testing.T) {
	rule := config.RuleConfig{
		ID:    "al-test",
		Regex: `SECRET_([A-Z]+)`,
		Allowlists: []config.Allowlist{
			{
				Description: "ignore tests",
				Paths:       []string{`_test\.go$`},
			},
			{
				Description: "ignore examples",
				StopWords:   []string{"example"},
			},
		},
	}

	rs, err := Compile([]config.RuleConfig{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}

	r := findRule(rs, "al-test")
	if len(r.Allowlists) != 2 {
		t.Fatalf("expected 2 allowlists, got %d", len(r.Allowlists))
	}

	// Test path filtering
	_, _, ok := r.Match("SECRET_REAL", "foo_test.go", "")
	if ok {
		t.Error("test file should be allowlisted by path")
	}

	// Test stop word filtering
	_, _, ok = r.Match("SECRET_EXAMPLE", "main.go", "")
	if ok {
		t.Error("EXAMPLE should be allowlisted by stop word")
	}

	// Normal match should succeed
	_, _, ok = r.Match("SECRET_REAL", "main.go", "")
	if !ok {
		t.Error("SECRET_REAL in main.go should match")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findRule(rs *RuleSet, id string) *CompiledRule {
	for i := range rs.Rules {
		if rs.Rules[i].ID == id {
			return &rs.Rules[i]
		}
	}
	return nil
}
