package rules

import (
	"regexp"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/config"
)

func TestCheckProximity_NoRequired(t *testing.T) {
	rule := CompiledRule{ID: "no-req"}
	if !rule.CheckProximity([]string{"line1", "line2"}, 0, 0) {
		t.Error("expected true when no required rules")
	}
}

func TestCheckProximity_RequiredFoundWithinLines(t *testing.T) {
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:          "aux",
				Regex:       regexp.MustCompile(`password`),
				WithinLines: 2,
			},
		},
	}

	lines := []string{
		"some code",
		"secret_key = ABC123",  // center (idx=1)
		"password = hunter2",
		"more code",
	}

	if !rule.CheckProximity(lines, 1, 0) {
		t.Error("expected true: required pattern is within 2 lines")
	}
}

func TestCheckProximity_RequiredOutsideLines(t *testing.T) {
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:          "aux",
				Regex:       regexp.MustCompile(`password`),
				WithinLines: 1,
			},
		},
	}

	lines := []string{
		"some code",
		"secret_key = ABC123",  // center (idx=1)
		"more code",
		"even more code",
		"password = hunter2",   // idx=4, distance=3 > WithinLines=1
	}

	if rule.CheckProximity(lines, 1, 0) {
		t.Error("expected false: required pattern is outside line proximity")
	}
}

func TestCheckProximity_ColumnProximity(t *testing.T) {
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:            "aux",
				Regex:         regexp.MustCompile(`token`),
				WithinColumns: 10,
			},
		},
	}

	// token at column 0, center at column 5 -> distance=5 <= 10
	lines := []string{"token = secret_value"}
	if !rule.CheckProximity(lines, 0, 5) {
		t.Error("expected true: required pattern within column proximity on same line")
	}

	// token at column 0, center at column 50 -> distance=50 > 10
	lines = []string{"token" + "                                              secret_value"}
	if rule.CheckProximity(lines, 0, 50) {
		t.Error("expected false: required pattern outside column proximity")
	}
}

func TestCheckProximity_ColumnProximityDifferentLine(t *testing.T) {
	// Column proximity only applies on the same line (i == centerIdx).
	// On a different line, if WithinLines is 0 (unlimited), only regex match matters.
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:            "aux",
				Regex:         regexp.MustCompile(`token`),
				WithinColumns: 5,
			},
		},
	}

	lines := []string{
		"no match here",
		"token is far away at column 0",  // different line, column check skipped
	}
	// centerIdx=0, the required is on line 1 (different line). WithinLines=0 means no line limit.
	// Column proximity is only checked when i == centerIdx, so this should match.
	if !rule.CheckProximity(lines, 0, 100) {
		t.Error("expected true: column proximity only checked on same line")
	}
}

func TestCheckProximity_MultipleRequired(t *testing.T) {
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:          "req1",
				Regex:       regexp.MustCompile(`password`),
				WithinLines: 3,
			},
			{
				ID:          "req2",
				Regex:       regexp.MustCompile(`username`),
				WithinLines: 3,
			},
		},
	}

	lines := []string{
		"username = admin",
		"secret_key = ABC123", // center
		"password = hunter2",
	}

	if !rule.CheckProximity(lines, 1, 0) {
		t.Error("expected true: both required patterns found within proximity")
	}

	// Only one required present
	lines2 := []string{
		"nothing here",
		"secret_key = ABC123", // center
		"password = hunter2",
	}

	if rule.CheckProximity(lines2, 1, 0) {
		t.Error("expected false: username not found within proximity")
	}
}

func TestCheckProximity_RequiredNotFound(t *testing.T) {
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:    "aux",
				Regex: regexp.MustCompile(`never_matches`),
			},
		},
	}

	lines := []string{"line1", "line2", "line3"}
	if rule.CheckProximity(lines, 1, 0) {
		t.Error("expected false: required pattern not found at all")
	}
}

func TestCheckProximity_RequiredAboveCenterLine(t *testing.T) {
	rule := CompiledRule{
		ID: "test",
		Required: []CompiledRequired{
			{
				ID:          "aux",
				Regex:       regexp.MustCompile(`header`),
				WithinLines: 2,
			},
		},
	}

	lines := []string{
		"header: value",       // idx=0, dist=2
		"other stuff",
		"secret_key = ABC123", // center idx=2
		"more stuff",
	}

	if !rule.CheckProximity(lines, 2, 0) {
		t.Error("expected true: required pattern above center within range")
	}
}

func TestCompileRule_WithRequired(t *testing.T) {
	rc := config.RuleConfig{
		ID:    "composite",
		Regex: `secret_key\s*=\s*(.+)`,
		Required: []config.RequiredRule{
			{
				ID:          "password-nearby",
				Regex:       `password`,
				WithinLines: 5,
			},
			{
				ID:            "token-col",
				Regex:         `token`,
				WithinColumns: 20,
			},
		},
	}

	rs, err := CompileWithOptions([]config.RuleConfig{rc}, nil, CompileOptions{UseDefault: false})
	if err != nil {
		t.Fatalf("CompileWithOptions error: %v", err)
	}

	rule := findRule(rs, "composite")
	if rule == nil {
		t.Fatal("composite rule not found")
	}
	if len(rule.Required) != 2 {
		t.Fatalf("expected 2 required rules, got %d", len(rule.Required))
	}
	if rule.Required[0].ID != "password-nearby" {
		t.Errorf("Required[0].ID = %q, want %q", rule.Required[0].ID, "password-nearby")
	}
	if rule.Required[0].WithinLines != 5 {
		t.Errorf("Required[0].WithinLines = %d, want 5", rule.Required[0].WithinLines)
	}
	if rule.Required[1].WithinColumns != 20 {
		t.Errorf("Required[1].WithinColumns = %d, want 20", rule.Required[1].WithinColumns)
	}
}

func TestCompileRule_WithRequiredInvalidRegex(t *testing.T) {
	rc := config.RuleConfig{
		ID:    "bad-req",
		Regex: `secret`,
		Required: []config.RequiredRule{
			{
				ID:    "bad",
				Regex: `[invalid`,
			},
		},
	}

	_, err := CompileWithOptions([]config.RuleConfig{rc}, nil, CompileOptions{UseDefault: false})
	if err == nil {
		t.Fatal("expected error for invalid required regex")
	}
}
