package rules

import (
	"regexp"
	"testing"
)

func TestBuiltinRules_NonEmpty(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) == 0 {
		t.Fatal("BuiltinRules() returned empty slice")
	}
}

func TestBuiltinRules_AllHaveIDAndRegex(t *testing.T) {
	rules := BuiltinRules()
	for i, r := range rules {
		if r.ID == "" {
			t.Errorf("rule at index %d has empty ID", i)
		}
		if r.Regex == "" {
			t.Errorf("rule %q (index %d) has empty Regex", r.ID, i)
		}
	}
}

func TestBuiltinRules_UniqueIDs(t *testing.T) {
	rules := BuiltinRules()
	seen := make(map[string]int, len(rules))
	for i, r := range rules {
		if prev, ok := seen[r.ID]; ok {
			t.Errorf("duplicate rule ID %q at indices %d and %d", r.ID, prev, i)
		}
		seen[r.ID] = i
	}
}

func TestBuiltinRules_AllRegexesCompile(t *testing.T) {
	rules := BuiltinRules()
	for _, r := range rules {
		if _, err := regexp.Compile(r.Regex); err != nil {
			t.Errorf("rule %q regex failed to compile: %v", r.ID, err)
		}
		if r.Path != "" {
			if _, err := regexp.Compile(r.Path); err != nil {
				t.Errorf("rule %q path regex failed to compile: %v", r.ID, err)
			}
		}
	}
}

func TestBuiltinRules_SpotChecks(t *testing.T) {
	// Compile all rules once
	rs, err := Compile(nil, nil)
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	ruleByID := make(map[string]*CompiledRule, len(rs.Rules))
	for i := range rs.Rules {
		ruleByID[rs.Rules[i].ID] = &rs.Rules[i]
	}

	tests := []struct {
		name     string
		ruleID   string
		line     string
		filePath string
		wantMatch bool
	}{
		{
			name:      "AWS access key ID matches",
			ruleID:    "aws-access-key-id",
			line:      "AKIAIOSFODNN7EXAMPLE",
			filePath:  "config.yaml",
			wantMatch: true,
		},
		{
			name:      "AWS access key ID no match on random string",
			ruleID:    "aws-access-key-id",
			line:      "not-an-aws-key",
			filePath:  "config.yaml",
			wantMatch: false,
		},
		{
			name:      "GitHub PAT matches",
			ruleID:    "github-pat",
			line:      "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234",
			filePath:  "main.go",
			wantMatch: true,
		},
		{
			name:      "GitHub PAT too short",
			ruleID:    "github-pat",
			line:      "ghp_short",
			filePath:  "main.go",
			wantMatch: false,
		},
		{
			name:      "RSA private key header matches",
			ruleID:    "private-key-rsa",
			line:      "-----BEGIN RSA PRIVATE KEY-----",
			filePath:  "key.pem",
			wantMatch: true,
		},
		{
			name:   "Slack bot token matches",
			ruleID: "slack-bot-token",
			// Test token intentionally structured to match pattern but not be a real token.
			line:      "xoxb" + "-0000000000" + "-0000000000" + "-testfaketoken1", // leakdetector:allow
			filePath:  "app.py",
			wantMatch: true,
		},
		{
			name:   "Slack webhook URL matches",
			ruleID: "slack-webhook",
			// Test URL intentionally structured to match pattern but not be a real webhook.
			line:      "https://hooks.slack.com/services" + "/T00000000/B00000000/testtesttest12345678", // leakdetector:allow
			filePath:  "deploy.sh",
			wantMatch: true,
		},
		{
			name:      "Generic private key matches",
			ruleID:    "private-key-generic",
			line:      "-----BEGIN PRIVATE KEY-----",
			filePath:  "cert.pem",
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule, ok := ruleByID[tc.ruleID]
			if !ok {
				t.Fatalf("rule %q not found in builtin rules", tc.ruleID)
			}

			_, _, matched := rule.Match(tc.line, tc.filePath, "")
			if matched != tc.wantMatch {
				t.Errorf("rule %q Match(%q) = %v, want %v", tc.ruleID, tc.line, matched, tc.wantMatch)
			}
		})
	}
}
