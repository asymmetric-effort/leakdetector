package finding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		commit string
		file   string
		ruleID string
		line   int
		want   string
	}{
		{
			name:   "all fields populated",
			commit: "abc1234",
			file:   "main.go",
			ruleID: "generic-api-key",
			line:   42,
			want:   "abc1234:main.go:generic-api-key:42",
		},
		{
			name:   "empty commit defaults to 0000000",
			commit: "",
			file:   "config.yaml",
			ruleID: "aws-secret",
			line:   10,
			want:   "0000000:config.yaml:aws-secret:10",
		},
		{
			name:   "different file path",
			commit: "def5678",
			file:   "src/deep/nested/file.py",
			ruleID: "private-key",
			line:   1,
			want:   "def5678:src/deep/nested/file.py:private-key:1",
		},
		{
			name:   "different rule same file and line",
			commit: "abc1234",
			file:   "main.go",
			ruleID: "password-in-url",
			line:   42,
			want:   "abc1234:main.go:password-in-url:42",
		},
		{
			name:   "line zero",
			commit: "aaa",
			file:   "f.txt",
			ruleID: "r",
			line:   0,
			want:   "aaa:f.txt:r:0",
		},
		{
			name:   "all empty strings except line",
			commit: "",
			file:   "",
			ruleID: "",
			line:   5,
			want:   "0000000:::5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeFingerprint(tt.commit, tt.file, tt.ruleID, tt.line)
			if got != tt.want {
				t.Errorf("ComputeFingerprint(%q, %q, %q, %d) = %q, want %q",
					tt.commit, tt.file, tt.ruleID, tt.line, got, tt.want)
			}
		})
	}
}

func TestFinding_Redact(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		match      string
		wantSecret string
		wantMatch  string
	}{
		{
			name:       "empty secret unchanged",
			secret:     "",
			match:      "some match",
			wantSecret: "",
			wantMatch:  "some match",
		},
		{
			name:       "single char secret redacted fully",
			secret:     "x",
			match:      "x",
			wantSecret: "REDACTED",
			wantMatch:  "REDACTED",
		},
		{
			name:       "four char secret redacted fully",
			secret:     "abcd",
			match:      "abcd",
			wantSecret: "REDACTED",
			wantMatch:  "REDACTED",
		},
		{
			name:       "five char secret partially redacted",
			secret:     "abcde",
			match:      "abcde",
			wantSecret: "ab...de",
			wantMatch:  "ab...de",
		},
		{
			name:       "long secret partially redacted",
			secret:     "super-secret-api-key-12345",
			match:      "Authorization: super-secret-api-key-12345",
			wantSecret: "su...45",
			wantMatch:  "su...45",
		},
		{
			name:       "already redacted style input treated normally",
			secret:     "RE...ED",
			match:      "RE...ED",
			wantSecret: "RE...ED",
			wantMatch:  "RE...ED",
		},
		{
			name:       "two char secret redacted fully",
			secret:     "ab",
			match:      "ab",
			wantSecret: "REDACTED",
			wantMatch:  "REDACTED",
		},
		{
			name:       "three char secret redacted fully",
			secret:     "abc",
			match:      "abc",
			wantSecret: "REDACTED",
			wantMatch:  "REDACTED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Secret: tt.secret,
				Match:  tt.match,
			}
			f.Redact()
			if f.Secret != tt.wantSecret {
				t.Errorf("Secret = %q, want %q", f.Secret, tt.wantSecret)
			}
			if f.Match != tt.wantMatch {
				t.Errorf("Match = %q, want %q", f.Match, tt.wantMatch)
			}
		})
	}
}

func TestLoadBaseline(t *testing.T) {
	t.Run("valid JSON file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "baseline.json")

		findings := []Finding{
			{
				RuleID:      "generic-api-key",
				Description: "Generic API Key",
				StartLine:   10,
				EndLine:     10,
				File:        "main.go",
				Secret:      "secret123",
				Fingerprint: "abc:main.go:generic-api-key:10",
			},
			{
				RuleID:      "aws-secret",
				Description: "AWS Secret",
				StartLine:   20,
				EndLine:     20,
				File:        "config.yaml",
				Secret:      "AKIA1234",
				Fingerprint: "def:config.yaml:aws-secret:20",
				Tags:        []string{"aws", "cloud"},
				Entropy:     4.5,
			},
		}
		data, err := json.Marshal(findings)
		if err != nil {
			t.Fatalf("failed to marshal test data: %v", err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		got, err := LoadBaseline(path)
		if err != nil {
			t.Fatalf("LoadBaseline() error = %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("LoadBaseline() returned %d findings, want 2", len(got))
		}
		if got[0].RuleID != "generic-api-key" {
			t.Errorf("got[0].RuleID = %q, want %q", got[0].RuleID, "generic-api-key")
		}
		if got[1].Fingerprint != "def:config.yaml:aws-secret:20" {
			t.Errorf("got[1].Fingerprint = %q, want %q", got[1].Fingerprint, "def:config.yaml:aws-secret:20")
		}
		if len(got[1].Tags) != 2 {
			t.Errorf("got[1].Tags length = %d, want 2", len(got[1].Tags))
		}
	})

	t.Run("empty array JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		got, err := LoadBaseline(path)
		if err != nil {
			t.Fatalf("LoadBaseline() error = %v", err)
		}
		if len(got) != 0 {
			t.Errorf("LoadBaseline() returned %d findings, want 0", len(got))
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte("{not valid json!!!"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := LoadBaseline(path)
		if err == nil {
			t.Fatal("LoadBaseline() expected error for invalid JSON, got nil")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := LoadBaseline("/nonexistent/path/to/baseline.json")
		if err == nil {
			t.Fatal("LoadBaseline() expected error for non-existent file, got nil")
		}
	})
}

func TestRedactPercent(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		pct        int
		wantSecret string
	}{
		{
			name:       "pct 0 fully redacts",
			secret:     "super-secret-key",
			pct:        0,
			wantSecret: "REDACTED",
		},
		{
			name:       "pct negative fully redacts",
			secret:     "super-secret-key",
			pct:        -10,
			wantSecret: "REDACTED",
		},
		{
			name:       "pct 100 no redaction",
			secret:     "super-secret-key",
			pct:        100,
			wantSecret: "super-secret-key",
		},
		{
			name:       "pct 150 no redaction",
			secret:     "super-secret-key",
			pct:        150,
			wantSecret: "super-secret-key",
		},
		{
			name:       "pct 50 shows half",
			secret:     "abcdefghij",
			pct:        50,
			wantSecret: "abcde...",
		},
		{
			name:       "empty secret unchanged",
			secret:     "",
			pct:        0,
			wantSecret: "",
		},
		{
			name:       "pct 10 shows at least 1 char",
			secret:     "ab",
			pct:        10,
			wantSecret: "a...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Secret: tt.secret,
				Match:  tt.secret,
			}
			f.RedactPercent(tt.pct)
			if f.Secret != tt.wantSecret {
				t.Errorf("Secret = %q, want %q", f.Secret, tt.wantSecret)
			}
			if f.Match != tt.wantSecret {
				t.Errorf("Match = %q, want %q", f.Match, tt.wantSecret)
			}
		})
	}
}

func TestLoadIgnoreFile(t *testing.T) {
	t.Run("valid file with fingerprints", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".leakdetectorignore")
		content := "abc123:main.go:api-key:10\ndef456:config.yaml:aws-secret:20\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		fps := LoadIgnoreFile(path)
		if len(fps) != 2 {
			t.Fatalf("expected 2 fingerprints, got %d", len(fps))
		}
		if fps[0] != "abc123:main.go:api-key:10" {
			t.Errorf("fps[0] = %q, want %q", fps[0], "abc123:main.go:api-key:10")
		}
		if fps[1] != "def456:config.yaml:aws-secret:20" {
			t.Errorf("fps[1] = %q, want %q", fps[1], "def456:config.yaml:aws-secret:20")
		}
	})

	t.Run("non-existent file returns nil", func(t *testing.T) {
		fps := LoadIgnoreFile("/nonexistent/path/.leakdetectorignore")
		if fps != nil {
			t.Errorf("expected nil for non-existent file, got %v", fps)
		}
	})

	t.Run("file with comments and blank lines", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".leakdetectorignore")
		content := "# This is a comment\n\nabc123:main.go:api-key:10\n\n# Another comment\ndef456:config.yaml:aws-secret:20\n\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		fps := LoadIgnoreFile(path)
		if len(fps) != 2 {
			t.Fatalf("expected 2 fingerprints (comments/blanks excluded), got %d", len(fps))
		}
	})

	t.Run("empty file returns nil", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".leakdetectorignore")
		if err := os.WriteFile(path, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}

		fps := LoadIgnoreFile(path)
		if fps != nil {
			t.Errorf("expected nil for empty file, got %v", fps)
		}
	})
}

func TestFilterFingerprints(t *testing.T) {
	tests := []struct {
		name         string
		findings     []Finding
		fingerprints []string
		wantLen      int
		wantIDs      []string
	}{
		{
			name:         "matching fingerprints removed",
			findings:     []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			fingerprints: []string{"fp1"},
			wantLen:      1,
			wantIDs:      []string{"b"},
		},
		{
			name:         "non-matching kept",
			findings:     []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			fingerprints: []string{"fp3"},
			wantLen:      2,
			wantIDs:      []string{"a", "b"},
		},
		{
			name:         "empty fingerprints returns all",
			findings:     []Finding{{RuleID: "a", Fingerprint: "fp1"}},
			fingerprints: []string{},
			wantLen:      1,
			wantIDs:      []string{"a"},
		},
		{
			name:         "nil fingerprints returns all",
			findings:     []Finding{{RuleID: "a", Fingerprint: "fp1"}},
			fingerprints: nil,
			wantLen:      1,
			wantIDs:      []string{"a"},
		},
		{
			name:         "all filtered",
			findings:     []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			fingerprints: []string{"fp1", "fp2"},
			wantLen:      0,
			wantIDs:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterFingerprints(tt.findings, tt.fingerprints)
			if len(got) != tt.wantLen {
				t.Fatalf("FilterFingerprints() returned %d findings, want %d", len(got), tt.wantLen)
			}
			for i, wantID := range tt.wantIDs {
				if got[i].RuleID != wantID {
					t.Errorf("got[%d].RuleID = %q, want %q", i, got[i].RuleID, wantID)
				}
			}
		})
	}
}

func TestFilterBaseline(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		baseline []Finding
		wantLen  int
		wantIDs  []string // expected RuleIDs in result
	}{
		{
			name:     "empty baseline keeps all findings",
			findings: []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			baseline: []Finding{},
			wantLen:  2,
			wantIDs:  []string{"a", "b"},
		},
		{
			name:     "matching fingerprints filtered out",
			findings: []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			baseline: []Finding{{Fingerprint: "fp1"}},
			wantLen:  1,
			wantIDs:  []string{"b"},
		},
		{
			name:     "all fingerprints match baseline",
			findings: []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			baseline: []Finding{{Fingerprint: "fp1"}, {Fingerprint: "fp2"}},
			wantLen:  0,
			wantIDs:  nil,
		},
		{
			name:     "no fingerprints match baseline",
			findings: []Finding{{RuleID: "a", Fingerprint: "fp1"}, {RuleID: "b", Fingerprint: "fp2"}},
			baseline: []Finding{{Fingerprint: "fp3"}, {Fingerprint: "fp4"}},
			wantLen:  2,
			wantIDs:  []string{"a", "b"},
		},
		{
			name:     "empty findings returns nil",
			findings: []Finding{},
			baseline: []Finding{{Fingerprint: "fp1"}},
			wantLen:  0,
			wantIDs:  nil,
		},
		{
			name:     "nil findings returns nil",
			findings: nil,
			baseline: []Finding{{Fingerprint: "fp1"}},
			wantLen:  0,
			wantIDs:  nil,
		},
		{
			name:     "nil baseline keeps all findings",
			findings: []Finding{{RuleID: "a", Fingerprint: "fp1"}},
			baseline: nil,
			wantLen:  1,
			wantIDs:  []string{"a"},
		},
		{
			name: "partial match filters only matching",
			findings: []Finding{
				{RuleID: "a", Fingerprint: "fp1"},
				{RuleID: "b", Fingerprint: "fp2"},
				{RuleID: "c", Fingerprint: "fp3"},
			},
			baseline: []Finding{{Fingerprint: "fp2"}},
			wantLen:  2,
			wantIDs:  []string{"a", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterBaseline(tt.findings, tt.baseline)
			if len(got) != tt.wantLen {
				t.Fatalf("FilterBaseline() returned %d findings, want %d", len(got), tt.wantLen)
			}
			for i, wantID := range tt.wantIDs {
				if got[i].RuleID != wantID {
					t.Errorf("got[%d].RuleID = %q, want %q", i, got[i].RuleID, wantID)
				}
			}
		})
	}
}
