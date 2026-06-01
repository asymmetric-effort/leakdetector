package scanner

import (
	"regexp"
	"strings"
	"testing"

	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

func TestIsExcludedPath(t *testing.T) {
	tests := []struct {
		name         string
		relPath      string
		excludePaths []string
		want         bool
	}{
		{
			name:         "exact match",
			relPath:      "vendor/lib.go",
			excludePaths: []string{"vendor/lib.go"},
			want:         true,
		},
		{
			name:         "prefix match on directory",
			relPath:      "vendor/github.com/pkg/errors/errors.go",
			excludePaths: []string{"vendor/"},
			want:         true,
		},
		{
			name:         "glob star match",
			relPath:      "config.yaml",
			excludePaths: []string{"*.yaml"},
			want:         true,
		},
		{
			name:         "glob match on basename",
			relPath:      "deep/nested/config.yaml",
			excludePaths: []string{"*.yaml"},
			want:         true,
		},
		{
			name:         "non-matching path",
			relPath:      "src/main.go",
			excludePaths: []string{"vendor/", "*.yaml", "test/"},
			want:         false,
		},
		{
			name:         "empty exclude list",
			relPath:      "anything.go",
			excludePaths: nil,
			want:         false,
		},
		{
			name:         "exact directory prefix",
			relPath:      "testdata/secrets.txt",
			excludePaths: []string{"testdata"},
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExcludedPath(tt.relPath, tt.excludePaths)
			if got != tt.want {
				t.Errorf("isExcludedPath(%q, %v) = %v, want %v",
					tt.relPath, tt.excludePaths, got, tt.want)
			}
		})
	}
}

func TestIsExcludedCommit(t *testing.T) {
	tests := []struct {
		name           string
		commit         string
		excludeCommits []string
		want           bool
	}{
		{
			name:           "full SHA match",
			commit:         "abc123def456789012345678901234567890abcd",
			excludeCommits: []string{"abc123def456789012345678901234567890abcd"},
			want:           true,
		},
		{
			name:           "short SHA match - exclude is prefix of commit",
			commit:         "abc123def456789012345678901234567890abcd",
			excludeCommits: []string{"abc123d"},
			want:           true,
		},
		{
			name:           "short SHA match - commit is prefix of exclude",
			commit:         "abc123d",
			excludeCommits: []string{"abc123def456789012345678901234567890abcd"},
			want:           true,
		},
		{
			name:           "non-matching commit",
			commit:         "abc123def456789012345678901234567890abcd",
			excludeCommits: []string{"ffffffffffffffffffffffffffffffffffffffff"},
			want:           false,
		},
		{
			name:           "empty exclude list",
			commit:         "abc123def456789012345678901234567890abcd",
			excludeCommits: nil,
			want:           false,
		},
		{
			name:           "multiple excludes, one matches",
			commit:         "abc123def456789012345678901234567890abcd",
			excludeCommits: []string{"1111111", "abc123d", "2222222"},
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExcludedCommit(tt.commit, tt.excludeCommits)
			if got != tt.want {
				t.Errorf("isExcludedCommit(%q, %v) = %v, want %v",
					tt.commit, tt.excludeCommits, got, tt.want)
			}
		})
	}
}

func TestHasInlineAllow(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "line with leakdetector:allow",
			line: `password = "secret123" // leakdetector:allow`,
			want: true,
		},
		{
			name: "line without allow marker",
			line: `password = "secret123"`,
			want: false,
		},
		{
			name: "hash comment style",
			line: `API_KEY=abc123 # leakdetector:allow`,
			want: true,
		},
		{
			name: "C-style block comment",
			line: `const key = "abc" /* leakdetector:allow */`,
			want: true,
		},
		{
			name: "marker embedded in word",
			line: `noleakdetector:allowlist`,
			want: true, // contains the substring
		},
		{
			name: "empty line",
			line: "",
			want: false,
		},
		{
			name: "marker at start of line",
			line: "leakdetector:allow this line",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasInlineAllow(tt.line)
			if got != tt.want {
				t.Errorf("hasInlineAllow(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

func TestIsGlobalAllowed(t *testing.T) {
	tests := []struct {
		name       string
		allowlists []rules.CompiledAllowlist
		secret     string
		match      string
		line       string
		filePath   string
		commit     string
		want       bool
	}{
		{
			name: "matching allowlist by regex on secret",
			allowlists: []rules.CompiledAllowlist{
				{
					Regexes: []*regexp.Regexp{regexp.MustCompile(`^EXAMPLE.*`)},
				},
			},
			secret:   "EXAMPLE_KEY_12345",
			match:    "key=EXAMPLE_KEY_12345",
			line:     `key=EXAMPLE_KEY_12345`,
			filePath: "test.go",
			commit:   "",
			want:     true,
		},
		{
			name: "non-matching allowlist",
			allowlists: []rules.CompiledAllowlist{
				{
					Regexes: []*regexp.Regexp{regexp.MustCompile(`^SAFE_.*`)},
				},
			},
			secret:   "REAL_SECRET_KEY",
			match:    "key=REAL_SECRET_KEY",
			line:     `key=REAL_SECRET_KEY`,
			filePath: "test.go",
			commit:   "",
			want:     false,
		},
		{
			name:       "empty allowlists",
			allowlists: nil,
			secret:     "anything",
			match:      "anything",
			line:       "anything",
			filePath:   "test.go",
			commit:     "",
			want:       false,
		},
		{
			name: "allowlist matching by path",
			allowlists: []rules.CompiledAllowlist{
				{
					Paths: []*regexp.Regexp{regexp.MustCompile(`.*_test\.go$`)},
				},
			},
			secret:   "some_secret",
			match:    "some_secret",
			line:     "some_secret",
			filePath: "scanner_test.go",
			commit:   "",
			want:     true,
		},
		{
			name: "allowlist matching by stop words",
			allowlists: []rules.CompiledAllowlist{
				{
					StopWords: []string{"example", "placeholder"},
				},
			},
			secret:   "example_api_key_value",
			match:    "example_api_key_value",
			line:     "key=example_api_key_value",
			filePath: "config.go",
			commit:   "",
			want:     true,
		},
		{
			name: "allowlist matching by commit",
			allowlists: []rules.CompiledAllowlist{
				{
					Commits: map[string]struct{}{
						"abc1234": {},
					},
				},
			},
			secret:   "my_secret",
			match:    "my_secret",
			line:     "my_secret",
			filePath: "file.go",
			commit:   "abc1234",
			want:     true,
		},
		{
			name: "multiple allowlists second matches",
			allowlists: []rules.CompiledAllowlist{
				{
					Regexes: []*regexp.Regexp{regexp.MustCompile(`^NOMATCH$`)},
				},
				{
					StopWords: []string{"test"},
				},
			},
			secret:   "test_value",
			match:    "test_value",
			line:     "test_value",
			filePath: "file.go",
			commit:   "",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGlobalAllowed(tt.allowlists, tt.secret, tt.match, tt.line, tt.filePath, tt.commit)
			if got != tt.want {
				t.Errorf("isGlobalAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateExcludePaths(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantErr  bool
	}{
		{"valid globs", []string{"*.go", "vendor/", "test_*"}, false},
		{"empty list", []string{}, false},
		{"nil list", nil, false},
		{"plain prefix", []string{"src/"}, false},
		{"unclosed bracket", []string{"[abc"}, true},
		{"valid bracket", []string{"[abc]"}, false},
		{"mixed valid and invalid", []string{"*.go", "[bad"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExcludePaths(tc.patterns)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil {
				// Error should be human-readable with the bad pattern.
				if !strings.Contains(err.Error(), tc.patterns[len(tc.patterns)-1]) {
					t.Errorf("error should contain the bad pattern, got: %v", err)
				}
			}
		})
	}
}

func TestValidateExcludeCommits(t *testing.T) {
	tests := []struct {
		name    string
		commits []string
		wantErr bool
	}{
		{"valid full hash", []string{"abc1234def5678901234567890123456789012ab"}, false},
		{"valid short hash 7 chars", []string{"abc1234"}, false},
		{"too short 6 chars", []string{"abc123"}, true},
		{"too short 1 char", []string{"a"}, true},
		{"empty list", []string{}, false},
		{"nil list", nil, false},
		{"non-hex chars", []string{"abc123g"}, true},
		{"uppercase hex", []string{"ABC1234"}, false},
		{"mixed valid and invalid", []string{"abc1234", "xy"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExcludeCommits(tc.commits)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil {
				if !strings.Contains(err.Error(), "exclude_commits") {
					t.Errorf("error should mention exclude_commits, got: %v", err)
				}
			}
		})
	}
}
