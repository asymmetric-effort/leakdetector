package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// initTempRepo creates a temporary git repository with an initial commit
// and returns the directory path. It configures user.name and user.email
// so that git commands work in CI-like environments.
func initTempRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	commands := [][]string{
		{"git", "init"},
		{"git", "config", "user.name", "Test User"},
		{"git", "config", "user.email", "test@example.com"},
	}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("command %v failed: %v\n%s", args, err, out)
		}
	}

	// Create an initial commit so HEAD exists.
	dummy := filepath.Join(dir, "README")
	if err := os.WriteFile(dummy, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"git", "add", "."},
		{"git", "commit", "-m", "initial"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("command %v failed: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestIsRepo(t *testing.T) {
	tests := []struct {
		name string
		setup func(t *testing.T) string
		want bool
	}{
		{
			name: "directory with .git is a repo",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			want: true,
		},
		{
			name: "directory without .git is not a repo",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
			want: false,
		},
		{
			name: ".git is a file not a directory",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: /tmp/other"), 0644); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			want: false,
		},
		{
			name: "nonexistent directory",
			setup: func(t *testing.T) string {
				return "/nonexistent/path/that/does/not/exist"
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			got := IsRepo(dir)
			if got != tt.want {
				t.Errorf("IsRepo(%q) = %v, want %v", dir, got, tt.want)
			}
		})
	}
}

func TestCurrentBranch(t *testing.T) {
	dir := initTempRepo(t)

	branch, err := CurrentBranch(dir)
	if err != nil {
		t.Fatalf("CurrentBranch() error: %v", err)
	}
	// Depending on git version the default branch may be "master" or "main".
	if branch != "master" && branch != "main" {
		t.Errorf("CurrentBranch() = %q, want %q or %q", branch, "master", "main")
	}
}

func TestCurrentBranch_InvalidDir(t *testing.T) {
	_, err := CurrentBranch("/nonexistent/path")
	if err == nil {
		t.Error("CurrentBranch() on invalid dir should return error, got nil")
	}
}

func TestBranchExists(t *testing.T) {
	dir := initTempRepo(t)

	// Determine the default branch name.
	defaultBranch, err := CurrentBranch(dir)
	if err != nil {
		t.Fatalf("could not determine default branch: %v", err)
	}

	tests := []struct {
		name   string
		branch string
		want   bool
	}{
		{
			name:   "existing branch",
			branch: defaultBranch,
			want:   true,
		},
		{
			name:   "non-existing branch",
			branch: "branch-that-does-not-exist",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BranchExists(dir, tt.branch)
			if err != nil {
				t.Fatalf("BranchExists() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("BranchExists(%q, %q) = %v, want %v", dir, tt.branch, got, tt.want)
			}
		})
	}
}

func TestLogArgs(t *testing.T) {
	tests := []struct {
		name       string
		branch     string
		wantLast   string
		wantNoAll  bool
	}{
		{
			name:      "empty branch includes --all",
			branch:    "",
			wantLast:  "--all",
			wantNoAll: false,
		},
		{
			name:      "specific branch appended",
			branch:    "feature-x",
			wantLast:  "feature-x",
			wantNoAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := LogArgs(tt.branch)

			if len(args) == 0 {
				t.Fatal("LogArgs() returned empty slice")
			}

			last := args[len(args)-1]
			if last != tt.wantLast {
				t.Errorf("LogArgs(%q): last arg = %q, want %q", tt.branch, last, tt.wantLast)
			}

			// Verify the args start with "log" and include expected flags.
			if args[0] != "log" {
				t.Errorf("LogArgs(%q): first arg = %q, want %q", tt.branch, args[0], "log")
			}

			hasAll := false
			for _, a := range args {
				if a == "--all" {
					hasAll = true
				}
			}
			if tt.wantNoAll && hasAll {
				t.Errorf("LogArgs(%q): should not contain --all when branch is specified", tt.branch)
			}
			if !tt.wantNoAll && !hasAll {
				t.Errorf("LogArgs(%q): should contain --all when branch is empty", tt.branch)
			}

			// Verify -p flag is present.
			hasP := false
			for _, a := range args {
				if a == "-p" {
					hasP = true
				}
			}
			if !hasP {
				t.Errorf("LogArgs(%q): should contain -p flag", tt.branch)
			}
		})
	}
}

func TestLogArgsFull(t *testing.T) {
	tests := []struct {
		name       string
		branch     string
		wantLast   string
		wantNoAll  bool
	}{
		{
			name:      "empty branch includes --all",
			branch:    "",
			wantLast:  "--all",
			wantNoAll: false,
		},
		{
			name:      "specific branch appended",
			branch:    "develop",
			wantLast:  "develop",
			wantNoAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := LogArgsFull(tt.branch)

			if len(args) == 0 {
				t.Fatal("LogArgsFull() returned empty slice")
			}

			last := args[len(args)-1]
			if last != tt.wantLast {
				t.Errorf("LogArgsFull(%q): last arg = %q, want %q", tt.branch, last, tt.wantLast)
			}

			if args[0] != "log" {
				t.Errorf("LogArgsFull(%q): first arg = %q, want %q", tt.branch, args[0], "log")
			}

			hasAll := false
			for _, a := range args {
				if a == "--all" {
					hasAll = true
				}
			}
			if tt.wantNoAll && hasAll {
				t.Errorf("LogArgsFull(%q): should not contain --all when branch is specified", tt.branch)
			}
			if !tt.wantNoAll && !hasAll {
				t.Errorf("LogArgsFull(%q): should contain --all when branch is empty", tt.branch)
			}

			// Verify -p flag is present.
			hasP := false
			for _, a := range args {
				if a == "-p" {
					hasP = true
				}
			}
			if !hasP {
				t.Errorf("LogArgsFull(%q): should contain -p flag", tt.branch)
			}

			// Verify format includes COMMIT_START marker.
			hasFormat := false
			for _, a := range args {
				if len(a) > 9 && a[:9] == "---COMMIT" {
					hasFormat = true
				}
			}
			if !hasFormat {
				// Check the --format arg contains COMMIT_START.
				for _, a := range args {
					if len(a) > 8 && a[:8] == "--format=" {
						if !containsSubstring(a, "COMMIT_START") {
							t.Errorf("LogArgsFull(%q): --format should contain COMMIT_START", tt.branch)
						}
						hasFormat = true
					}
				}
			}
		})
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && findSubstring(s, sub)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
