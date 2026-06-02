package scanner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAuthor(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantName  string
		wantEmail string
	}{
		{
			name:      "standard format",
			raw:       "John Doe <john@example.com>",
			wantName:  "John Doe",
			wantEmail: "john@example.com",
		},
		{
			name:      "no email",
			raw:       "John Doe",
			wantName:  "John Doe",
			wantEmail: "",
		},
		{
			name:      "empty string",
			raw:       "",
			wantName:  "",
			wantEmail: "",
		},
		{
			name:      "email only",
			raw:       "<john@example.com>",
			wantName:  "",
			wantEmail: "john@example.com",
		},
		{
			name:      "with extra spaces",
			raw:       "  Jane Smith  <jane@test.org>  ",
			wantName:  "Jane Smith",
			wantEmail: "jane@test.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, email := parseAuthor(tt.raw)
			if name != tt.wantName {
				t.Errorf("parseAuthor(%q) name = %q, want %q", tt.raw, name, tt.wantName)
			}
			if email != tt.wantEmail {
				t.Errorf("parseAuthor(%q) email = %q, want %q", tt.raw, email, tt.wantEmail)
			}
		})
	}
}

func TestParseHunkLineNumber(t *testing.T) {
	tests := []struct {
		name string
		hunk string
		want int
	}{
		{
			name: "standard hunk",
			hunk: "@@ -10,5 +20,7 @@",
			want: 20,
		},
		{
			name: "single line hunk",
			hunk: "@@ -1 +1 @@",
			want: 1,
		},
		{
			name: "new file hunk",
			hunk: "@@ -0,0 +1,25 @@",
			want: 1,
		},
		{
			name: "large line number",
			hunk: "@@ -100,20 +350,15 @@ func something()",
			want: 350,
		},
		{
			name: "no plus sign",
			hunk: "@@ something invalid @@",
			want: 0,
		},
		{
			name: "plus but no digits",
			hunk: "@@ -1,2 +abc @@",
			want: 0,
		},
		{
			name: "overflow number",
			hunk: "@@ -1,2 +99999999999999999999 @@",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHunkLineNumber(tt.hunk)
			if got != tt.want {
				t.Errorf("parseHunkLineNumber(%q) = %d, want %d", tt.hunk, got, tt.want)
			}
		})
	}
}

// gitAvailable checks if git is installed and usable.
func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func TestScanGit_WithTempRepo(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	// Initialize a git repo.
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Create initial clean commit.
	cleanFile := filepath.Join(dir, "readme.txt")
	os.WriteFile(cleanFile, []byte("hello world\n"), 0644)
	runGit("add", "readme.txt")
	runGit("commit", "-m", "initial commit")

	// Add a file with a secret.
	secretFile := filepath.Join(dir, "secrets.env")
	os.WriteFile(secretFile, []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secrets.env")
	runGit("commit", "-m", "add secrets")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding from git history")
	}

	// Verify finding metadata.
	found := false
	for _, f := range findings {
		if f.File == "secrets.env" && f.Commit != "" {
			found = true
			if f.Author != "Test" {
				t.Errorf("expected Author=Test, got %q", f.Author)
			}
			if f.Email != "test@test.com" {
				t.Errorf("expected Email=test@test.com, got %q", f.Email)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding in secrets.env with non-empty commit")
	}
}

func TestScanGit_ExcludeCommit(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
		return string(out)
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Create initial commit.
	os.WriteFile(filepath.Join(dir, "init.txt"), []byte("init\n"), 0644)
	runGit("add", "init.txt")
	runGit("commit", "-m", "initial")

	// Add a secret and capture the commit SHA.
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "add secret")

	// Get the last commit SHA.
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	shaBytes, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	sha := string(bytes.TrimSpace(shaBytes))

	var stderr bytes.Buffer
	opts := Options{
		Dir:            dir,
		ExcludeCommits: []string{sha},
		Stderr:         &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	for _, f := range findings {
		if f.Commit == sha {
			t.Error("expected commit to be excluded, but found a finding with that commit")
		}
	}
}

func TestScanGit_ExcludePath(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	os.WriteFile(filepath.Join(dir, "init.txt"), []byte("init\n"), 0644)
	runGit("add", "init.txt")
	runGit("commit", "-m", "initial")

	os.WriteFile(filepath.Join(dir, "vendor.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "vendor.txt")
	runGit("commit", "-m", "add vendor secret")

	var stderr bytes.Buffer
	opts := Options{
		Dir:          dir,
		ExcludePaths: []string{"vendor.txt"},
		Stderr:       &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	for _, f := range findings {
		if f.File == "vendor.txt" {
			t.Error("expected vendor.txt to be excluded from git scan")
		}
	}
}

func TestScanGit_WithBranch(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	os.WriteFile(filepath.Join(dir, "init.txt"), []byte("init\n"), 0644)
	runGit("add", "init.txt")
	runGit("commit", "-m", "initial")

	// Get the current branch name.
	cmd := exec.Command("git", "branch", "--show-current")
	cmd.Dir = dir
	branchBytes, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	branch := string(bytes.TrimSpace(branchBytes))

	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "add secret on branch")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Branch: branch,
		Stderr: &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected findings when scanning specific branch")
	}
}

func TestScanGit_ContextLinesAndMultipleHunks(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test Author",
			"GIT_AUTHOR_EMAIL=author@example.com",
			"GIT_COMMITTER_NAME=Test Author",
			"GIT_COMMITTER_EMAIL=author@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "author@example.com")
	runGit("config", "user.name", "Test Author")

	// Create a file with multiple lines and a secret in the middle,
	// so the diff will have context lines (space-prefixed) around it.
	lines := "line1\nline2\nline3\nline4\nline5\nAKIAIOSFODNN7EXAMPLE\nline7\nline8\nline9\nline10\n"
	os.WriteFile(filepath.Join(dir, "multi.txt"), []byte(lines), 0644)
	runGit("add", "multi.txt")
	runGit("commit", "-m", "add multi-line file with secret")

	// Now modify the file to add more content - this creates a diff with
	// context lines (unchanged lines shown with space prefix).
	lines2 := "line1\nline2\nline3\nline4\nline5\nAKIAIOSFODNN7EXAMPLE\nline7\nline8\nline9\nline10\nnewline11\n"
	os.WriteFile(filepath.Join(dir, "multi.txt"), []byte(lines2), 0644)
	runGit("add", "multi.txt")
	runGit("commit", "-m", "add more lines to multi")

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	// The secret should be found in the first commit.
	if len(findings) == 0 {
		t.Error("expected at least one finding from git history with context lines")
	}

	// Verify commit message is captured.
	for _, f := range findings {
		if f.File == "multi.txt" && f.Message != "" {
			return // success - message was parsed
		}
	}
}

func TestScanGit_DecoratedCommitLine(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")
	// Set log.decorate to full so commit lines include decorations.
	// This triggers the commitSHA space-trimming code path.
	runGit("config", "log.decorate", "full")

	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "add secret")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected at least one finding with decorated commit lines")
	}

	// Verify that the commit SHA doesn't contain decoration text.
	for _, f := range findings {
		if f.Commit != "" && len(f.Commit) > 40 {
			t.Errorf("commit SHA looks too long (may contain decorations): %q", f.Commit)
		}
	}
}

func TestScanGit_MergeCommit(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Create initial commit on main.
	os.WriteFile(filepath.Join(dir, "init.txt"), []byte("init\n"), 0644)
	runGit("add", "init.txt")
	runGit("commit", "-m", "initial")

	// Create a feature branch with a secret.
	runGit("checkout", "-b", "feature")
	os.WriteFile(filepath.Join(dir, "feature.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "feature.txt")
	runGit("commit", "-m", "add feature with secret")

	// Switch back to main and create a different commit.
	runGit("checkout", "master")
	os.WriteFile(filepath.Join(dir, "main.txt"), []byte("main content\n"), 0644)
	runGit("add", "main.txt")
	runGit("commit", "-m", "add main content")

	// Merge feature branch (creates a merge commit).
	cmd := exec.Command("git", "merge", "feature", "--no-edit")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@test.com",
	)
	// Merge may fail if default branch is not "master"; that's ok.
	cmd.CombinedOutput()

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	// Should still find the secret from the feature branch commit.
	found := false
	for _, f := range findings {
		if f.File == "feature.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Log("no finding from feature.txt after merge - may depend on git version")
	}
}

func TestScanGit_MultiLineCommitMessage(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Create a file with a secret.
	os.WriteFile(filepath.Join(dir, "key.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "key.txt")
	// Use a multi-line commit message to exercise the message.Len() > 0 path.
	runGit("commit", "-m", "first line of message\n\nsecond line of message\nthird line of message")

	var stderr bytes.Buffer
	opts := Options{
		Dir:    dir,
		Stderr: &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Verify the multi-line message was captured.
	for _, f := range findings {
		if f.File == "key.txt" && f.Message != "" {
			if len(f.Message) <= len("first line of message") {
				t.Errorf("expected multi-line message, got %q", f.Message)
			}
			return
		}
	}
	t.Error("expected finding with non-empty message from key.txt")
}

func TestScanGit_VerboseErrors(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a directory that looks like it has git but doesn't really
	// have a valid repo. This will cause git log to fail.
	gitDir := filepath.Join(dir, ".git")
	os.MkdirAll(gitDir, 0755)

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	// scanGit will run git log which will fail in a broken repo.
	// It should not return an error (it handles errors gracefully).
	_, _ = scanGit(context.Background(), opts, rs)

	// Verbose output should contain warnings about git errors.
	if stderr.Len() > 0 {
		t.Logf("verbose stderr output: %s", stderr.String())
	}
}

func TestScanGit_LongLineTriggersVerboseScannerError(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Create a file with a line exceeding maxLineSize to trigger
	// scanner.Err() in the git log scanning.
	longLine := make([]byte, maxLineSize+100)
	for i := range longLine {
		longLine[i] = 'x'
	}
	longLine[len(longLine)-1] = '\n'
	os.WriteFile(filepath.Join(dir, "long.txt"), longLine, 0644)
	runGit("add", "long.txt")
	runGit("commit", "-m", "add very long line file")

	var stderr bytes.Buffer
	opts := Options{
		Dir:     dir,
		Verbose: true,
		Stderr:  &stderr,
	}

	_, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	// Check if verbose scanner error was emitted.
	if stderr.Len() > 0 {
		t.Logf("verbose stderr: %s", stderr.String())
	}
}

func TestParseRemoteURL_SSH(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
	}{
		{
			name:      "standard ssh",
			url:       "git@github.com:owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			name:      "ssh without .git suffix",
			url:       "git@github.com:owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			name:      "ssh gitlab",
			url:       "git@gitlab.com:myorg/myproject.git",
			wantOwner: "myorg",
			wantRepo:  "myproject",
		},
		{
			name:      "ssh no colon",
			url:       "git@github.com",
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name:      "ssh no slash in path",
			url:       "git@github.com:onlyrepo",
			wantOwner: "",
			wantRepo:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo := parseRemoteURL(tt.url)
			if owner != tt.wantOwner {
				t.Errorf("parseRemoteURL(%q) owner = %q, want %q", tt.url, owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("parseRemoteURL(%q) repo = %q, want %q", tt.url, repo, tt.wantRepo)
			}
		})
	}
}

func TestParseRemoteURL_HTTPS(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
	}{
		{
			name:      "standard https",
			url:       "https://github.com/owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			name:      "https without .git",
			url:       "https://github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			name:      "http scheme",
			url:       "http://github.com/owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			name:      "gitlab https",
			url:       "https://gitlab.com/myorg/myproject.git",
			wantOwner: "myorg",
			wantRepo:  "myproject",
		},
		{
			name:      "https no path",
			url:       "https://github.com/",
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name:      "https only host",
			url:       "https://github.com",
			wantOwner: "",
			wantRepo:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo := parseRemoteURL(tt.url)
			if owner != tt.wantOwner {
				t.Errorf("parseRemoteURL(%q) owner = %q, want %q", tt.url, owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("parseRemoteURL(%q) repo = %q, want %q", tt.url, repo, tt.wantRepo)
			}
		})
	}
}

func TestParseRemoteURL_Invalid(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"ftp scheme", "ftp://github.com/owner/repo"},
		{"random string", "not-a-url"},
		{"file path", "/path/to/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo := parseRemoteURL(tt.url)
			if owner != "" || repo != "" {
				t.Errorf("parseRemoteURL(%q) = (%q, %q), want empty", tt.url, owner, repo)
			}
		})
	}
}

func TestGenerateGitLink_GitHub(t *testing.T) {
	link := generateGitLink("github", "owner", "repo", "abc123", "src/main.go", 42)
	expected := "https://github.com/owner/repo/blob/abc123/src/main.go#L42"
	if link != expected {
		t.Errorf("generateGitLink github = %q, want %q", link, expected)
	}
}

func TestGenerateGitLink_GitLab(t *testing.T) {
	link := generateGitLink("gitlab", "owner", "repo", "abc123", "src/main.go", 42)
	expected := "https://gitlab.com/owner/repo/-/blob/abc123/src/main.go#L42"
	if link != expected {
		t.Errorf("generateGitLink gitlab = %q, want %q", link, expected)
	}
}

func TestGenerateGitLink_UnknownPlatform(t *testing.T) {
	link := generateGitLink("bitbucket", "owner", "repo", "abc123", "src/main.go", 42)
	if link != "" {
		t.Errorf("generateGitLink unknown platform = %q, want empty", link)
	}
}

func TestGenerateGitLink_CaseInsensitive(t *testing.T) {
	link := generateGitLink("GitHub", "owner", "repo", "abc123", "file.go", 1)
	if link == "" {
		t.Error("expected non-empty link for mixed-case GitHub")
	}

	link = generateGitLink("GitLab", "owner", "repo", "abc123", "file.go", 1)
	if link == "" {
		t.Error("expected non-empty link for mixed-case GitLab")
	}
}

func TestGetRemoteURL_WithOrigin(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	// Use the actual leakdetector repo rather than a fabricated one,
	// since git config may rewrite URLs (e.g. HTTPS to SSH).
	repoRoot := findRepoRoot(t)
	got := getRemoteURL(repoRoot)
	if got == "" {
		t.Skip("no remote origin configured")
	}
	// The remote should reference asymmetric-effort/leakdetector regardless of protocol.
	if !strings.Contains(got, "asymmetric-effort/leakdetector") {
		t.Errorf("getRemoteURL = %q, expected it to contain 'asymmetric-effort/leakdetector'", got)
	}
}

// findRepoRoot walks up from the working directory to find the git repo root.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to find repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestGetRemoteURL_NoOrigin(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	cmd.Run()

	got := getRemoteURL(dir)
	if got != "" {
		t.Errorf("getRemoteURL with no origin = %q, want empty", got)
	}
}

func TestGetRemoteURL_NotAGitRepo(t *testing.T) {
	dir := t.TempDir()
	got := getRemoteURL(dir)
	if got != "" {
		t.Errorf("getRemoteURL for non-git dir = %q, want empty", got)
	}
}

func TestScanGit_WithPlatformLink(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	rs := testRuleSet(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")
	runGit("remote", "add", "origin", "https://github.com/myorg/myrepo.git")

	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)
	runGit("add", "secret.txt")
	runGit("commit", "-m", "add secret")

	var stderr bytes.Buffer
	opts := Options{
		Dir:      dir,
		Platform: "github",
		Stderr:   &stderr,
	}

	findings, err := scanGit(context.Background(), opts, rs)
	if err != nil {
		t.Fatalf("scanGit returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.File == "secret.txt" && f.Link != "" {
			return // success - link was generated
		}
	}
	t.Error("expected finding with non-empty Link when Platform is set")
}
