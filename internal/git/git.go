package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IsRepo returns true if the given directory is a git repository.
func IsRepo(dir string) bool {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Stat(gitDir)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// CurrentBranch returns the name of the current branch.
func CurrentBranch(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// BranchExists returns true if the named branch exists.
func BranchExists(dir, branch string) (bool, error) {
	cmd := exec.Command("git", "rev-parse", "--verify", branch)
	cmd.Dir = dir
	err := cmd.Run()
	if err != nil {
		return false, nil
	}
	return true, nil
}

// LogArgs returns the git log arguments for scanning.
func LogArgs(branch string) []string {
	args := []string{"log", "-p", "--diff-filter=A", "--diff-filter=M",
		"--no-merges", "--format=%H%n%an%n%ae%n%aI%n%s%n---COMMIT_END---"}
	if branch != "" {
		args = append(args, branch)
	} else {
		args = append(args, "--all")
	}
	return args
}

// LogArgsFull returns git log arguments that capture all changes including
// additions and modifications in a parseable format.
func LogArgsFull(branch string) []string {
	args := []string{"log", "-p",
		"--no-merges",
		"--format=---COMMIT_START---%n%H%n%an%n%ae%n%aI%n%s"}
	if branch != "" {
		args = append(args, branch)
	} else {
		args = append(args, "--all")
	}
	return args
}
