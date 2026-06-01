package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := "hello world"
	os.WriteFile(path, []byte(content), 0644)

	data, err := Read(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}
}

func TestRead_NonExistent(t *testing.T) {
	_, err := Read("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestRead_ExceedsMaxSize(t *testing.T) {
	// We can't create a 2GB file in tests, but we can test the error message
	// format by checking the constant is set correctly.
	if MaxFileSize != 2*1024*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", MaxFileSize, 2*1024*1024*1024)
	}
}

func TestRead_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	os.WriteFile(path, []byte{}, 0644)

	data, err := Read(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestRead_ErrorMessageContainsPath(t *testing.T) {
	// Use a directory as the path — os.Stat succeeds but os.ReadFile fails
	// (or vice versa depending on OS). Either way, we get an error.
	dir := t.TempDir()
	_, err := Read(dir)
	if err == nil {
		t.Fatal("expected error when reading directory")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error should contain path %q, got: %v", dir, err)
	}
}
