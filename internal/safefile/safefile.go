package safefile

import (
	"fmt"
	"os"
)

// MaxFileSize is the maximum size in bytes for configuration, baseline,
// template, and ignore files. Files exceeding this limit are rejected.
const MaxFileSize = 2 * 1024 * 1024 * 1024 // 2 GB

// Read reads a file after verifying its size does not exceed MaxFileSize.
func Read(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file %s exceeds maximum size (%d bytes > %d bytes)", path, info.Size(), MaxFileSize)
	}
	return os.ReadFile(path)
}
