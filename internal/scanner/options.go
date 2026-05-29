package scanner

import "io"

// Options controls scanner behavior.
type Options struct {
	Dir            string
	SkipHistory    bool
	Branch         string
	Stdin          bool
	ExcludeCommits []string
	ExcludePaths   []string
	MaxFileSizeMB  int
	Verbose        bool
	Stderr         io.Writer
}
