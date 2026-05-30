package scanner

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

const maxArchiveFileSize = 100 * 1024 * 1024 // 100MB per extracted file

// isSafeArchiveEntry returns true if the archive entry name does not contain
// path traversal components. Rejects names with ".." segments or absolute paths.
func isSafeArchiveEntry(name string) bool {
	if filepath.IsAbs(name) {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// scanArchive scans the contents of an archive file for secrets.
// archivePath is the path notation using ! as separator (e.g. "file.tar.gz!inner.txt").
// depth tracks nesting level against maxDepth.
func scanArchive(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	if depth > maxDepth || maxDepth <= 0 {
		return nil
	}

	// Check for double extensions first (.tar.gz, .tar.bz2) before single extensions,
	// because filepath.Ext only returns the last extension.
	base := strings.ToLower(fullPath)
	if strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tar.gzip") {
		return scanTarGzip(fullPath, relPath, depth, maxDepth, rs, opts)
	}
	if strings.HasSuffix(base, ".tar.bz2") {
		return scanTarBzip2(fullPath, relPath, depth, maxDepth, rs, opts)
	}

	ext := strings.ToLower(filepath.Ext(fullPath))
	switch ext {
	case ".zip":
		return scanZip(fullPath, relPath, depth, maxDepth, rs, opts)
	case ".gz", ".gzip":
		return scanGzip(fullPath, relPath, depth, maxDepth, rs, opts)
	case ".tar":
		return scanTar(fullPath, relPath, depth, maxDepth, rs, opts)
	case ".tgz":
		return scanTarGzip(fullPath, relPath, depth, maxDepth, rs, opts)
	case ".bz2":
		return scanBzip2(fullPath, relPath, depth, maxDepth, rs, opts)
	}

	return nil
}

// isArchive returns true if the file extension indicates an archive format.
func isArchive(path string) bool {
	lower := strings.ToLower(path)
	// Check double extensions first.
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tar.gzip") ||
		strings.HasSuffix(lower, ".tar.bz2") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".gz", ".gzip", ".tar", ".tgz", ".bz2":
		return true
	}
	return false
}

func scanZip(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	r, err := zip.OpenReader(fullPath)
	if err != nil {
		if opts.Verbose {
			fmt.Fprintf(opts.Stderr, "warning: cannot open zip %s: %v\n", relPath, err)
		}
		return nil
	}
	defer r.Close()

	var findings []finding.Finding
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !isSafeArchiveEntry(f.Name) {
			continue
		}
		if f.UncompressedSize64 > maxArchiveFileSize {
			continue
		}

		innerPath := relPath + "!" + f.Name
		rc, err := f.Open()
		if err != nil {
			continue
		}
		findings = append(findings, scanArchiveReader(rc, innerPath, "", rs, opts)...)
		rc.Close()
	}
	return findings
}

func scanGzip(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer gz.Close()

	innerName := strings.TrimSuffix(filepath.Base(fullPath), filepath.Ext(fullPath))
	innerPath := relPath + "!" + innerName
	return scanArchiveReader(io.LimitReader(gz, maxArchiveFileSize), innerPath, "", rs, opts)
}

func scanTar(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	return scanTarReader(tar.NewReader(f), relPath, depth, maxDepth, rs, opts)
}

func scanTarGzip(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer gz.Close()

	return scanTarReader(tar.NewReader(gz), relPath, depth, maxDepth, rs, opts)
}

func scanBzip2(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	innerName := strings.TrimSuffix(filepath.Base(fullPath), filepath.Ext(fullPath))
	innerPath := relPath + "!" + innerName
	return scanArchiveReader(io.LimitReader(bzip2.NewReader(f), maxArchiveFileSize), innerPath, "", rs, opts)
}

func scanTarBzip2(fullPath, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	return scanTarReader(tar.NewReader(bzip2.NewReader(f)), relPath, depth, maxDepth, rs, opts)
}

func scanTarReader(tr *tar.Reader, relPath string, depth, maxDepth int, rs *rules.RuleSet, opts Options) []finding.Finding {
	var findings []finding.Finding
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !isSafeArchiveEntry(hdr.Name) {
			continue
		}
		if hdr.Size > maxArchiveFileSize {
			continue
		}

		innerPath := relPath + "!" + hdr.Name
		findings = append(findings, scanArchiveReader(io.LimitReader(tr, hdr.Size), innerPath, "", rs, opts)...)
	}
	return findings
}

func scanArchiveReader(r io.Reader, filePath, commit string, rs *rules.RuleSet, opts Options) []finding.Finding {
	var findings []finding.Finding
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lineFindings := matchLine(line, lineNum, filePath, commit, rs, opts)
		findings = append(findings, lineFindings...)
	}
	return findings
}
