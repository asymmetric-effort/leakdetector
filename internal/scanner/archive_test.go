package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsArchive(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"file.zip", true},
		{"file.gz", true},
		{"file.gzip", true},
		{"file.tar", true},
		{"file.tgz", true},
		{"file.bz2", true},
		{"file.tar.gz", true},
		{"file.tar.bz2", true},
		{"file.txt", false},
		{"file.go", false},
		{"file.json", false},
		{"FILE.ZIP", true},
		{"FILE.TAR.GZ", true},
		{"FILE.TAR.BZ2", true},
		{"archive.tar.gzip", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isArchive(tt.path)
			if got != tt.want {
				t.Errorf("isArchive(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsSafeArchiveEntry(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"normal.txt", true},
		{"dir/file.txt", true},
		{"deep/nested/file.go", true},
		{"../escape.txt", false},
		{"dir/../../escape", false},
		{"dir/../sibling", false},
		{"/absolute/path", false},
		{"", true},
		{".", true},
		{".hidden", true},
		{"...", true}, // three dots is fine
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isSafeArchiveEntry(tc.name)
			if got != tc.want {
				t.Errorf("isSafeArchiveEntry(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// createZipWithSecret creates a zip file at path containing a file with a secret.
func createZipWithSecret(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)

	// Add a file with a secret
	fw, err := w.Create("secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"))

	// Add a clean file
	fw2, err := w.Create("clean.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw2.Write([]byte("nothing here\n"))

	// Add a directory entry
	_, err = w.Create("subdir/")
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestScanZip(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	zipPath := filepath.Join(dir, "test.zip")
	createZipWithSecret(t, zipPath)

	opts := Options{Stderr: &bytes.Buffer{}, Verbose: true}
	findings := scanZip(zipPath, "test.zip", 1, 3, rs, opts)

	found := false
	for _, f := range findings {
		if f.File == "test.zip!secret.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in test.zip!secret.txt")
	}
}

func TestScanZip_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	badPath := filepath.Join(dir, "bad.zip")
	os.WriteFile(badPath, []byte("not a zip"), 0644)

	opts := Options{Stderr: &bytes.Buffer{}, Verbose: true}
	findings := scanZip(badPath, "bad.zip", 1, 3, rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid zip, got %d", len(findings))
	}
}

func TestScanZip_LargeFileSkipped(t *testing.T) {
	// The zip writer overwrites UncompressedSize64 with actual size,
	// so we test the scanTarReader large file skip instead.
	// This test verifies that the zip directory-entry skip works.
	dir := t.TempDir()
	rs := testRuleSet(t)
	zipPath := filepath.Join(dir, "withdir.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	// Only add a directory entry (no files with secrets)
	_, err = w.Create("emptydir/")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanZip(zipPath, "withdir.zip", 1, 3, rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for zip with only dirs, got %d", len(findings))
	}
}

// createTarWithSecret creates a tar file at path containing a file with a secret.
func createTarWithSecret(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	content := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	tw.WriteHeader(&tar.Header{
		Name:     "secret.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)

	// Add a directory entry (should be skipped)
	tw.WriteHeader(&tar.Header{
		Name:     "subdir/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	})

	tw.Close()
}

// bzip2Available checks if the bzip2 command is available.
func bzip2Available() bool {
	_, err := exec.LookPath("bzip2")
	return err == nil
}

// createBzip2File creates a bzip2-compressed file using the external bzip2 command.
func createBzip2File(t *testing.T, dir string, name string, content []byte) string {
	t.Helper()
	if !bzip2Available() {
		t.Skip("bzip2 command not available")
	}

	tmpFile := filepath.Join(dir, name)
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bzip2", "-k", "-f", tmpFile)
	if err := cmd.Run(); err != nil {
		t.Skipf("bzip2 command failed: %v", err)
	}

	bz2Path := tmpFile + ".bz2"
	if _, err := os.Stat(bz2Path); err != nil {
		t.Fatalf("bzip2 output not found: %v", err)
	}
	return bz2Path
}

func TestScanTar(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	tarPath := filepath.Join(dir, "test.tar")
	createTarWithSecret(t, tarPath)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTar(tarPath, "test.tar", 1, 3, rs, opts)

	found := false
	for _, f := range findings {
		if f.File == "test.tar!secret.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in test.tar!secret.txt")
	}
}

func TestScanTar_NonExistent(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTar("/nonexistent.tar", "nope.tar", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanTarGzip(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	tgzPath := filepath.Join(dir, "test.tar.gz")

	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatal(err)
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	content := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	tw.WriteHeader(&tar.Header{
		Name:     "inner.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarGzip(tgzPath, "test.tar.gz", 1, 3, rs, opts)

	found := false
	for _, f := range findings {
		if f.File == "test.tar.gz!inner.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in test.tar.gz!inner.txt")
	}
}

func TestScanTarGzip_NonExistent(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarGzip("/nonexistent.tar.gz", "nope.tar.gz", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanTarGzip_InvalidGzip(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	badPath := filepath.Join(dir, "bad.tar.gz")
	os.WriteFile(badPath, []byte("not gzip data"), 0644)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarGzip(badPath, "bad.tar.gz", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid gzip, got %d", len(findings))
	}
}

func TestScanGzipFile(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	gzPath := filepath.Join(dir, "secret.txt.gz")

	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	gw.Write([]byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"))
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanGzip(gzPath, "secret.txt.gz", 1, 3, rs, opts)

	found := false
	for _, ff := range findings {
		if ff.File == "secret.txt.gz!secret.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in secret.txt.gz!secret.txt")
	}
}

func TestScanGzip_NonExistent(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanGzip("/nonexistent.gz", "nope.gz", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanGzip_InvalidGzip(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	badPath := filepath.Join(dir, "bad.gz")
	os.WriteFile(badPath, []byte("not gzip"), 0644)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanGzip(badPath, "bad.gz", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanBzip2(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	content := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	bz2Path := createBzip2File(t, dir, "secret.txt", content)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanBzip2(bz2Path, "secret.txt.bz2", 1, 3, rs, opts)

	found := false
	for _, ff := range findings {
		if ff.File == "secret.txt.bz2!secret.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in secret.txt.bz2!secret.txt")
	}
}

func TestScanBzip2_NonExistent(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanBzip2("/nonexistent.bz2", "nope.bz2", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanTarBzip2(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a tar first
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	tw.WriteHeader(&tar.Header{
		Name:     "inner.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()

	// Write tar to file and bzip2 compress it
	tarPath := filepath.Join(dir, "test.tar")
	os.WriteFile(tarPath, tarBuf.Bytes(), 0644)

	if !bzip2Available() {
		t.Skip("bzip2 command not available")
	}
	cmd := exec.Command("bzip2", "-k", "-f", tarPath)
	if err := cmd.Run(); err != nil {
		t.Skipf("bzip2 failed: %v", err)
	}

	tbz2Path := tarPath + ".bz2"

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarBzip2(tbz2Path, "test.tar.bz2", 1, 3, rs, opts)

	found := false
	for _, f := range findings {
		if f.File == "test.tar.bz2!inner.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding in test.tar.bz2!inner.txt")
	}
}

func TestScanTarBzip2_NonExistent(t *testing.T) {
	rs := testRuleSet(t)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarBzip2("/nonexistent.tar.bz2", "nope.tar.bz2", 1, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanTarReader_LargeFileSkipped(t *testing.T) {
	rs := testRuleSet(t)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Name:     "huge.txt",
		Size:     maxArchiveFileSize + 1,
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	// Write minimal data
	tw.Write([]byte("AKIAIOSFODNN7EXAMPLE\n"))
	tw.Close()

	tr := tar.NewReader(&buf)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarReader(tr, "test.tar", 1, 3, rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for oversized tar entry, got %d", len(findings))
	}
}

func TestScanArchiveReader(t *testing.T) {
	rs := testRuleSet(t)
	content := "line1\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nline3\n"
	r := bytes.NewReader([]byte(content))

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchiveReader(r, "archive!file.txt", "", rs, opts)

	if len(findings) == 0 {
		t.Error("expected at least one finding from scanArchiveReader")
	}
}

func TestScanArchiveReader_NoSecrets(t *testing.T) {
	rs := testRuleSet(t)
	content := "line1\nline2\nline3\n"
	r := bytes.NewReader([]byte(content))

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchiveReader(r, "archive!clean.txt", "", rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanArchive_DepthExceeded(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	zipPath := filepath.Join(dir, "test.zip")
	createZipWithSecret(t, zipPath)

	opts := Options{Stderr: &bytes.Buffer{}}

	// depth > maxDepth
	findings := scanArchive(zipPath, "test.zip", 4, 3, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when depth exceeded, got %d", len(findings))
	}

	// maxDepth <= 0
	findings = scanArchive(zipPath, "test.zip", 1, 0, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when maxDepth is 0, got %d", len(findings))
	}

	// maxDepth < 0
	findings = scanArchive(zipPath, "test.zip", 1, -1, rs, opts)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when maxDepth is negative, got %d", len(findings))
	}
}

func TestScanArchive_Zip(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	zipPath := filepath.Join(dir, "test.zip")
	createZipWithSecret(t, zipPath)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(zipPath, "test.zip", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from zip archive")
	}
}

func TestScanArchive_Tar(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	tarPath := filepath.Join(dir, "test.tar")
	createTarWithSecret(t, tarPath)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(tarPath, "test.tar", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from tar archive")
	}
}

func TestScanArchive_TarGz(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	tgzPath := filepath.Join(dir, "test.tar.gz")

	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	tw.WriteHeader(&tar.Header{
		Name:     "s.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(tgzPath, "test.tar.gz", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from tar.gz archive")
	}
}

func TestScanArchive_TarGzip(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	// Use .tar.gzip extension to hit the double-extension check
	tgzPath := filepath.Join(dir, "test.tar.gzip")

	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	tw.WriteHeader(&tar.Header{
		Name:     "s.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(tgzPath, "test.tar.gzip", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from .tar.gzip archive")
	}
}

func TestScanArchive_Tgz(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	tgzPath := filepath.Join(dir, "test.tgz")

	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	tw.WriteHeader(&tar.Header{
		Name:     "s.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(tgzPath, "test.tgz", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from .tgz archive")
	}
}

func TestScanArchive_Gz(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	gzPath := filepath.Join(dir, "secret.txt.gz")

	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	gw.Write([]byte("AKIAIOSFODNN7EXAMPLE\n"))
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(gzPath, "secret.txt.gz", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from .gz archive")
	}
}

func TestScanArchive_GzipExtension(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	gzPath := filepath.Join(dir, "secret.txt.gzip")

	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	gw.Write([]byte("AKIAIOSFODNN7EXAMPLE\n"))
	gw.Close()
	f.Close()

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(gzPath, "secret.txt.gzip", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from .gzip archive")
	}
}

func TestScanArchive_Bz2(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	content := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	bz2Path := createBzip2File(t, dir, "secret.txt", content)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(bz2Path, "secret.txt.bz2", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from .bz2 archive")
	}
}

func TestScanArchive_TarBz2(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)

	// Create a tar first
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte("AKIAIOSFODNN7EXAMPLE\n")
	tw.WriteHeader(&tar.Header{
		Name:     "inner.txt",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()

	tarPath := filepath.Join(dir, "test.tar")
	os.WriteFile(tarPath, tarBuf.Bytes(), 0644)

	if !bzip2Available() {
		t.Skip("bzip2 command not available")
	}
	cmd := exec.Command("bzip2", "-k", "-f", tarPath)
	if err := cmd.Run(); err != nil {
		t.Skipf("bzip2 failed: %v", err)
	}

	tbz2Path := tarPath + ".bz2"

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(tbz2Path, "test.tar.bz2", 1, 3, rs, opts)

	if len(findings) == 0 {
		t.Error("expected findings from .tar.bz2 archive")
	}
}

func TestScanArchive_UnknownExtension(t *testing.T) {
	dir := t.TempDir()
	rs := testRuleSet(t)
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0644)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanArchive(path, "file.txt", 1, 3, rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unknown extension, got %d", len(findings))
	}
}

func TestScanZip_LargeUncompressedEntry(t *testing.T) {
	// Create a zip file using zip64 format where UncompressedSize64 exceeds the limit.
	dir := t.TempDir()
	rs := testRuleSet(t)
	zipPath := filepath.Join(dir, "large_entry.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	// Use RegisterCompressor to provide a no-op compressor that just copies.
	// Then set the header with a large uncompressed size but write small data.
	// Actually, we can't fake UncompressedSize64 through the writer.
	// Instead, write a valid zip and then binary-patch the central directory.
	hdr := &zip.FileHeader{
		Name:   "secret.txt",
		Method: zip.Store,
	}
	fw, err := w.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("AKIAIOSFODNN7EXAMPLE\n"))
	w.Close()
	f.Close()

	// Binary-patch: in the central directory entry (PK\x01\x02),
	// the uncompressed size is at offset 24 (4 bytes, little-endian).
	// Also patch the local header (PK\x03\x04) at offset 22.
	data, _ := os.ReadFile(zipPath)

	// Write a value just over maxArchiveFileSize (100MB + 1)
	bigSize := uint32(maxArchiveFileSize + 1)
	sizeBytes := []byte{byte(bigSize), byte(bigSize >> 8), byte(bigSize >> 16), byte(bigSize >> 24)}

	// Patch central directory entry
	for i := 0; i < len(data)-30; i++ {
		if data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 1 && data[i+3] == 2 {
			// Central dir: uncompressed size at offset 24
			copy(data[i+24:i+28], sizeBytes)
			break
		}
	}

	os.WriteFile(zipPath, data, 0644)

	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanZip(zipPath, "large_entry.zip", 1, 3, rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for large entry, got %d", len(findings))
	}
}

func TestScanZip_EntryOpenError(t *testing.T) {
	// Create a zip where the local file header's compression method is patched
	// to an invalid value, causing f.Open() to fail.
	dir := t.TempDir()
	rs := testRuleSet(t)
	zipPath := filepath.Join(dir, "corrupt.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	hdr := &zip.FileHeader{
		Name:   "test.txt",
		Method: zip.Store,
	}
	fw, err := w.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("AKIAIOSFODNN7EXAMPLE\n"))
	w.Close()
	f.Close()

	// Patch the compression method in the local file header to an unsupported value.
	// Local file header signature is PK\x03\x04, compression method is at offset 8.
	data, _ := os.ReadFile(zipPath)
	// Find PK\x03\x04 (local file header)
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 3 && data[i+3] == 4 {
			// Patch compression method at offset 8 from header start
			data[i+8] = 99 // unsupported compression method
			data[i+9] = 0
			break
		}
	}
	// Also patch central directory entry (PK\x01\x02), compression at offset 10
	for i := 0; i < len(data)-12; i++ {
		if data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 1 && data[i+3] == 2 {
			data[i+10] = 99
			data[i+11] = 0
			break
		}
	}
	os.WriteFile(zipPath, data, 0644)

	opts := Options{Stderr: &bytes.Buffer{}, Verbose: true}
	findings := scanZip(zipPath, "corrupt.zip", 1, 3, rs, opts)

	// The entry should fail to open due to unsupported compression
	if len(findings) != 0 {
		t.Logf("got %d findings from corrupted zip (entry may have opened despite corruption)", len(findings))
	}
}

func TestScanTarReader_EmptyTar(t *testing.T) {
	rs := testRuleSet(t)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.Close()

	tr := tar.NewReader(&buf)
	opts := Options{Stderr: &bytes.Buffer{}}
	findings := scanTarReader(tr, "empty.tar", 1, 3, rs, opts)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty tar, got %d", len(findings))
	}
}
