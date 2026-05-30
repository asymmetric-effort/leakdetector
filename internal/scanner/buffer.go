package scanner

import (
	"sort"
	"strings"

	"github.com/asymmetric-effort/leakdetector/internal/decoder"
	"github.com/asymmetric-effort/leakdetector/internal/finding"
	"github.com/asymmetric-effort/leakdetector/internal/rules"
)

const (
	// defaultWindowSize is the sliding window size for matching.
	// Must be large enough to capture any secret split across lines.
	defaultWindowSize = 4096

	// windowOverlap is how much consecutive windows overlap to ensure
	// a secret at any split point is fully contained in at least one window.
	windowOverlap = 1024
)

// fileBuffer holds a file's content as a byte buffer with a precomputed
// line offset index for efficient line/column lookups.
type fileBuffer struct {
	data       []byte
	lineStarts []int // byte offsets where each line begins (0-indexed)
}

// newFileBuffer creates a fileBuffer from raw bytes and builds the line index.
func newFileBuffer(data []byte) *fileBuffer {
	fb := &fileBuffer{data: data}
	fb.buildLineIndex()
	return fb
}

// buildLineIndex computes the byte offset of each line start.
func (fb *fileBuffer) buildLineIndex() {
	fb.lineStarts = append(fb.lineStarts, 0)
	for i := 0; i < len(fb.data); i++ {
		if fb.data[i] == '\n' {
			if i+1 < len(fb.data) {
				fb.lineStarts = append(fb.lineStarts, i+1)
			}
		}
	}
}

// lineCount returns the number of lines in the buffer.
func (fb *fileBuffer) lineCount() int {
	return len(fb.lineStarts)
}

// lineAt returns the content of line n (0-indexed) as a string, without
// the trailing newline.
func (fb *fileBuffer) lineAt(n int) string {
	if n < 0 || n >= len(fb.lineStarts) {
		return ""
	}
	start := fb.lineStarts[n]
	end := len(fb.data)
	if n+1 < len(fb.lineStarts) {
		end = fb.lineStarts[n+1]
	}
	// Strip trailing \n and \r.
	for end > start && (fb.data[end-1] == '\n' || fb.data[end-1] == '\r') {
		end--
	}
	return string(fb.data[start:end])
}

// lineColFromOffset converts a byte offset to a 1-indexed (line, column) pair.
func (fb *fileBuffer) lineColFromOffset(offset int) (int, int) {
	// Binary search for the line containing this offset.
	lineIdx := sort.Search(len(fb.lineStarts), func(i int) bool {
		return fb.lineStarts[i] > offset
	}) - 1
	if lineIdx < 0 {
		lineIdx = 0
	}
	col := offset - fb.lineStarts[lineIdx] + 1
	return lineIdx + 1, col // 1-indexed
}

// linesForProximity returns a slice of line strings centered on lineIdx
// (0-indexed) for proximity rule checking. Includes lines within the range
// [lineIdx - radius, lineIdx + radius].
func (fb *fileBuffer) linesForProximity(lineIdx, radius int) []string {
	start := lineIdx - radius
	if start < 0 {
		start = 0
	}
	end := lineIdx + radius + 1
	if end > fb.lineCount() {
		end = fb.lineCount()
	}
	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		lines = append(lines, fb.lineAt(i))
	}
	return lines
}

// proximityCenter returns the index within the linesForProximity slice
// that corresponds to the original lineIdx.
func (fb *fileBuffer) proximityCenter(lineIdx, radius int) int {
	start := lineIdx - radius
	if start < 0 {
		start = 0
	}
	return lineIdx - start
}

// matchKey uniquely identifies a match for deduplication.
type matchKey struct {
	ruleID string
	offset int
}

// scanBuffer scans a file buffer using sliding windows to detect secrets,
// including those split across line boundaries.
func scanBuffer(fb *fileBuffer, filePath, commit string, rs *rules.RuleSet, opts Options) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[matchKey]struct{})

	windowSize := defaultWindowSize
	step := windowSize - windowOverlap
	if step <= 0 {
		step = 1
	}

	// Slide a window across the buffer.
	for offset := 0; offset < len(fb.data); offset += step {
		end := offset + windowSize
		if end > len(fb.data) {
			end = len(fb.data)
		}
		window := string(fb.data[offset:end])

		// Check for inline allow in the window.
		// We check per-line later, but skip windows that are entirely allowed.

		for i := range rs.Rules {
			rule := &rs.Rules[i]

			// Path filter.
			if rule.Path != nil && !rule.Path.MatchString(filePath) {
				continue
			}

			// Keyword pre-filter against the window.
			if len(rule.Keywords) > 0 {
				lower := strings.ToLower(window)
				found := false
				for _, kw := range rule.Keywords {
					if strings.Contains(lower, strings.ToLower(kw)) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			if rule.Regex == nil {
				continue
			}

			// Find all matches in this window.
			allLocs := rule.Regex.FindAllStringSubmatchIndex(window, -1)
			for _, loc := range allLocs {
				matchStart := loc[0]
				matchEnd := loc[1]
				absOffset := offset + matchStart

				// Deduplicate: same rule + same byte offset = same finding.
				key := matchKey{ruleID: rule.ID, offset: absOffset}
				if _, exists := seen[key]; exists {
					continue
				}

				fullMatch := window[matchStart:matchEnd]

				// Extract secret from capture group.
				secret := fullMatch
				if rule.SecretGroup > 0 {
					gi := rule.SecretGroup * 2
					if gi+1 < len(loc) && loc[gi] >= 0 {
						secret = window[loc[gi]:loc[gi+1]]
					}
				}

				// Entropy check.
				mr := rule.MatchContent(fullMatch, secret, filePath, commit)
				if !mr.Found {
					continue
				}

				// Determine the line this match is on.
				line, col := fb.lineColFromOffset(absOffset)
				lineIdx := line - 1 // 0-indexed

				// Check inline allow on the line containing the match.
				lineContent := fb.lineAt(lineIdx)
				if hasInlineAllow(lineContent) {
					continue
				}

				// Check global allowlists.
				if isGlobalAllowed(rs.Allowlists, mr.Secret, mr.FullMatch, lineContent, filePath, commit) {
					continue
				}

				// Check proximity/composite rules.
				if len(rule.Required) > 0 {
					maxRadius := 0
					for _, req := range rule.Required {
						if req.WithinLines > maxRadius {
							maxRadius = req.WithinLines
						}
					}
					if maxRadius == 0 {
						maxRadius = 5
					}
					proxyLines := fb.linesForProximity(lineIdx, maxRadius)
					center := fb.proximityCenter(lineIdx, maxRadius)
					if !rule.CheckProximity(proxyLines, center, col-1) {
						continue
					}
				}

				seen[key] = struct{}{}

				endLine, endCol := fb.lineColFromOffset(offset + matchEnd - 1)

				f := finding.Finding{
					RuleID:      rule.ID,
					Description: rule.Description,
					StartLine:   line,
					EndLine:     endLine,
					StartColumn: col,
					EndColumn:   endCol + 1,
					Match:       mr.FullMatch,
					Secret:      mr.Secret,
					File:        filePath,
					Commit:      commit,
					Tags:        copyTags(rule.Tags),
					Entropy:     mr.Entropy,
					Fingerprint: finding.ComputeFingerprint(commit, filePath, rule.ID, line),
				}

				// Generate platform link.
				if opts.Platform != "" && commit == "" {
					link := generateFileLink(opts, filePath, line)
					if link != "" {
						f.Link = link
					}
				}

				// Attempt decoding.
				if opts.MaxDecodeDepth > 0 {
					decoded := decoder.Decode(mr.Secret, opts.MaxDecodeDepth)
					for _, d := range decoded {
						for j := range rs.Rules {
							dmr := rs.Rules[j].Match(d.Value, filePath, commit)
							if dmr.Found && !isGlobalAllowed(rs.Allowlists, dmr.Secret, dmr.FullMatch, d.Value, filePath, commit) {
								f.Tags = append(f.Tags, "decoded:"+d.Encoding)
								break
							}
						}
					}
				}

				findings = append(findings, f)
			}
		}

		// If we've reached the end, stop.
		if end >= len(fb.data) {
			break
		}
	}

	return findings
}
