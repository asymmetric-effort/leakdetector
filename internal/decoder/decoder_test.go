package decoder

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

func TestDecode_MaxDepthZero(t *testing.T) {
	result := Decode("anything", 0)
	if result != nil {
		t.Errorf("expected nil for maxDepth 0, got %v", result)
	}
}

func TestDecode_NegativeMaxDepth(t *testing.T) {
	result := Decode("anything", -1)
	if result != nil {
		t.Errorf("expected nil for negative maxDepth, got %v", result)
	}
}

func TestDecode_Base64Standard(t *testing.T) {
	original := "this is a secret key value"
	encoded := base64.StdEncoding.EncodeToString([]byte(original))

	results := Decode(encoded, 1)
	if len(results) == 0 {
		t.Fatal("expected at least one decoded result for valid base64")
	}

	found := false
	for _, d := range results {
		if d.Value == original && d.Encoding == "base64" && d.Depth == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected base64 decoded result with value %q, got %v", original, results)
	}
}

func TestDecode_Base64URLSafe(t *testing.T) {
	// Use a string that encodes differently in URL-safe vs standard base64
	original := "value with special chars??"
	encoded := base64.URLEncoding.EncodeToString([]byte(original))

	// Make sure it's different from standard encoding (contains - or _ instead of + or /)
	stdEncoded := base64.StdEncoding.EncodeToString([]byte(original))
	if encoded == stdEncoded {
		// Pick a value that will produce different encodings
		original = "abc>>>def???ghi"
		encoded = base64.URLEncoding.EncodeToString([]byte(original))
	}

	results := Decode(encoded, 1)

	found := false
	for _, d := range results {
		if d.Value == original && d.Encoding == "base64url" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected base64url decoded result with value %q, got %v", original, results)
	}
}

func TestDecode_Base64BothStdAndURL(t *testing.T) {
	// When std and URL base64 produce the same decoded value and maxDepth allows
	// recursion, the decoded value gets added to `seen` and the URL-safe path skips it.
	// With maxDepth=1, recursion doesn't happen so both results appear.
	original := "this is a test value!"
	encoded := base64.StdEncoding.EncodeToString([]byte(original))

	// Verify both encodings produce the same encoded output for this input
	urlEncoded := base64.URLEncoding.EncodeToString([]byte(original))
	if encoded != urlEncoded {
		t.Skip("encodings differ for this input; test not applicable")
	}

	// With maxDepth=2, the recursive call adds the decoded value to seen,
	// so URL-safe decoding should be deduped.
	results := Decode(encoded, 2)
	count := 0
	for _, d := range results {
		if d.Value == original {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 decoded result (deduped via seen), got %d: %v", count, results)
	}
}

func TestDecode_Hex(t *testing.T) {
	original := "this is a hex test!!"
	encoded := hex.EncodeToString([]byte(original))

	if len(encoded) < 32 {
		t.Fatal("encoded hex too short for test")
	}

	results := Decode(encoded, 1)

	found := false
	for _, d := range results {
		if d.Value == original && d.Encoding == "hex" && d.Depth == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected hex decoded result with value %q, got %v", original, results)
	}
}

func TestDecode_HexTooShort(t *testing.T) {
	// "short" = 5 bytes = 10 hex chars, under the 32-char minimum
	encoded := hex.EncodeToString([]byte("short"))

	results := Decode(encoded, 1)
	for _, d := range results {
		if d.Encoding == "hex" {
			t.Errorf("did not expect hex decoding for short string, got %v", d)
		}
	}
}

func TestDecode_PercentEncoded(t *testing.T) {
	original := "hello world/path?key=val"
	encoded := url.QueryEscape(original)

	results := Decode(encoded, 1)

	found := false
	for _, d := range results {
		if d.Value == original && d.Encoding == "percent" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected percent decoded result with value %q, got %v", original, results)
	}
}

func TestDecode_PercentEncodedNoChange(t *testing.T) {
	// A string with % but that doesn't actually change after unescape should not be added.
	// url.QueryUnescape("abc") returns "abc" (same as input), so no result.
	// But "abc" has no %, so percent path is skipped anyway.
	// We need a string with % that unescapes to itself -- that's not really possible
	// with valid percent encoding. So test a string without % to confirm the path is skipped.
	results := Decode("nopercent", 1)
	for _, d := range results {
		if d.Encoding == "percent" {
			t.Errorf("did not expect percent decoding, got %v", d)
		}
	}
}

func TestDecode_InvalidEncodings(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"random text", "this is just random text not encoded"},
		{"invalid base64 chars", "!!!invalid-base64-string!!!===="},
		{"short string", "abc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := Decode(tc.input, 1)
			if len(results) != 0 {
				t.Errorf("expected no decoded results for %q, got %v", tc.input, results)
			}
		})
	}
}

func TestDecode_RecursiveBase64(t *testing.T) {
	original := "deeply nested secret"
	inner := base64.StdEncoding.EncodeToString([]byte(original))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))

	results := Decode(outer, 3)

	foundDepth1 := false
	foundDepth2 := false
	for _, d := range results {
		if d.Value == inner && d.Depth == 1 {
			foundDepth1 = true
		}
		if d.Value == original && d.Depth == 2 {
			foundDepth2 = true
		}
	}

	if !foundDepth1 {
		t.Error("expected depth-1 decoded result (the inner base64 string)")
	}
	if !foundDepth2 {
		t.Error("expected depth-2 decoded result (the original string)")
	}
}

func TestDecode_RecursionLimitedByMaxDepth(t *testing.T) {
	original := "deeply nested secret"
	inner := base64.StdEncoding.EncodeToString([]byte(original))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))

	// maxDepth=1 should only decode one layer
	results := Decode(outer, 1)

	for _, d := range results {
		if d.Value == original {
			t.Error("should not have reached original string with maxDepth=1")
		}
	}
}

func TestDecode_Base64TooShort(t *testing.T) {
	// base64 of a very short string produces <16 char encoded output
	short := base64.StdEncoding.EncodeToString([]byte("hi"))
	// "hi" -> "aGk=" which is 4 chars, under the 16 minimum
	results := Decode(short, 1)
	for _, d := range results {
		if d.Encoding == "base64" || d.Encoding == "base64url" {
			t.Errorf("did not expect base64 decoding for short encoded string, got %v", d)
		}
	}
}

func TestDecode_NonPrintableOutput(t *testing.T) {
	// Create a base64-encoded string that decodes to non-printable bytes.
	nonPrintable := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11}
	encoded := base64.StdEncoding.EncodeToString(nonPrintable)

	results := Decode(encoded, 1)
	for _, d := range results {
		if d.Encoding == "base64" || d.Encoding == "base64url" {
			t.Errorf("non-printable decoded output should be filtered, got %v", d)
		}
	}
}

func TestDecode_NonPrintableHex(t *testing.T) {
	// 16+ bytes of non-printable data -> 32+ hex chars
	nonPrintable := make([]byte, 16)
	for i := range nonPrintable {
		nonPrintable[i] = byte(i) // includes 0x00-0x0F, most non-printable
	}
	encoded := hex.EncodeToString(nonPrintable)

	results := Decode(encoded, 1)
	for _, d := range results {
		if d.Encoding == "hex" {
			t.Errorf("non-printable hex output should be filtered, got %v", d)
		}
	}
}

func TestDecode_SeenDedup(t *testing.T) {
	// If the same decoded value would be produced twice, it should be deduped.
	original := "this is a test value!"
	encoded := base64.StdEncoding.EncodeToString([]byte(original))

	results := Decode(encoded, 2)
	count := 0
	for _, d := range results {
		if d.Value == original {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected deduplication, but got %d results with same value", count)
	}
}

func TestTags(t *testing.T) {
	tests := []struct {
		name     string
		decoded  []Decoded
		expected []string
	}{
		{
			name:     "nil input",
			decoded:  nil,
			expected: []string{},
		},
		{
			name:     "empty input",
			decoded:  []Decoded{},
			expected: []string{},
		},
		{
			name: "single depth-1 result",
			decoded: []Decoded{
				{Value: "test", Encoding: "base64", Depth: 1},
			},
			expected: []string{"decoded:base64"},
		},
		{
			name: "single depth-2 result",
			decoded: []Decoded{
				{Value: "test", Encoding: "hex", Depth: 2},
			},
			expected: []string{"decoded:hex", "decode-depth:2"},
		},
		{
			name: "multiple results mixed depths",
			decoded: []Decoded{
				{Value: "outer", Encoding: "base64", Depth: 1},
				{Value: "inner", Encoding: "base64", Depth: 2},
			},
			expected: []string{"decoded:base64", "decoded:base64", "decode-depth:2"},
		},
		{
			name: "percent encoding",
			decoded: []Decoded{
				{Value: "test", Encoding: "percent", Depth: 1},
			},
			expected: []string{"decoded:percent"},
		},
		{
			name: "depth 3",
			decoded: []Decoded{
				{Value: "val", Encoding: "base64url", Depth: 3},
			},
			expected: []string{"decoded:base64url", "decode-depth:3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tags := Tags(tc.decoded)
			if len(tags) != len(tc.expected) {
				t.Fatalf("expected %d tags, got %d: %v", len(tc.expected), len(tags), tags)
			}
			for i, tag := range tags {
				if tag != tc.expected[i] {
					t.Errorf("tag[%d]: expected %q, got %q", i, tc.expected[i], tag)
				}
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"empty", []byte{}, true},
		{"ascii letters", []byte("hello world"), true},
		{"with newline", []byte("hello\nworld"), true},
		{"with carriage return", []byte("hello\r\nworld"), true},
		{"with tab", []byte("hello\tworld"), true},
		{"with all allowed whitespace", []byte("a\n\r\tb"), true},
		{"unicode printable", []byte("héllo wörld"), true},
		{"null byte", []byte{0x00}, false},
		{"bell char", []byte{0x07}, false},
		{"backspace", []byte{0x08}, false},
		{"vertical tab", []byte{0x0B}, false},
		{"form feed", []byte{0x0C}, false},
		{"escape", []byte{0x1B}, false},
		{"delete", []byte{0x7F}, false},
		{"mixed printable and non-printable", []byte("hello\x00world"), false},
		{"control char in middle", []byte("abc\x01def"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isPrintable(tc.input)
			if result != tc.expected {
				t.Errorf("isPrintable(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty string", "", true},
		{"valid lowercase", "0123456789abcdef", true},
		{"valid uppercase", "0123456789ABCDEF", true},
		{"valid mixed case", "aAbBcCdDeEfF0123", true},
		{"odd length", "abc", false},
		{"odd length single char", "a", false},
		{"invalid char g", "abcdefgh", false},
		{"spaces", "ab cd", false},
		{"special chars", "ab!@", false},
		{"valid two chars", "ff", true},
		{"hex with non-hex letter", "zz", false},
		{"just digits even length", "0000", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isHex(tc.input)
			if result != tc.expected {
				t.Errorf("isHex(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestDecode_HexUpperCase(t *testing.T) {
	original := "this is a hex test!!"
	encoded := strings.ToUpper(hex.EncodeToString([]byte(original)))

	results := Decode(encoded, 1)

	found := false
	for _, d := range results {
		if d.Value == original && d.Encoding == "hex" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected hex decoded result for uppercase hex, got %v", results)
	}
}

func TestDecode_PercentEncodedInvalidSequence(t *testing.T) {
	// Invalid percent encoding like %ZZ should cause QueryUnescape to fail
	input := "hello%ZZworld"
	results := Decode(input, 1)
	for _, d := range results {
		if d.Encoding == "percent" {
			t.Errorf("should not decode invalid percent encoding, got %v", d)
		}
	}
}

func TestDecode_HexOddLengthLong(t *testing.T) {
	// 33 hex chars (odd length) - isHex returns false
	input := strings.Repeat("a", 33)
	results := Decode(input, 1)
	for _, d := range results {
		if d.Encoding == "hex" {
			t.Errorf("should not decode odd-length hex, got %v", d)
		}
	}
}

func TestDecode_HexInvalidCharsLong(t *testing.T) {
	// 32+ chars that look like hex but contain invalid characters
	input := strings.Repeat("g", 32)
	results := Decode(input, 1)
	for _, d := range results {
		if d.Encoding == "hex" {
			t.Errorf("should not decode non-hex chars, got %v", d)
		}
	}
}

func TestDecode_PercentRecursiveIntoBase64(t *testing.T) {
	// Percent-encode a base64 string, then decode should find both layers
	original := "recursive secret val"
	b64 := base64.StdEncoding.EncodeToString([]byte(original))
	percentEncoded := url.QueryEscape(b64)

	// Only works if percent encoding actually changes the string
	if percentEncoded == b64 {
		t.Skip("percent encoding didn't change base64 string")
	}

	results := Decode(percentEncoded, 3)

	foundPercent := false
	foundBase64 := false
	for _, d := range results {
		if d.Encoding == "percent" && d.Value == b64 {
			foundPercent = true
		}
		if d.Value == original {
			foundBase64 = true
		}
	}
	if !foundPercent {
		t.Error("expected percent decoded result")
	}
	if !foundBase64 {
		t.Error("expected base64 decoded result from recursive decoding")
	}
}

func TestDecode_EmptyString(t *testing.T) {
	results := Decode("", 1)
	if len(results) != 0 {
		t.Errorf("expected no results for empty string, got %v", results)
	}
}
