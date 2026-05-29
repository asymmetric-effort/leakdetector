package entropy

import (
	"math"
	"strings"
	"testing"
)

func TestShannon(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		// Edge cases
		{
			name:    "empty string",
			input:   "",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single character",
			input:   "a",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single character repeated",
			input:   "aaaaaaaaaa",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single character repeated long",
			input:   strings.Repeat("x", 1000),
			wantMin: 0,
			wantMax: 0,
		},

		// Two characters: entropy should be exactly 1.0 for equal distribution
		{
			name:    "two characters alternating",
			input:   "abababababab",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "two characters equal count",
			input:   "aabb",
			wantMin: 1.0,
			wantMax: 1.0,
		},

		// Known entropy values
		{
			name:    "four unique characters equal distribution",
			input:   "abcdabcdabcd",
			wantMin: 2.0,
			wantMax: 2.0,
		},
		{
			name:    "eight unique characters equal distribution",
			input:   "abcdefghabcdefgh",
			wantMin: 3.0,
			wantMax: 3.0,
		},

		// All unique characters (high entropy)
		{
			name:    "all unique ASCII chars short",
			input:   "abcdefghij",
			wantMin: 3.3,
			wantMax: 3.4,
		},
		{
			name:    "all 26 lowercase letters",
			input:   "abcdefghijklmnopqrstuvwxyz",
			wantMin: 4.7,
			wantMax: 4.71,
		},

		// Secret-like strings (high entropy)
		{
			name:    "secret-like mixed characters",
			input:   "aB3$kL9#mN",
			wantMin: 3.0,
			wantMax: 4.0,
		},
		{
			name:    "hex token",
			input:   "a1b2c3d4e5f6a7b8",
			wantMin: 3.5,
			wantMax: 4.1,
		},
		{
			name:    "base64-like token",
			input:   "dGhpcyBpcyBhIHRlc3Q=",
			wantMin: 3.0,
			wantMax: 4.5,
		},
		{
			name:    "API key simulation",
			input:   "sk-proj-abc123XYZ789!@#",
			wantMin: 3.5,
			wantMax: 5.0,
		},

		// Non-secret strings (low entropy)
		{
			name:    "common word password",
			input:   "password",
			wantMin: 2.5,
			wantMax: 3.0,
		},
		{
			name:    "repeated pattern",
			input:   "abcabcabcabc",
			wantMin: 1.58,
			wantMax: 1.59,
		},
		{
			name:    "mostly one character",
			input:   "aaaaaaaab",
			wantMin: 0.5,
			wantMax: 0.6,
		},

		// Various lengths
		{
			name:    "two characters length 2",
			input:   "ab",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "three characters length 3",
			input:   "abc",
			wantMin: 1.58,
			wantMax: 1.59,
		},
		{
			name:    "long repeated two chars",
			input:   strings.Repeat("ab", 500),
			wantMin: 1.0,
			wantMax: 1.0,
		},

		// Unicode characters
		{
			name:    "unicode single repeated",
			input:   "aaaa",
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "unicode two chars alternating",
			input:   "abab",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "unicode CJK characters all unique",
			input:   "\u4e16\u754c\u4f60\u597d",
			wantMin: 2.0,
			wantMax: 2.0,
		},
		{
			name:    "mixed ASCII and unicode",
			input:   "a\u00e9\u00ef\u00f6\u00fc",
			wantMin: 2.3,
			wantMax: 2.33,
		},
		{
			name:    "emoji characters all unique",
			input:   "\U0001f600\U0001f601\U0001f602\U0001f603",
			wantMin: 2.0,
			wantMax: 2.0,
		},
		{
			name:    "emoji repeated",
			input:   "\U0001f600\U0001f600\U0001f600\U0001f600",
			wantMin: 0,
			wantMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Shannon(tt.input)
			if got < tt.wantMin-1e-9 || got > tt.wantMax+1e-9 {
				t.Errorf("Shannon(%q) = %f, want [%f, %f]", tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestShannonExactValues(t *testing.T) {
	// Test mathematically exact entropy values
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{"empty", "", 0},
		{"single char", "a", 0},
		{"repeated char", "aaaa", 0},
		{"two equal chars", "ab", 1.0},
		{"four equal chars", "abcd", 2.0},
		{"eight equal chars", "abcdefgh", 3.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Shannon(tt.input)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("Shannon(%q) = %f, want exactly %f", tt.input, got, tt.want)
			}
		})
	}
}

func TestShannonProperties(t *testing.T) {
	t.Run("entropy is non-negative", func(t *testing.T) {
		inputs := []string{"", "a", "ab", "abc", "hello world", "\x00\x01\x02"}
		for _, s := range inputs {
			got := Shannon(s)
			if got < 0 {
				t.Errorf("Shannon(%q) = %f, want non-negative", s, got)
			}
		}
	})

	t.Run("more unique chars means higher entropy", func(t *testing.T) {
		e1 := Shannon("aaaa")
		e2 := Shannon("aabb")
		e3 := Shannon("abcd")
		if e1 >= e2 {
			t.Errorf("entropy of 'aaaa' (%f) should be less than 'aabb' (%f)", e1, e2)
		}
		if e2 >= e3 {
			t.Errorf("entropy of 'aabb' (%f) should be less than 'abcd' (%f)", e2, e3)
		}
	})

	t.Run("entropy is order independent", func(t *testing.T) {
		e1 := Shannon("aabb")
		e2 := Shannon("abab")
		e3 := Shannon("bbaa")
		e4 := Shannon("baba")
		if math.Abs(e1-e2) > 1e-9 || math.Abs(e2-e3) > 1e-9 || math.Abs(e3-e4) > 1e-9 {
			t.Errorf("entropy should be order-independent: %f, %f, %f, %f", e1, e2, e3, e4)
		}
	})

	t.Run("maximum entropy bounded by log2 of unique chars", func(t *testing.T) {
		// For N unique chars with equal frequency, entropy = log2(N)
		inputs := []string{"ab", "abcd", "abcdefgh", "abcdefghijklmnop"}
		for _, s := range inputs {
			got := Shannon(s)
			maxEntropy := math.Log2(float64(len([]rune(s))))
			if got > maxEntropy+1e-9 {
				t.Errorf("Shannon(%q) = %f, exceeds max entropy %f", s, got, maxEntropy)
			}
		}
	})
}

func TestShannonRuneVsByte(t *testing.T) {
	// Verify the function counts runes, not bytes.
	// Multi-byte UTF-8 chars should each count as one symbol.
	t.Run("multi-byte runes counted correctly", func(t *testing.T) {
		// Two unique runes, equal frequency => entropy should be 1.0
		input := "\u00e9\u00e9\u00fc\u00fc" // each is 2 bytes in UTF-8
		got := Shannon(input)
		if math.Abs(got-1.0) > 1e-9 {
			t.Errorf("Shannon(%q) = %f, want 1.0", input, got)
		}
	})

	t.Run("four byte runes", func(t *testing.T) {
		// Two unique emoji, equal frequency => entropy 1.0
		input := "\U0001f600\U0001f600\U0001f601\U0001f601"
		got := Shannon(input)
		if math.Abs(got-1.0) > 1e-9 {
			t.Errorf("Shannon(%q) = %f, want 1.0", input, got)
		}
	})
}
