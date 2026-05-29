package entropy

import "math"

// Shannon calculates the Shannon entropy of a string.
// Returns a value between 0 (no randomness) and 8.0 (maximum randomness for byte data).
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int, 64)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
