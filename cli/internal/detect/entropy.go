package detect

import "math"

// ShannonEntropy computes the Shannon entropy (in bits) of a string.
// It treats the input as a sequence of runes and is safe for UTF-8.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freq := make(map[rune]int)
	var length int

	for _, r := range s {
		freq[r]++
		length++
	}

	if length == 0 {
		return 0
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(length)
		entropy += -p * math.Log2(p)
	}
	return entropy
}

