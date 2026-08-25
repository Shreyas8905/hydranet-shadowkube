// Package algo2: Levenshtein is a standard Wagner-Fischer edit distance
// over byte slices. Used by Algorithm 2 (the scorer) for per-event d
// computation against the baseline sequences built by Algorithm 1.
//
// We normalize the result: distance is divided by max(len(a), len(b)) so the
// returned score is in [0, 1]. This makes thresholds comparable across
// event types with different string lengths.
package algo2

// Levenshtein returns the normalized edit distance (0..1) between a and b.
// 0 = identical, 1 = completely different.
func Levenshtein(a, b string) float64 {
	if a == b {
		return 0
	}
	ar := []byte(a)
	br := []byte(b)
	if len(ar) == 0 && len(br) == 0 {
		return 0
	}
	if len(ar) == 0 || len(br) == 0 {
		return 1
	}
	// Use two rows; memory O(min(n,m)).
	if len(ar) < len(br) {
		ar, br = br, ar
	}
	n, m := len(ar), len(br)
	prev := make([]int, m+1)
	cur := make([]int, m+1)
	for j := 0; j <= m; j++ {
		prev[j] = j
	}
	for i := 1; i <= n; i++ {
		cur[0] = i
		for j := 1; j <= m; j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := cur[j-1] + 1
			sub := prev[j-1] + cost
			cur[j] = min3(del, ins, sub)
		}
		prev, cur = cur, prev
	}
	d := prev[m]
	maxLen := len(ar)
	if len(br) > maxLen {
		maxLen = len(br)
	}
	return float64(d) / float64(maxLen)
}

// LevenshteinRaw returns the raw (un-normalized) edit distance. Useful for
// tests that want to assert exact integer values.
func LevenshteinRaw(a, b string) int {
	if a == b {
		return 0
	}
	ar := []byte(a)
	br := []byte(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}
	if len(ar) < len(br) {
		ar, br = br, ar
	}
	n, m := len(ar), len(br)
	prev := make([]int, m+1)
	cur := make([]int, m+1)
	for j := 0; j <= m; j++ {
		prev[j] = j
	}
	for i := 1; i <= n; i++ {
		cur[0] = i
		for j := 1; j <= m; j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[m]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// MinLevenshtein returns min over scores for s against each baseline.
// Returns 0 if baselines is empty (no baseline = no signal).
func MinLevenshtein(s string, baselines []string) float64 {
	if len(baselines) == 0 {
		return 0
	}
	best := 1.0
	for _, b := range baselines {
		if d := Levenshtein(s, b); d < best {
			best = d
		}
	}
	return best
}
