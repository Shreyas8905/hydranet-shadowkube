// Package algo1 implements Algorithm 1 from the ShadowKube paper:
// LCS-based baseline extraction.
//
// Input: a collection of event sequences for one group (sliding window of
// recent activity). For each event type (file / exec / net) the inputs are
// strings — file paths, or argv joined with spaces.
//
// Output: a representative sequence W_n (the "longest common subsequence
// across all observed sequences") that the scorer compares each new event
// against.
//
// We implement the Wagner-Fischer LCS DP (O(n*m) per pair) and then an
// outer loop that re-runs LCS over the result + remaining sequences until
// convergence. The paper notes this "extract" stage happens offline between
// attacks; the detector uses the extracted baselines online.
package algo1

import "strings"

// LCS returns the longest common subsequence of two slice-of-string
// sequences, ordered. Standard DP with O(n*m) time and space.
//
// The result preserves order from `a`. Ties are broken by taking elements
// from `a` first.
func LCS(a, b []string) []string {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return nil
	}
	// dp[i][j] = length of LCS of a[:i], b[:j]
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	// Backtrack.
	out := make([]string, 0, dp[n][m])
	i, j := n, m
	for i > 0 && j > 0 {
		switch {
		case a[i-1] == b[j-1]:
			out = append(out, a[i-1])
			i--
			j--
		case dp[i-1][j] >= dp[i][j-1]:
			i--
		default:
			j--
		}
	}
	// Reverse.
	for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
		out[l], out[r] = out[r], out[l]
	}
	return out
}

// Extract computes the converged baseline W_n from a collection of sequences
// by repeatedly taking the LCS against the running baseline.
//
// Convergence: when LCS(LCS(a,b), c) == LCS(a,b), a new sequence c is already
// represented by the current baseline; we stop and return. The paper's
// stopping condition is implicit but this is faithful in spirit.
func Extract(sequences [][]string) []string {
	if len(sequences) == 0 {
		return nil
	}
	baseline := append([]string(nil), sequences[0]...)
	for _, s := range sequences[1:] {
		if len(s) == 0 {
			continue
		}
		next := LCS(baseline, s)
		if equalSeqs(next, baseline) {
			// `s` is already represented; no change.
			continue
		}
		baseline = next
	}
	return baseline
}

// Stringify is a convenience for converting a sequence of exec/file events
// into a []string. For exec events it returns [cmd]; for file it returns
// [path]; for net it returns [dstIp:dstPort]. The scorer only needs string
// proximity so the exact representation is flexible.
func StringifyFile(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, len(paths))
	copy(out, paths)
	return out
}

// StringifyExec joins each (binary + argv) pair as a single space-separated
// string. Empty cmds collapse to the binary.
func StringifyExec(binaries, argvs []string) []string {
	if len(binaries) == 0 {
		return nil
	}
	out := make([]string, len(binaries))
	for i := range binaries {
		argv := ""
		if i < len(argvs) {
			argv = argvs[i]
		}
		if argv == "" {
			out[i] = binaries[i]
		} else {
			out[i] = strings.TrimSpace(binaries[i] + " " + argv)
		}
	}
	return out
}

func equalSeqs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
