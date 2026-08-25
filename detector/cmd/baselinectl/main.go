// Command baselinectl builds and inspects detector baselines.
//
// Usage:
//
//   baselinectl extract --from <ndjson-path> [--out <baseline-dir>] [--groups a,b,c]
//   baselinectl status   [--dir <baseline-dir>]
//
// `extract` reads a pre-recorded NDJSON event log (typically produced by
// running the probe in --dry-run mode for a few minutes) and runs Algorithm
// 1 over each group's file / exec / net sequences. The result is persisted
// as one <safe>.json per group under <baseline-dir>.
//
// `status` lists groups with persisted baselines and prints their sequence
// counts.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/shadowkube-repro/detector/internal/algo1"
	"github.com/shadowkube-repro/detector/internal/baseline"
	"github.com/shadowkube-repro/detector/internal/group"
	"github.com/shadowkube-repro/pkg/event"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "extract":
		extract(os.Args[2:])
	case "status":
		status(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  baselinectl extract --from <events.ndjson> [--out <dir>] [--groups a,b,c]
  baselinectl status   [--dir <dir>]
`)
}

// extract implements `baselinectl extract`.
func extract(args []string) {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	from := fs.String("from", "", "NDJSON input file (required)")
	out := fs.String("out", "/var/lib/shadowkube/baselines", "baseline output directory")
	groupsFilter := fs.String("groups", "", "comma-separated group keys to extract (default: all)")
	fs.Parse(args)
	if *from == "" {
		log.Fatalf("extract: --from is required")
	}

	f, err := os.Open(*from)
	if err != nil {
		log.Fatalf("extract: open %s: %v", *from, err)
	}
	defer f.Close()

	store, err := baseline.NewStore(*out)
	if err != nil {
		log.Fatalf("extract: store: %v", err)
	}

	// Per-group accumulators.
	type acc struct {
		files []string
		execs []string
		execsByBin map[string][]string
		netPeers map[string]struct{}
	}
	groups := map[group.Key]*acc{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	matchesFilter := func(k group.Key) bool {
		if *groupsFilter == "" {
			return true
		}
		for _, want := range strings.Split(*groupsFilter, ",") {
			want = strings.TrimSpace(want)
			if want == "" {
				continue
			}
			if string(k) == want {
				return true
			}
		}
		return false
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		k := group.Resolve(ev)
		if !matchesFilter(k) {
			continue
		}
		a, ok := groups[k]
		if !ok {
			a = &acc{
				execsByBin: map[string][]string{},
				netPeers:   map[string]struct{}{},
			}
			groups[k] = a
		}
		switch ev.Type {
		case event.TypeFile:
			if ev.Payload.Path != "" {
				a.files = append(a.files, ev.Payload.Path)
			}
		case event.TypeExec:
			if ev.Payload.Cmd != "" {
				a.execs = append(a.execs, ev.Payload.Cmd)
				bin := firstToken(ev.Payload.Cmd)
				if bin != "" {
					a.execsByBin[bin] = append(a.execsByBin[bin], strings.TrimSpace(strings.TrimPrefix(ev.Payload.Cmd, bin)))
				}
			}
		case event.TypeNet:
			if ev.Payload.DstIP != "" {
				a.netPeers[fmt.Sprintf("%s:%d", ev.Payload.DstIP, ev.Payload.DstPort)] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("extract: read: %v", err)
	}

	// Run Algorithm 1 on each group.
	for k, a := range groups {
		gf := &baseline.GroupFile{}

		// file: extract representative LCS over the observed path set.
		gf.File = algo1.Extract(splitByGroup(a.files))

		// exec: per-binary representative argv strings.
		execOut := make(map[string][]string, len(a.execsByBin))
		for bin, argvs := range a.execsByBin {
			// run LCS over the argv strings to extract the common subsequence.
			seq := algo1.Extract(splitByGroup(argvs))
			if seq == nil {
				seq = argvs
			}
			execOut[bin] = seq
		}
		gf.Exec = execOut

		// net: write the peer set as a sorted slice.
		peers := make([]string, 0, len(a.netPeers))
		for p := range a.netPeers {
			peers = append(peers, p)
		}
		sort.Strings(peers)
		gf.Net = peers

		groupName := groupNameString(k)
		if err := store.Save(groupName, gf); err != nil {
			log.Fatalf("extract: save %s: %v", groupName, err)
		}
		fmt.Printf("extract: group=%s files=%d execs=%d nets=%d -> %s\n",
			k, len(a.files), len(a.execs), len(a.netPeers), store.PathFor(groupName))
	}
}

// status implements `baselinectl status`.
func status(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := fs.String("dir", "/var/lib/shadowkube/baselines", "baseline directory")
	fs.Parse(args)

	store, err := baseline.NewStore(*dir)
	if err != nil {
		log.Fatalf("status: store: %v", err)
	}
	groups, err := store.List()
	if err != nil {
		log.Fatalf("status: list: %v", err)
	}
	sort.Strings(groups)
	for _, safe := range groups {
		gf, err := store.Load(safe)
		if err != nil || gf == nil {
			fmt.Printf("%s : <unreadable>\n", safe)
			continue
		}
		files, execs, nets := 0, 0, 0
		if arr, ok := gf.File.([]any); ok {
			files = len(arr)
		}
		if m, ok := gf.Exec.(map[string]any); ok {
			execs = len(m)
		}
		if arr, ok := gf.Net.([]any); ok {
			nets = len(arr)
		}
		fmt.Printf("%s : files=%d execs=%d nets=%d frozen=%t\n", safe, files, execs, nets, gf.Frozen)
	}
}

func splitByGroup(s []string) [][]string {
	if len(s) == 0 {
		return nil
	}
	// Per the paper we run LCS over a collection of sequences. We treat each
	// observed string as a single-element sequence; this is the simplest
	// faithful interpretation that still produces a useful baseline.
	out := make([][]string, len(s))
	for i, x := range s {
		out[i] = []string{x}
	}
	return out
}

func firstToken(s string) string {
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s
	}
	return s[:idx]
}

func groupNameString(k group.Key) string { return string(k) }
