# attack-sim - ShadowKube Phase 5

`attack-sim` provides deterministic, safe lab traffic for validating the
ShadowKube detector and actuator. It does not exploit a real vulnerability or
fetch malware. Instead, it emits the same shared `pkg/event.Event` records that
the probe sends and uses the existing HTTP APIs.

## Commands

```text
attack-sim case-study-1   # Docker API / Kinsing-style sequence from the paper
attack-sim case-study-2   # weather-app command-injection / reverse-shell sequence
attack-sim benchmark      # repeat actuator conversion and write Table 6 results
```

Case studies use a fresh group name on every run. Each sends benign baseline
events followed by four unexpected network connections, which exceed the
default detector threshold (`L=3`, `c=1`). When an alarm is returned, the
simulator submits the alarm to the actuator with a synthetic pod and node.
This is appropriate for dry-run actuator verification. The detector's own
`ACTUATOR_URL` webhook can also be configured for full fan-out testing; avoid
submitting the same case to both paths at once because that intentionally
creates two alarms.

## Configuration

All settings are environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DETECTOR_URL` | `http://127.0.0.1:8080/events` | detector ingest endpoint |
| `ACTUATOR_URL` | `http://127.0.0.1:8081/alarms` | actuator alarm endpoint |
| `BENCHMARK_RUNS` | `10` | number of benchmark conversions |
| `BENCHMARK_OUTPUT` | `benchmark-results.json` | JSON result path |
| `BENCHMARK_MARKDOWN` | `benchmark-results.md` | Markdown result path |

## Build

```bash
cd attack-sim
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go build -o /tmp/attack-sim ./cmd/attack-sim
```

See the repository-level [RunBenchmark.md](../RunBenchmark.md) for the full
cluster workflow, local dry-run workflow, and interpretation of results.
