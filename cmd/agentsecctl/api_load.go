package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
)

// These first-page reads are fixed by scenario version. A caller cannot supply
// a path, query, cursor, method or mutation. Every page has an explicit limit.
var apiLoadPaths = [4]string{"/api/v1/agents?limit=50", "/api/v1/findings?limit=50", "/api/v1/integrations?limit=50", "/api/v1/tools?limit=50"}

type apiLoadScenario struct {
	Version           string `json:"version"`
	Profile           string `json:"profile"`
	ProfileSHA256     string `json:"profile_sha256"`
	DeploymentKind    string `json:"deployment_kind"`
	ReleaseSHA        string `json:"release_sha"`
	DurationSeconds   int    `json:"duration_seconds"`
	RequestsPerSecond int    `json:"requests_per_second"`
	Concurrency       int    `json:"concurrency"`
	RequestTimeoutMS  int    `json:"request_timeout_ms"`
}

type apiLoadSample struct {
	Index     int    `json:"index"`
	Outcome   string `json:"outcome"`
	Status    int    `json:"status"`
	LatencyNS int64  `json:"latency_ns"`
}

type apiLoadMeasurement struct {
	Scenario    apiLoadScenario `json:"scenario"`
	StartedAt   string          `json:"started_at"`
	ElapsedNS   int64           `json:"elapsed_ns"`
	Interrupted bool            `json:"interrupted"`
	Samples     []apiLoadSample `json:"samples"`
}

type apiLoadGate struct {
	Scenario   apiLoadScenario `json:"scenario"`
	Provenance string          `json:"provenance"`
	Requests   int             `json:"requests"`
	Errors     int             `json:"errors"`
	ErrorRate  float64         `json:"error_rate"`
	P50        int64           `json:"p50_ns"`
	P95        int64           `json:"p95_ns"`
	P99        int64           `json:"p99_ns"`
	Outcomes   map[string]int  `json:"outcomes"`
	Paths      [4]string       `json:"paths"`
	Passed     bool            `json:"passed"`
}

func (value apiLoadScenario) valid() bool {
	return value.Version == "bounded-api-read-v1" && validIdentifier(value.Profile) && canonicalLoadHex(value.ProfileSHA256, 64) && canonicalLoadHex(value.ReleaseSHA, 40) && (value.DeploymentKind == "local" || value.DeploymentKind == "reference") && value.DurationSeconds >= 1 && value.DurationSeconds <= 300 && value.RequestsPerSecond >= 1 && value.RequestsPerSecond <= 100 && value.Concurrency >= 1 && value.Concurrency <= 16 && value.DurationSeconds*value.RequestsPerSecond >= 20 && value.RequestTimeoutMS >= 100 && value.RequestTimeoutMS <= 30000
}

func canonicalLoadHex(value string, size int) bool {
	_, err := hex.DecodeString(value)
	return len(value) == size && strings.ToLower(value) == value && err == nil
}

func decodeAPILoad(reader io.Reader, target any) error {
	const limit = 8 << 20
	encoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(encoded) > limit {
		return errResilienceRejected
	}
	unique := json.NewDecoder(bytes.NewReader(encoded))
	if !consumeUniqueReleaseJSONLimit(unique, 0, 30000) {
		return errResilienceRejected
	}
	if _, err = unique.Token(); err != io.EOF {
		return errResilienceRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errResilienceRejected
	}
	// Compare JSON values after decoding to reject case aliases, missing fields
	// and null required values, which encoding/json otherwise accepts silently.
	canonical, err := json.Marshal(target)
	if err != nil {
		return errResilienceRejected
	}
	var original, normalized any
	if json.Unmarshal(encoded, &original) != nil || json.Unmarshal(canonical, &normalized) != nil || !reflect.DeepEqual(original, normalized) {
		return errResilienceRejected
	}
	return nil
}

func evaluateAPILoadMeasurement(value apiLoadMeasurement) (apiLoadGate, error) {
	scenario := value.Scenario
	count := scenario.DurationSeconds * scenario.RequestsPerSecond
	started, err := time.Parse(time.RFC3339Nano, value.StartedAt)
	if !scenario.valid() || err != nil || started.Unix() <= 0 || started.UTC().Format(time.RFC3339Nano) != value.StartedAt || len(value.Samples) != count || value.ElapsedNS <= 0 || value.ElapsedNS > int64(300*time.Second) || value.ElapsedNS > int64(time.Duration(scenario.DurationSeconds)*time.Second+time.Duration(scenario.RequestTimeoutMS)*time.Millisecond+time.Second) {
		return apiLoadGate{}, errResilienceRejected
	}
	if !value.Interrupted && value.ElapsedNS < int64(time.Duration(count-1)*time.Second/time.Duration(scenario.RequestsPerSecond)) {
		return apiLoadGate{}, errResilienceRejected
	}
	report := apiLoadGate{Scenario: scenario, Provenance: "operator-declared-unattested", Requests: count, Outcomes: make(map[string]int), Paths: apiLoadPaths}
	latencies := make([]time.Duration, 0, count)
	var endpointAttempts [4]int
	for i, sample := range value.Samples {
		if sample.Index != i || sample.LatencyNS < 0 || sample.LatencyNS > int64(31*time.Second) {
			return apiLoadGate{}, errResilienceRejected
		}
		if sample.LatencyNS > 0 && int64(time.Duration(i)*time.Second/time.Duration(scenario.RequestsPerSecond))+sample.LatencyNS > value.ElapsedNS {
			return apiLoadGate{}, errResilienceRejected
		}
		valid := false
		switch sample.Outcome {
		case "ok":
			valid = sample.Status == 200 && sample.LatencyNS > 0
		case "http":
			valid = sample.Status >= 201 && sample.Status <= 599 && sample.LatencyNS > 0
		case "invalid_response":
			valid = sample.Status == 200 && sample.LatencyNS > 0
		case "transport":
			valid = sample.Status == 0 && sample.LatencyNS > 0
		case "capacity", "scheduler_late", "cancelled":
			valid = sample.Status == 0 && sample.LatencyNS == 0
		}
		if !valid {
			return apiLoadGate{}, errResilienceRejected
		}
		report.Outcomes[sample.Outcome]++
		if sample.Outcome != "ok" {
			report.Errors++
		}
		if sample.LatencyNS > 0 {
			latencies = append(latencies, time.Duration(sample.LatencyNS))
			endpointAttempts[i%4]++
		}
	}
	report.ErrorRate = float64(report.Errors) / float64(count)
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		report.P50 = int64(percentile(latencies, 50))
		report.P95 = int64(percentile(latencies, 95))
		report.P99 = int64(percentile(latencies, 99))
	}
	report.Passed = !value.Interrupted && len(latencies) >= 20 && report.P95 <= int64(750*time.Millisecond) && report.ErrorRate <= 0.01 && report.Outcomes["capacity"] == 0 && report.Outcomes["scheduler_late"] == 0 && report.Outcomes["cancelled"] == 0
	for _, attempts := range endpointAttempts {
		report.Passed = report.Passed && attempts >= 5
	}
	if !report.Passed {
		return report, errResilienceRejected
	}
	return report, nil
}

func runAPILoadCommand(output io.Writer, input io.Reader, arguments []string) error {
	if len(arguments) == 2 && arguments[1] == "help" {
		_, err := io.WriteString(output, "agentsecctl api-load lint < scenario.json\nagentsecctl api-load run --endpoint HTTPS_ORIGIN --credential-file PRIVATE_PAT_FILE --ca-bundle-file CA_PEM < scenario.json > measurement.json\nagentsecctl api-load evaluate < measurement.json > gate.json\nRun only against an authorized deployment. Local results are not reference deployment proof. Failed measured gates return nonzero and retain their JSON output. See docs/operations/api-reference-load.md.\n")
		return err
	}
	if len(arguments) == 2 && arguments[1] == "lint" {
		var scenario apiLoadScenario
		if decodeAPILoad(input, &scenario) != nil || !scenario.valid() {
			return errResilienceRejected
		}
		return encodeJSON(output, map[string]any{"scenario": scenario, "paths": apiLoadPaths, "requests": scenario.DurationSeconds * scenario.RequestsPerSecond, "p95_limit_ns": int64(750 * time.Millisecond), "error_rate_limit": 0.01, "maximum_wall_clock_ns": int64(300 * time.Second)})
	}
	if len(arguments) >= 2 && arguments[1] == "run" {
		return runAPILoadHTTPCommand(output, input, arguments)
	}
	if len(arguments) != 2 || arguments[1] != "evaluate" {
		return errInvalidArguments
	}
	var value apiLoadMeasurement
	if decodeAPILoad(input, &value) != nil {
		return errResilienceRejected
	}
	report, err := evaluateAPILoadMeasurement(value)
	if report.Requests == 0 {
		return errResilienceRejected
	}
	if encodeErr := encodeJSON(output, report); encodeErr != nil {
		return encodeErr
	}
	return err
}
