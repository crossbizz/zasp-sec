package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A missing command or an evaluator that counts client omissions as successful
// requests must fail these tests. Expected percentiles are hand-calculated.
func TestAPILoadEvaluateCommandMeasuresAndRetainsFailedGate(t *testing.T) {
	artifact := apiLoadTestArtifact()
	var output bytes.Buffer
	if err := runCommand(&output, strings.NewReader(artifact), []string{"api-load", "evaluate"}, "dev"); err != nil {
		t.Fatalf("measured artifact rejected: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["passed"] != true || report["p50_ns"] != float64(50_000_000) || report["p95_ns"] != float64(95_000_000) || report["p99_ns"] != float64(99_000_000) || report["provenance"] != "operator-declared-unattested" {
		t.Fatalf("wrong measured gate: %s", output.Bytes())
	}
	failed := strings.Replace(artifact, `"outcome":"ok","status":200,"latency_ns":1000000`, `"outcome":"capacity","status":0,"latency_ns":0`, 1)
	output.Reset()
	if err := runCommand(&output, strings.NewReader(failed), []string{"api-load", "evaluate"}, "dev"); err == nil {
		t.Fatal("client capacity omission passed")
	}
	if !strings.Contains(output.String(), `"passed":false`) || !strings.Contains(output.String(), `"capacity":1`) {
		t.Fatalf("failed gate artifact lost: %s", output.Bytes())
	}
}

func TestAPILoadRunCommandUsesRealTLSReadsAndCompleteBoundedSchedule(t *testing.T) {
	var active, peak, seen atomic.Int32
	server, args := apiLoadTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); current > old && !peak.CompareAndSwap(old, current); old = peak.Load() {
		}
		if r.Method != "GET" || r.URL.RawQuery != "limit=50" || !contains([]string{"/api/v1/agents", "/api/v1/findings", "/api/v1/integrations", "/api/v1/tools"}, r.URL.Path) || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 48) {
			t.Error("load request escaped bounded authenticated reads")
		}
		seen.Add(1)
		time.Sleep(70 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		item := `{"id":"pid_10000001-0000-4000-8000-000000000001","name":"Fixture agent","kind":"agent","evidence_id":"pid_20000001-0000-4000-8000-000000000001","version":1,"owner":"","team":"","tags":[],"confidence_basis_points":10000,"first_seen":"2026-09-10T19:00:00Z","last_seen":"2026-09-10T19:00:00Z","observed_at":"2026-09-10T19:00:00Z","fresh_until":"2026-09-10T20:00:00Z","freshness_state":"fresh"}`
		switch r.URL.Path {
		case "/api/v1/tools":
			item = strings.Replace(item, `"kind":"agent"`, `"kind":"tool"`, 1)
		case "/api/v1/integrations":
			item = `{"id":"pid_10000001-0000-4000-8000-000000000001","name":"Fixture integration","connector_key":"github","configuration":{"authorization_mode":"github_app"},"status":"active","created_at":"2026-09-10T19:00:00Z","updated_at":"2026-09-10T19:00:00Z"}`
		case "/api/v1/findings":
			item = `{"id":"pid_10000001-0000-4000-8000-000000000001","title":"Fixture finding","source":"posture","severity":"high","status":"open","version":1,"evidence_ids":["pid_20000001-0000-4000-8000-000000000001"],"risk_factors":[],"created_at":"2026-09-10T19:00:00Z","updated_at":"2026-09-10T19:00:00Z"}`
		}
		_, _ = w.Write([]byte(`{"items":[` + item + `],"page_info":{"has_more":false,"next_cursor":null}}`))
	}))
	defer server.Close()
	var output bytes.Buffer
	var fixture map[string]json.RawMessage
	_ = json.Unmarshal([]byte(apiLoadTestArtifact()), &fixture)
	scenario := strings.Replace(string(fixture["scenario"]), `"duration_seconds":5`, `"duration_seconds":2`, 1)
	if err := runCommand(&output, strings.NewReader(scenario), args, "dev"); err != nil {
		t.Fatalf("real TLS load rejected: %v; artifact %s", err, output.Bytes())
	}
	if seen.Load() != 40 || peak.Load() < 2 || peak.Load() > 4 {
		t.Fatalf("wrong actual schedule: requests=%d peak=%d", seen.Load(), peak.Load())
	}
	var measured apiLoadMeasurement
	if err := decodeAPILoad(bytes.NewReader(output.Bytes()), &measured); err != nil {
		t.Fatal(err)
	}
	if len(measured.Samples) != 40 || measured.ElapsedNS < int64(1950*time.Millisecond) {
		t.Fatalf("missing measured schedule: %#v", measured)
	}
	if strings.Contains(output.String(), strings.Repeat("t", 48)) || strings.Contains(output.String(), "localhost") || strings.Contains(output.String(), "page_info") {
		t.Fatal("measurement retained credential, target or body")
	}
	if report, err := evaluateAPILoadMeasurement(measured); err != nil || !report.Passed {
		t.Fatalf("measurement gate: %#v %v", report, err)
	}
}

func apiLoadTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	directory := t.TempDir()
	credential, ca := filepath.Join(directory, "token"), filepath.Join(directory, "ca.pem")
	if err = os.WriteFile(credential, []byte(strings.Repeat("t", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := url.Parse(server.URL)
	return server, []string{"api-load", "run", "--endpoint", "https://localhost:" + endpoint.Port(), "--credential-file", credential, "--ca-bundle-file", ca}
}

func apiLoadTestArtifact() string {
	samples := make([]map[string]any, 100)
	for i := range samples {
		samples[i] = map[string]any{"index": i, "outcome": "ok", "status": 200, "latency_ns": (i + 1) * 1_000_000}
	}
	value := map[string]any{
		"scenario":   map[string]any{"version": "bounded-api-read-v1", "profile": "local-ci", "profile_sha256": strings.Repeat("a", 64), "deployment_kind": "local", "release_sha": strings.Repeat("b", 40), "duration_seconds": 5, "requests_per_second": 20, "concurrency": 4, "request_timeout_ms": 500},
		"started_at": "2026-09-10T19:00:00Z", "elapsed_ns": int64(5_100_000_000), "interrupted": false, "samples": samples,
	}
	encoded, _ := json.Marshal(value)
	// Keep the first observation's member order fixed for the explicit mutation.
	return strings.Replace(string(encoded), `"index":0,"latency_ns":1000000,"outcome":"ok","status":200`, `"index":0,"outcome":"ok","status":200,"latency_ns":1000000`, 1)
}

func TestAPILoadEvaluatorRejectsUnboundedIncompleteOrAmbiguousEvidence(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"unknown": func(v string) string {
			return strings.Replace(v, `"interrupted":false`, `"interrupted":false,"secret":"private"`, 1)
		},
		"duplicate": func(v string) string {
			return strings.Replace(v, `"interrupted":false`, `"interrupted":false,"interrupted":false`, 1)
		},
		"case alias": func(v string) string { return strings.Replace(v, `"interrupted"`, `"Interrupted"`, 1) },
		"null":       func(v string) string { return strings.Replace(v, `"interrupted":false`, `"interrupted":null`, 1) },
		"missing":    func(v string) string { return strings.Replace(v, `"interrupted":false,`, ``, 1) },
		"too long":   func(v string) string { return strings.Replace(v, `"duration_seconds":5`, `"duration_seconds":301`, 1) },
		"unbounded rate": func(v string) string {
			return strings.Replace(v, `"requests_per_second":20`, `"requests_per_second":101`, 1)
		},
		"unbounded concurrency": func(v string) string { return strings.Replace(v, `"concurrency":4`, `"concurrency":17`, 1) },
		"unbound profile":       func(v string) string { return strings.Replace(v, strings.Repeat("a", 64), "", 1) },
		"sample omitted": func(v string) string {
			return strings.Replace(v, `"requests_per_second":20`, `"requests_per_second":21`, 1)
		},
		"sample duplicated": func(v string) string { return strings.Replace(v, `"index":1,`, `"index":0,`, 1) },
		"fake success":      func(v string) string { return strings.Replace(v, `"status":200`, `"status":401`, 1) },
		"zero latency":      func(v string) string { return strings.Replace(v, `"latency_ns":1000000`, `"latency_ns":0`, 1) },
		"short run":         func(v string) string { return strings.Replace(v, `"elapsed_ns":5100000000`, `"elapsed_ns":100`, 1) },
		"trailing":          func(v string) string { return v + `{}` },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := runCommand(&output, strings.NewReader(mutate(apiLoadTestArtifact())), []string{"api-load", "evaluate"}, "dev"); err == nil {
				t.Fatal("invalid evidence passed")
			}
			if output.Len() != 0 {
				t.Fatalf("invalid evidence emitted report: %s", output.Bytes())
			}
		})
	}
}

func TestAPILoadMaximumWallClockIncludesDrain(t *testing.T) {
	var value apiLoadMeasurement
	if err := decodeAPILoad(strings.NewReader(apiLoadTestArtifact()), &value); err != nil {
		t.Fatal(err)
	}
	value.Scenario.DurationSeconds = 300
	value.Scenario.RequestsPerSecond = 1
	value.Samples = make([]apiLoadSample, 300)
	for i := range value.Samples {
		value.Samples[i] = apiLoadSample{Index: i, Outcome: "ok", Status: 200, LatencyNS: 1_000_000}
	}
	value.ElapsedNS = int64(300 * time.Second)
	if _, err := evaluateAPILoadMeasurement(value); err != nil {
		t.Fatalf("exact bound rejected: %v", err)
	}
	value.ElapsedNS++
	if _, err := evaluateAPILoadMeasurement(value); err == nil {
		t.Fatal("run beyond five-minute wall clock passed")
	}
}

func TestAPILoadHTTPFailuresAndClientCapacityCannotPass(t *testing.T) {
	var leaked atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer receiver.Close()
	for _, mode := range []string{"unauthorized", "redirect", "html", "oversize", "capacity", "timeout", "unexpected2xx", "invalid_record"} {
		t.Run(mode, func(t *testing.T) {
			var active atomic.Int32
			server, args := apiLoadTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if n := active.Add(1); mode == "capacity" && n > 1 {
					t.Error("configured concurrency exceeded")
				}
				defer active.Add(-1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				switch mode {
				case "unexpected2xx":
					w.WriteHeader(201)
				case "invalid_record":
					_, _ = w.Write([]byte(`{"items":[null,42,{}],"page_info":{"has_more":false,"next_cursor":null}}`))
				case "unauthorized":
					w.WriteHeader(401)
				case "redirect":
					w.Header().Set("Location", receiver.URL)
					w.WriteHeader(302)
				case "html":
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<html>sign in</html>"))
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
				case "capacity":
					select {
					case <-time.After(120 * time.Millisecond):
						_, _ = w.Write([]byte(`{"items":[],"page_info":{"has_more":false,"next_cursor":null}}`))
					case <-r.Context().Done():
					}
				case "timeout":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			var fixture apiLoadMeasurement
			if err := decodeAPILoad(strings.NewReader(apiLoadTestArtifact()), &fixture); err != nil {
				t.Fatal(err)
			}
			fixture.Scenario.DurationSeconds = 1
			if mode == "capacity" {
				fixture.Scenario.Concurrency = 1
			}
			fixture.Scenario.RequestTimeoutMS = 100
			if mode == "capacity" {
				fixture.Scenario.RequestTimeoutMS = 500
			}
			input, _ := json.Marshal(fixture.Scenario)
			var output bytes.Buffer
			if err := runCommand(&output, bytes.NewReader(input), args, "dev"); err == nil {
				t.Fatal("failed real requests passed")
			}
			var measured apiLoadMeasurement
			if err := decodeAPILoad(bytes.NewReader(output.Bytes()), &measured); err != nil {
				t.Fatalf("failure artifact lost: %s %v", output.Bytes(), err)
			}
			report, err := evaluateAPILoadMeasurement(measured)
			if err == nil || report.Requests != 20 {
				t.Fatalf("bad failure accounting %#v %v", report, err)
			}
			if mode == "capacity" && report.Outcomes["capacity"] == 0 {
				t.Fatal("capacity omissions lost")
			}
			if leaked.Load() != 0 {
				t.Fatal("redirect sent traffic or credentials to another origin")
			}
		})
	}
}

func TestAPILoadCancellationWaitsForActiveRequestsAndRetainsUnsentSamples(t *testing.T) {
	server, args := apiLoadTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client, err := NewRecoveryClient(RecoveryClientConfig{Endpoint: args[3], CredentialFile: args[5], CABundleFile: args[7], Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var fixture apiLoadMeasurement
	if err = decodeAPILoad(strings.NewReader(apiLoadTestArtifact()), &fixture); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	measurement, err := measureAPILoad(ctx, fixture.Scenario, client)
	if err != nil || !measurement.Interrupted || len(measurement.Samples) != 100 || time.Since(started) > time.Second {
		t.Fatalf("cancel did not stop/drain run: %#v %v", measurement, err)
	}
	report, err := evaluateAPILoadMeasurement(measurement)
	if err == nil || report.Outcomes["cancelled"] < 90 || report.Requests != 100 {
		t.Fatalf("canceled samples disappeared: %#v %v", report, err)
	}
}

func TestAPILoadLintReturnsExecutableBoundsWithoutNetworkConfiguration(t *testing.T) {
	var fixture apiLoadMeasurement
	if err := decodeAPILoad(strings.NewReader(apiLoadTestArtifact()), &fixture); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(fixture.Scenario)
	var output bytes.Buffer
	if err := runCommand(&output, bytes.NewReader(encoded), []string{"api-load", "lint"}, "dev"); err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Paths          []string `json:"paths"`
		Requests       int      `json:"requests"`
		P95LimitNS     int64    `json:"p95_limit_ns"`
		ErrorRateLimit float64  `json:"error_rate_limit"`
	}
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Paths) != 4 || plan.Paths[0] != "/api/v1/agents?limit=50" || plan.Requests != 100 || plan.P95LimitNS != 750_000_000 || plan.ErrorRateLimit != 0.01 {
		t.Fatalf("wrong linted executable plan %s", output.Bytes())
	}
	output.Reset()
	if err := runCommand(&output, strings.NewReader(""), []string{"api-load", "help"}, "dev"); err != nil || !strings.Contains(output.String(), "--credential-file") {
		t.Fatalf("missing CLI usage: %v %s", err, output.Bytes())
	}
}

func TestAPILoadRejectsObservationCompletingAfterMeasurement(t *testing.T) {
	var value apiLoadMeasurement
	if err := decodeAPILoad(strings.NewReader(apiLoadTestArtifact()), &value); err != nil {
		t.Fatal(err)
	}
	value.ElapsedNS = 5_000_000_000
	if _, err := evaluateAPILoadMeasurement(value); err == nil {
		t.Fatal("sample completes at5.05s but artifact ends at5s")
	}
}
