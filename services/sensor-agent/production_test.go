package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	corev1 "k8s.io/api/core/v1"
)

func TestBuildSensorAgentDependenciesUsesRegularRotatableTokenAndHardenedTransport(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tokenFile, logFile, cursorFile := filepath.Join(directory, "token"), filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeSensorFixture(t, tokenFile, fixtureAgentToken(), 0o600)
	writeSensorFixture(t, logFile, tetragonAgentFixture()+"\n", 0o600)
	config := fixtureAgentConfig(tokenFile, logFile, cursorFile)
	requests := 0
	dependencies, err := buildSensorAgentDependencies(config, func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("X-Zasp-Runtime-Schema") != "runtime-event-enrollment-v1" || request.Header.Get("X-Zasp-Expected-Enrollment") != strings.Repeat("a", 64) {
			t.Fatal("production construction did not bind the runtime request to its installation")
		}
		if request.URL.Scheme != "https" || request.Header.Get("Authorization") != "Bearer "+fixtureAgentToken() || request.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("request = %#v", request)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": []string{"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	})
	if err != nil {
		t.Fatalf("buildSensorAgentDependencies: %v", err)
	}
	t.Cleanup(func() { _ = dependencies.Close() })
	result, err := dependencies.Processor.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || requests != 1 {
		t.Fatalf("ProcessAvailable = %#v, %v, requests=%d", result, err, requests)
	}
	rotated := "zasp_sensor_v1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	writeSensorFixture(t, tokenFile, rotated, 0o600)
	if value, err := dependencies.ReadToken(); err != nil || string(value) != rotated {
		t.Fatalf("rotated token = %q, %v", value, err)
	}
}

func TestBuildSensorAgentDependenciesRejectsSymlinkOrPermissiveTokenBeforeProviderIO(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o644, 0o400} {
		directory := t.TempDir()
		tokenFile, logFile := filepath.Join(directory, "token"), filepath.Join(directory, "tetragon.log")
		writeSensorFixture(t, tokenFile, fixtureAgentToken(), mode)
		writeSensorFixture(t, logFile, "", 0o600)
		if dependencies, err := buildSensorAgentDependencies(fixtureAgentConfig(tokenFile, logFile, filepath.Join(directory, "cursor")), func(*http.Request) (*http.Response, error) { t.Fatal("provider called"); return nil, nil }); err == nil || dependencies != (sensorAgentDependencies{}) {
			t.Fatalf("mode %o = %#v, %v", mode, dependencies, err)
		}
	}
	directory := t.TempDir()
	target, link, logFile := filepath.Join(directory, "target"), filepath.Join(directory, "token"), filepath.Join(directory, "tetragon.log")
	writeSensorFixture(t, target, fixtureAgentToken(), 0o600)
	writeSensorFixture(t, logFile, "", 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if dependencies, err := buildSensorAgentDependencies(fixtureAgentConfig(link, logFile, filepath.Join(directory, "cursor")), func(*http.Request) (*http.Response, error) { t.Fatal("provider called"); return nil, nil }); err == nil || dependencies != (sensorAgentDependencies{}) {
		t.Fatalf("symlink = %#v, %v", dependencies, err)
	}
}

func TestBuildSensorAgentDependenciesRejectsExpiredRuntimeFixtureBeforeTransport(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tokenFile, logFile, cursorFile := filepath.Join(directory, "token"), filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeSensorFixture(t, tokenFile, fixtureAgentToken(), 0o600)
	writeSensorFixture(t, logFile, tetragonAgentFixtureAt(time.Now().UTC().Add(-25*time.Hour))+"\n", 0o600)
	dependencies, err := buildSensorAgentDependencies(fixtureAgentConfig(tokenFile, logFile, cursorFile), func(*http.Request) (*http.Response, error) {
		t.Fatal("expired event reached transport")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dependencies.Close() })
	if result, err := dependencies.Processor.ProcessAvailable(context.Background()); !errors.Is(err, sensoradapter.ErrEnvelopeExpired) || result != (sensoradapter.StreamResult{}) {
		t.Fatalf("expired fixture result=%+v error=%v", result, err)
	}
}

func TestSensorAgentRejectsReservedCheckpointInputCollisions(t *testing.T) {
	for _, input := range []string{"token", "kernel", "btf"} {
		for _, reserved := range sensoradapter.ReservedCursorNames("cursor.json") {
			for _, alias := range []bool{false, true} {
				name := input + "/" + reserved + "/direct"
				if alias {
					name = input + "/" + reserved + "/parent-alias"
				}
				t.Run(name, func(t *testing.T) {
					directory := t.TempDir()
					inputDirectory := directory
					if alias {
						inputDirectory = filepath.Join(t.TempDir(), "alias")
						if err := os.Symlink(directory, inputDirectory); err != nil {
							t.Fatal(err)
						}
					}
					inputPath := filepath.Join(inputDirectory, reserved)
					tokenPath := filepath.Join(directory, "token")
					logPath := filepath.Join(directory, "tetragon.log")
					cursorPath := filepath.Join(directory, "cursor.json")
					writeSensorFixture(t, tokenPath, fixtureAgentToken(), 0o600)
					writeSensorFixture(t, logPath, tetragonAgentFixture()+"\n", 0o600)
					config := fixtureAgentConfig(tokenPath, logPath, cursorPath)
					value := "configured input must survive"
					switch input {
					case "token":
						config.TokenFile, value = inputPath, fixtureAgentToken()
					case "kernel":
						config.KernelFile = inputPath
					case "btf":
						config.BTFFile = inputPath
					}
					writeSensorFixture(t, inputPath, value, 0o600)
					before, err := os.Stat(inputPath)
					if err != nil {
						t.Fatal(err)
					}
					dependencies, err := buildSensorAgentDependencies(config, func(*http.Request) (*http.Response, error) {
						t.Fatal("colliding input reached provider I/O")
						return nil, nil
					})
					if dependencies.Processor != nil {
						_ = dependencies.Close()
					}
					if err != errSensorRuntime || dependencies != (sensorAgentDependencies{}) {
						t.Fatal("reserved input was not rejected during construction", err)
					}
					after, statErr := os.Stat(inputPath)
					body, readErr := os.ReadFile(inputPath)
					if statErr != nil || readErr != nil || !os.SameFile(before, after) || string(body) != value {
						t.Fatal("rejected input changed", statErr, readErr)
					}
					for _, slot := range sensoradapter.ReservedCursorNames("cursor.json") {
						if slot == reserved {
							continue
						}
						if _, err := os.Lstat(filepath.Join(directory, slot)); !os.IsNotExist(err) {
							t.Fatal("rejected configuration created cursor state", slot, err)
						}
					}
					// Identical basenames in separate directories remain valid.
					config.CursorFile = filepath.Join(t.TempDir(), "cursor.json")
					dependencies, err = buildSensorAgentDependencies(config, func(*http.Request) (*http.Response, error) {
						t.Fatal("construction called provider")
						return nil, nil
					})
					if err != nil {
						t.Fatal("disjoint input was rejected", err)
					}
					if err := dependencies.Close(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestSensorAgentBoundInstallationReplaysAfterRestartWithRotatedToken(t *testing.T) {
	directory := t.TempDir()
	tokenFile, logFile, cursorFile := filepath.Join(directory, "token"), filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	now := time.Now().UTC().Add(-time.Second)
	firstLine := tetragonAgentFixtureAt(now) + "\n"
	writeSensorFixture(t, tokenFile, fixtureAgentToken(), 0o600)
	writeSensorFixture(t, logFile, firstLine, 0o600)
	config := fixtureAgentConfig(tokenFile, logFile, cursorFile)
	var bodies [][]byte
	transport := func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		checkpoint, err := os.ReadFile(cursorFile)
		if err != nil || !bytes.Contains(checkpoint, []byte(base64.StdEncoding.EncodeToString(body))) || bytes.Contains(checkpoint, []byte("zasp_sensor_v1.")) || request.Header.Get("X-Zasp-Expected-Enrollment") != config.EnrollmentBinding {
			t.Fatal("request was not durably frozen for the installation before transport", err)
		}
		if len(bodies) == 1 {
			return nil, sensoradapter.ErrClientRetryable
		}
		if request.Header.Get("Authorization") == "Bearer "+fixtureAgentToken() {
			t.Fatal("restarted sensor reused the old credential")
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": []string{"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	}
	first, err := buildSensorAgentDependencies(config, transport)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := first.Processor.ProcessAvailable(context.Background()); err != sensoradapter.ErrClientRetryable || result != (sensoradapter.StreamResult{}) {
		t.Fatal("uncertain request did not remain pending", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	rotated := "zasp_sensor_v1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	writeSensorFixture(t, tokenFile, rotated, 0o600)
	writeSensorFixture(t, logFile, firstLine+tetragonAgentFixtureAt(now.Add(500*time.Millisecond))+"\n", 0o600)
	// A token replacement cannot replace the enrollment pinned in old state.
	drift := config
	drift.EnrollmentBinding = strings.Repeat("b", 64)
	wrong, err := buildSensorAgentDependencies(drift, func(*http.Request) (*http.Response, error) {
		t.Fatal("changed enrollment reached transport")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cursorFile)
	if _, err := wrong.Processor.ProcessAvailable(context.Background()); err != sensoradapter.ErrStream {
		t.Fatal("changed installation accepted pending work", err)
	}
	if err := wrong.Close(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(cursorFile)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected installation changed pending state")
	}
	restarted, err := buildSensorAgentDependencies(config, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	for i := 0; i < 2; i++ {
		if result, err := restarted.Processor.ProcessAvailable(context.Background()); err != nil || result.Read != 1 || result.Submitted != 1 {
			t.Fatal("restart did not separate pending and appended input", result, err)
		}
	}
	if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[1]) || bytes.Equal(bodies[1], bodies[2]) {
		t.Fatal("restart regrouped or rewrote pending work")
	}
}

func TestBuildClusteredSensorAgentDependenciesWiresExactEventProbeAndHeartbeat(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tokenFile, logFile, cursorFile := filepath.Join(directory, "token"), filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	kernelFile, btfFile := filepath.Join(directory, "kernel"), filepath.Join(directory, "vmlinux")
	writeSensorFixture(t, tokenFile, fixtureAgentToken(), 0o600)
	writeSensorFixture(t, logFile, tetragonAgentFixture()+"\n", 0o600)
	writeSensorFixture(t, kernelFile, "6.8.1\n", 0o444)
	writeSensorFixture(t, btfFile, "btf", 0o444)
	config := fixtureAgentConfig(tokenFile, logFile, cursorFile)
	config.KernelFile, config.BTFFile = kernelFile, btfFile
	api := newMemoryClusterAPI([]corev1.Pod{readyTetragonPod("tetragon-a", "node-a")})
	paths := make([]string, 0, 2)
	dependencies, err := buildClusteredSensorAgentDependencies(config, api, func(request *http.Request) (*http.Response, error) {
		paths = append(paths, request.URL.Path)
		status, body := http.StatusNoContent, ""
		if request.URL.Path == "/internal/v1/runtime/events" {
			status, body = http.StatusAccepted, `{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Cache-Control": []string{"no-store"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	}, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(tetragonMetricsFixture()))}, nil
	})
	if err != nil {
		t.Fatalf("buildClusteredSensorAgentDependencies: %v", err)
	}
	t.Cleanup(func() { _ = dependencies.Close() })
	result, err := dependencies.Runtime.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || !reflect.DeepEqual(paths, []string{"/internal/v1/runtime/events", "/internal/v1/sensor/heartbeat"}) {
		t.Fatalf("ProcessAvailable = %#v, %v, paths=%v", result, err, paths)
	}
}

func TestRunSensorAgentLoopUpdatesReadinessAndStopsWithoutBusyPolling(t *testing.T) {
	t.Parallel()
	processor := &scriptedAgentProcessor{results: []agentProcessResult{{result: sensoradapter.StreamResult{Idle: true}}, {err: sensoradapter.ErrClientRetryable}, {result: sensoradapter.StreamResult{Submitted: 1}}}}
	ready := make([]bool, 0, 3)
	ticks := make(chan time.Time, 3)
	ticks <- time.Now()
	ticks <- time.Now()
	close(ticks)
	ctx, cancel := context.WithCancel(context.Background())
	err := runSensorAgentLoop(ctx, processor, ticks, func(value bool) {
		ready = append(ready, value)
		if len(ready) == 3 {
			cancel()
		}
	})
	if err != nil || processor.calls != 3 || !reflect.DeepEqual(ready, []bool{true, false, true}) {
		t.Fatalf("runSensorAgentLoop = %v, calls=%d, ready=%v", err, processor.calls, ready)
	}
}

func TestRunSensorAgentLoopContainsProcessorPanic(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	processor := agentProcessorFunc(func(context.Context) (sensoradapter.StreamResult, error) { cancel(); panic("provider-secret") })
	ready := []bool{}
	if err := runSensorAgentLoop(ctx, processor, make(chan time.Time), func(value bool) { ready = append(ready, value) }); err != nil || !reflect.DeepEqual(ready, []bool{false}) {
		t.Fatalf("runSensorAgentLoop = %v, ready=%v", err, ready)
	}
}

func TestClusteredAgentProcessorReportsEveryNodeAndDegradesFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		streamErr  error
		probeErr   error
		clusterErr error
		wantErr    bool
		wantStatus string
		wantDrops  uint64
	}{
		"healthy":         {wantStatus: "healthy"},
		"stream failure":  {streamErr: sensoradapter.ErrClientRetryable, wantErr: true, wantStatus: "degraded", wantDrops: 1},
		"probe failure":   {probeErr: ErrProbeRetryable, wantErr: true, wantStatus: "degraded"},
		"cluster failure": {clusterErr: ErrClusterRetryable, wantErr: true, wantStatus: "healthy"},
	} {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			coordinator := &recordingClusterReporter{err: test.clusterErr}
			processor := &clusteredAgentProcessor{
				nodeName: "node-a",
				stream: agentProcessorFunc(func(context.Context) (sensoradapter.StreamResult, error) {
					return sensoradapter.StreamResult{Read: 1, Submitted: 1}, test.streamErr
				}),
				probe: nodeReporterFunc(func(context.Context, sensoradapter.StreamResult) (NodeReport, error) {
					return NodeReport{NodeName: "node-a", ObservedAt: now, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.0", BTF: true}, test.probeErr
				}),
				coordinator: coordinator,
			}
			result, err := processor.ProcessAvailable(context.Background())
			if (err != nil) != test.wantErr || result.Submitted != 1 || coordinator.calls != 1 || coordinator.report.Status != test.wantStatus || coordinator.report.Drops != test.wantDrops {
				t.Fatalf("ProcessAvailable = %#v, %v, calls=%d, report=%#v", result, err, coordinator.calls, coordinator.report)
			}
		})
	}
}

func TestClusteredAgentProcessorContainsProbeAndCoordinatorPanics(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		probe       localNodeReporter
		coordinator clusterReporter
	}{
		"probe": {probe: nodeReporterFunc(func(context.Context, sensoradapter.StreamResult) (NodeReport, error) { panic("provider-secret") }), coordinator: &recordingClusterReporter{}},
		"coordinator": {probe: nodeReporterFunc(func(context.Context, sensoradapter.StreamResult) (NodeReport, error) {
			return NodeReport{Status: "healthy", Capabilities: []string{"process"}, Kernel: "6.8.0"}, nil
		}), coordinator: clusterReporterFunc(func(context.Context, NodeReport) error { panic("cluster-secret") })},
	} {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			processor := &clusteredAgentProcessor{nodeName: "node-a", stream: agentProcessorFunc(func(context.Context) (sensoradapter.StreamResult, error) {
				return sensoradapter.StreamResult{Idle: true}, nil
			}), probe: test.probe, coordinator: test.coordinator}
			if _, err := processor.ProcessAvailable(context.Background()); !errors.Is(err, errSensorRuntime) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("ProcessAvailable = %v", err)
			}
		})
	}
}

type agentProcessResult struct {
	result sensoradapter.StreamResult
	err    error
}
type scriptedAgentProcessor struct {
	calls   int
	results []agentProcessResult
}

func (value *scriptedAgentProcessor) ProcessAvailable(context.Context) (sensoradapter.StreamResult, error) {
	item := value.results[value.calls]
	value.calls++
	return item.result, item.err
}

type agentProcessorFunc func(context.Context) (sensoradapter.StreamResult, error)

func (function agentProcessorFunc) ProcessAvailable(ctx context.Context) (sensoradapter.StreamResult, error) {
	return function(ctx)
}

type nodeReporterFunc func(context.Context, sensoradapter.StreamResult) (NodeReport, error)

func (function nodeReporterFunc) Report(ctx context.Context, result sensoradapter.StreamResult) (NodeReport, error) {
	return function(ctx, result)
}

type clusterReporterFunc func(context.Context, NodeReport) error

func (function clusterReporterFunc) Tick(ctx context.Context, report NodeReport) error {
	return function(ctx, report)
}

type recordingClusterReporter struct {
	calls  int
	report NodeReport
	err    error
}

func (reporter *recordingClusterReporter) Tick(_ context.Context, report NodeReport) error {
	reporter.calls++
	reporter.report = report
	return reporter.err
}

func fixtureAgentConfig(token, log, cursor string) sensorAgentConfig {
	return sensorAgentConfig{ControlPlaneURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), TokenFile: token, LogFile: log, CursorFile: cursor, Namespace: "agentsec", PodName: "sensor-agent-a", NodeName: "node-a", KernelFile: "/proc/sys/kernel/osrelease", BTFFile: "/sys/kernel/btf/vmlinux", MetricsURL: "http://10.0.0.8:2112/metrics", BatchSize: 100, MaximumProcesses: 1000, PollInterval: time.Second, OperationTimeout: time.Second, ShutdownTimeout: 5 * time.Second, LeaseDuration: 15 * time.Second, ReportTTL: 30 * time.Second}
}
func fixtureAgentToken() string {
	return "zasp_sensor_v1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
}
func writeSensorFixture(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
}
func tetragonAgentFixture() string {
	// Production dependencies use the real clock. A fixed historical event turns
	// these successful-ingest wiring tests into accidental freshness rejections.
	return tetragonAgentFixtureAt(time.Now().UTC().Add(-time.Second))
}

func tetragonAgentFixtureAt(when time.Time) string {
	body := `{"process_exec":{"process":{"exec_id":"exec-1","pid":42,"uid":1000,"cwd":"/tmp","binary":"/usr/bin/agent","arguments":"","flags":"execve","start_time":"2026-08-20T12:00:00.000Z","auid":4294967295,"pod":{"namespace":"agentsec","name":"agent-a","uid":"11111111-2222-4333-8444-555555555555","container":{"id":"containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"agent","image":{"id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"agent:prod"},"start_time":"2026-08-20T11:59:00.000Z","pid":12,"security_context":{}},"pod_labels":{"app":"agent"},"workload":"agent-a","workload_kind":"Pod"},"docker":"aaaaaaaaaaaaaaaaaaaaaaaa","parent_exec_id":"parent-1","cap":{},"ns":{},"tid":42,"process_credentials":{},"in_init_tree":false}},"node_name":"node-a","time":"2026-08-20T12:00:00.000Z","cluster_name":"cluster-a","node_labels":{}}`
	body = strings.ReplaceAll(body, "2026-08-20T12:00:00.000Z", when.UTC().Format("2006-01-02T15:04:05.000Z"))
	return strings.ReplaceAll(body, "2026-08-20T11:59:00.000Z", when.UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000Z"))
}
