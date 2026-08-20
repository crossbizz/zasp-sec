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
	return sensorAgentConfig{ControlPlaneURL: "https://runtime.example.test", TokenFile: token, LogFile: log, CursorFile: cursor, Namespace: "agentsec", PodName: "sensor-agent-a", NodeName: "node-a", KernelFile: "/proc/sys/kernel/osrelease", BTFFile: "/sys/kernel/btf/vmlinux", MetricsURL: "http://10.0.0.8:2112/metrics", BatchSize: 100, MaximumProcesses: 1000, PollInterval: time.Second, OperationTimeout: time.Second, ShutdownTimeout: 5 * time.Second, LeaseDuration: 15 * time.Second, ReportTTL: 30 * time.Second}
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
	return `{"process_exec":{"process":{"exec_id":"exec-1","pid":42,"uid":1000,"cwd":"/tmp","binary":"/usr/bin/agent","arguments":"","flags":"execve","start_time":"2026-08-20T12:00:00.000Z","auid":4294967295,"pod":{"namespace":"agentsec","name":"agent-a","uid":"11111111-2222-4333-8444-555555555555","container":{"id":"containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"agent","image":{"id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"agent:prod"},"start_time":"2026-08-20T11:59:00.000Z","pid":12,"security_context":{}},"pod_labels":{"app":"agent"},"workload":"agent-a","workload_kind":"Pod"},"docker":"aaaaaaaaaaaaaaaaaaaaaaaa","parent_exec_id":"parent-1","cap":{},"ns":{},"tid":42,"process_credentials":{},"in_init_tree":false}},"node_name":"node-a","time":"2026-08-20T12:00:00.000Z","cluster_name":"cluster-a","node_labels":{}}`
}
