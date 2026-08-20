package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
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

func fixtureAgentConfig(token, log, cursor string) sensorAgentConfig {
	return sensorAgentConfig{ControlPlaneURL: "https://runtime.example.test", TokenFile: token, LogFile: log, CursorFile: cursor, BatchSize: 100, MaximumProcesses: 1000, PollInterval: time.Second, OperationTimeout: time.Second, ShutdownTimeout: 5 * time.Second}
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
