package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestLineageConsumerDaemonTokenReadChecksEveryAttempt(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "symlink", "hardlink", "permissive", "wrong-owner", "malformed", "oversize", "closed"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			reader, err := newTokenReader(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			owner := uint32(os.Geteuid())
			if kind != "missing" {
				writeSensorFixture(t, path, fixtureAgentToken(), 0600)
			}
			switch kind {
			case "symlink":
				target := filepath.Join(t.TempDir(), "saved")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			case "permissive":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner++
			case "malformed":
				writeSensorFixture(t, path, strings.Repeat("!", 81), 0600)
			case "oversize":
				writeSensorFixture(t, path, fixtureAgentToken()+"x", 0600)
			case "closed":
				reader.Close()
			}
			raw, err := readLineageToken(reader, owner)
			defer clear(raw)
			if kind == "valid" {
				if err != nil || string(raw) != fixtureAgentToken() {
					t.Fatal("valid token rejected", err)
				}
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
				dependencies := sensorAgentDependencies{token: reader, Lineage: &lineageConsumerRuntime{}}
				rotated, err := dependencies.ReadToken()
				clear(rotated)
				if err == nil {
					t.Fatal("later read bypassed strict ownership/mode admission")
				}
			} else if err == nil || len(raw) != 0 {
				t.Fatal("unsafe token returned")
			}
		})
	}
}

type lineageReadinessBody struct {
	io.Reader
	closed bool
}

func (body *lineageReadinessBody) Close() error { body.closed = true; return nil }

func TestLineageConsumerDaemonReadinessIsBoundedAndCredentialless(t *testing.T) {
	for _, kind := range []string{"ready", "newline", "unavailable", "malformed", "oversize", "encoded", "response-error"} {
		t.Run(kind, func(t *testing.T) {
			body := &lineageReadinessBody{Reader: strings.NewReader(`{"status":"ready"}`)}
			daemon := &lineageConsumerRuntime{readyDo: func(request *http.Request) (*http.Response, error) {
				deadline, ok := request.Context().Deadline()
				if !ok || time.Until(deadline) > time.Second || request.URL.String() != "http://127.0.0.1:8082/readyz" || request.Method != http.MethodGet || len(request.Header) != 0 || request.Body != nil {
					t.Error("unbounded or credentialed producer request")
				}
				response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}
				switch kind {
				case "newline":
					body.Reader = strings.NewReader("{\"status\":\"ready\"}\n")
				case "unavailable":
					response.StatusCode = http.StatusServiceUnavailable
				case "malformed":
					body.Reader = strings.NewReader(`{"status":"healthy"}`)
				case "oversize":
					body.Reader = strings.NewReader(strings.Repeat("x", 129))
				case "encoded":
					response.Header.Set("Content-Encoding", "gzip")
				case "response-error":
					return response, errors.New("private transport detail")
				}
				return response, nil
			}}
			ready := daemon.producerReady(context.Background())
			if ready != (kind == "ready" || kind == "newline") || !body.closed {
				t.Fatal("readiness accepted bad response or leaked body", ready, body.closed)
			}
		})
	}
}

func TestLineageConsumerDaemonRejectsProtectedAncestorBeforeWrites(t *testing.T) {
	fixture, state, config := lineageSlotsFixture(t)
	config.Acknowledgments.Close()
	settings := lineageConsumerDaemonConfig(t, fixture.generation.spool.root.Name(), fixture.ackPath, state)
	protected, err := os.OpenRoot(filepath.Dir(state))
	if err != nil {
		t.Fatal(err)
	}
	defer protected.Close()
	dependencies, err := buildLineageConsumerDependencies(settings, nil, lineageProducerReadyFixture, uint32(os.Geteuid()), sensoradapter.PinnedInput{Parent: protected, Name: "token"})
	if err == nil {
		dependencies.Close()
		t.Fatal("protected ancestor accepted")
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected admission wrote consumer state", len(entries), err)
	}
}

func lineageConsumerDaemonConfig(t *testing.T, spool, acks, state string) sensorAgentConfig {
	t.Helper()
	config := fixtureAgentConfig(filepath.Join(t.TempDir(), "token"), "", "")
	config.Role = "lineage-consumer"
	config.TokenSource = "owned-file"
	config.SpoolDirectory, config.AckDirectory, config.StateDirectory = spool, acks, state
	config.EnrollmentBinding = strings.Repeat("b", 64)
	config.KernelFile = filepath.Join(t.TempDir(), "osrelease")
	config.BTFFile = filepath.Join(t.TempDir(), "vmlinux")
	writeSensorFixture(t, config.KernelFile, "6.8.1\n", 0444)
	writeSensorFixture(t, config.BTFFile, "btf", 0444)
	return config
}

func lineageProducerReadyFixture(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"status":"ready"}`))}, nil
}

func TestLineageConsumerDaemonBuildsWithoutTokenAndCleansUp(t *testing.T) {
	for _, source := range []string{"owned-file", "kubernetes-projected"} {
		t.Run(source, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			state := slots.root.Name()
			slots.Close()
			slots.config.Acknowledgments.Close()
			config := lineageConsumerDaemonConfig(t, fixture.generation.spool.root.Name(), fixture.ackPath, state)
			config.TokenSource = source
			requests := 0
			dependencies, err := buildLineageConsumerDependencies(config, func(*http.Request) (*http.Response, error) {
				requests++
				t.Error("credential-free cleanup called upload transport")
				return nil, nil
			}, lineageProducerReadyFixture, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal("missing token prevented startup", err)
			}
			defer dependencies.Close()
			if result, err := dependencies.Runtime.ProcessAvailable(context.Background()); err != nil || !result.Idle || requests != 0 {
				t.Fatal("cleanup without credentials", result, err)
			}
			if _, err := os.Lstat(filepath.Join(state, lineageSlotCursor(assignment.Slot))); !os.IsNotExist(err) {
				t.Fatal("checkpoint wasn't retired", err)
			}
			if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
				t.Fatal(err)
			}
			if _, err := dependencies.Runtime.ProcessAvailable(context.Background()); err != nil || requests != 0 {
				t.Fatal("release without credentials", err)
			}
			if entries, err := os.ReadDir(state); err != nil || len(entries) != 3 {
				t.Fatal("slot history remains", len(entries), err)
			}
		})
	}
}

func TestLineageConsumerProjectedTokenConfiguration(t *testing.T) {
	config := lineageConsumerDaemonConfig(t, "/spool", "/acks", "/state")
	config.TokenSource = "kubernetes-projected"
	if !validSensorAgentConfig(config) {
		t.Fatal("projected mode rejected")
	}
	config.TokenFile = filepath.Join(filepath.Dir(config.TokenFile), "alternate")
	if validSensorAgentConfig(config) {
		t.Fatal("noncanonical projected key accepted")
	}
	legacy := fixtureAgentConfig("/credentials/token", "/events/stream", "/state/cursor")
	legacy.TokenSource = "kubernetes-projected"
	if validSensorAgentConfig(legacy) {
		t.Fatal("legacy consumer accepted projected mode")
	}
}

func TestLineageConsumerDaemonRequiresExplicitDistinctDirectories(t *testing.T) {
	env := validSensorAgentEnvironment()
	env["ZASP_SENSOR_ROLE"] = "lineage-consumer"
	env["ZASP_SENSOR_TOKEN_SOURCE"] = "owned-file"
	delete(env, "ZASP_TETRAGON_LOG_FILE")
	delete(env, "ZASP_SENSOR_CURSOR_FILE")
	env["ZASP_LINEAGE_SPOOL_DIRECTORY"] = "/var/lib/zasp/producer"
	env["ZASP_LINEAGE_ACK_DIRECTORY"] = "/var/lib/zasp/acks"
	env["ZASP_LINEAGE_STATE_DIRECTORY"] = "/var/lib/zasp/consumer"
	if _, err := loadSensorAgentConfig(func(key string) string { return env[key] }); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ key, value string }{
		{"ZASP_SENSOR_TOKEN_SOURCE", ""},
		{"ZASP_SENSOR_TOKEN_SOURCE", "unknown"},
		{"ZASP_LINEAGE_STATE_DIRECTORY", ""},
		{"ZASP_LINEAGE_STATE_DIRECTORY", "/var/lib/zasp/producer"},
		{"ZASP_LINEAGE_STATE_DIRECTORY", "/var/run/secrets/zasp-sensor"},
		{"ZASP_SENSOR_CURSOR_FILE", "/var/lib/zasp/cursor.json"},
		{"ZASP_TETRAGON_LOG_FILE", "/var/run/cilium/tetragon/tetragon.log"},
		{"ZASP_SENSOR_ROLE", "unknown"},
	} {
		t.Run(change.key+"="+change.value, func(t *testing.T) {
			changed := cloneEnvironment(env)
			changed[change.key] = change.value
			if _, err := loadSensorAgentConfig(func(key string) string { return changed[key] }); err == nil {
				t.Fatal("unsafe lineage consumer configuration accepted")
			}
		})
	}
}

func TestLineageConsumerDaemonCleansUpBeforeReportingDeadProducer(t *testing.T) {
	fixture, slots, assignment := lineageRetiringSlotFixture(t)
	state := slots.root.Name()
	slots.Close()
	slots.config.Acknowledgments.Close()
	config := lineageConsumerDaemonConfig(t, fixture.generation.spool.root.Name(), fixture.ackPath, state)
	dependencies, err := buildLineageConsumerDependencies(config, func(*http.Request) (*http.Response, error) {
		t.Error("cleanup requested an upload credential")
		return nil, errSensorRuntime
	}, func(request *http.Request) (*http.Response, error) {
		response, err := lineageProducerReadyFixture(request)
		response.StatusCode = http.StatusServiceUnavailable
		return response, err
	}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.Close()
	coordinator := &recordingClusterReporter{}
	processor := &clusteredAgentProcessor{
		nodeName: "node-a", stream: dependencies.Runtime, preserveKnownDrops: true,
		probe: nodeReporterFunc(func(_ context.Context, stream sensoradapter.StreamResult) (NodeReport, error) {
			return NodeReport{NodeName: "node-a", ObservedAt: time.Now(), Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.1", BTF: true, Drops: stream.Dropped}, nil
		}), coordinator: coordinator,
	}
	result, err := processor.ProcessAvailable(context.Background())
	if err == nil || result.Dropped != 0 || coordinator.calls != 1 || coordinator.report.Status != "degraded" || coordinator.report.Drops != 0 {
		t.Fatal("producer failure invented event loss or wasn't reported", result, coordinator.report, err)
	}
	if _, err := os.Lstat(filepath.Join(state, lineageSlotCursor(assignment.Slot))); !os.IsNotExist(err) {
		t.Fatal("dead producer gated checkpoint retirement", err)
	}
}
