package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func lineageDaemonEnvironment() map[string]string {
	return map[string]string{
		"ZASP_SENSOR_ROLE":                "lineage-producer",
		"ZASP_LINEAGE_SPOOL_DIRECTORY":    "/var/lib/zasp/producer",
		"ZASP_LINEAGE_ACK_DIRECTORY":      "/var/lib/zasp/acknowledgments",
		"ZASP_TETRAGON_SOCKET":            "/var/run/tetragon/tetragon.sock",
		"ZASP_HOST_BOOT_ID_FILE":          "/host/proc/sys/kernel/random/boot_id",
		"ZASP_SENSOR_NODE_NAME":           "node-a",
		"ZASP_SENSOR_ENROLLMENT_BINDING":  strings.Repeat("b", 64),
		"ZASP_SENSOR_CONTROL_PLANE_URL":   "https://runtime.example.test",
		"ZASP_LINEAGE_CONSUMER_UID":       "65532",
		"ZASP_SENSOR_BATCH_SIZE":          "100",
		"ZASP_LINEAGE_FLUSH_INTERVAL":     "1s",
		"ZASP_LINEAGE_IDENTITY_INTERVAL":  "5s",
		"ZASP_LINEAGE_MAX_GENERATION_AGE": "5m0s",
		"ZASP_SENSOR_OPERATION_TIMEOUT":   "5s",
		"ZASP_SENSOR_POLL_INTERVAL":       "1s",
		"ZASP_SENSOR_SHUTDOWN_TIMEOUT":    "15s",
	}
}

func TestLineageProducerDaemonConfigHasNoProductCredential(t *testing.T) {
	env := lineageDaemonEnvironment()
	config, err := loadLineageProducerDaemonConfig(func(key string) string { return env[key] })
	if err != nil || config.Loop.Pump.MaximumDuration != 5*time.Minute || config.Loop.Scope.ConsumerUID != 65532 {
		t.Fatal(config, err)
	}
	for _, change := range []struct{ key, value string }{
		{"ZASP_SENSOR_TOKEN_FILE", "/secrets/product-token"},
		{"ZASP_SENSOR_ROLE", "consumer"},
		{"ZASP_LINEAGE_CONSUMER_UID", "0"},
		{"ZASP_LINEAGE_CONSUMER_UID", "-1"},
		{"ZASP_LINEAGE_CONSUMER_UID", "065532"},
		{"ZASP_LINEAGE_SPOOL_DIRECTORY", "/var/lib/zasp"},
		{"ZASP_LINEAGE_ACK_DIRECTORY", "/var/lib/zasp/producer"},
		{"ZASP_LINEAGE_SPOOL_DIRECTORY", "/var/run/secrets/kubernetes.io"},
		{"ZASP_TETRAGON_SOCKET", "/var/lib/zasp/producer/socket"},
		{"ZASP_LINEAGE_MAX_GENERATION_AGE", "0s"},
		{"ZASP_LINEAGE_MAX_GENERATION_AGE", "2h0m0s"},
		{"ZASP_SENSOR_POLL_INTERVAL", "50ms"},
		{"ZASP_SENSOR_CONTROL_PLANE_URL", "http://runtime.example.test"},
	} {
		t.Run(change.key+"="+change.value, func(t *testing.T) {
			env := lineageDaemonEnvironment()
			env[change.key] = change.value
			if _, err := loadLineageProducerDaemonConfig(func(key string) string { return env[key] }); err == nil {
				t.Fatal("unsafe producer configuration accepted")
			}
		})
	}
}

func TestLineageBoundSpoolRejectsReplacementBeforeLockCreation(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "spool")
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	pin, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	expected, err := pin.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(parent, "preserved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	if spool, err := newBoundLineageSpool(path, uint32(os.Geteuid()), expected); err == nil || spool != nil {
		t.Fatal("replaced admission accepted")
	}
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
		t.Fatal("producer wrote to replaced root", err)
	}
}

func TestSensorDaemonRunsHealthAndJoinsBeforeClosingDependencies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	listener := make(chan net.Listener, 1)
	running := make(chan struct{})
	var joined, closed atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- serveSensorDaemon(ctx, io.Discard, "test-v1", "sensor-lineage-producer", ":8082", time.Second, 10*time.Second, func(ctx context.Context, ticks <-chan time.Time, ready func(bool)) error {
			ready(true)
			close(running)
			<-ctx.Done()
			ready(false)
			joined.Store(true)
			return nil
		}, func() error {
			if !joined.Load() {
				t.Error("closed dependencies before runtime joined")
			}
			closed.Store(true)
			return nil
		}, func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != ":8082" {
				t.Error("producer listener mismatch")
			}
			opened, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				listener <- opened
			}
			return opened, err
		})
	}()
	var address net.Listener
	select {
	case address = <-listener:
	case <-ctx.Done():
		t.Fatal("listener not started")
	}
	select {
	case <-running:
	case <-ctx.Done():
		t.Fatal("runtime not started")
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + address.Addr().String() + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("producer not ready", response.StatusCode)
	}
	cancel()
	if err := <-done; err != nil || !closed.Load() {
		t.Fatal("daemon shutdown", err)
	}
}
