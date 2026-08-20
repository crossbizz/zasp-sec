package main

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestLocalSensorProbeReportsExactKernelBTFRateAndDrops(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	kernel := filepath.Join(directory, "kernel")
	btf := filepath.Join(directory, "vmlinux")
	writeSensorFixture(t, kernel, "6.8.1\n", 0o444)
	writeSensorFixture(t, btf, "btf", 0o444)
	probe, err := NewLocalSensorProbe(LocalSensorProbeConfig{NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "http://10.0.0.8:2112/metrics", PollInterval: time.Second, Do: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "http://10.0.0.8:2112/metrics" {
			t.Fatalf("request=%#v", request)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain; version=0.0.4"}}, Body: io.NopCloser(strings.NewReader(tetragonMetricsFixture()))}, nil
	}, Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatalf("NewLocalSensorProbe: %v", err)
	}
	report, err := probe.Report(context.Background(), sensoradapter.StreamResult{Read: 7, Submitted: 7, Dropped: 2})
	if err != nil || report.NodeName != "node-a" || report.Status != "degraded" || report.Kernel != "6.8.1" || !report.BTF || report.EventRate != 7 || report.Drops != 5 || !reflect.DeepEqual(report.Capabilities, []string{"file", "network", "process"}) {
		t.Fatalf("Report=%#v,%v", report, err)
	}
}

func TestLocalSensorProbeFailsDegradedWithoutLeakingMetricsOrBlockingHeartbeat(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	kernel := filepath.Join(directory, "kernel")
	btf := filepath.Join(directory, "missing")
	writeSensorFixture(t, kernel, "6.8.1\n", 0o444)
	probe, err := NewLocalSensorProbe(LocalSensorProbeConfig{NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "http://10.0.0.8:2112/metrics", PollInterval: time.Second, Do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("provider-secret"))}, nil
	}, Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatalf("NewLocalSensorProbe:%v", err)
	}
	report, err := probe.Report(context.Background(), sensoradapter.StreamResult{Dropped: 1})
	if err == nil || strings.Contains(err.Error(), "secret") || report.Status != "degraded" || report.BTF || report.Drops != 1 || !reflect.DeepEqual(report.Capabilities, []string{"process"}) {
		t.Fatalf("Report=%#v,%v", report, err)
	}
}

func TestLocalSensorProbeRejectsMalformedMetricsAndUnsafeConfig(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	kernel := filepath.Join(directory, "kernel")
	btf := filepath.Join(directory, "btf")
	writeSensorFixture(t, kernel, "6.8.1\n", 0o444)
	writeSensorFixture(t, btf, "btf", 0o444)
	for name, body := range map[string]string{"missing": strings.Replace(tetragonMetricsFixture(), "tetragon_observer_ringbuf_errors_total 1\n", "", 1), "negative": strings.Replace(tetragonMetricsFixture(), "events_lost_total 1", "events_lost_total -1", 1), "fraction": strings.Replace(tetragonMetricsFixture(), "errors_total 1", "errors_total 1.5", 1), "duplicate": tetragonMetricsFixture() + "tetragon_observer_ringbuf_errors_total 1\n", "oversized": strings.Repeat("x", maximumTetragonMetricsBytes+1)} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			probe, _ := NewLocalSensorProbe(LocalSensorProbeConfig{NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "http://10.0.0.8:2112/metrics", PollInterval: time.Second, Do: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			}, Now: time.Now})
			if _, err := probe.Report(context.Background(), sensoradapter.StreamResult{}); err == nil {
				t.Fatal("malformed metrics accepted")
			}
		})
	}
	for name, config := range map[string]LocalSensorProbeConfig{"dns metrics": {NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "http://tetragon:2112/metrics", PollInterval: time.Second, Do: http.DefaultClient.Do, Now: time.Now}, "https metrics": {NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "https://10.0.0.8:2112/metrics", PollInterval: time.Second, Do: http.DefaultClient.Do, Now: time.Now}, "relative kernel": {NodeName: "node-a", KernelFile: "kernel", BTFFile: btf, MetricsURL: "http://10.0.0.8:2112/metrics", PollInterval: time.Second, Do: http.DefaultClient.Do, Now: time.Now}, "nil do": {NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "http://10.0.0.8:2112/metrics", PollInterval: time.Second, Now: time.Now}} {
		name, config := name, config
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if value, err := NewLocalSensorProbe(config); err == nil || value != nil {
				t.Fatalf("NewLocalSensorProbe=%#v,%v", value, err)
			}
		})
	}
}

func TestParseTetragonDropsIgnoresUnrelatedLabelsWithSpaces(t *testing.T) {
	t.Parallel()
	payload := "tetragon_missed_link_probes_total{attach=\"kprobe_multi security_file_permission\",policy=\"zasp-sensitive-file\"} 0\n" + tetragonMetricsFixture()
	if drops, err := parseTetragonDrops([]byte(payload)); err != nil || drops != 3 {
		t.Fatalf("parseTetragonDrops = %d, %v", drops, err)
	}
}

func tetragonMetricsFixture() string {
	return "# TYPE tetragon_export_ratelimit_events_dropped_total counter\n" +
		"tetragon_export_ratelimit_events_dropped_total 0\n" +
		"tetragon_notify_overflowed_events_total 0\n" +
		"tetragon_observer_ringbuf_errors_total 1\n" +
		"tetragon_observer_ringbuf_events_lost_total 1\n" +
		"tetragon_observer_ringbuf_queue_events_lost_total 1\n"
}
