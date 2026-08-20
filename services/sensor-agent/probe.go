package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

const maximumTetragonMetricsBytes = 1 << 20

var (
	ErrProbe            = errors.New("sensor probe rejected")
	ErrProbeRetryable   = errors.New("sensor probe temporarily unavailable")
	tetragonDropMetrics = []string{
		"tetragon_export_ratelimit_events_dropped_total",
		"tetragon_notify_overflowed_events_total",
		"tetragon_observer_ringbuf_errors_total",
		"tetragon_observer_ringbuf_events_lost_total",
		"tetragon_observer_ringbuf_queue_events_lost_total",
	}
)

type LocalSensorProbeConfig struct {
	NodeName     string
	KernelFile   string
	BTFFile      string
	MetricsURL   string
	PollInterval time.Duration
	Do           func(*http.Request) (*http.Response, error)
	Now          func() time.Time
}

type LocalSensorProbe struct {
	mu           sync.Mutex
	config       LocalSensorProbeConfig
	adapterDrops uint64
}

func NewLocalSensorProbe(config LocalSensorProbeConfig) (*LocalSensorProbe, error) {
	parsed, err := url.Parse(config.MetricsURL)
	host := net.ParseIP(parsed.Hostname())
	if err != nil || parsed.Scheme != "http" || host == nil || parsed.Port() != "2112" || parsed.Path != "/metrics" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !validKubernetesName(config.NodeName) || !validAbsolute(config.KernelFile) || !validAbsolute(config.BTFFile) || config.KernelFile == config.BTFFile || config.PollInterval < 50*time.Millisecond || config.PollInterval > 30*time.Second || config.Do == nil || config.Now == nil {
		return nil, ErrProbe
	}
	if _, ok := clusterNow(config.Now); !ok {
		return nil, ErrProbe
	}
	return &LocalSensorProbe{config: config}, nil
}

func (probe *LocalSensorProbe) Report(ctx context.Context, result sensoradapter.StreamResult) (NodeReport, error) {
	if probe == nil || ctx == nil || ctx.Err() != nil || result.Read < 0 || result.Submitted < 0 || result.Submitted > result.Read {
		return NodeReport{}, ErrProbeRetryable
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	now, ok := clusterNow(probe.config.Now)
	if !ok {
		return NodeReport{}, ErrProbeRetryable
	}
	if ^uint64(0)-probe.adapterDrops < result.Dropped {
		probe.adapterDrops = 1_000_000_000
	} else {
		probe.adapterDrops += result.Dropped
	}
	if probe.adapterDrops > 1_000_000_000 {
		probe.adapterDrops = 1_000_000_000
	}
	kernel, kernelErr := readProbeText(probe.config.KernelFile, 128)
	btfErr := validateBTFFile(probe.config.BTFFile)
	providerDrops, metricsErr := probe.readTetragonDrops(ctx)
	totalDrops := probe.adapterDrops
	if providerDrops > 1_000_000_000-totalDrops {
		totalDrops = 1_000_000_000
	} else {
		totalDrops += providerDrops
	}
	rate := uint64(result.Submitted)
	if rate > 1_000_000_000 {
		rate = 1_000_000_000
	} else if probe.config.PollInterval != time.Second {
		if rate > uint64(1_000_000_000)*uint64(probe.config.PollInterval)/uint64(time.Second) {
			rate = 1_000_000_000
		} else {
			rate = rate * uint64(time.Second) / uint64(probe.config.PollInterval)
		}
	}
	report := NodeReport{NodeName: probe.config.NodeName, ObservedAt: now, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: kernel, BTF: btfErr == nil, EventRate: rate, Drops: totalDrops}
	if report.Kernel == "" {
		report.Kernel = "unknown"
	}
	if kernelErr != nil || btfErr != nil || metricsErr != nil {
		report.Status = "degraded"
		report.Capabilities = []string{"process"}
	} else if totalDrops > 0 {
		report.Status = "degraded"
	}
	if kernelErr != nil || btfErr != nil || metricsErr != nil {
		return report, ErrProbeRetryable
	}
	return report, nil
}

func (probe *LocalSensorProbe) readTetragonDrops(ctx context.Context) (uint64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.config.MetricsURL, nil)
	if err != nil {
		return 0, ErrProbeRetryable
	}
	request.Header.Set("Accept", "text/plain")
	response, err := safeProbeDo(probe.config.Do, request)
	if err != nil || response == nil || response.Body == nil {
		return 0, ErrProbeRetryable
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumTetragonMetricsBytes+1))
	defer clear(body)
	media := response.Header.Get("Content-Type")
	if readErr != nil || len(body) == 0 || len(body) > maximumTetragonMetricsBytes || response.StatusCode != http.StatusOK || !strings.HasPrefix(media, "text/plain") && !strings.HasPrefix(media, "application/openmetrics-text") {
		return 0, ErrProbeRetryable
	}
	return parseTetragonDrops(body)
}

func parseTetragonDrops(payload []byte) (uint64, error) {
	if !utf8.Valid(payload) || !bytes.HasSuffix(payload, []byte{'\n'}) {
		return 0, ErrProbe
	}
	targets := make(map[string]map[string]struct{}, len(tetragonDropMetrics))
	totals := make(map[string]uint64, len(tetragonDropMetrics))
	for _, name := range tetragonDropMetrics {
		targets[name] = map[string]struct{}{}
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 16<<10 {
			return 0, ErrProbe
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, ErrProbe
		}
		token := fields[0]
		name := token
		if index := strings.IndexByte(token, '{'); index >= 0 {
			if !strings.HasSuffix(token, "}") {
				return 0, ErrProbe
			}
			name = token[:index]
		}
		seen, tracked := targets[name]
		if !tracked {
			continue
		}
		if _, duplicate := seen[token]; duplicate {
			return 0, ErrProbe
		}
		seen[token] = struct{}{}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != fields[1] || value > 1_000_000_000 {
			return 0, ErrProbe
		}
		if totals[name] > 1_000_000_000-value {
			return 0, ErrProbe
		}
		totals[name] += value
	}
	var result uint64
	for _, name := range tetragonDropMetrics {
		if len(targets[name]) == 0 {
			return 0, ErrProbe
		}
		if result > 1_000_000_000-totals[name] {
			return 0, ErrProbe
		}
		result += totals[name]
	}
	return result, nil
}

func readProbeText(path string, maximum int) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > int64(maximum+1) {
		return "", ErrProbe
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrProbe
	}
	defer file.Close()
	opened, err := file.Stat()
	after, afterErr := os.Lstat(path)
	if err != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return "", ErrProbe
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum+2)))
	if err != nil || len(raw) == 0 || len(raw) > maximum+1 {
		return "", ErrProbe
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return "", ErrProbe
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", ErrProbe
		}
	}
	return value, nil
}
func validateBTFFile(path string) error {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return ErrProbe
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrProbe
	}
	defer file.Close()
	opened, err := file.Stat()
	after, afterErr := os.Lstat(path)
	if err != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return ErrProbe
	}
	content := make([]byte, 1)
	read, readErr := file.Read(content)
	clear(content)
	if readErr != nil && readErr != io.EOF || read != 1 {
		return ErrProbe
	}
	return nil
}
func safeProbeDo(do func(*http.Request) (*http.Response, error), request *http.Request) (response *http.Response, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = ErrProbeRetryable
		}
	}()
	return do(request)
}
