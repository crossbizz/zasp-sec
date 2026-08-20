package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

var errSensorRuntime = errors.New("sensor agent runtime unavailable")

type tokenReader struct {
	mu     sync.Mutex
	root   *os.Root
	name   string
	closed bool
}

type sensorAgentDependencies struct {
	Processor        *sensoradapter.FileProcessor
	Runtime          agentProcessor
	heartbeats       heartbeatSink
	token            *tokenReader
	transport        *http.Transport
	metricsTransport *http.Transport
}

type clusterAuthorityAPI interface {
	clusterLeaseAPI
	clusterPodAPI
}

type localNodeReporter interface {
	Report(context.Context, sensoradapter.StreamResult) (NodeReport, error)
}

type clusterReporter interface {
	Tick(context.Context, NodeReport) error
}

type clusteredAgentProcessor struct {
	nodeName    string
	stream      agentProcessor
	probe       localNodeReporter
	coordinator clusterReporter
}

func buildSensorAgentDependencies(config sensorAgentConfig, injectedDo func(*http.Request) (*http.Response, error)) (sensorAgentDependencies, error) {
	if !validSensorAgentConfig(config) {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	reader, err := newTokenReader(config.TokenFile)
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	validated, err := reader.Read()
	clear(validated)
	if err != nil {
		_ = reader.Close()
		return sensorAgentDependencies{}, errSensorRuntime
	}
	var transport *http.Transport
	do := injectedDo
	if do == nil {
		transport = &http.Transport{
			Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
			ResponseHeaderTimeout: config.OperationTimeout, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 16 << 10,
		}
		client := &http.Client{Transport: transport, Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		do = client.Do
	}
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: config.ControlPlaneURL, Token: reader.Read, Do: do, Now: time.Now})
	if err != nil {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		_ = reader.Close()
		return sensorAgentDependencies{}, errSensorRuntime
	}
	normalizer, err := sensoradapter.NewNormalizer(config.MaximumProcesses)
	if err != nil {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		_ = reader.Close()
		return sensorAgentDependencies{}, errSensorRuntime
	}
	processor, err := sensoradapter.NewFileProcessor(sensoradapter.FileProcessorConfig{LogPath: config.LogFile, CursorPath: config.CursorFile, Normalizer: normalizer, Sink: client, MaximumLines: config.BatchSize})
	if err != nil {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		_ = reader.Close()
		return sensorAgentDependencies{}, errSensorRuntime
	}
	return sensorAgentDependencies{Processor: processor, Runtime: processor, heartbeats: client, token: reader, transport: transport}, nil
}

func buildProductionSensorAgentDependencies(config sensorAgentConfig) (sensorAgentDependencies, error) {
	if !validSensorAgentConfig(config) {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	api, err := newInClusterAPI(config.Namespace)
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	return buildClusteredSensorAgentDependencies(config, api, nil, nil)
}

func buildClusteredSensorAgentDependencies(config sensorAgentConfig, api clusterAuthorityAPI, controlPlaneDo, metricsDo func(*http.Request) (*http.Response, error)) (sensorAgentDependencies, error) {
	if nilClusterValue(api) {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	dependencies, err := buildSensorAgentDependencies(config, controlPlaneDo)
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	fail := func() (sensorAgentDependencies, error) {
		_ = dependencies.Close()
		return sensorAgentDependencies{}, errSensorRuntime
	}
	if metricsDo == nil {
		dependencies.metricsTransport = &http.Transport{
			Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
			DisableCompression: true, ForceAttemptHTTP2: false, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
			ResponseHeaderTimeout: config.OperationTimeout, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 16 << 10,
		}
		metricsClient := &http.Client{Transport: dependencies.metricsTransport, Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		metricsDo = metricsClient.Do
	}
	probe, err := NewLocalSensorProbe(LocalSensorProbeConfig{NodeName: config.NodeName, KernelFile: config.KernelFile, BTFFile: config.BTFFile, MetricsURL: config.MetricsURL, PollInterval: config.PollInterval, Do: metricsDo, Now: time.Now})
	if err != nil {
		return fail()
	}
	coordinator, err := NewClusterCoordinator(ClusterCoordinatorConfig{Namespace: config.Namespace, PodName: config.PodName, NodeName: config.NodeName, LeaseDuration: config.LeaseDuration, ReportTTL: config.ReportTTL, Leases: api, Pods: api, Heartbeats: dependencies.heartbeats, Now: time.Now})
	if err != nil {
		return fail()
	}
	dependencies.Runtime = &clusteredAgentProcessor{nodeName: config.NodeName, stream: dependencies.Processor, probe: probe, coordinator: coordinator}
	return dependencies, nil
}

func (dependencies sensorAgentDependencies) ReadToken() ([]byte, error) {
	if dependencies.token == nil {
		return nil, errSensorRuntime
	}
	return dependencies.token.Read()
}

func (dependencies sensorAgentDependencies) Close() error {
	if dependencies.Processor == nil || dependencies.token == nil {
		return errSensorRuntime
	}
	if dependencies.transport != nil {
		dependencies.transport.CloseIdleConnections()
	}
	if dependencies.metricsTransport != nil {
		dependencies.metricsTransport.CloseIdleConnections()
	}
	processorErr, tokenErr := dependencies.Processor.Close(), dependencies.token.Close()
	if processorErr != nil || tokenErr != nil {
		return errSensorRuntime
	}
	return nil
}

func newTokenReader(path string) (*tokenReader, error) {
	if !validAbsolute(path) {
		return nil, errSensorRuntime
	}
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, errSensorRuntime
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, errSensorRuntime
	}
	return &tokenReader{root: root, name: filepath.Base(path)}, nil
}

func (reader *tokenReader) Read() ([]byte, error) {
	if reader == nil {
		return nil, errSensorRuntime
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil, errSensorRuntime
	}
	before, err := reader.root.Lstat(reader.name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Mode()&os.ModeSymlink != 0 || before.Size() != 81 {
		return nil, errSensorRuntime
	}
	file, err := reader.root.Open(reader.name)
	if err != nil {
		return nil, errSensorRuntime
	}
	defer file.Close()
	opened, err := file.Stat()
	after, afterErr := reader.root.Lstat(reader.name)
	if err != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errSensorRuntime
	}
	value, err := io.ReadAll(io.LimitReader(file, 82))
	if err != nil || len(value) != 81 {
		clear(value)
		return nil, errSensorRuntime
	}
	credential, err := sensor.ParseTokenCredential(string(value))
	if err != nil {
		clear(value)
		return nil, errSensorRuntime
	}
	credential.Destroy()
	return value, nil
}

func (reader *tokenReader) Close() error {
	if reader == nil {
		return errSensorRuntime
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	if reader.root.Close() != nil {
		return errSensorRuntime
	}
	return nil
}

type agentProcessor interface {
	ProcessAvailable(context.Context) (sensoradapter.StreamResult, error)
}

func (processor *clusteredAgentProcessor) ProcessAvailable(ctx context.Context) (sensoradapter.StreamResult, error) {
	if processor == nil || ctx == nil || ctx.Err() != nil || !validKubernetesName(processor.nodeName) || nilAgentValue(processor.stream) || nilClusterValue(processor.probe) || nilClusterValue(processor.coordinator) {
		return sensoradapter.StreamResult{}, errSensorRuntime
	}
	result, streamErr := safeProcessAvailable(processor.stream, ctx)
	report, probeErr := safeNodeReport(processor.probe, ctx, result)
	if !validNodeReportWithoutAuthority(report) {
		report = NodeReport{NodeName: processor.nodeName, Status: "degraded", Capabilities: []string{"process"}, Kernel: "unknown"}
	}
	if streamErr != nil || probeErr != nil {
		report.Status = "degraded"
		if streamErr != nil && report.Drops < 1_000_000_000 {
			report.Drops++
		}
	}
	clusterErr := safeClusterReport(processor.coordinator, ctx, report)
	if streamErr != nil || probeErr != nil || clusterErr != nil {
		return result, errSensorRuntime
	}
	return result, nil
}

func validNodeReportWithoutAuthority(report NodeReport) bool {
	return (report.Status == "healthy" || report.Status == "degraded") && validCapabilities(report.Capabilities) && boundedClusterText(report.Kernel, 128) && report.EventRate <= 1_000_000_000 && report.Drops <= 1_000_000_000
}

func safeNodeReport(probe localNodeReporter, ctx context.Context, result sensoradapter.StreamResult) (report NodeReport, err error) {
	defer func() {
		if recover() != nil {
			report = NodeReport{}
			err = ErrProbeRetryable
		}
	}()
	return probe.Report(ctx, result)
}

func safeClusterReport(coordinator clusterReporter, ctx context.Context, report NodeReport) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrClusterRetryable
		}
	}()
	return coordinator.Tick(ctx, report)
}

func runSensorAgentLoop(ctx context.Context, processor agentProcessor, ticks <-chan time.Time, setReady func(bool)) error {
	if ctx == nil || nilAgentValue(processor) || ticks == nil || setReady == nil {
		return errSensorRuntime
	}
	for {
		_, err := safeProcessAvailable(processor, ctx)
		setReady(err == nil)
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return errSensorRuntime
			}
		}
	}
}

func safeProcessAvailable(processor agentProcessor, ctx context.Context) (result sensoradapter.StreamResult, err error) {
	defer func() {
		if recover() != nil {
			result = sensoradapter.StreamResult{}
			err = errSensorRuntime
		}
	}()
	return processor.ProcessAvailable(ctx)
}

func nilAgentValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
