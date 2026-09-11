package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageConsumerRuntime struct {
	mu             sync.Mutex
	slots          *lineageConsumerSlots
	acks           *lineageAcknowledgments
	producer       *lineageCompletionReader
	client         *sensoradapter.ProductionClient
	maximum        int
	operation      time.Duration
	readyDo        func(*http.Request) (*http.Response, error)
	readyTransport *http.Transport
	protectedRoots []*os.Root
	closed         bool
}

func buildProductionLineageConsumerDependencies(config sensorAgentConfig, do func(*http.Request) (*http.Response, error)) (sensorAgentDependencies, error) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	credentials, err := os.OpenRoot("/var/run/secrets/kubernetes.io/serviceaccount")
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	dependencies, err := buildLineageConsumerDependencies(config, do, nil, 0, sensoradapter.PinnedInput{Parent: credentials, Name: "token"})
	if err != nil {
		credentials.Close()
		return sensorAgentDependencies{}, err
	}
	lineage := dependencies.Lineage
	lineage.protectedRoots = append(lineage.protectedRoots, credentials)
	return dependencies, nil
}

func buildLineageConsumerDependencies(config sensorAgentConfig, controlPlaneDo, producerDo func(*http.Request) (*http.Response, error), producerUID uint32, extraProtected ...sensoradapter.PinnedInput) (_ sensorAgentDependencies, err error) {
	if !validSensorAgentConfig(config) || config.Role != "lineage-consumer" || producerUID == ^uint32(0) {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	token, err := newTokenReader(config.TokenFile)
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	token.projected = config.TokenSource == "kubernetes-projected"
	lineage := &lineageConsumerRuntime{maximum: config.MaximumProcesses, operation: config.OperationTimeout}
	dependencies := sensorAgentDependencies{Lineage: lineage, Runtime: lineage, token: token}
	defer func() {
		if err != nil {
			dependencies.Close()
		}
	}()
	protected := []sensoradapter.PinnedInput{{Parent: token.root, Name: token.name}}
	for _, path := range []string{config.KernelFile, config.BTFFile} {
		root, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			return sensorAgentDependencies{}, errSensorRuntime
		}
		lineage.protectedRoots = append(lineage.protectedRoots, root)
		protected = append(protected, sensoradapter.PinnedInput{Parent: root, Name: filepath.Base(path)})
	}
	protected = append(protected, extraProtected...)
	paths := []string{config.SpoolDirectory, config.AckDirectory, config.StateDirectory, filepath.Dir(config.TokenFile), filepath.Dir(config.KernelFile), filepath.Dir(config.BTFFile)}
	for _, input := range extraProtected {
		if input.Parent == nil {
			return sensorAgentDependencies{}, errSensorRuntime
		}
		paths = append(paths, input.Parent.Name())
	}
	var resolved []string
	for _, path := range paths {
		actual, err := filepath.EvalSymlinks(path)
		if err != nil {
			return sensorAgentDependencies{}, errSensorRuntime
		}
		resolved = append(resolved, actual)
	}
	if !lineagePathsSeparate(resolved) {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	lineage.producer, err = newLineageCompletionReader(config.SpoolDirectory, producerUID)
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	lineage.acks, err = newLineageAcknowledgments(config.AckDirectory)
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	lineage.slots, err = newLineageConsumerSlots(config.StateDirectory, lineageSlotConfig{EnrollmentBinding: config.EnrollmentBinding, Destination: config.ControlPlaneURL + "/internal/v1/runtime/events", Producer: lineage.producer, Acknowledgments: lineage.acks, ProtectedInputs: protected})
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	if controlPlaneDo == nil {
		dependencies.transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.OperationTimeout, MaxResponseHeaderBytes: 16 << 10}
		client := &http.Client{Transport: dependencies.transport, Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		controlPlaneDo = client.Do
	}
	lineage.client, err = sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: config.ControlPlaneURL, EnrollmentBinding: config.EnrollmentBinding, Token: func() ([]byte, error) { return readLineageToken(token, uint32(os.Geteuid())) }, Do: controlPlaneDo, Now: time.Now})
	if err != nil {
		return sensorAgentDependencies{}, errSensorRuntime
	}
	dependencies.heartbeats = lineage.client
	if producerDo == nil {
		lineage.readyTransport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableCompression: true, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 8 << 10}
		client := &http.Client{Transport: lineage.readyTransport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		producerDo = client.Do
	}
	lineage.readyDo = producerDo
	return dependencies, nil
}

func (runtime *lineageConsumerRuntime) ProcessAvailable(ctx context.Context) (sensoradapter.StreamResult, error) {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return sensoradapter.StreamResult{}, errSensorRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed || runtime.slots == nil || runtime.client == nil || runtime.readyDo == nil {
		return sensoradapter.StreamResult{}, errSensorRuntime
	}
	operation, cancel := context.WithTimeout(ctx, runtime.operation)
	progress, err := runtime.slots.ReconcileConsumer(operation, runtime.client, runtime.maximum)
	cancel()
	result := sensoradapter.StreamResult{Read: progress.Read, Submitted: progress.Submitted, Dropped: uint64(progress.Read - progress.Submitted), Idle: progress.Read == 0, ProducerDroppedTotal: progress.ProducerDroppedTotal, CoverageUnknown: progress.CoverageUnknown}
	// Producer readiness never gates local cleanup. It does prevent an idle
	// consumer from reporting a dead collector as healthy.
	ready := runtime.producerReady(ctx)
	if err != nil || !ready {
		if err != nil {
			result.CoverageUnknown = true
		}
		return result, errSensorRuntime
	}
	return result, nil
}

func (runtime *lineageConsumerRuntime) producerReady(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "http://127.0.0.1:8082/readyz", nil)
	if err != nil {
		return false
	}
	response, err := runtime.readyDo(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil {
		return false
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > 128 || response.Header.Get("Content-Encoding") != "" {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 129))
	return err == nil && len(raw) <= 128 && (string(raw) == `{"status":"ready"}` || string(raw) == "{\"status\":\"ready\"}\n") && bounded.Err() == nil
}

func (runtime *lineageConsumerRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return nil
	}
	runtime.closed = true
	if runtime.readyTransport != nil {
		runtime.readyTransport.CloseIdleConnections()
	}
	var failed bool
	if runtime.slots != nil {
		failed = runtime.slots.Close() != nil || failed
	}
	if runtime.acks != nil {
		failed = runtime.acks.Close() != nil || failed
	}
	if runtime.producer != nil {
		failed = runtime.producer.Close() != nil || failed
	}
	for _, root := range runtime.protectedRoots {
		failed = root.Close() != nil || failed
	}
	if failed {
		return errSensorRuntime
	}
	return nil
}

// The token may be absent at startup or rotate between attempts. It must be an
// exact consumer-owned, single-link regular file at the moment it is read.
func readLineageToken(reader *tokenReader, owner uint32) ([]byte, error) {
	if reader == nil {
		return nil, errSensorRuntime
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed || reader.root == nil {
		return nil, errSensorRuntime
	}
	if reader.projected {
		return readProjectedLineageTokenLocked(reader, owner)
	}
	before, err := reader.root.Lstat(reader.name)
	if err != nil || !lineageOwnedRegular(before, owner, 0600) || before.Size() != 81 {
		return nil, errSensorRuntime
	}
	file, err := reader.root.OpenFile(reader.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errSensorRuntime
	}
	defer file.Close()
	opened, err := file.Stat()
	after, afterErr := reader.root.Lstat(reader.name)
	if err != nil || afterErr != nil || !lineageOwnedRegular(opened, owner, 0600) || !lineageOwnedRegular(after, owner, 0600) || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errSensorRuntime
	}
	raw, err := io.ReadAll(io.LimitReader(file, 82))
	final, finalErr := file.Stat()
	named, namedErr := reader.root.Lstat(reader.name)
	if err != nil || len(raw) != 81 || finalErr != nil || namedErr != nil || !lineageOwnedRegular(final, owner, 0600) || !lineageOwnedRegular(named, owner, 0600) || final.Size() != 81 || named.Size() != 81 || !os.SameFile(opened, final) || !os.SameFile(final, named) {
		clear(raw)
		return nil, errSensorRuntime
	}
	credential, err := sensor.ParseTokenCredential(string(raw))
	if err != nil {
		clear(raw)
		return nil, errSensorRuntime
	}
	credential.Destroy()
	return raw, nil
}
