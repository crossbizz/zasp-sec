package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The egress-discovery role finds workloads that call model APIs or remote
// MCP servers without any change to the workload. It joins two things it can
// see on the node: DNS answers (packet capture in the host network
// namespace) and outbound connections (Tetragon's tcp_connect events, which
// carry the pod's workload). A workload that was given an address for a
// catalog name and then connected to that address is recorded under the
// catalog token. The result is published in a ConfigMap the Kubernetes
// discovery collector reads; nothing is sent anywhere else.
type egressDiscoveryConfig struct {
	Namespace, NodeName, TetragonSocket, HealthAddress string
	PublishInterval, PollInterval, ShutdownTimeout     time.Duration
}

func loadEgressDiscoveryConfig(getenv func(string) string) (egressDiscoveryConfig, error) {
	if getenv == nil {
		return egressDiscoveryConfig{}, errSensorConfig
	}
	config := egressDiscoveryConfig{Namespace: getenv("ZASP_SENSOR_NAMESPACE"), NodeName: getenv("ZASP_SENSOR_NODE_NAME"), TetragonSocket: getenv("ZASP_TETRAGON_SOCKET")}
	port, err := parseBoundedInteger(getenv("ZASP_EGRESS_HEALTH_PORT"), 1024, 65535)
	if err != nil {
		return egressDiscoveryConfig{}, errSensorConfig
	}
	config.HealthAddress = ":" + strconv.Itoa(port)
	if config.PublishInterval, err = parseBoundedDuration(getenv("ZASP_EGRESS_PUBLISH_INTERVAL"), 10*time.Second, time.Hour); err != nil {
		return egressDiscoveryConfig{}, errSensorConfig
	}
	if config.PollInterval, err = parseBoundedDuration(getenv("ZASP_SENSOR_POLL_INTERVAL"), 50*time.Millisecond, 30*time.Second); err != nil {
		return egressDiscoveryConfig{}, errSensorConfig
	}
	if config.ShutdownTimeout, err = parseBoundedDuration(getenv("ZASP_SENSOR_SHUTDOWN_TIMEOUT"), 5*time.Second, time.Minute); err != nil {
		return egressDiscoveryConfig{}, errSensorConfig
	}
	if !validKubernetesName(config.Namespace) || !validKubernetesName(config.NodeName) || !validAbsolute(config.TetragonSocket) {
		return egressDiscoveryConfig{}, errSensorConfig
	}
	return config, nil
}

type egressDiscovery struct {
	config  egressDiscoveryConfig
	tracker *egressTracker
	api     egressConfigMaps
	output  io.Writer
	now     func() time.Time
	// capture and stream are the two sources; tests replace them.
	capture func(context.Context, func(dnsResolution)) error
	stream  func(context.Context, func(), func(egressConnection)) error
	closers []func() error
}

func buildProductionEgressDiscovery(config egressDiscoveryConfig, output io.Writer) (*egressDiscovery, error) {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, errSensorRuntime
	}
	clusterConfig.Timeout = 5 * time.Second
	clusterConfig.QPS, clusterConfig.Burst = 1, 2
	clusterConfig.UserAgent = "zasp-egress-discovery/v1"
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, errSensorRuntime
	}
	capture, err := openDNSCapture()
	if err != nil {
		return nil, errSensorRuntime
	}
	now := func() time.Time { return time.Now().UTC() }
	return &egressDiscovery{
		config: config, tracker: newEgressTracker(now), api: client.CoreV1().ConfigMaps(config.Namespace), output: output, now: now,
		capture: capture.run,
		stream: func(ctx context.Context, connected func(), deliver func(egressConnection)) error {
			return streamEgressConnections(ctx, config.TetragonSocket, connected, deliver)
		},
		closers: []func() error{capture.Close},
	}, nil
}

func (discovery *egressDiscovery) Close() error {
	var first error
	for _, closer := range discovery.closers {
		if err := closer(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// run owns the two sources and the publish loop. The DNS capture failing is
// fatal (the pod restarts); the Tetragon stream is retried, and the role is
// not ready while it is down.
func (discovery *egressDiscovery) run(ctx context.Context, ticks <-chan time.Time, ready func(bool)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	restoreCtx, cancelRestore := context.WithTimeout(ctx, 10*time.Second)
	if document, ok := loadEgressObservations(restoreCtx, discovery.api, discovery.config.NodeName); ok {
		discovery.tracker.restore(document)
	}
	cancelRestore()
	captureDone := make(chan error, 1)
	go func() { captureDone <- discovery.capture(ctx, discovery.tracker.observeResolution) }()
	var streaming atomic.Bool
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		for ctx.Err() == nil {
			_ = discovery.stream(ctx, func() { streaming.Store(true) }, func(connection egressConnection) {
				discovery.tracker.observeConnection(connection.namespace, connection.kind, connection.name, connection.source, connection.destination)
			})
			streaming.Store(false)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}()
	defer func() { cancel(); <-streamDone }()
	var lastPublish time.Time
	published := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-captureDone:
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				err = errEgressCapture
			}
			return err
		case <-ticks:
			ready(streaming.Load())
			now := discovery.now()
			if published && now.Sub(lastPublish) < discovery.config.PublishInterval {
				continue
			}
			lastPublish = now
			document, changed := discovery.tracker.snapshot(discovery.config.NodeName)
			if published && !changed {
				continue
			}
			publishCtx, cancelPublish := context.WithTimeout(ctx, 10*time.Second)
			err := publishEgressObservations(publishCtx, discovery.api, document)
			cancelPublish()
			if err != nil {
				discovery.tracker.markChanged()
				continue
			}
			published = true
			matched, joined, dropped := discovery.tracker.counters()
			// Counts only: no name, address or workload is logged.
			fmt.Fprintf(discovery.output, "egress-discovery published workloads=%d catalog_names=%d joined_connections=%d dropped_resolutions=%d\n", len(document.Workloads), matched, joined, dropped)
		}
	}
}

func serveEgressDiscovery(ctx context.Context, output io.Writer, version string, getenv func(string) string, listen func(string, string) (net.Listener, error)) error {
	config, err := loadEgressDiscoveryConfig(getenv)
	if err != nil {
		return err
	}
	discovery, err := buildProductionEgressDiscovery(config, output)
	if err != nil {
		return err
	}
	return serveSensorDaemon(ctx, output, version, "sensor-egress-discovery", config.HealthAddress, config.PollInterval, config.ShutdownTimeout, discovery.run, discovery.Close, listen)
}
