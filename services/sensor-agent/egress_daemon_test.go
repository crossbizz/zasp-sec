package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

type egressTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *egressTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *egressTestClock) Advance(step time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(step)
	clock.mu.Unlock()
}

// flakyConfigMaps wraps a fake API: the next failGets Get calls fail, and
// writes are counted.
type flakyConfigMaps struct {
	egressConfigMaps
	failGets atomic.Int32
	writes   atomic.Int32
}

func (api *flakyConfigMaps) Get(ctx context.Context, name string, options metav1.GetOptions) (*corev1.ConfigMap, error) {
	if api.failGets.Add(-1) >= 0 {
		return nil, errors.New("api server unavailable")
	}
	api.failGets.Store(0)
	return api.egressConfigMaps.Get(ctx, name, options)
}

func (api *flakyConfigMaps) Create(ctx context.Context, value *corev1.ConfigMap, options metav1.CreateOptions) (*corev1.ConfigMap, error) {
	api.writes.Add(1)
	return api.egressConfigMaps.Create(ctx, value, options)
}

func (api *flakyConfigMaps) Update(ctx context.Context, value *corev1.ConfigMap, options metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	api.writes.Add(1)
	return api.egressConfigMaps.Update(ctx, value, options)
}

func blockingCapture(ctx context.Context, _ func(dnsResolution)) error {
	<-ctx.Done()
	return nil
}

func connectedStream(ctx context.Context, connected func(), _ func(egressConnection)) error {
	connected()
	<-ctx.Done()
	return nil
}

func newEgressDiscoveryForTest(api egressConfigMaps, clock *egressTestClock) (*egressDiscovery, *lockedBuffer) {
	output := &lockedBuffer{}
	return &egressDiscovery{
		config:  egressDiscoveryConfig{Namespace: "zasp-edge", NodeName: "node-a", PublishInterval: 10 * time.Second},
		tracker: newEgressTracker(clock.Now), api: api, output: output, now: clock.Now,
		capture: blockingCapture, stream: connectedStream,
	}, output
}

// egressRun drives discovery.run with hand-fed ticks. The loop handles one
// tick at a time, so a tick that was accepted proves the previous one was
// fully processed.
type egressRun struct {
	t      *testing.T
	ticks  chan time.Time
	ready  chan bool
	done   chan error
	cancel context.CancelFunc
}

func startEgressRun(t *testing.T, ctx context.Context, discovery *egressDiscovery) *egressRun {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	run := &egressRun{t: t, ticks: make(chan time.Time), ready: make(chan bool, 1), done: make(chan error, 1), cancel: cancel}
	go func() { run.done <- discovery.run(ctx, run.ticks, func(value bool) { run.ready <- value }) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-run.done:
		case <-time.After(10 * time.Second):
			t.Error("run did not stop")
		}
	})
	return run
}

// tick delivers one tick and returns the readiness the loop reported for it.
func (run *egressRun) tick() bool {
	run.t.Helper()
	select {
	case run.ticks <- time.Time{}:
	case err := <-run.done:
		run.t.Fatalf("run ended early: %v", err)
	case <-time.After(10 * time.Second):
		run.t.Fatal("tick not accepted")
	}
	return <-run.ready
}

func (run *egressRun) stop() error {
	run.t.Helper()
	run.cancel()
	select {
	case err := <-run.done:
		run.done <- err
		return err
	case <-time.After(10 * time.Second):
		run.t.Fatal("run did not stop after cancellation")
		return nil
	}
}

func publishedWorkloads(t *testing.T, api egressConfigMaps) []string {
	t.Helper()
	document, ok := loadEgressObservations(context.Background(), api, "node-a")
	if !ok {
		return nil
	}
	var names []string
	for _, workload := range document.Workloads {
		names = append(names, workload.Name)
	}
	return names
}

func joinEgress(tracker *egressTracker, pod, destination, host, kind, workload string) {
	tracker.observeResolution(dnsResolution{client: netip.MustParseAddr(pod), name: host, addresses: []netip.Addr{netip.MustParseAddr(destination)}})
	tracker.observeConnection("shop", kind, workload, netip.MustParseAddr(pod), netip.MustParseAddr(destination))
}

func TestEgressDiscoveryRunRepublishesAfterFailedWrite(t *testing.T) {
	clock := &egressTestClock{now: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)}
	api := &flakyConfigMaps{egressConfigMaps: fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")}
	discovery, output := newEgressDiscoveryForTest(api, clock)
	joinEgress(discovery.tracker, "10.1.2.3", "104.18.6.192", "api.openai.com", "Deployment", "support-bot")
	run := startEgressRun(t, context.Background(), discovery)

	run.tick() // first publish
	run.tick() // same instant: inside the interval, nothing to do
	if got := publishedWorkloads(t, api); len(got) != 1 || got[0] != "support-bot" || api.writes.Load() != 1 {
		t.Fatalf("first publish: %v, writes %d", got, api.writes.Load())
	}

	joinEgress(discovery.tracker, "10.1.2.4", "160.79.104.10", "api.anthropic.com", "Job", "nightly")
	api.failGets.Store(1)
	clock.Advance(10 * time.Second)
	run.tick() // the write fails
	run.tick()
	if got := publishedWorkloads(t, api); len(got) != 1 || api.writes.Load() != 1 {
		t.Fatalf("a failed write changed the ConfigMap: %v", got)
	}

	// Nothing new was observed, but the failed document is offered again.
	clock.Advance(10 * time.Second)
	run.tick()
	run.tick()
	if got := publishedWorkloads(t, api); len(got) != 2 || api.writes.Load() != 2 {
		t.Fatalf("the failed document was not retried: %v, writes %d", got, api.writes.Load())
	}

	// No change: no write, however much time passes.
	clock.Advance(time.Minute)
	run.tick()
	run.tick()
	if api.writes.Load() != 2 {
		t.Fatalf("an unchanged document was rewritten: writes %d", api.writes.Load())
	}

	// A change inside the interval waits for the interval.
	joinEgress(discovery.tracker, "10.1.2.5", "104.18.6.193", "api.openai.com", "StatefulSet", "agent")
	clock.Advance(5 * time.Second)
	run.tick()
	run.tick()
	if api.writes.Load() != 2 {
		t.Fatal("published inside the publish interval")
	}
	clock.Advance(5 * time.Second)
	run.tick()
	run.tick()
	if got := publishedWorkloads(t, api); len(got) != 3 || api.writes.Load() != 3 {
		t.Fatalf("the delayed change was not published: %v", got)
	}

	if err := run.stop(); err != nil {
		t.Fatalf("run = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[2], "egress-discovery published workloads=3 ") {
		t.Fatalf("status lines = %q", lines)
	}
	for _, leaked := range []string{"support-bot", "nightly", "shop", "openai", "10.1.2", "104.18"} {
		if strings.Contains(output.String(), leaked) {
			t.Fatalf("status output carries %q", leaked)
		}
	}
}

func TestEgressDiscoveryRunRestoresPublishedObservations(t *testing.T) {
	ctx := context.Background()
	clock := &egressTestClock{now: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)}
	api := &flakyConfigMaps{egressConfigMaps: fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")}
	seen := clock.Now().Add(-48 * time.Hour)
	if err := publishEgressObservations(ctx, api, egressDocument(seen, egressWorkload("legacy", "anthropic", seen))); err != nil {
		t.Fatal(err)
	}
	discovery, _ := newEgressDiscoveryForTest(api, clock)
	run := startEgressRun(t, ctx, discovery)
	run.tick()
	run.tick()
	document, ok := loadEgressObservations(ctx, api, "node-a")
	if !ok || len(document.Workloads) != 1 || document.Workloads[0].Name != "legacy" || document.Workloads[0].Destinations[0].LastSeen != agentsignals.FormatEgressTime(seen) || document.GeneratedAt != agentsignals.FormatEgressTime(clock.Now()) {
		t.Fatalf("a restart lost what was published: %+v, %v", document, ok)
	}
	if err := run.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestEgressDiscoveryRunFailsClosedWhenCaptureEnds(t *testing.T) {
	broken := errors.New("socket closed underneath")
	for name, test := range map[string]struct {
		result error
		want   error
	}{"capture fails": {broken, broken}, "capture returns without error": {nil, errEgressCapture}} {
		t.Run(name, func(t *testing.T) {
			clock := &egressTestClock{now: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)}
			api := &flakyConfigMaps{egressConfigMaps: fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")}
			discovery, _ := newEgressDiscoveryForTest(api, clock)
			discovery.capture = func(context.Context, func(dnsResolution)) error { return test.result }
			// The stream may or may not have started before the capture
			// failed; either way none may still be running when run returns.
			var streamsRunning atomic.Int32
			discovery.stream = func(ctx context.Context, connected func(), _ func(egressConnection)) error {
				streamsRunning.Add(1)
				defer streamsRunning.Add(-1)
				connected()
				<-ctx.Done()
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := discovery.run(ctx, make(chan time.Time), func(bool) { t.Error("reported readiness without a tick") })
			if !errors.Is(err, test.want) || ctx.Err() != nil {
				t.Fatalf("run = %v, want %v", err, test.want)
			}
			if streamsRunning.Load() != 0 {
				t.Fatal("run returned while the connection stream was still running")
			}
			if api.writes.Load() != 0 {
				t.Fatal("wrote after the capture failed")
			}
		})
	}
}

func TestEgressDiscoveryRunTracksStreamReadinessAndStopsPromptly(t *testing.T) {
	clock := &egressTestClock{now: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)}
	api := &flakyConfigMaps{egressConfigMaps: fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")}
	discovery, _ := newEgressDiscoveryForTest(api, clock)
	drop := make(chan struct{})
	var attempts atomic.Int32
	pod, openai := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("104.18.6.192")
	discovery.stream = func(ctx context.Context, connected func(), deliver func(egressConnection)) error {
		attempts.Add(1)
		// Deliver before reporting connected, so readiness implies delivery.
		deliver(egressConnection{namespace: "shop", kind: "Deployment", name: "support-bot", source: pod, destination: openai})
		connected()
		select {
		case <-drop:
			return errEgressStream
		case <-ctx.Done():
			return nil
		}
	}
	discovery.tracker.observeResolution(dnsResolution{client: pod, name: "api.openai.com", addresses: []netip.Addr{openai}})
	run := startEgressRun(t, context.Background(), discovery)
	deadline := time.Now().Add(10 * time.Second)
	for !run.tick() {
		if time.Now().After(deadline) {
			t.Fatal("never ready while the stream was open")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, joined, _ := discovery.tracker.counters(); joined != 1 {
		t.Fatalf("the streamed connection was not joined: %d", joined)
	}
	close(drop)
	for run.tick() {
		if time.Now().After(deadline) {
			t.Fatal("still ready after the stream dropped")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The stream is now in its reconnect back-off; cancellation must not
	// wait for it.
	started := time.Now()
	if err := run.stop(); err != nil {
		t.Fatalf("run = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("stopping waited out the back-off: %v", elapsed)
	}
	if attempts.Load() != 1 {
		t.Fatalf("stream attempts = %d", attempts.Load())
	}
}

func TestEgressDiscoveryRunReturnsNilWhenAlreadyCancelled(t *testing.T) {
	clock := &egressTestClock{now: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)}
	api := &flakyConfigMaps{egressConfigMaps: fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")}
	discovery, _ := newEgressDiscoveryForTest(api, clock)
	discovery.capture = func(ctx context.Context, _ func(dnsResolution)) error { return ctx.Err() }
	discovery.stream = func(ctx context.Context, _ func(), _ func(egressConnection)) error { return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := discovery.run(ctx, make(chan time.Time), func(bool) {}); err != nil {
		t.Fatalf("run = %v", err)
	}
	if api.writes.Load() != 0 {
		t.Fatal("a cancelled run wrote")
	}
}

func TestEgressDiscoveryCloseRunsEveryCloserAndKeepsFirstError(t *testing.T) {
	first, second := errors.New("first"), errors.New("second")
	var calls []string
	discovery := &egressDiscovery{closers: []func() error{
		func() error { calls = append(calls, "a"); return nil },
		func() error { calls = append(calls, "b"); return first },
		func() error { calls = append(calls, "c"); return second },
	}}
	if err := discovery.Close(); err != first || strings.Join(calls, "") != "abc" {
		t.Fatalf("Close = %v, calls %v", err, calls)
	}
	if err := (&egressDiscovery{}).Close(); err != nil {
		t.Fatalf("empty Close = %v", err)
	}
}

func egressEnvironment() map[string]string {
	return map[string]string{"ZASP_SENSOR_NAMESPACE": "zasp-edge", "ZASP_SENSOR_NODE_NAME": "node-a", "ZASP_TETRAGON_SOCKET": "/var/run/tetragon/tetragon.sock", "ZASP_EGRESS_HEALTH_PORT": "18083", "ZASP_EGRESS_PUBLISH_INTERVAL": "1m0s", "ZASP_SENSOR_POLL_INTERVAL": "1s", "ZASP_SENSOR_SHUTDOWN_TIMEOUT": "15s"}
}

func TestLoadEgressDiscoveryConfigRejectsEachInvalidSetting(t *testing.T) {
	if _, err := loadEgressDiscoveryConfig(nil); !errors.Is(err, errSensorConfig) {
		t.Fatalf("nil getenv: %v", err)
	}
	for key, bad := range map[string]string{
		"ZASP_SENSOR_NAMESPACE":        "Zasp_Edge",
		"ZASP_SENSOR_NODE_NAME":        "-node",
		"ZASP_TETRAGON_SOCKET":         "/var/run/tetragon/../tetragon.sock",
		"ZASP_EGRESS_HEALTH_PORT":      "65536",
		"ZASP_EGRESS_PUBLISH_INTERVAL": "2h0m0s",
		"ZASP_SENSOR_POLL_INTERVAL":    "10ms",
		"ZASP_SENSOR_SHUTDOWN_TIMEOUT": "2m0s",
	} {
		values := egressEnvironment()
		values[key] = bad
		if config, err := loadEgressDiscoveryConfig(func(key string) string { return values[key] }); !errors.Is(err, errSensorConfig) || config != (egressDiscoveryConfig{}) {
			t.Errorf("%s=%q: config %+v, err %v", key, bad, config, err)
		}
	}
	for _, key := range []string{"ZASP_EGRESS_HEALTH_PORT", "ZASP_EGRESS_PUBLISH_INTERVAL", "ZASP_SENSOR_POLL_INTERVAL", "ZASP_SENSOR_SHUTDOWN_TIMEOUT"} {
		values := egressEnvironment()
		delete(values, key)
		if _, err := loadEgressDiscoveryConfig(func(key string) string { return values[key] }); err == nil {
			t.Errorf("missing %s accepted", key)
		}
	}
	values := egressEnvironment()
	config, err := loadEgressDiscoveryConfig(func(key string) string { return values[key] })
	if err != nil || config.PollInterval != time.Second || config.ShutdownTimeout != 15*time.Second || config.TetragonSocket != "/var/run/tetragon/tetragon.sock" || config.Namespace != "zasp-edge" || config.NodeName != "node-a" {
		t.Fatalf("config = %+v, %v", config, err)
	}
}

// Outside a cluster there is no API credential: the role must refuse to
// start rather than run without anywhere to publish.
func TestBuildProductionEgressDiscoveryRefusesOutsideCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	values := egressEnvironment()
	config, err := loadEgressDiscoveryConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := buildProductionEgressDiscovery(config, &lockedBuffer{})
	if discovery != nil || !errors.Is(err, errSensorRuntime) {
		t.Fatalf("discovery = %v, err = %v", discovery, err)
	}
}

func TestServeEgressDiscoveryFailsBeforeListening(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	listen := func(string, string) (net.Listener, error) {
		t.Error("listened before the role could run")
		return nil, errors.New("unexpected listen")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	invalid := egressEnvironment()
	invalid["ZASP_EGRESS_HEALTH_PORT"] = "80"
	var output lockedBuffer
	if err := serveEgressDiscovery(ctx, &output, "v1.0.0", func(key string) string { return invalid[key] }, listen); !errors.Is(err, errSensorConfig) {
		t.Fatalf("invalid configuration: %v", err)
	}
	valid := egressEnvironment()
	if err := serveEgressDiscovery(ctx, &output, "v1.0.0", func(key string) string { return valid[key] }, listen); !errors.Is(err, errSensorRuntime) {
		t.Fatalf("outside a cluster: %v", err)
	}
	if output.String() != "" {
		t.Fatalf("printed %q before starting", output.String())
	}
}
