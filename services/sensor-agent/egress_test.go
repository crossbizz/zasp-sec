package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

// dnsResponse builds a response to one A question with a CNAME followed by
// the given addresses, using name compression the way real servers do.
func dnsResponse(name string, addresses ...string) []byte {
	message := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, byte(1 + len(addresses)), 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 1, 0, 1)
	// CNAME record: owner is a pointer to the question, target "edge.example".
	target := []byte{4, 'e', 'd', 'g', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	message = append(message, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, byte(len(target)))
	targetOffset := len(message)
	message = append(message, target...)
	for _, address := range addresses {
		parsed := netip.MustParseAddr(address)
		message = append(message, 0xc0, byte(targetOffset))
		if parsed.Is4() {
			raw := parsed.As4()
			message = append(message, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			message = append(message, raw[:]...)
		} else {
			raw := parsed.As16()
			message = append(message, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
			message = append(message, raw[:]...)
		}
	}
	return message
}

func ipv4UDP(source, destination string, sourcePort uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	src, dst := netip.MustParseAddr(source).As4(), netip.MustParseAddr(destination).As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], 40000)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func ipv6UDP(source, destination string, sourcePort uint16, payload []byte) []byte {
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6] = 0x60, 17
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	src, dst := netip.MustParseAddr(source).As16(), netip.MustParseAddr(destination).As16()
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	binary.BigEndian.PutUint16(packet[40:42], sourcePort)
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(payload)))
	copy(packet[48:], payload)
	return packet
}

func TestParseDNSResponsePacket(t *testing.T) {
	packet := ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsResponse("API.OpenAI.com", "104.18.6.192", "2606:4700::6812:6c0"))
	resolution, ok := parseDNSResponsePacket(packet)
	if !ok || resolution.client != netip.MustParseAddr("10.1.2.3") || resolution.name != "api.openai.com" || len(resolution.addresses) != 2 || resolution.addresses[0] != netip.MustParseAddr("104.18.6.192") || resolution.addresses[1] != netip.MustParseAddr("2606:4700::6812:6c0") {
		t.Fatalf("resolution = %+v, %v", resolution, ok)
	}
	six, ok := parseDNSResponsePacket(ipv6UDP("fd00::a", "fd00::1:2", 53, dnsResponse("api.anthropic.com", "160.79.104.10")))
	if !ok || six.client != netip.MustParseAddr("fd00::1:2") || six.name != "api.anthropic.com" {
		t.Fatalf("ipv6 resolution = %+v, %v", six, ok)
	}
	query := dnsResponse("api.openai.com", "1.2.3.4")
	query[2] &^= 0x80
	failed := dnsResponse("api.openai.com", "1.2.3.4")
	failed[3] |= 3
	fragment := ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsResponse("api.openai.com", "1.2.3.4"))
	fragment[6] = 0x20
	loop := dnsResponse("api.openai.com", "1.2.3.4")
	loop[12], loop[13] = 0xc0, 12
	for name, bad := range map[string][]byte{
		"empty": nil, "not udp 53": ipv4UDP("10.96.0.10", "10.1.2.3", 5353, dnsResponse("api.openai.com", "1.2.3.4")),
		"query": ipv4UDP("10.96.0.10", "10.1.2.3", 53, query), "nxdomain": ipv4UDP("10.96.0.10", "10.1.2.3", 53, failed),
		"fragment": fragment, "pointer loop": ipv4UDP("10.96.0.10", "10.1.2.3", 53, loop),
		"no addresses": ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsResponse("api.openai.com")),
	} {
		if got, ok := parseDNSResponsePacket(bad); ok {
			t.Errorf("%s: accepted %+v", name, got)
		}
	}
	// Every truncation of a valid packet is refused or parsed, never a panic.
	for length := range len(packet) {
		parseDNSResponsePacket(packet[:length])
	}
}

func TestEgressTrackerJoinsResolutionToConnection(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newEgressTracker(func() time.Time { return now })
	pod, other := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("10.1.2.4")
	openai, plain := netip.MustParseAddr("104.18.6.192"), netip.MustParseAddr("93.184.216.34")
	tracker.observeResolution(dnsResolution{client: pod, name: "api.openai.com", addresses: []netip.Addr{openai}})
	tracker.observeResolution(dnsResolution{client: pod, name: "example.com", addresses: []netip.Addr{plain}})
	if tracker.observeConnection("shop", "Deployment", "web", pod, plain) {
		t.Fatal("a name outside the catalog joined")
	}
	if tracker.observeConnection("shop", "Deployment", "web", other, openai) {
		t.Fatal("a pod that never resolved the name joined on the address alone")
	}
	if tracker.observeConnection("shop", "Pod", "web", pod, openai) || tracker.observeConnection("shop", "Deployment", "", pod, openai) {
		t.Fatal("a connection without a workload owner joined")
	}
	if !tracker.observeConnection("shop", "Deployment", "support-bot", pod, openai) {
		t.Fatal("the resolving pod's connection did not join")
	}
	document, changed := tracker.snapshot("node-a")
	if !changed || len(document.Workloads) != 1 || document.Workloads[0].Name != "support-bot" || len(document.Workloads[0].Destinations) != 1 || document.Workloads[0].Destinations[0].Token != "openai" {
		t.Fatalf("document = %+v, changed %v", document, changed)
	}
	if _, changed := tracker.snapshot("node-a"); changed {
		t.Fatal("an unchanged tracker reported a change")
	}
	now = now.Add(10 * time.Minute)
	tracker.observeConnection("shop", "Deployment", "support-bot", pod, openai)
	if _, changed := tracker.snapshot("node-a"); changed {
		t.Fatal("a repeat inside the granularity rewrote the document")
	}
	now = now.Add(2 * time.Hour)
	if tracker.observeConnection("shop", "Deployment", "support-bot", pod, openai) {
		t.Fatal("an expired resolution joined")
	}
	restored := newEgressTracker(func() time.Time { return now })
	restored.restore(document)
	if again, _ := restored.snapshot("node-a"); len(again.Workloads) != 1 {
		t.Fatalf("restore lost the workload: %+v", again)
	}
	now = now.Add(agentsignals.EgressObservationRetention + time.Hour)
	if expired, changed := tracker.snapshot("node-a"); len(expired.Workloads) != 0 || !changed {
		t.Fatalf("retention did not prune: %+v", expired)
	}
}

type fakeTetragon struct {
	tetragon.UnimplementedFineGuidanceSensorsServer
	events chan *tetragon.GetEventsResponse
}

func (*fakeTetragon) GetVersion(context.Context, *tetragon.GetVersionRequest) (*tetragon.GetVersionResponse, error) {
	return &tetragon.GetVersionResponse{Version: "v1.7.0"}, nil
}

func (server *fakeTetragon) GetEvents(request *tetragon.GetEventsRequest, stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
	if len(request.GetAllowList()) != 1 || len(request.GetAllowList()[0].GetEventSet()) != 1 || request.GetAllowList()[0].GetEventSet()[0] != tetragon.EventType_PROCESS_KPROBE {
		return context.Canceled
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event := <-server.events:
			if stream.Send(event) != nil {
				return nil
			}
		}
	}
}

func connectEvent(function, namespace, kind, workload, source, destination string) *tetragon.GetEventsResponse {
	return &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{
		FunctionName: function,
		Process:      &tetragon.Process{Pod: &tetragon.Pod{Namespace: namespace, Workload: workload, WorkloadKind: kind}},
		Args:         []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{Saddr: source, Daddr: destination, Dport: 443, Protocol: "IPPROTO_TCP"}}}},
	}}}
}

func startFakeTetragon(t *testing.T) (*fakeTetragon, string) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "tetragon.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeTetragon{events: make(chan *tetragon.GetEventsResponse, 16)}
	tetragon.RegisterFineGuidanceSensorsServer(server, fake)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	return fake, socket
}

func TestStreamEgressConnectionsReadsOnlyTCPConnect(t *testing.T) {
	server, socket := startFakeTetragon(t)
	server.events <- connectEvent("security_file_permission", "shop", "Deployment", "web", "10.1.2.3", "1.2.3.4")
	server.events <- connectEvent("tcp_connect", "shop", "Deployment", "support-bot", "::ffff:10.1.2.3", "104.18.6.192")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connected := false
	var got []egressConnection
	err := streamEgressConnections(ctx, socket, func() { connected = true }, func(connection egressConnection) {
		got = append(got, connection)
		cancel()
	})
	if err != nil || !connected || len(got) != 1 || got[0].name != "support-bot" || got[0].kind != "Deployment" || got[0].source != netip.MustParseAddr("10.1.2.3") || got[0].destination != netip.MustParseAddr("104.18.6.192") {
		t.Fatalf("got %+v, connected %v, err %v", got, connected, err)
	}
	if streamEgressConnections(context.Background(), filepath.Join(t.TempDir(), "absent.sock"), func() { t.Fatal("connected to nothing") }, func(egressConnection) {}) == nil {
		t.Fatal("a missing socket did not fail")
	}
}

func TestPublishEgressObservationsCreatesUpdatesAndRestores(t *testing.T) {
	ctx := context.Background()
	api := fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	empty := agentsignals.EgressObservations{Version: agentsignals.EgressObservationsVersion, Node: "node-a", GeneratedAt: agentsignals.FormatEgressTime(now), Workloads: []agentsignals.EgressWorkload{}}
	if err := publishEgressObservations(ctx, api, empty); err != nil {
		t.Fatal(err)
	}
	if list, _ := api.List(ctx, metav1.ListOptions{}); len(list.Items) != 0 {
		t.Fatal("a node with nothing to report wrote a ConfigMap")
	}
	document := empty
	document.Workloads = []agentsignals.EgressWorkload{{Namespace: "shop", Kind: "Deployment", Name: "support-bot", Destinations: []agentsignals.EgressDestination{{Token: "openai", LastSeen: agentsignals.FormatEgressTime(now)}}}}
	for range 2 {
		if err := publishEgressObservations(ctx, api, document); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := api.Get(ctx, egressConfigMapName("node-a"), metav1.GetOptions{})
	if err != nil || stored.Labels[agentsignals.EgressObservationsLabel] != "v1" || strings.Contains(stored.Data[agentsignals.EgressObservationsKey], "104.") {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	if loaded, ok := loadEgressObservations(ctx, api, "node-a"); !ok || len(loaded.Workloads) != 1 {
		t.Fatalf("load = %+v, %v", loaded, ok)
	}
	if _, ok := loadEgressObservations(ctx, api, "node-b"); ok {
		t.Fatal("loaded another node's document")
	}
	bad := document
	bad.Workloads = []agentsignals.EgressWorkload{{Namespace: "shop", Kind: "Deployment", Name: "x", Destinations: []agentsignals.EgressDestination{{Token: "not_catalog", LastSeen: agentsignals.FormatEgressTime(now)}}}}
	if publishEgressObservations(ctx, api, bad) == nil {
		t.Fatal("published a document the collector would refuse")
	}
}

// The whole role with a real packet capture on loopback, a real gRPC stream
// from a stand-in Tetragon, and a fake API server: a DNS answer followed by
// a connection ends as a ConfigMap naming the workload and the catalog token.
func TestEgressDiscoveryEndToEndOnLoopback(t *testing.T) {
	capture, err := openDNSCapture()
	if err != nil {
		t.Skip("packet capture needs CAP_NET_RAW")
	}
	resolver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		capture.Close()
		t.Skip("cannot bind port 53 on loopback")
	}
	defer resolver.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, socket := startFakeTetragon(t)
	clientset := fake.NewSimpleClientset()
	api := clientset.CoreV1().ConfigMaps("zasp-edge")
	now := func() time.Time { return time.Now().UTC() }
	var output lockedBuffer
	discovery := &egressDiscovery{
		config: egressDiscoveryConfig{Namespace: "zasp-edge", NodeName: "node-a", PublishInterval: time.Millisecond}, tracker: newEgressTracker(now), api: api, output: &output, now: now,
		capture: capture.run,
		stream: func(ctx context.Context, connected func(), deliver func(egressConnection)) error {
			return streamEgressConnections(ctx, socket, connected, deliver)
		},
		closers: []func() error{capture.Close},
	}
	defer discovery.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ticks := make(chan time.Time)
	readiness := make(chan bool, 64)
	done := make(chan error, 1)
	go func() { done <- discovery.run(ctx, ticks, func(value bool) { readiness <- value }) }()
	tick := func() { ticks <- time.Now() }
	for ready := false; !ready; {
		tick()
		ready = <-readiness
		time.Sleep(20 * time.Millisecond)
	}
	// The pod "resolves" the name: a DNS response arrives from port 53.
	if _, err := resolver.WriteToUDP(dnsResponse("api.anthropic.com", "160.79.104.10"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.WriteToUDP(dnsResponse("example.com", "93.184.216.34"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for matched, _, _ := discovery.tracker.counters(); matched == 0; matched, _, _ = discovery.tracker.counters() {
		if time.Now().After(deadline) {
			t.Fatal("the capture never saw the DNS response")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Then it connects: to the plain site, and to the model API.
	server.events <- connectEvent("tcp_connect", "shop", "Deployment", "web", "127.0.0.1", "93.184.216.34")
	server.events <- connectEvent("tcp_connect", "shop", "Deployment", "support-bot", "127.0.0.1", "160.79.104.10")
	for _, joined, _ := discovery.tracker.counters(); joined == 0; _, joined, _ = discovery.tracker.counters() {
		if time.Now().After(deadline) {
			t.Fatal("the connection never joined")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var document agentsignals.EgressObservations
	for ok := false; !ok; document, ok = loadEgressObservations(ctx, api, "node-a") {
		if time.Now().After(deadline) {
			t.Fatal("nothing was published")
		}
		tick()
		<-readiness
		time.Sleep(20 * time.Millisecond)
	}
	if len(document.Workloads) != 1 || document.Workloads[0].Namespace != "shop" || document.Workloads[0].Kind != "Deployment" || document.Workloads[0].Name != "support-bot" || len(document.Workloads[0].Destinations) != 1 || document.Workloads[0].Destinations[0].Token != "anthropic" {
		t.Fatalf("document = %+v", document)
	}
	list, _ := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	for _, item := range list.Items {
		for _, leaked := range []string{"160.79", "93.184", "anthropic.com", "example.com", "127.0.0.1"} {
			if strings.Contains(item.Data[agentsignals.EgressObservationsKey], leaked) {
				t.Fatalf("the published document carries %q", leaked)
			}
		}
	}
	if !strings.Contains(output.String(), "egress-discovery published workloads=1") {
		t.Fatalf("status line = %q", output.String())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run = %v", err)
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (value *lockedBuffer) Write(body []byte) (int, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.buffer.Write(body)
}

func (value *lockedBuffer) String() string {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.buffer.String()
}

func TestLoadEgressDiscoveryConfig(t *testing.T) {
	values := map[string]string{"ZASP_SENSOR_NAMESPACE": "zasp-edge", "ZASP_SENSOR_NODE_NAME": "node-a", "ZASP_TETRAGON_SOCKET": "/var/run/tetragon/tetragon.sock", "ZASP_EGRESS_HEALTH_PORT": "18083", "ZASP_EGRESS_PUBLISH_INTERVAL": "1m0s", "ZASP_SENSOR_POLL_INTERVAL": "1s", "ZASP_SENSOR_SHUTDOWN_TIMEOUT": "15s"}
	config, err := loadEgressDiscoveryConfig(func(key string) string { return values[key] })
	if err != nil || config.HealthAddress != ":18083" || config.PublishInterval != time.Minute {
		t.Fatalf("config = %+v, %v", config, err)
	}
	for key, bad := range map[string]string{"ZASP_SENSOR_NODE_NAME": "", "ZASP_TETRAGON_SOCKET": "tetragon.sock", "ZASP_EGRESS_HEALTH_PORT": "80", "ZASP_EGRESS_PUBLISH_INTERVAL": "1s"} {
		prior := values[key]
		values[key] = bad
		if _, err := loadEgressDiscoveryConfig(func(key string) string { return values[key] }); err == nil {
			t.Errorf("%s=%q accepted", key, bad)
		}
		values[key] = prior
	}
	_ = corev1.ConfigMap{}
}
