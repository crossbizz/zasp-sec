package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type lineageGRPCFixture struct {
	tetragon.UnimplementedFineGuidanceSensorsServer
	version  string
	events   chan *tetragon.GetEventsResponse
	requests chan *tetragon.GetEventsRequest
	versions atomic.Int32
	headers  chan metadata.MD
}

func (fixture *lineageGRPCFixture) GetVersion(ctx context.Context, _ *tetragon.GetVersionRequest) (*tetragon.GetVersionResponse, error) {
	fixture.versions.Add(1)
	if headers, ok := metadata.FromIncomingContext(ctx); ok {
		select {
		case fixture.headers <- headers:
		default:
		}
	}
	return &tetragon.GetVersionResponse{Version: fixture.version}, nil
}

func (fixture *lineageGRPCFixture) GetEvents(request *tetragon.GetEventsRequest, stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
	if headers, ok := metadata.FromIncomingContext(stream.Context()); ok {
		select {
		case fixture.headers <- headers:
		default:
		}
	}
	select {
	case fixture.requests <- proto.Clone(request).(*tetragon.GetEventsRequest):
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	for {
		select {
		case event := <-fixture.events:
			if err := stream.Send(event); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func startLineageGRPCFixture(t *testing.T, version string) (string, *grpc.Server, *lineageGRPCFixture) {
	t.Helper()
	path, listener := lineageSocketFixture(t)
	server := grpc.NewServer()
	fixture := &lineageGRPCFixture{version: version, events: make(chan *tetragon.GetEventsResponse, 8), requests: make(chan *tetragon.GetEventsRequest, 8), headers: make(chan metadata.MD, 2)}
	tetragon.RegisterFineGuidanceSensorsServer(server, fixture)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	return path, server, fixture
}

func TestLineageSubscriptionActualUnixStreamAndFixedRequest(t *testing.T) {
	path, _, fixture := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	subscription, err := newLineageSubscription(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	select {
	case request := <-fixture.requests:
		if !proto.Equal(request, lineageSubscriptionRequest()) {
			t.Fatal("fixed subscription request changed in transport")
		}
	case <-ctx.Done():
		t.Fatal("subscription request not received")
	}
	fixture.events <- lineageProviderFixture("exec")
	line, err := subscription.Next()
	if err != nil || !strings.Contains(string(line), `"exec_id":"exec-42"`) || strings.Contains(string(line), "secret-") {
		t.Fatalf("record: %q, %v", line, err)
	}
	if fixture.versions.Load() != 1 {
		t.Fatal("version not checked exactly once")
	}
	filtered := lineageProviderFixture("exec")
	filtered.GetProcessExec().Process.Pod.Namespace = "kube-system"
	fixture.events <- filtered
	if line, err := subscription.Next(); len(line) != 0 || !errors.Is(err, errLineageEventFiltered) {
		t.Fatal("filtered event not reported")
	}
	fixture.events <- lineageProviderFixture("exec")
	if _, err := subscription.Next(); err != nil {
		t.Fatal("filter unexpectedly ended stream")
	}
	if err := subscription.Close(); err != nil {
		t.Fatal(err)
	}
	if err := subscription.Close(); err != nil {
		t.Fatal("close not idempotent")
	}
	if _, err := subscription.Next(); !errors.Is(err, errLineageSubscription) {
		t.Fatal("closed subscription readable")
	}
}

func TestLineageSubscriptionRefusesUnverifiedVersionAndOversize(t *testing.T) {
	for _, version := range []string{"", "v1.6.0", "v1.7.0-secret-suffix"} {
		t.Run(version, func(t *testing.T) {
			path, _, fixture := startLineageGRPCFixture(t, version)
			endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer endpoint.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			subscription, err := newLineageSubscription(ctx, endpoint)
			if subscription != nil || !errors.Is(err, errLineageSubscription) || ctx.Err() != nil {
				t.Fatalf("version refusal: %v", err)
			}
			select {
			case <-fixture.requests:
				t.Fatal("events requested before accepted version")
			default:
			}
		})
	}
	path, _, fixture := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	subscription, err := newLineageSubscription(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	oversize := lineageProviderFixture("exec")
	oversize.GetProcessExec().Process.Arguments = strings.Repeat("secret-oversize", 30000)
	fixture.events <- oversize
	if line, err := subscription.Next(); len(line) != 0 || !errors.Is(err, errLineageSubscription) {
		t.Fatalf("oversize transport: %q, %v", line, err)
	}
	if ctx.Err() != nil {
		t.Fatal("timeout masked receive bound")
	}
}

func TestLineageSubscriptionCloseCancelsBlockedRead(t *testing.T) {
	path, _, _ := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	subscription, err := newLineageSubscription(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := subscription.Next(); result <- err }()
	subscription.Close()
	select {
	case err := <-result:
		if !errors.Is(err, errLineageSubscription) {
			t.Fatalf("close result: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("close did not release read")
	}
}

func TestLineageSubscriptionCannotRedialReplacementServer(t *testing.T) {
	path, server, fixture := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	subscription, err := newLineageSubscription(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	fixture.events <- lineageProviderFixture("exec")
	if _, err := subscription.Next(); err != nil {
		t.Fatal(err)
	}
	server.Stop()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := subscription.Next(); !errors.Is(err, errLineageSubscription) {
		t.Fatal("stream failure not terminal")
	}
	if _, err := subscription.Next(); !errors.Is(err, errLineageSubscription) {
		t.Fatal("terminal stream restarted")
	}
	listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if connection, err := listener.AcceptUnix(); err == nil {
		connection.Close()
		t.Fatal("replacement server received connection")
	}
	if ctx.Err() != nil {
		t.Fatal("test deadline masked failed reconnect")
	}
}

func TestLineageSubscriptionDoesNotForwardCallerMetadata(t *testing.T) {
	path, _, fixture := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	parent := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "secret-token", "x-org", "secret-tenant"))
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	subscription, err := newLineageSubscription(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	for i := 0; i < 2; i++ {
		select {
		case headers := <-fixture.headers:
			if len(headers.Get("authorization")) != 0 || len(headers.Get("x-org")) != 0 {
				t.Fatal("caller credentials reached local source")
			}
		case <-ctx.Done():
			t.Fatal("missing source request")
		}
	}
}

func TestLineageSubscriptionStartupCancellationReleasesEndpoint(t *testing.T) {
	path, _ := lineageSocketFixture(t) // Listening endpoint never serves HTTP/2.
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if subscription, err := newLineageSubscription(ctx, endpoint); subscription != nil || !errors.Is(err, errLineageSubscription) {
		t.Fatal("stalled startup accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("startup ignored cancellation")
	}
	if conn, err := endpoint.DialOnce(context.Background()); conn != nil || !errors.Is(err, errLineageSocket) {
		t.Fatal("failed startup retained reusable endpoint")
	}
}

type heldLineageReceive struct {
	grpc.ServerStreamingClient[tetragon.GetEventsResponse]
	received chan struct{}
	release  chan struct{}
}

func (held *heldLineageReceive) Recv() (*tetragon.GetEventsResponse, error) {
	event, err := held.ServerStreamingClient.Recv()
	close(held.received)
	<-held.release
	return event, err
}

func TestLineageSubscriptionCancellationRejectsAlreadyReceivedEvent(t *testing.T) {
	path, _, fixture := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	subscription, err := newLineageSubscription(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	// Hold an event actually received over gRPC at the Next/Recv boundary, so
	// cancellation timing is deterministic without production test hooks.
	held := &heldLineageReceive{ServerStreamingClient: subscription.events, received: make(chan struct{}), release: make(chan struct{})}
	subscription.events = held
	fixture.events <- lineageProviderFixture("exec")
	type result struct {
		line []byte
		err  error
	}
	results := make(chan result, 1)
	go func() { line, err := subscription.Next(); results <- result{line, err} }()
	select {
	case <-held.received:
	case <-ctx.Done():
		close(held.release)
		t.Fatal("event not received")
	}
	cancel()
	close(held.release)
	select {
	case result := <-results:
		if len(result.line) != 0 || !errors.Is(result.err, errLineageSubscription) {
			t.Fatalf("cancelled generation returned event: %q, %v", result.line, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read did not return")
	}
}
