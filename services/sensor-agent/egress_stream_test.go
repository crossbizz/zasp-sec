package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEgressConnectionFromEventRefusesOtherEvents(t *testing.T) {
	valid := func() *tetragon.GetEventsResponse {
		return connectEvent("tcp_connect", "shop", "Deployment", "support-bot", "10.1.2.3", "104.18.6.192")
	}
	mutate := func(change func(*tetragon.ProcessKprobe)) *tetragon.GetEventsResponse {
		event := valid()
		change(event.GetProcessKprobe())
		return event
	}
	for name, event := range map[string]*tetragon.GetEventsResponse{
		"nil event":      nil,
		"exec event":     {Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}},
		"other function": mutate(func(probe *tetragon.ProcessKprobe) { probe.FunctionName = "tcp_close" }),
		"no arguments":   mutate(func(probe *tetragon.ProcessKprobe) { probe.Args = nil }),
		"two arguments":  mutate(func(probe *tetragon.ProcessKprobe) { probe.Args = append(probe.Args, probe.Args[0]) }),
		"not a socket": mutate(func(probe *tetragon.ProcessKprobe) {
			probe.Args[0] = &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_IntArg{IntArg: 3}}
		}),
		"no process":      mutate(func(probe *tetragon.ProcessKprobe) { probe.Process = nil }),
		"host process":    mutate(func(probe *tetragon.ProcessKprobe) { probe.Process.Pod = nil }),
		"empty source":    mutate(func(probe *tetragon.ProcessKprobe) { probe.Args[0].GetSockArg().Saddr = "" }),
		"bad destination": mutate(func(probe *tetragon.ProcessKprobe) { probe.Args[0].GetSockArg().Daddr = "api.openai.com" }),
	} {
		if connection, ok := egressConnectionFromEvent(event); ok {
			t.Errorf("%s: accepted %+v", name, connection)
		}
	}
	six, ok := egressConnectionFromEvent(connectEvent("tcp_connect", "shop", "StatefulSet", "agent", "fd00::1:2", "2607:6bc0::10"))
	if !ok || six.kind != "StatefulSet" || six.source != netip.MustParseAddr("fd00::1:2") || six.destination != netip.MustParseAddr("2607:6bc0::10") {
		t.Fatalf("ipv6 connection = %+v, %v", six, ok)
	}
}

// scriptedTetragon is a Tetragon stand-in whose two RPCs the test supplies;
// an unset RPC answers Unimplemented, as an old or wrong server would.
type scriptedTetragon struct {
	tetragon.UnimplementedFineGuidanceSensorsServer
	version func() (*tetragon.GetVersionResponse, error)
	events  func(grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error
}

func (server *scriptedTetragon) GetVersion(context.Context, *tetragon.GetVersionRequest) (*tetragon.GetVersionResponse, error) {
	if server.version == nil {
		return nil, status.Error(codes.Unimplemented, "GetVersion")
	}
	return server.version()
}

func (server *scriptedTetragon) GetEvents(_ *tetragon.GetEventsRequest, stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
	if server.events == nil {
		return status.Error(codes.Unimplemented, "GetEvents")
	}
	return server.events(stream)
}

func startScriptedTetragon(t *testing.T, server *scriptedTetragon) string {
	t.Helper()
	// A short directory keeps the socket path inside the sun_path limit.
	directory, err := os.MkdirTemp("", "egr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "t.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, server)
	go grpcServer.Serve(listener)
	t.Cleanup(grpcServer.Stop)
	return socket
}

func tetragonVersion() (*tetragon.GetVersionResponse, error) {
	return &tetragon.GetVersionResponse{Version: "v1.7.0"}, nil
}

func TestStreamEgressConnectionsFailsWhenTetragonDoesNotAnswer(t *testing.T) {
	socket := startScriptedTetragon(t, &scriptedTetragon{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := streamEgressConnections(ctx, socket, func() { t.Error("reported connected without a version answer") }, func(egressConnection) { t.Error("delivered a connection") })
	if !errors.Is(err, errEgressStream) {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamEgressConnectionsReportsServerSideEnd(t *testing.T) {
	huge := connectEvent("tcp_connect", "shop", "Deployment", "support-bot", "10.1.2.3", "104.18.6.192")
	huge.GetProcessKprobe().FunctionName = strings.Repeat("x", 300<<10)
	for name, events := range map[string]func(grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error{
		"stream ends cleanly": func(grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error { return nil },
		"stream fails": func(grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
			return status.Error(codes.Unavailable, "restarting")
		},
		"oversized event": func(stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
			if err := stream.Send(huge); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			socket := startScriptedTetragon(t, &scriptedTetragon{version: tetragonVersion, events: events})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			connected := false
			err := streamEgressConnections(ctx, socket, func() { connected = true }, func(connection egressConnection) { t.Errorf("delivered %+v", connection) })
			// The caller must see an error so it marks the role not ready
			// and reconnects; a nil here would read as a clean shutdown.
			if !errors.Is(err, errEgressStream) || !connected || ctx.Err() != nil {
				t.Fatalf("err = %v, connected %v, ctx %v", err, connected, ctx.Err())
			}
		})
	}
}
