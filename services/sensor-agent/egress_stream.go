package main

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var errEgressStream = errors.New("sensor egress connection stream unavailable")

// egressConnection is the part of a Tetragon tcp_connect event the egress
// role uses: who connected, and from and to which address.
type egressConnection struct {
	namespace, kind, name string
	source, destination   netip.Addr
}

// The request asks only for kprobe events and only for the fields read
// below. The server-side field filter is a courtesy to Tetragon; the
// converter never reads anything else either way.
func egressEventsRequest() *tetragon.GetEventsRequest {
	return &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_KPROBE}}},
		DenyList:  []*tetragon.Filter{{HealthCheck: wrapperspb.Bool(true)}, {Namespace: []string{"", "cilium", "kube-system"}}},
		FieldFilters: []*tetragon.FieldFilter{{
			EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_KPROBE},
			Fields:   &fieldmaskpb.FieldMask{Paths: []string{"process.pod.namespace", "process.pod.workload", "process.pod.workload_kind", "function_name", "args"}},
			Action:   tetragon.FieldFilterAction_INCLUDE,
		}},
	}
}

// egressConnectionFromEvent returns the connection a tcp_connect kprobe
// event describes, or false for any other event.
func egressConnectionFromEvent(event *tetragon.GetEventsResponse) (egressConnection, bool) {
	probe := event.GetProcessKprobe()
	if probe == nil || probe.GetFunctionName() != "tcp_connect" || len(probe.GetArgs()) != 1 {
		return egressConnection{}, false
	}
	socket := probe.GetArgs()[0].GetSockArg()
	pod := probe.GetProcess().GetPod()
	if socket == nil || pod == nil {
		return egressConnection{}, false
	}
	source, sourceErr := netip.ParseAddr(socket.GetSaddr())
	destination, destinationErr := netip.ParseAddr(socket.GetDaddr())
	if sourceErr != nil || destinationErr != nil {
		return egressConnection{}, false
	}
	return egressConnection{namespace: pod.GetNamespace(), kind: pod.GetWorkloadKind(), name: pod.GetWorkload(), source: source.Unmap(), destination: destination.Unmap()}, true
}

// streamEgressConnections subscribes to the local Tetragon socket and
// delivers connections until the stream or the context ends. connected is
// called once Tetragon answered and the subscription is open. The caller reconnects.
func streamEgressConnections(ctx context.Context, socketPath string, connected func(), deliver func(egressConnection)) error {
	client, err := grpc.NewClient("passthrough:///tetragon-local",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithDisableRetry(), grpc.WithDisableServiceConfig(), grpc.WithNoProxy(),
		grpc.WithAuthority("tetragon-local"), grpc.WithUserAgent("zasp-egress-discovery/v1"),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256<<10), grpc.MaxCallSendMsgSize(16<<10)),
	)
	if err != nil {
		return errEgressStream
	}
	defer client.Close()
	api := tetragon.NewFineGuidanceSensorsClient(client)
	// GetEvents returns before the transport connects; a unary call proves
	// the socket answers.
	if _, err := api.GetVersion(ctx, &tetragon.GetVersionRequest{}); err != nil {
		return errEgressStream
	}
	events, err := api.GetEvents(ctx, egressEventsRequest())
	if err != nil {
		return errEgressStream
	}
	connected()
	for {
		event, err := events.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errEgressStream
		}
		if connection, ok := egressConnectionFromEvent(event); ok {
			deliver(connection)
		}
	}
}
