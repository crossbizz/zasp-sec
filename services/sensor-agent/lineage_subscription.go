package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var errLineageSubscription = errors.New("sensor lineage subscription unavailable")

type lineageSubscription struct {
	endpoint *lineageSocket
	client   *grpc.ClientConn
	events   grpc.ServerStreamingClient[tetragon.GetEventsResponse]
	cancel   context.CancelFunc
	context  context.Context
	closed   atomic.Bool
	recv     sync.Mutex
}

// Takes ownership of endpoint, including on failure. This is only for the
// trusted Tetragon-side producer. The authenticated Unix transport is local;
// insecure credentials here do not permit arbitrary TCP dialing. GetVersion is
// a compatibility gate, not server-image attestation. A generation owner must
// still match host/Node identities around this construction before writing.
func newLineageSubscription(ctx context.Context, endpoint *lineageSocket) (_ *lineageSubscription, err error) {
	if ctx == nil || ctx.Err() != nil || endpoint == nil {
		endpoint.Close()
		return nil, errLineageSubscription
	}
	lifetime, cancel := context.WithCancel(metadata.NewOutgoingContext(ctx, nil))
	subscription := &lineageSubscription{endpoint: endpoint, cancel: cancel, context: lifetime}
	startup, cancelStartup := context.WithTimeout(lifetime, 3*time.Second)
	stopStartup := context.AfterFunc(startup, cancel)
	defer func() {
		stopStartup()
		cancelStartup()
		if err != nil {
			subscription.Close()
		}
	}()
	client, clientErr := grpc.NewClient("passthrough:///tetragon-local",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return endpoint.DialOnce(ctx) }),
		grpc.WithDisableRetry(), grpc.WithDisableServiceConfig(), grpc.WithNoProxy(),
		grpc.WithAuthority("tetragon-local"), grpc.WithUserAgent("zasp-lineage-producer/v1"),
		grpc.WithMaxHeaderListSize(16<<10),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256<<10), grpc.MaxCallSendMsgSize(16<<10)),
	)
	if clientErr != nil {
		return nil, errLineageSubscription
	}
	subscription.client = client
	api := tetragon.NewFineGuidanceSensorsClient(client)
	version, versionErr := api.GetVersion(startup, &tetragon.GetVersionRequest{})
	if versionErr != nil || version == nil || version.Version != "v1.7.0" || len(version.ProtoReflect().GetUnknown()) != 0 {
		return nil, errLineageSubscription
	}
	subscription.events, err = api.GetEvents(lifetime, lineageSubscriptionRequest())
	if err != nil || startup.Err() != nil || !stopStartup() {
		return nil, errLineageSubscription
	}
	return subscription, nil
}

// A transport failure ends the generation permanently. Filtered or rejected
// provider records remain distinct, nonterminal results for the producer's
// explicit exclusion/drop accounting. Callers must never treat them as events.
// Concurrent readers serialize; Close cancels a blocked read without that lock.
func (subscription *lineageSubscription) Next() ([]byte, error) {
	if subscription == nil {
		return nil, errLineageSubscription
	}
	subscription.recv.Lock()
	defer subscription.recv.Unlock()
	if subscription.closed.Load() || subscription.context == nil || subscription.context.Err() != nil {
		subscription.Close()
		return nil, errLineageSubscription
	}
	event, err := subscription.events.Recv()
	if err != nil {
		subscription.Close()
		return nil, errLineageSubscription
	}
	if subscription.closed.Load() || subscription.context.Err() != nil {
		subscription.Close()
		return nil, errLineageSubscription
	}
	line, err := sanitizeLineageEvent(event)
	if subscription.closed.Load() || subscription.context.Err() != nil {
		subscription.Close()
		return nil, errLineageSubscription
	}
	return line, err
}

func (subscription *lineageSubscription) Close() error {
	if subscription == nil || subscription.closed.Swap(true) {
		return nil
	}
	if subscription.cancel != nil {
		subscription.cancel()
	}
	if subscription.client != nil {
		subscription.client.Close()
	}
	if subscription.endpoint != nil {
		subscription.endpoint.Close()
	}
	return nil
}
