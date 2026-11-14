package nango

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The production constructors build their own transport; these tests prove
// the bounds they accept and that Close is safe in every state, without
// reaching a network.
func TestProductionConstructorsBoundTheTimeoutAndRequireAResolver(t *testing.T) {
	resolver := serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) { return nil, errors.New("unused") })
	for _, timeout := range []time.Duration{100 * time.Millisecond, time.Second, 10 * time.Second} {
		proxy, err := NewProductionProxyClient(resolver, timeout)
		if err != nil || proxy == nil || proxy.client.Timeout != timeout || proxy.client.CheckRedirect == nil || proxy.client.Transport == nil {
			t.Fatalf("NewProductionProxyClient(%s) = %+v, %v", timeout, proxy, err)
		}
		connections, err := NewProductionConnectionClient(resolver, timeout)
		if err != nil || connections == nil || connections.client.Timeout != timeout || connections.now == nil {
			t.Fatalf("NewProductionConnectionClient(%s) = %+v, %v", timeout, connections, err)
		}
		if now := connections.now(); now.IsZero() || now.Location() != time.UTC {
			t.Fatalf("connection client clock = %v, want a UTC time", now)
		}
		if proxy.Close() != nil || proxy.Close() != nil || connections.Close() != nil || connections.Close() != nil {
			t.Fatal("Close failed or was not repeatable")
		}
	}
	for _, timeout := range []time.Duration{0, 99 * time.Millisecond, 10*time.Second + time.Nanosecond, -time.Second} {
		if client, err := NewProductionConnectionClient(resolver, timeout); !errors.Is(err, ErrInvalid) || client != nil {
			t.Errorf("NewProductionConnectionClient(%s) = %v, %v; want ErrInvalid", timeout, client, err)
		}
		if client, err := NewProductionProxyClient(resolver, timeout); !errors.Is(err, ErrInvalid) || client != nil {
			t.Errorf("NewProductionProxyClient(%s) = %v, %v; want ErrInvalid", timeout, client, err)
		}
	}
	if client, err := NewProductionConnectionClient(nil, time.Second); !errors.Is(err, ErrInvalid) || client != nil {
		t.Fatalf("NewProductionConnectionClient(nil resolver) = %v, %v", client, err)
	}
	var nilConnections *ProductionConnectionClient
	var nilProxy *ProductionProxyClient
	if nilConnections.Close() != nil || (&ProductionConnectionClient{}).Close() != nil || nilProxy.Close() != nil || (&ProductionProxyClient{}).Close() != nil {
		t.Fatal("Close of an unset client failed")
	}
}
