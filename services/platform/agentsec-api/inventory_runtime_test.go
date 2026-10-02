package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type inventoryReadinessProbe struct {
	apiserver.JSONDatabase
	current bool
	err     error
	calls   int
	context context.Context
}

func (d *inventoryReadinessProbe) CurrentAuthorizationRequired() bool { return d.current }
func (d *inventoryReadinessProbe) CurrentAuthorizationInventoryReady(ctx context.Context) error {
	d.calls++
	d.context = ctx
	return d.err
}

func TestCurrentInventoryReadinessSurvivesTracing(t *testing.T) {
	for _, failure := range []error{nil, apiserver.ErrRepositoryUnavailable} {
		probe := &inventoryReadinessProbe{current: true, err: failure}
		wrapped := &tracedJSONDatabase{next: probe}
		ready, ok := any(wrapped).(interface{ CurrentAuthorizationInventoryReady(context.Context) error })
		if !ok {
			t.Fatal("tracing loses the current inventory authority guard")
		}
		ctx := context.WithValue(context.Background(), inventoryRuntimeContextKey{}, "inventory readiness")
		if err := ready.CurrentAuthorizationInventoryReady(ctx); !errors.Is(err, failure) || probe.calls != 1 || probe.context != ctx {
			t.Fatalf("readiness=%v calls=%d context forwarded=%t", err, probe.calls, probe.context == ctx)
		}
	}
}

type inventoryRuntimeContextKey struct{}

func TestCurrentInventoryReadinessRefusesMissingAuthority(t *testing.T) {
	var missing *tracedJSONDatabase
	var typedNil *inventoryReadinessProbe
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name     string
		database *tracedJSONDatabase
		ctx      context.Context
	}{
		{"nil wrapper", missing, context.Background()},
		{"nil database", &tracedJSONDatabase{}, context.Background()},
		{"typed nil database", &tracedJSONDatabase{next: typedNil}, context.Background()},
		{"legacy database", &tracedJSONDatabase{next: &inventoryReadinessProbe{}}, context.Background()},
		{"nil context", &tracedJSONDatabase{next: &inventoryReadinessProbe{current: true}}, nil},
		{"cancelled context", &tracedJSONDatabase{next: &inventoryReadinessProbe{current: true}}, cancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, ok := any(tc.database).(interface{ CurrentAuthorizationInventoryReady(context.Context) error })
			if !ok {
				t.Fatal("tracing loses the current inventory authority guard")
			}
			if err := ready.CurrentAuthorizationInventoryReady(tc.ctx); !errors.Is(err, apiserver.ErrRepositoryUnavailable) {
				t.Fatalf("unsafe readiness=%v", err)
			}
			if tc.database != nil {
				if probe, ok := tc.database.next.(*inventoryReadinessProbe); ok && probe != nil && probe.calls != 0 {
					t.Fatal("invalid probe issued native authority read")
				}
			}
		})
	}
}
