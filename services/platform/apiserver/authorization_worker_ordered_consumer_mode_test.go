package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The real fixture must reject requests that would omit independent controls
// without a complete application producer and a single downstream consumer.
func TestOrderedPolicyConnectedConsumerOptions(t *testing.T) {
	application := func(ordered68TestFlowContext) {}
	consume := func(*testing.T, context.Context, *pgx.Conn, json.RawMessage, string) {}
	connected := ordered69LifecycleConsumer{phase: "application-complete", application: application, connectedConsumer: true}
	for _, tc := range []struct {
		name                      string
		catalog, approval, writer bool
		acceptance                *ordered68PolicyAcceptance
		lifecycle                 []ordered69LifecycleConsumer
		want                      bool
	}{
		{name: "default-full-boundary", want: true},
		{name: "default-application", lifecycle: []ordered69LifecycleConsumer{{phase: "application-complete", application: application}}, want: true},
		{name: "connected-application", lifecycle: []ordered69LifecycleConsumer{connected}, want: true},
		{name: "missing-callback", lifecycle: []ordered69LifecycleConsumer{{phase: "application-complete", connectedConsumer: true}}},
		{name: "wrong-callback", lifecycle: []ordered69LifecycleConsumer{{phase: "application-complete", consume: consume, connectedConsumer: true}}},
		{name: "both-callbacks", lifecycle: []ordered69LifecycleConsumer{{phase: "application-complete", consume: consume, application: application, connectedConsumer: true}}},
		{name: "duplicate-consumers", lifecycle: []ordered69LifecycleConsumer{connected, connected}},
		{name: "catalog", catalog: true, lifecycle: []ordered69LifecycleConsumer{connected}},
		{name: "approval-only", approval: true, lifecycle: []ordered69LifecycleConsumer{connected}},
		{name: "writer-catalog", writer: true, lifecycle: []ordered69LifecycleConsumer{connected}},
		{name: "other-acceptance", acceptance: &ordered68PolicyAcceptance{consume: func(ordered68PolicyAcceptanceContext) {}}, lifecycle: []ordered69LifecycleConsumer{connected}},
		{name: "approval-phase", lifecycle: []ordered69LifecycleConsumer{{phase: "approval", consume: consume, connectedConsumer: true}}},
		{name: "reserved-phase", lifecycle: []ordered69LifecycleConsumer{{phase: "block-reserved", consume: consume, connectedConsumer: true}}},
		{name: "started-phase", lifecycle: []ordered69LifecycleConsumer{{phase: "block-started", consume: consume, connectedConsumer: true}}},
		{name: "unknown-phase", lifecycle: []ordered69LifecycleConsumer{{phase: "unknown", application: application, connectedConsumer: true}}},
		{name: "retained-approval", approval: true, lifecycle: []ordered69LifecycleConsumer{{phase: "approval", consume: consume}}, want: true},
		{name: "retained-reserved", lifecycle: []ordered69LifecycleConsumer{{phase: "block-reserved", consume: consume}}, want: true},
		{name: "retained-started", lifecycle: []ordered69LifecycleConsumer{{phase: "block-started", consume: consume}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ordered68PolicyOptionsValid(tc.catalog, tc.approval, tc.writer, tc.acceptance, tc.lifecycle...); got != tc.want {
				t.Fatalf("fixture options accepted=%v, want %v", got, tc.want)
			}
		})
	}
}
