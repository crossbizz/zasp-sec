package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type orderedReadbackExecutor struct {
	*orderedTestRecordingExecutor
	readErr  error
	finalErr error
}

func (e *orderedReadbackExecutor) ExecuteOrderedTestDispatchReadback(ctx context.Context, _ authorization.WorkerDecision) (json.RawMessage, error) {
	_ = e.record(ctx, "readback")
	return json.RawMessage(`{"read":true}`), e.readErr
}
func (e *orderedReadbackExecutor) Execute(ctx context.Context, _ authorization.WorkerDecision) (json.RawMessage, error) {
	_ = e.record(ctx, "dispatch")
	return json.RawMessage(`{"send_permit":true}`), e.finalErr
}
func TestOrderedDispatchCompositionBoundaries(t *testing.T) {
	for _, stage := range []string{"success", "readback", "callback", "revoked", "cancel", "panic"} {
		t.Run(stage, func(t *testing.T) {
			start := workerPlanningStartFixture()
			scope, _ := temporalScope(start)
			step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f1")
			var events []string
			f := &orderedReadbackExecutor{orderedTestRecordingExecutor: &orderedTestRecordingExecutor{t: t, events: &events, label: "forward"}}
			c := &orderedTestRecordingExecutor{t: t, events: &events, label: "captured"}
			d := &workerOrderedTestDatabase{forward: f, compensation: c, start: start}
			// The interface assertion is a consuming missing-route failure before implementation.
			dispatcher, ok := any(d).(apiserver.OrderedTestLinkedDispatcher)
			if !ok {
				t.Fatal("current database lacks composed dispatch")
			}
			q, _ := json.Marshal(temporalEffectFields(start, step, "dispatch", map[string]any{}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "readback" {
				f.readErr = authorization.ErrConflict
			}
			if stage == "revoked" {
				f.finalErr = authorization.ErrDenied
			}
			callback := func(raw json.RawMessage) error {
				events = append(events, "verify")
				if string(raw) != `{"read":true}` {
					t.Fatal("readback changed")
				}
				if stage == "callback" {
					return authorization.ErrInvalid
				}
				if stage == "cancel" {
					cancel()
				}
				if stage == "panic" {
					panic("readback verifier")
				}
				return nil
			}
			if stage == "panic" {
				func() {
					defer func() {
						if recover() == nil {
							t.Fatal("callback panic swallowed")
						}
					}()
					_, _ = dispatcher.DispatchOrderedTestLinked(ctx, q, callback)
				}()
				if strings.Join(events, ",") != "forward:authorize:ordered68.linked.dispatch,forward:readback,verify" {
					t.Fatal(events)
				}
				return
			}
			_, err := dispatcher.DispatchOrderedTestLinked(ctx, q, callback)
			want := "forward:authorize:ordered68.linked.dispatch,forward:readback"
			if stage != "readback" {
				want += ",verify"
			}
			if stage == "success" || stage == "revoked" {
				want += ",forward:dispatch"
			}
			if strings.Join(events, ",") != want {
				t.Fatal(events, want)
			}
			if stage == "success" && err != nil || stage != "success" && err == nil {
				t.Fatal(stage, err)
			}
			if stage == "revoked" && !errors.Is(err, authorization.ErrDenied) {
				t.Fatal(err)
			}
		})
	}
}

func TestOrderedDispatchCompositionRejectsForeignRouteBeforeAuthorization(t *testing.T) {
	start := workerPlanningStartFixture()
	scope, _ := temporalScope(start)
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f1")
	for _, kind := range []string{"nil-verifier", "foreign-scope", "foreign-step", "read", "nonempty", "missing-compensation"} {
		t.Run(kind, func(t *testing.T) {
			var events []string
			f := &orderedReadbackExecutor{orderedTestRecordingExecutor: &orderedTestRecordingExecutor{t: t, events: &events, label: "forward"}}
			d := &workerOrderedTestDatabase{forward: f, compensation: f, start: start}
			fields := temporalEffectFields(start, step, "dispatch", map[string]any{})
			verify := func(json.RawMessage) error { t.Fatal("invalid route reached verifier"); return nil }
			switch kind {
			case "nil-verifier":
				verify = nil
			case "foreign-scope":
				fields["organization_id"] = start.Ref.RunID
			case "foreign-step":
				fields["step_id"] = start.Ref.RunID
			case "read":
				fields["operation"] = "read"
			case "nonempty":
				fields["payload"] = map[string]any{"unexpected": true}
			case "missing-compensation":
				d.compensation = nil
			}
			raw, _ := json.Marshal(fields)
			if _, err := d.DispatchOrderedTestLinked(context.Background(), raw, verify); !errors.Is(err, authorization.ErrInvalid) || len(events) != 0 {
				t.Fatal("foreign dispatch reached authority", err, events)
			}
		})
	}
}
