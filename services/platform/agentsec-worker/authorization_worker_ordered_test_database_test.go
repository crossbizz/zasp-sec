package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestOrderedTestDatabaseClosedRoutes(t *testing.T) {
	start := workerPlanningStartFixture()
	scope, _ := temporalScope(start)
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f1")
	d := &workerOrderedTestDatabase{start: start}
	for _, tc := range []struct {
		family, operation, want string
		captured                bool
		limit                   int
	}{
		{"effect", "reserve", "ordered68.effect.reserve", false, 4096},
		{"effect", "start", "ordered68.effect.start", false, 4096},
		{"effect", "read", "ordered68.effect.read", true, 4096},
		{"effect", "unknown", "ordered68.effect.unknown", true, 4096},
		{"linked", "read", "ordered68.linked.read", false, 131072},
		{"linked", "input", "ordered68.linked.input", false, 131072},
		{"linked", "dispatch", "ordered68.linked.dispatch", false, 131072},
		{"test_settle", "complete", "ordered68.test.settle", false, 1500000},
		{"test_stop", "stop", "ordered68.test.stop", true, 4096},
	} {
		t.Run(tc.want, func(t *testing.T) {
			fields := temporalEffectFields(start, step, tc.operation, map[string]any{})
			statement := "SELECT zasp_temporal68." + tc.family + "($1::jsonb)"
			raw, _ := json.Marshal(fields)
			op, captured, err := d.route(statement, raw)
			if err != nil || string(op) != tc.want || captured != tc.captured {
				t.Fatal(op, captured, err)
			}
			for _, name := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation"} {
				old := fields[name]
				fields[name] = "foreign"
				bad, _ := json.Marshal(fields)
				fields[name] = old
				if _, _, err := d.route(statement, bad); !errors.Is(err, authorization.ErrInvalid) {
					t.Fatal("foreign binding accepted", name, err)
				}
			}
			if _, _, err := d.route(statement, append([]byte(`{"operation":"other",`), raw[1:]...)); err == nil {
				t.Fatal("duplicate accepted")
			}
			if _, _, err := d.route(statement, append(raw, []byte(strings.Repeat(" ", tc.limit))...)); err == nil {
				t.Fatal("oversize accepted")
			}
			if _, _, err := d.route("SELECT arbitrary($1::jsonb)", raw); err == nil {
				t.Fatal("arbitrary SQL accepted")
			}
		})
	}
	state, _ := json.Marshal(map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "run_id": start.Ref.RunID, "definition_version": start.DefinitionVersion})
	if op, captured, err := d.route(orderedTestStateStatement, state); err != nil || !captured || op != "ordered68.test.state" {
		t.Fatal(op, captured, err)
	}
	for _, bad := range []json.RawMessage{nil, []byte(`null`), append(state, []byte(`{}`)...)} {
		if _, _, err := d.route(orderedTestStateStatement, bad); err == nil {
			t.Fatal("malformed state accepted")
		}
	}
	var stateFields map[string]any
	_ = json.Unmarshal(state, &stateFields)
	for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "definition_version"} {
		old := stateFields[field]
		stateFields[field] = "foreign"
		bad, _ := json.Marshal(stateFields)
		stateFields[field] = old
		if _, _, err := d.route(orderedTestStateStatement, bad); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("foreign state accepted", field, err)
		}
	}
	progress := map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "run_id": start.Ref.RunID, "step_id": step, "operation": "progress", "actor_id": "owned-worker", "run_version": 2, "approval_version": 1, "fresh_auth_at": time.Now().UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(progress)
	if op, captured, err := d.route(`SELECT zasp_temporal68.progress($1::jsonb)`, raw); err != nil || captured || op != "ordered68.progress" {
		t.Fatal(op, captured, err)
	}
	for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "run_version", "approval_version", "fresh_auth_at"} {
		old := progress[field]
		progress[field] = "invalid"
		bad, _ := json.Marshal(progress)
		progress[field] = old
		if _, _, err := d.route(`SELECT zasp_temporal68.progress($1::jsonb)`, bad); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("foreign progress accepted", field, err)
		}
	}
}

type orderedTestRecordingExecutor struct {
	t      *testing.T
	events *[]string
	label  string
	fail   error
}

func (e *orderedTestRecordingExecutor) record(ctx context.Context, event string) error {
	e.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		e.t.Fatal("unbounded signed runner call")
	}
	*e.events = append(*e.events, e.label+":"+event)
	return e.fail
}
func (e *orderedTestRecordingExecutor) ReadyFor(ctx context.Context, op authorization.WorkerOperation) error {
	return e.record(ctx, "ready:"+string(op))
}
func (e *orderedTestRecordingExecutor) PrepareOrdered68Operation(ctx context.Context, op authorization.WorkerOperation, _ json.RawMessage) error {
	return e.record(ctx, "prepare:"+string(op))
}
func (e *orderedTestRecordingExecutor) Authorize(ctx context.Context, op authorization.WorkerOperation, _ json.RawMessage) (authorization.WorkerDecision, error) {
	return authorization.WorkerDecision{}, e.record(ctx, "authorize:"+string(op))
}
func (e *orderedTestRecordingExecutor) Execute(ctx context.Context, _ authorization.WorkerDecision) (json.RawMessage, error) {
	return json.RawMessage(`{}`), e.record(ctx, "execute")
}

func TestOrderedTestDatabaseSignedCallOrderAndReadiness(t *testing.T) {
	start := workerPlanningStartFixture()
	scope, _ := temporalScope(start)
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f1")
	var events []string
	forward := &orderedTestRecordingExecutor{t: t, events: &events, label: "forward"}
	comp := &orderedTestRecordingExecutor{t: t, events: &events, label: "captured"}
	d := &workerOrderedTestDatabase{start: start, forward: forward, compensation: comp}
	ready := `SELECT to_jsonb(zasp_temporal68.ready($1,$2))`
	for _, args := range [][]any{nil, {migrations.ProductionTemporalExecutor().Checksum()}, {"wrong", migrations.TemporalExecutorFingerprint()}, {migrations.ProductionTemporalExecutor().Checksum(), "wrong"}, {migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint(), "extra"}} {
		if _, err := d.QueryJSON(context.Background(), ready, args...); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("ready pins accepted", err)
		}
	}
	if len(events) != 0 {
		t.Fatal("invalid ready reached executor", events)
	}
	if raw, err := d.QueryJSON(context.Background(), ready, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint()); err != nil || string(raw) != "true" {
		t.Fatal(string(raw), err)
	}
	if strings.Join(events, ",") != "forward:ready:ordered68.linked.read,captured:ready:ordered68.test.state" {
		t.Fatal(events)
	}
	events = nil
	for _, tc := range []struct{ op, want string }{{"reserve", "forward:prepare:ordered68.effect.reserve,forward:authorize:ordered68.effect.reserve,forward:execute"}, {"read", "captured:authorize:ordered68.effect.read,captured:execute"}, {"unknown", "captured:authorize:ordered68.effect.unknown,captured:execute"}} {
		raw, _ := json.Marshal(temporalEffectFields(start, step, tc.op, map[string]any{}))
		if _, err := d.QueryJSON(context.Background(), `SELECT zasp_temporal68.effect($1::jsonb)`, raw); err != nil {
			t.Fatal(err)
		}
		if strings.Join(events, ",") != tc.want {
			t.Fatal(events)
		}
		events = nil
	}
	forward.fail = authorization.ErrConflict
	raw, _ := json.Marshal(temporalEffectFields(start, step, "reserve", map[string]any{}))
	if _, err := d.QueryJSON(context.Background(), `SELECT zasp_temporal68.effect($1::jsonb)`, raw); !errors.Is(err, authorization.ErrConflict) {
		t.Fatal(err)
	}
	if strings.Join(events, ",") != "forward:prepare:ordered68.effect.reserve" {
		t.Fatal("failed preparation continued", events)
	}
}

func TestOrderedTestDatabaseNoUnsignedFallback(t *testing.T) {
	d := &workerOrderedTestDatabase{start: workerPlanningStartFixture()}
	if _, err := d.QueryJSON(context.Background(), `SELECT zasp_temporal68.effect($1::jsonb)`, json.RawMessage(`{}`)); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal(err)
	}
	if err := d.Exec(context.Background(), "SELECT arbitrary()"); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestOrderedTestProductSelectsOnlyNamedDatabase(t *testing.T) {
	legacy := singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("named Test reached raw executor")
		return nil, nil
	})
	for _, which := range []string{"forward", "captured", "both"} {
		p := &temporalSecurityAgentProduct{executor: legacy}
		if which != "captured" {
			p.workerForward = &authorization.WorkerExecutor{}
		}
		if which != "forward" {
			p.workerCompensation = &authorization.WorkerExecutor{}
		}
		if _, ok := p.orderedTestDatabase(workerPlanningStartFixture()).(*workerOrderedTestDatabase); !ok {
			t.Fatal("named configuration fell back", which)
		}
	}
	p := &temporalSecurityAgentProduct{executor: legacy}
	if _, ok := p.orderedTestDatabase(workerPlanningStartFixture()).(*workerOrderedTestDatabase); ok {
		t.Fatal("historical path unexpectedly selected")
	}
}

func TestOrderedTestDatabasePreservesNativeLargeRequestLimits(t *testing.T) {
	start := workerPlanningStartFixture()
	scope, _ := temporalScope(start)
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", start.Ref.RunID+"\x1f1")
	d := &workerOrderedTestDatabase{start: start}
	for _, tc := range []struct {
		family, operation string
		size, limit       int
	}{{"linked", "input", 90000, 131072}, {"test_settle", "complete", 1400000, 1500000}} {
		raw, _ := json.Marshal(temporalEffectFields(start, step, tc.operation, map[string]any{"body": strings.Repeat("a", tc.size)}))
		if len(raw) <= 65536 || len(raw) > tc.limit {
			t.Fatal("test boundary invalid", len(raw))
		}
		if _, _, err := d.route("SELECT zasp_temporal68."+tc.family+"($1::jsonb)", raw); err != nil {
			t.Fatal("native size narrowed", tc.family, len(raw), err)
		}
	}
}
