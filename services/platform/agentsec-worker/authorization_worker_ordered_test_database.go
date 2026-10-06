package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

const orderedTestStateStatement = `SELECT jsonb_build_object('run_id',v->'run_id','definition_version',v->'definition_version','run_state',v->'run_state','effects',COALESCE((SELECT jsonb_agg(jsonb_build_object('step_id',x->'step_id','effect_key',x->'effect_key','generation',x->'generation','state',x->'state','action_key',x->'action_key')) FROM jsonb_array_elements(v->'effects') x WHERE x->>'action_key'='run_test'),'[]'::jsonb)) FROM (SELECT zasp_temporal68.status($1::jsonb) v) q`

type orderedTestExecutor interface {
	ReadyFor(context.Context, authorization.WorkerOperation) error
	PrepareOrdered68Operation(context.Context, authorization.WorkerOperation, json.RawMessage) error
	Authorize(context.Context, authorization.WorkerOperation, json.RawMessage) (authorization.WorkerDecision, error)
	Execute(context.Context, authorization.WorkerDecision) (json.RawMessage, error)
}

// No raw connection is retained here. The runner's finite native calls map to
// one signed family, including recovery and its small status projection.
type workerOrderedTestDatabase struct {
	forward, compensation orderedTestExecutor
	start                 orchestration.StartRequest
}

func (d *workerOrderedTestDatabase) route(statement string, raw json.RawMessage) (authorization.WorkerOperation, bool, error) {
	if d == nil {
		return "", false, authorization.ErrInvalid
	}
	scope, err := temporalScope(d.start)
	if err != nil || d.start.DefinitionVersion < 1 {
		return "", false, authorization.ErrInvalid
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", d.start.Ref.RunID+"\x1f1")
	var q struct {
		Organization      string          `json:"organization_id"`
		Workspace         string          `json:"workspace_id"`
		Environment       string          `json:"environment_id"`
		Run               string          `json:"run_id"`
		Step              string          `json:"step_id"`
		Generation        int64           `json:"generation"`
		Operation         string          `json:"operation"`
		Payload           json.RawMessage `json:"payload"`
		DefinitionVersion int64           `json:"definition_version"`
		Actor             string          `json:"actor_id"`
		RunVersion        int64           `json:"run_version"`
		ApprovalVersion   int64           `json:"approval_version"`
		Fresh             string          `json:"fresh_auth_at"`
	}
	limit := 4096
	if statement == `SELECT zasp_temporal68.linked($1::jsonb)` {
		limit = 131072
	}
	if statement == `SELECT zasp_temporal68.test_settle($1::jsonb)` {
		limit = 1500000
	}
	fields := []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "operation", "payload"}
	if statement == orderedTestStateStatement {
		fields = []string{"organization_id", "workspace_id", "environment_id", "run_id", "definition_version"}
	}
	if statement == `SELECT zasp_temporal68.progress($1::jsonb)` {
		fields = []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "actor_id", "run_version", "approval_version", "fresh_auth_at"}
	}
	if len(raw) > limit {
		return "", false, authorization.ErrInvalid
	}
	if !orderedTestClosedRequest(raw, fields) || decodeStrictWorkerJSON(raw, &q) != nil || q.Organization != d.start.Ref.OrganizationID || q.Workspace != d.start.Ref.WorkspaceID || q.Environment != d.start.Ref.EnvironmentID || q.Run != d.start.Ref.RunID {
		return "", false, authorization.ErrInvalid
	}
	if statement == orderedTestStateStatement {
		if q.DefinitionVersion != d.start.DefinitionVersion {
			return "", false, authorization.ErrInvalid
		}
		return "ordered68.test.state", true, nil
	}
	if q.Step != step {
		return "", false, authorization.ErrInvalid
	}
	if statement == `SELECT zasp_temporal68.progress($1::jsonb)` {
		_, err := time.Parse(time.RFC3339Nano, q.Fresh)
		if q.Operation != "progress" || q.RunVersion < 1 || q.RunVersion > 999999 || q.ApprovalVersion < 1 || q.ApprovalVersion > 999999 || len(q.Actor) < 1 || len(q.Actor) > 128 || strings.TrimSpace(q.Actor) != q.Actor || err != nil {
			return "", false, authorization.ErrInvalid
		}
		return "ordered68.progress", false, nil
	}
	if q.Generation != 1 {
		return "", false, authorization.ErrInvalid
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(q.Payload, &payload) != nil || payload == nil {
		return "", false, authorization.ErrInvalid
	}
	empty := len(payload) == 0
	switch statement {
	case `SELECT zasp_temporal68.effect($1::jsonb)`:
		if empty && stringInWorker(q.Operation, "reserve", "start", "read", "unknown") {
			return authorization.WorkerOperation("ordered68.effect." + q.Operation), q.Operation == "read" || q.Operation == "unknown", nil
		}
	case `SELECT zasp_temporal68.linked($1::jsonb)`:
		if q.Operation == "input" || empty && stringInWorker(q.Operation, "read", "dispatch") {
			return authorization.WorkerOperation("ordered68.linked." + q.Operation), false, nil
		}
	case `SELECT zasp_temporal68.test_settle($1::jsonb)`:
		if q.Operation == "complete" {
			return "ordered68.test.settle", false, nil
		}
	case `SELECT zasp_temporal68.test_stop($1::jsonb)`:
		if q.Operation == "stop" && empty {
			return "ordered68.test.stop", true, nil
		}
	}
	return "", false, authorization.ErrInvalid
}

// The caller has applied the literal operation's native byte bound. The
// unrelated policy object's64KiB bound must not shrink linked/settlement input.
func orderedTestClosedRequest(raw json.RawMessage, keys []string) bool {
	if !utf8.Valid(raw) {
		return false
	}
	fields, ok := securityAgentOrderedJSONObject(raw)
	if !ok || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, present := fields[key]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func (*workerOrderedTestDatabase) Close() error { return nil }
func (*workerOrderedTestDatabase) Exec(context.Context, string, ...any) error {
	return authorization.ErrInvalid
}
func (*workerOrderedTestDatabase) SchemaVersion(context.Context) (string, error) {
	return "", authorization.ErrInvalid
}
func (d *workerOrderedTestDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || nilWorkerDependency(d.forward) || nilWorkerDependency(d.compensation) {
		return nil, authorization.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if statement == `SELECT to_jsonb(zasp_temporal68.ready($1,$2))` {
		if len(args) != 2 || args[0] != migrations.TemporalExecutorChecksum() || args[1] != migrations.TemporalExecutorFingerprint() {
			return nil, authorization.ErrInvalid
		}
		if err := d.forward.ReadyFor(bounded, "ordered68.linked.read"); err != nil {
			return nil, err
		}
		if err := d.compensation.ReadyFor(bounded, "ordered68.test.state"); err != nil {
			return nil, err
		}
		return json.RawMessage(`true`), nil
	}
	if len(args) != 1 {
		return nil, authorization.ErrInvalid
	}
	var raw json.RawMessage
	switch value := args[0].(type) {
	case json.RawMessage:
		raw = append(json.RawMessage(nil), value...)
	case []byte:
		raw = append(json.RawMessage(nil), value...)
	default:
		return nil, authorization.ErrInvalid
	}
	op, captured, err := d.route(statement, raw)
	if err != nil {
		return nil, err
	}
	executor := d.forward
	if captured {
		executor = d.compensation
	}
	if op == "ordered68.effect.reserve" {
		if err := executor.PrepareOrdered68Operation(bounded, op, raw); err != nil {
			return nil, err
		}
	}
	decision, err := executor.Authorize(bounded, op, raw)
	if err != nil {
		return nil, err
	}
	return executor.Execute(bounded, decision)
}

var _ apiserver.JSONDatabase = (*workerOrderedTestDatabase)(nil)

func (p *temporalSecurityAgentProduct) orderedTestDatabase(start orchestration.StartRequest) apiserver.JSONDatabase {
	if p.workerForward != nil || p.workerCompensation != nil {
		return &workerOrderedTestDatabase{forward: p.workerForward, compensation: p.workerCompensation, start: start}
	}
	return p.executor
}
