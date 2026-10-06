package main

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type workerSingleTestDatabase struct {
	base                  apiserver.JSONDatabase
	forward, compensation *authorization.WorkerExecutor
	start                 orchestration.StartRequest
}

var _ apiserver.JSONDatabase = (*workerSingleTestDatabase)(nil)

func (*workerSingleTestDatabase) SchemaVersion(context.Context) (string, error) {
	return "", authorization.ErrInvalid
}
func (*workerSingleTestDatabase) Exec(context.Context, string, ...any) error {
	return authorization.ErrInvalid
}
func (d *workerSingleTestDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if d == nil || ctx == nil || d.forward == nil || d.compensation == nil {
		return nil, authorization.ErrInvalid
	}
	if statement == `SELECT to_jsonb(zasp_temporal74.client_ready($1,$2))` {
		if len(args) != 2 || args[0] != migrations.TemporalTestExecutorChecksum() || args[1] != migrations.TemporalTestExecutorFingerprint() || d.base == nil {
			return nil, authorization.ErrInvalid
		}
		return d.base.QueryJSON(ctx, statement, args...)
	}
	if len(args) != 1 {
		return nil, authorization.ErrInvalid
	}
	raw, ok := args[0].(json.RawMessage)
	if !ok {
		return nil, authorization.ErrInvalid
	}
	var q struct {
		Organization string          `json:"organization_id"`
		Workspace    string          `json:"workspace_id"`
		Environment  string          `json:"environment_id"`
		Run          string          `json:"run_id"`
		Step         string          `json:"step_id"`
		Generation   int             `json:"generation"`
		Operation    string          `json:"operation"`
		Payload      json.RawMessage `json:"payload"`
	}
	if decodeStrictWorkerJSON(raw, &q) != nil || q.Organization != d.start.Ref.OrganizationID || q.Workspace != d.start.Ref.WorkspaceID || q.Environment != d.start.Ref.EnvironmentID || q.Run != d.start.Ref.RunID || q.Generation != 1 {
		return nil, authorization.ErrInvalid
	}
	scope, err := temporalScope(d.start)
	if err != nil {
		return nil, authorization.ErrInvalid
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", q.Run+"\x1f0")
	if q.Step != step {
		return nil, authorization.ErrInvalid
	}
	var operation authorization.WorkerOperation
	executor := d.forward
	switch statement {
	case `SELECT zasp_temporal74.test_state($1::jsonb)`:
		if q.Operation != "read" {
			return nil, authorization.ErrInvalid
		}
		operation = "test74.state"
		executor = d.compensation
	case `SELECT zasp_temporal74.effect($1::jsonb)`:
		if !stringInWorker(q.Operation, "reserve", "start", "read", "unknown") {
			return nil, authorization.ErrInvalid
		}
		operation = authorization.WorkerOperation("test74.effect." + q.Operation)
		if q.Operation == "read" || q.Operation == "unknown" {
			executor = d.compensation
		}
	case `SELECT zasp_temporal74.linked($1::jsonb)`:
		if !stringInWorker(q.Operation, "read", "input", "dispatch") {
			return nil, authorization.ErrInvalid
		}
		operation = authorization.WorkerOperation("test74.linked." + q.Operation)
	case `SELECT zasp_temporal74.test_settle($1::jsonb)`:
		if !stringInWorker(q.Operation, "input", "child", "snapshot", "complete") {
			return nil, authorization.ErrInvalid
		}
		operation = authorization.WorkerOperation("test74.settlement." + q.Operation)
		executor = d.compensation
	default:
		return nil, authorization.ErrInvalid
	}
	decision, err := executor.Authorize(ctx, operation, raw)
	if err != nil {
		return nil, err
	}
	return executor.Execute(ctx, decision)
}
