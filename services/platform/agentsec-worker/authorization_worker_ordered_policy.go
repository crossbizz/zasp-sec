package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type workerOrderedPolicyDatabase struct {
	forward, compensation *authorization.WorkerExecutor
	start                 orchestration.StartRequest
	step                  string
	cleanup               bool
}

func (d *workerOrderedPolicyDatabase) route(statement string, raw json.RawMessage) (authorization.WorkerOperation, bool, error) {
	q, err := d.request(raw)
	if err != nil {
		return "", false, err
	}
	empty := func() bool { _, ok := securityAgentOrderedClosedObject(q.Payload); return ok }
	switch statement {
	case `SELECT zasp_temporal68.effect($1::jsonb)`:
		if !d.cleanup && empty() {
			switch q.Operation {
			case "reserve":
				return "ordered68.effect.reserve", false, nil
			case "start":
				return "ordered68.effect.start", false, nil
			}
		}
	case `SELECT zasp_temporal68.application($1::jsonb)`:
		if !d.cleanup && empty() {
			switch q.Operation {
			case "read":
				return "ordered68.application.read", false, nil
			case "complete":
				// Completion creates active controls and a receipt that permits
				// later execution. It requires current forward authority on replay.
				return "ordered68.application.complete", false, nil
			}
		}
	case `SELECT zasp_temporal68.cleanup($1::jsonb)`:
		if d.cleanup && empty() {
			switch q.Operation {
			case "prepare":
				return "ordered68.cleanup.prepare", true, nil
			case "read":
				return "ordered68.cleanup.read", true, nil
			case "complete":
				return "ordered68.cleanup.complete", true, nil
			}
		}
	case `SELECT zasp_temporal68.delivery($1::jsonb)`:
		var payload struct {
			DeviceID string `json:"device_id"`
			Phase    string `json:"phase"`
			Digest   string `json:"digest"`
		}
		allowed := []string{"device_id", "phase"}
		if q.Operation == "read" || q.Operation == "ack" {
			allowed = append(allowed, "digest")
		} else if q.Operation != "prepare" {
			break
		}
		if _, ok := securityAgentOrderedClosedObject(q.Payload, allowed...); !ok || decodeStrictWorkerJSON(q.Payload, &payload) != nil || !validSecurityAgentPlannerProductID(payload.DeviceID) {
			break
		}
		phase := "apply"
		if d.cleanup {
			phase = "cleanup"
		}
		if payload.Phase != phase || q.Operation != "prepare" && !providerAckPattern.MatchString(payload.Digest) {
			break
		}
		return authorization.WorkerOperation("ordered68.delivery." + phase + "." + q.Operation), d.cleanup || q.Operation != "prepare", nil
	}
	return "", false, authorization.ErrInvalid
}

type workerOrderedPolicyRequest struct {
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	RunID          string          `json:"run_id"`
	StepID         string          `json:"step_id"`
	Generation     int64           `json:"generation"`
	Operation      string          `json:"operation"`
	Payload        json.RawMessage `json:"payload"`
}

func (d *workerOrderedPolicyDatabase) request(raw json.RawMessage) (workerOrderedPolicyRequest, error) {
	var q workerOrderedPolicyRequest
	if d == nil || len(raw) > 32768 {
		return q, authorization.ErrInvalid
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "operation", "payload"); !ok || decodeStrictWorkerJSON(raw, &q) != nil ||
		q.OrganizationID != d.start.Ref.OrganizationID || q.WorkspaceID != d.start.Ref.WorkspaceID || q.EnvironmentID != d.start.Ref.EnvironmentID || q.RunID != d.start.Ref.RunID || q.StepID != d.step || q.Generation != 1 {
		return q, authorization.ErrInvalid
	}
	for _, id := range []string{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID} {
		if !validSecurityAgentPlannerProductID(id) {
			return q, authorization.ErrInvalid
		}
	}
	return q, nil
}

// This adapter owns no database connection and has no raw fallback. Unsupported
// native operations stay unavailable until their fixed authorization is shipped.
func (*workerOrderedPolicyDatabase) Close() error { return nil }
func (*workerOrderedPolicyDatabase) Exec(context.Context, string, ...any) error {
	return authorization.ErrInvalid
}
func (*workerOrderedPolicyDatabase) SchemaVersion(context.Context) (string, error) {
	return "", authorization.ErrInvalid
}
func (d *workerOrderedPolicyDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || len(args) != 1 {
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
	if executor == nil {
		return nil, authorization.ErrInvalid
	}
	if op == "ordered68.delivery.apply.prepare" {
		if err := executor.PrepareOrdered68Operation(ctx, op, raw); err != nil {
			return nil, err
		}
	}
	decision, err := executor.Authorize(ctx, op, raw)
	if err != nil {
		return nil, err
	}
	return executor.Execute(ctx, decision)
}

var _ apiserver.JSONDatabase = (*workerOrderedPolicyDatabase)(nil)
