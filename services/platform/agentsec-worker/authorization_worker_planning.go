package main

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// One admitted invocation, with fixed native entries. This adapter
// cannot fall through to an unguarded family or return a compensation job body.
type workerFindingPlanningDatabase struct {
	base         apiserver.JSONDatabase
	forward      *authorization.WorkerExecutor
	compensation *authorization.WorkerExecutor
	start        orchestration.StartRequest
	family       workerPlanningFamily
}

type workerPlanningFamily uint8

const (
	workerPlanningFinding workerPlanningFamily = iota
	workerPlanningTest74
	workerPlanningOrdered68
)

// The selector belongs to product composition, never to workflow input or SQL.
func (d *workerFindingPlanningDatabase) entries() (ready, state, plan, prefix string, ok bool) {
	if d == nil {
		return
	}
	switch d.family {
	case workerPlanningFinding:
		return `SELECT to_jsonb(zasp_temporal78.client_ready($1,$2))`, `SELECT zasp_temporal78.planning_state($1::jsonb)`, `SELECT zasp_temporal78.plan($1::jsonb)`, "finding.planning.", true
	case workerPlanningTest74:
		return `SELECT to_jsonb(zasp_temporal74.client_ready($1,$2))`, `SELECT zasp_temporal74.planning_state($1::jsonb)`, `SELECT zasp_temporal74.plan($1::jsonb)`, "test74.planning.", true
	case workerPlanningOrdered68:
		return `SELECT to_jsonb(zasp_temporal68.ready($1,$2))`, `SELECT zasp_temporal68.status($1::jsonb)->'planning'`, `SELECT zasp_temporal68.plan($1::jsonb)`, "ordered68.planning.", true
	default:
		return
	}
}

// Recovery has no job/context result. A successful return means the exact
// captured intent was settled or its existing terminal evidence revalidated.
type capturedPlanningRecovery interface {
	RecoverCapturedPlanning(context.Context, json.RawMessage, []byte) error
}

type workerPlanningRecoveryMetadata struct {
	RunID            string `json:"run_id"`
	State            string `json:"state"`
	ReservationID    string `json:"reservation_id"`
	RequestDigest    string `json:"request_digest"`
	CredentialDigest string `json:"credential_digest"`
	UsageKnown       bool   `json:"usage_known"`
	HasResponse      bool   `json:"has_response"`
}

func (d *workerFindingPlanningDatabase) recoveryMetadata(raw json.RawMessage) (workerPlanningRecoveryMetadata, error) {
	var m workerPlanningRecoveryMetadata
	fields, ok := securityAgentOrderedJSONObject(raw)
	if !ok || len(fields) != 7 || len(raw) > 4096 || decodeStrictWorkerJSON(raw, &m) != nil || m.RunID != d.start.Ref.RunID || !stringInWorker(m.State, "loaded", "prepared", "started", "completed", "settled", "artifacts", "needs_human") {
		return m, authorization.ErrConflict
	}
	for _, key := range []string{"run_id", "state", "reservation_id", "request_digest", "credential_digest", "usage_known", "has_response"} {
		if len(fields[key]) == 0 || key != "request_digest" && key != "credential_digest" && bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return m, authorization.ErrConflict
		}
	}
	scope, err := temporalScope(d.start)
	if err != nil {
		return m, authorization.ErrInvalid
	}
	reservation, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_planning_reservation", d.start.Ref.RunID)
	if m.ReservationID != reservation {
		return m, authorization.ErrConflict
	}
	if m.UsageKnown && !m.HasResponse || m.State == "loaded" && m.RequestDigest != "" || stringInWorker(m.State, "loaded", "prepared", "started") && m.HasResponse || stringInWorker(m.State, "completed", "settled", "artifacts") && !m.HasResponse {
		return m, authorization.ErrConflict
	}
	if m.RequestDigest == "" {
		if !stringInWorker(m.State, "loaded", "needs_human") || m.CredentialDigest != "" || m.UsageKnown || m.HasResponse || !bytes.Equal(bytes.TrimSpace(fields["request_digest"]), []byte("null")) || !bytes.Equal(bytes.TrimSpace(fields["credential_digest"]), []byte("null")) {
			return m, authorization.ErrConflict
		}
	} else if !providerAckPattern.MatchString(m.RequestDigest) || !providerAckPattern.MatchString(m.CredentialDigest) {
		return m, authorization.ErrConflict
	}
	return m, nil
}

func (d *workerFindingPlanningDatabase) RecoverCapturedPlanning(ctx context.Context, identity json.RawMessage, body []byte) error {
	_, _, _, prefix, supported := d.entries()
	if !supported || d.compensation == nil || len(body) > 65536 {
		return authorization.ErrInvalid
	}
	fields, ok := securityAgentOrderedClosedObject(identity, "organization_id", "workspace_id", "environment_id", "run_id", "definition_version")
	expected := temporalStartFields(d.start)
	delete(expected, "input_digest")
	if !ok {
		return authorization.ErrInvalid
	}
	for key, value := range expected {
		encoded, _ := json.Marshal(value)
		if !bytes.Equal(bytes.TrimSpace(fields[key]), encoded) {
			return authorization.ErrInvalid
		}
	}
	call := func(phase string, payload any) (workerPlanningRecoveryMetadata, error) {
		q := map[string]any{}
		for key, value := range expected {
			q[key] = value
		}
		q["operation"] = phase
		if phase != "recovery" {
			q["payload"] = payload
		}
		request, err := json.Marshal(q)
		if err != nil {
			return workerPlanningRecoveryMetadata{}, authorization.ErrInvalid
		}
		decision, err := d.compensation.Authorize(ctx, authorization.WorkerOperation(prefix+phase), request)
		if err != nil {
			return workerPlanningRecoveryMetadata{}, err
		}
		raw, err := d.compensation.Execute(ctx, decision)
		if err != nil {
			return workerPlanningRecoveryMetadata{}, err
		}
		return d.recoveryMetadata(raw)
	}
	prior, err := call("recovery", nil)
	if err != nil {
		return err
	}
	payload := map[string]any{}
	if len(body) > 0 && prior.State != "needs_human" {
		payload["raw"] = string(body)
	}
	terminal, err := call("reconcile", payload)
	if err != nil {
		return err
	}
	if terminal.State != "needs_human" {
		return authorization.ErrConflict
	}
	if prior.State == "needs_human" && len(body) > 0 && !prior.UsageKnown {
		var response struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &response) != nil || response.ID == "" || prior.RequestDigest == "" {
			return authorization.ErrInvalid
		}
		// UsageKnown describes the original terminal job. A prior late charge
		// does not rewrite that job; native immutable-ledger replay validates
		// this exact association and prevents another charge.
		terminal, err = call("late_usage", map[string]any{"raw": string(body), "request_digest": prior.RequestDigest, "credential_digest": prior.CredentialDigest, "reservation_id": prior.ReservationID, "response_id": response.ID, "response_digest": orderedPlanningDigest(body)})
		if err != nil {
			return err
		}
		if terminal.State != "needs_human" {
			return authorization.ErrConflict
		}
	}
	return nil
}

var _ apiserver.JSONDatabase = (*workerFindingPlanningDatabase)(nil)

func (*workerFindingPlanningDatabase) Exec(context.Context, string, ...any) error {
	return authorization.ErrInvalid
}

func (*workerFindingPlanningDatabase) SchemaVersion(context.Context) (string, error) {
	return "", authorization.ErrInvalid
}

func (d *workerFindingPlanningDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	ready, state, plan, prefix, supported := d.entries()
	if !supported || d.forward == nil || d.base == nil {
		return nil, authorization.ErrInvalid
	}
	if statement == ready && len(args) == 2 {
		return d.base.QueryJSON(ctx, statement, args...)
	}
	if len(args) != 1 {
		return nil, authorization.ErrInvalid
	}
	var raw json.RawMessage
	switch value := args[0].(type) {
	case json.RawMessage:
		raw = value
	case []byte:
		raw = value
	default:
		return nil, authorization.ErrInvalid
	}
	if len(raw) > 524288 {
		return nil, authorization.ErrInvalid
	}
	var q struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		RunID          string `json:"run_id"`
		Version        int64  `json:"definition_version"`
		Operation      string `json:"operation"`
	}
	if json.Unmarshal(raw, &q) != nil || q.OrganizationID != d.start.Ref.OrganizationID || q.WorkspaceID != d.start.Ref.WorkspaceID || q.EnvironmentID != d.start.Ref.EnvironmentID || q.RunID != d.start.Ref.RunID || q.Version != d.start.DefinitionVersion {
		return nil, authorization.ErrInvalid
	}
	phase := q.Operation
	switch statement {
	case state:
		if phase != "" {
			return nil, authorization.ErrInvalid
		}
		phase = "state"
	case plan:
		switch phase {
		case "load", "prepare", "start", "result", "settle", "artifacts", "admit":
		default:
			return nil, authorization.ErrInvalid
		}
	default:
		return nil, authorization.ErrInvalid
	}
	decision, err := d.forward.Authorize(ctx, authorization.WorkerOperation(prefix+phase), raw)
	if err != nil {
		return nil, err
	}
	return d.forward.Execute(ctx, decision)
}
