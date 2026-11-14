package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// A planner request that left the worker has one of three outcomes: a
// captured response (accounted from its usage), an unknown outcome (the
// reservation stays open: usage is unknown, never zero), or a definite
// refusal by the provider before any generation.
//
// The provider contract (OpenRouter, "Errors and debugging",
// https://openrouter.ai/docs/api_reference/errors-and-debugging) reports a
// request error as an HTTP status equal to error.code in the body, and an
// error that occurs during generation with HTTP 200. Three statuses are
// request errors raised before a model is called, so nothing was generated
// and nothing is charged:
//
//	401 invalid credentials
//	402 insufficient credits
//	429 rate limited
//
// 403 covers moderation and guardrail blocks, which can follow prompt
// processing by an upstream provider, and 408/502/503 can follow a dispatch.
// Those, a transport failure, and any answer that is not exactly the
// provider's error envelope stay unknown.
const securityAgentPlannerRejectionLimit = 16 * 1024

// plannerProviderRejection is the evidence of a definite refusal: the status
// and the provider's error body, exactly as received.
type plannerProviderRejection struct {
	Status int
	Body   []byte
}

func (*plannerProviderRejection) Error() string { return "planner provider rejected the request" }

// classifyPlannerProviderRejection returns the evidence of a definite
// refusal, or nil when the answer does not prove one.
func classifyPlannerProviderRejection(status int, body []byte) *plannerProviderRejection {
	if status != 401 && status != 402 && status != 429 {
		return nil
	}
	if len(body) < 2 || len(body) > securityAgentPlannerRejectionLimit || !utf8.Valid(body) || !attackLabJSONKeys(json.NewDecoder(bytes.NewReader(body)), nil, 0) {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return nil
	}
	// A body that names a response, a choice or usage is not a refusal
	// before generation, whatever its status.
	for _, key := range []string{"id", "choices", "usage"} {
		if _, present := fields[key]; present {
			return nil
		}
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(fields["error"], &envelope) != nil || envelope == nil {
		return nil
	}
	code := bytes.TrimSpace(envelope["code"])
	if string(code) != strconv.Itoa(status) {
		return nil
	}
	return &plannerProviderRejection{Status: status, Body: bytes.Clone(body)}
}

// payload is the reconciliation payload PostgreSQL accepts for this evidence
// (migrations/baseline/completion.sql, section W2).
func (r *plannerProviderRejection) payload() map[string]any {
	return map[string]any{"rejected": map[string]any{"status": r.Status, "raw": string(r.Body)}}
}

// capturedPlanningRejection reconciles a started intent whose request the
// provider definitely refused. A successful return means the reservation was
// released and the terminal evidence recorded.
type capturedPlanningRejection interface {
	RecoverRejectedPlanning(context.Context, json.RawMessage, *plannerProviderRejection) error
}

func (d *workerFindingPlanningDatabase) RecoverRejectedPlanning(ctx context.Context, identity json.RawMessage, rejection *plannerProviderRejection) error {
	_, _, _, prefix, supported := d.entries()
	// Only the single-test and finding-response releases accept the evidence.
	if !supported || d.family == workerPlanningOrdered68 || d.compensation == nil || rejection == nil || classifyPlannerProviderRejection(rejection.Status, rejection.Body) == nil {
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
	// The evidence belongs to a started intent with no response. Any other
	// state is reconciled as it always was.
	if prior.State != "started" || prior.HasResponse {
		return authorization.ErrConflict
	}
	terminal, err := call("reconcile", rejection.payload())
	if err != nil {
		return err
	}
	if terminal.State != "needs_human" || terminal.HasResponse || terminal.UsageKnown {
		return authorization.ErrConflict
	}
	return nil
}

// planUnavailable ends a finding-response run whose planner cannot be asked
// (no pricing approval is bound to its scope). The worker first captures the
// run, so the workflow can always clean it up, then records the planning
// intent and reconciles it unsent: the run ends needs_human with the reason
// planner_not_sent, holds no reservation and no capacity, and the workflow
// observes a terminal run.
func (p *temporalFindingResponseProduct) planUnavailable(ctx context.Context, q orchestration.StartRequest) error {
	if p == nil || p.shared == nil || nilWorkerDependency(p.shared.executor) {
		return orchestration.ErrInvalid
	}
	fields := temporalStartFields(q)
	delete(fields, "input_digest")
	identity, err := json.Marshal(fields)
	if err != nil {
		return orchestration.ErrInvalid
	}
	load := map[string]any{"operation": "load"}
	reconcile := map[string]any{"operation": "reconcile", "payload": map[string]any{}}
	for key, value := range fields {
		load[key], reconcile[key] = value, value
	}
	loadRequest, _ := json.Marshal(load)
	reconcileRequest, _ := json.Marshal(reconcile)
	const stateSQL, planSQL = `SELECT zasp_temporal78.planning_state($1::jsonb)`, `SELECT zasp_temporal78.plan($1::jsonb)`
	var db apiserver.JSONDatabase = p.shared.executor
	if p.shared.workerForward != nil {
		request, encodeErr := json.Marshal(temporalStartFields(q))
		if encodeErr != nil {
			return orchestration.ErrInvalid
		}
		if err := retryWorkerAuthorization(ctx, func() error { return p.shared.workerForward.PrepareFinding(ctx, request) }); err != nil {
			return err
		}
		db = &workerFindingPlanningDatabase{base: p.shared.executor, forward: p.shared.workerForward, compensation: p.shared.workerCompensation, start: q}
	}
	state, err := db.QueryJSON(ctx, stateSQL, identity)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(state), []byte("null")) {
		if _, err := db.QueryJSON(ctx, planSQL, loadRequest); err != nil {
			return err
		}
	}
	if recovery, ok := db.(capturedPlanningRecovery); ok {
		return recovery.RecoverCapturedPlanning(ctx, identity, nil)
	}
	raw, err := db.QueryJSON(ctx, planSQL, reconcileRequest)
	if err != nil {
		return err
	}
	var terminal struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &terminal) != nil || terminal.State != "needs_human" {
		return orchestration.ErrConflict
	}
	return nil
}

// plannerRejectionFrom extracts the evidence of a definite refusal from a
// send error.
func plannerRejectionFrom(err error) *plannerProviderRejection {
	var rejection *plannerProviderRejection
	if errors.As(err, &rejection) && rejection != nil {
		return rejection
	}
	return nil
}
