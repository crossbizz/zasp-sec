package main

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type temporalFindingResponseProduct struct{ shared *temporalSecurityAgentProduct }

func (p *temporalSecurityAgentProduct) FindingResponseProduct() orchestration.FindingResponseProduct {
	return &temporalFindingResponseProduct{shared: p}
}

func (p *temporalFindingResponseProduct) inspect(ctx context.Context, q orchestration.StartRequest, db apiserver.JSONDatabase) (temporalSingleState, error) {
	var state temporalSingleState
	if p == nil || p.shared == nil || q.DefinitionVersion < 1 || q.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(q.InputDigest) {
		return state, orchestration.ErrInvalid
	}
	id, err := orchestration.FindingResponseWorkflowID(q.Ref)
	if err != nil {
		return state, err
	}
	scope, err := temporalScope(q)
	if err != nil {
		return state, err
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", q.Ref.RunID+"\x1f0")
	raw, err := temporalQuery(ctx, db, `SELECT zasp_temporal78.inspect($1::jsonb)`, temporalStartFields(q))
	if err != nil {
		return state, err
	}
	fields, closed := securityAgentOrderedJSONObject(raw)
	closed = closed && len(fields) == 8 && len(fields["planning_state"]) > 0 && len(fields["deadline"]) > 0
	for _, key := range []string{"phase", "workflow_id", "step_id", "action_key", "run_state", "unresolved"} {
		closed = closed && len(fields[key]) > 0 && !bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null"))
	}
	if len(raw) > 4096 || !closed || decodeStrictWorkerJSON(raw, &state) != nil || state.WorkflowID != id || state.StepID != step || state.Action != "update_finding_response" || !stringInWorker(state.Phase, "planning", "apply", "terminal", "waiting_approval", "pending", "permission_lost", "stopping", "stale") || state.RunState == "" || state.Phase == "terminal" && state.Unresolved {
		return state, orchestration.ErrConflict
	}
	if state.Deadline != nil {
		if _, err := time.Parse(time.RFC3339Nano, *state.Deadline); err != nil {
			return state, orchestration.ErrConflict
		}
	}
	return state, nil
}

func (p *temporalFindingResponseProduct) Observe(ctx context.Context, q orchestration.StartRequest) (orchestration.RunState, error) {
	if p == nil || p.shared == nil {
		return orchestration.RunState{}, orchestration.ErrInvalid
	}
	state, err := p.inspect(ctx, q, p.shared.executor)
	return orchestration.RunState{Phase: state.Phase}, temporalProductError(ctx, err)
}

func (p *temporalFindingResponseProduct) Plan(ctx context.Context, q orchestration.StartRequest) error {
	if p == nil || p.shared == nil {
		return orchestration.ErrInvalid
	}
	state, err := p.inspect(ctx, q, p.shared.executor)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	if state.Phase != "planning" {
		return nil
	}
	for _, selection := range p.shared.bindings {
		if selection.OrganizationID == q.Ref.OrganizationID && selection.WorkspaceID == q.Ref.WorkspaceID && selection.EnvironmentID == q.Ref.EnvironmentID {
			db := p.shared.executor
			if p.shared.workerForward != nil {
				request, encodeErr := json.Marshal(temporalStartFields(q))
				if encodeErr != nil {
					return orchestration.ErrInvalid
				}
				if err := p.shared.workerForward.PrepareFinding(ctx, request); err != nil {
					return temporalProductError(ctx, err)
				}
				db = &workerFindingPlanningDatabase{base: db, forward: p.shared.workerForward, compensation: p.shared.workerCompensation, start: q}
			}
			_, err := p.shared.planner.RunFindingResponsePlanning(ctx, db, p.shared.store, selection, q.Ref.RunID, q.DefinitionVersion)
			return temporalProductError(ctx, err)
		}
	}
	return orchestration.ErrInvalid
}

func (p *temporalFindingResponseProduct) Apply(ctx context.Context, q orchestration.StartRequest) error {
	if p == nil || p.shared == nil {
		return orchestration.ErrInvalid
	}
	state, err := p.inspect(ctx, q, p.shared.executor)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	if state.Phase != "apply" && !(p.shared.workerForward != nil && state.RunState == "remediated") {
		return nil
	}
	var raw json.RawMessage
	if p.shared.workerForward != nil {
		request, encodeErr := json.Marshal(temporalStartFields(q))
		if encodeErr != nil {
			return orchestration.ErrInvalid
		}
		operation := authorization.FindingApply
		if state.RunState == "remediated" {
			operation = authorization.FindingReplay
		} else if err := p.shared.workerForward.PrepareFinding(ctx, request); err != nil {
			return temporalProductError(ctx, err)
		}
		decision, authorizeErr := p.shared.workerForward.Authorize(ctx, operation, request)
		if authorizeErr != nil {
			return temporalProductError(ctx, authorizeErr)
		}
		raw, err = p.shared.workerForward.Execute(ctx, decision)
	} else {
		raw, err = temporalQuery(ctx, p.shared.executor, `SELECT zasp_temporal78.apply($1::jsonb)`, temporalStartFields(q))
	}
	if err != nil {
		return temporalProductError(ctx, err)
	}
	var receipt struct {
		Contract   int    `json:"contract_version"`
		WorkflowID string `json:"workflow_id"`
		RunID      string `json:"run_id"`
		StepID     string `json:"step_id"`
		State      string `json:"state"`
		OutcomeID  string `json:"outcome_id"`
		Digest     string `json:"result_digest"`
	}
	_, closed := securityAgentOrderedClosedObject(raw, "contract_version", "workflow_id", "run_id", "step_id", "state", "outcome_id", "result_digest")
	scope, err := temporalScope(q)
	if err != nil {
		return orchestration.ErrInvalid
	}
	outcome, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_effect", q.Ref.RunID+"\x1f"+state.StepID+"\x1fupdate_finding_response")
	if len(raw) > 4096 || !closed || decodeStrictWorkerJSON(raw, &receipt) != nil || receipt.Contract != 78 || receipt.WorkflowID != state.WorkflowID || receipt.RunID != q.Ref.RunID || receipt.StepID != state.StepID || receipt.State != "remediated" || receipt.OutcomeID != outcome || !providerAckPattern.MatchString(receipt.Digest) {
		return orchestration.ErrConflict
	}
	return nil
}

func (p *temporalFindingResponseProduct) Cleanup(ctx context.Context, q orchestration.CleanupRequest) error {
	if p == nil || p.shared == nil || !stringInWorker(q.Reason, "terminal", "workflow_failed", "workflow_cancelled", "workflow_deadline") {
		return orchestration.ErrInvalid
	}
	state, err := p.inspect(ctx, q.Start, p.shared.compensation)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	fields := temporalStartFields(q.Start)
	fields["reason"] = q.Reason
	var raw json.RawMessage
	if p.shared.workerCompensation != nil {
		request, encodeErr := json.Marshal(fields)
		if encodeErr != nil {
			return orchestration.ErrInvalid
		}
		decision, authorizeErr := p.shared.workerCompensation.Authorize(ctx, authorization.FindingCleanup, request)
		if authorizeErr != nil {
			return temporalProductError(ctx, authorizeErr)
		}
		raw, err = p.shared.workerCompensation.Execute(ctx, decision)
	} else {
		raw, err = temporalQuery(ctx, p.shared.compensation, `SELECT zasp_temporal78.cleanup($1::jsonb)`, fields)
	}
	if err != nil {
		return temporalProductError(ctx, err)
	}
	var receipt struct {
		WorkflowID     string `json:"workflow_id"`
		Pending        bool   `json:"pending"`
		EvidenceDigest string `json:"evidence_digest"`
	}
	_, closed := securityAgentOrderedClosedObject(raw, "workflow_id", "pending", "evidence_digest")
	if len(raw) > 4096 || !closed || json.Unmarshal(raw, &receipt) != nil || receipt.WorkflowID != state.WorkflowID || !providerAckPattern.MatchString(receipt.EvidenceDigest) {
		return orchestration.ErrConflict
	}
	if receipt.Pending {
		return orchestration.ErrCleanupPending
	}
	return nil
}
