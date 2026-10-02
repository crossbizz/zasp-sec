package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"time"
)

type temporalSingleTestProduct struct{ shared *temporalSecurityAgentProduct }

func (p *temporalSecurityAgentProduct) SingleTestProduct() orchestration.SingleTestProduct {
	var product orchestration.SingleTestProduct = &temporalSingleTestProduct{shared: p}
	if p.singleTestDiagnostic != nil {
		product = p.singleTestDiagnostic(product)
	}
	return product
}

type temporalSingleState struct {
	Phase         string  `json:"phase"`
	WorkflowID    string  `json:"workflow_id"`
	StepID        string  `json:"step_id"`
	Action        string  `json:"action_key"`
	RunState      string  `json:"run_state"`
	PlanningState *string `json:"planning_state"`
	Deadline      *string `json:"deadline"`
	Unresolved    bool    `json:"unresolved"`
}

func (p *temporalSingleTestProduct) inspect(ctx context.Context, q orchestration.StartRequest, db apiserver.JSONDatabase) (temporalSingleState, error) {
	return p.inspectNative(ctx, q, db)
}

func (p *temporalSingleTestProduct) capturedLifecycle(ctx context.Context, phase string, fields map[string]any) (json.RawMessage, error) {
	if p == nil || p.shared == nil || ctx == nil || p.shared.workerCompensation == nil || !stringInWorker(phase, "inspect", "cleanup", "recovery_status") {
		return nil, orchestration.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil, orchestration.ErrInvalid
	}
	decision, err := p.shared.workerCompensation.Authorize(ctx, authorization.WorkerOperation("test74.lifecycle."+phase), raw)
	if err != nil {
		return nil, err
	}
	return p.shared.workerCompensation.Execute(ctx, decision)
}

// This retained reader returns only bounded workflow state, never planning
// context. Worker phases may use it only after their own boundary is wired.
func (p *temporalSingleTestProduct) inspectNative(ctx context.Context, q orchestration.StartRequest, db apiserver.JSONDatabase) (temporalSingleState, error) {
	var state temporalSingleState
	id, err := orchestration.SingleTestWorkflowID(q.Ref)
	if err != nil {
		return state, err
	}
	scope, err := temporalScope(q)
	if err != nil {
		return state, err
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", q.Ref.RunID+"\x1f0")
	var raw json.RawMessage
	if p != nil && p.shared != nil && p.shared.workerForward != nil {
		raw, err = p.capturedLifecycle(ctx, "inspect", temporalStartFields(q))
	} else {
		raw, err = temporalQuery(ctx, db, `SELECT zasp_temporal74.inspect($1::jsonb)`, temporalStartFields(q))
	}
	if err != nil {
		return state, err
	}
	if len(raw) > 4096 || decodeStrictWorkerJSON(raw, &state) != nil || state.WorkflowID != id || state.StepID != step || !stringInWorker(state.Action, "run_test", "rerun_test") || !stringInWorker(state.Phase, "planning", "test", "settling", "terminal", "waiting_approval", "pending", "permission_lost", "stopping") || state.RunState == "" || state.Phase == "terminal" && state.Unresolved {
		return state, orchestration.ErrConflict
	}
	if state.Deadline != nil {
		if _, err := time.Parse(time.RFC3339Nano, *state.Deadline); err != nil {
			return state, orchestration.ErrConflict
		}
	}
	return state, nil
}
func (p *temporalSingleTestProduct) Observe(ctx context.Context, q orchestration.StartRequest) (orchestration.RunState, error) {
	v, err := p.inspect(ctx, q, p.shared.executor)
	return orchestration.RunState{Phase: v.Phase}, temporalProductError(ctx, err)
}
func (p *temporalSingleTestProduct) Plan(ctx context.Context, q orchestration.StartRequest) error {
	if p == nil || p.shared == nil {
		return orchestration.ErrInvalid
	}
	v, err := p.inspectNative(ctx, q, p.shared.executor)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	if v.Phase != "planning" {
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
				if err := p.shared.workerForward.PrepareTest74(ctx, request); err != nil {
					return temporalProductError(ctx, err)
				}
				db = &workerFindingPlanningDatabase{base: db, forward: p.shared.workerForward, compensation: p.shared.workerCompensation, start: q, family: workerPlanningTest74}
			}
			_, err := p.shared.planner.RunSingleTestPlanning(ctx, db, p.shared.store, selection, q.Ref.RunID, q.DefinitionVersion)
			return temporalProductError(ctx, err)
		}
	}
	return orchestration.ErrInvalid
}
func (p *temporalSingleTestProduct) Test(ctx context.Context, q orchestration.StartRequest) error {
	v, err := p.inspectNative(ctx, q, p.shared.executor)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	if v.Phase != "test" && !(p.shared.workerForward != nil && v.Phase == "permission_lost" && v.PlanningState != nil && *v.PlanningState == "admitted") {
		return nil
	}
	scope, err := temporalScope(q)
	if err != nil {
		return err
	}
	db := p.shared.executor
	if p.shared.workerForward != nil {
		db = &workerSingleTestDatabase{base: db, forward: p.shared.workerForward, compensation: p.shared.workerCompensation, start: q}
	}
	return temporalProductError(ctx, p.shared.runner.RunSingleTest(ctx, db, scope, q.Ref.RunID, v.StepID, v.Action))
}
func (p *temporalSingleTestProduct) Settle(ctx context.Context, q orchestration.StartRequest) error {
	v, err := p.inspectNative(ctx, q, p.shared.executor)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	if v.Phase == "terminal" {
		return nil
	}
	scope, err := temporalScope(q)
	if err != nil {
		return err
	}
	db := p.shared.executor
	if p.shared.workerForward != nil {
		db = &workerSingleTestDatabase{base: db, forward: p.shared.workerForward, compensation: p.shared.workerCompensation, start: q}
	}
	return temporalProductError(ctx, p.shared.runner.SettleSingleTest(ctx, db, scope, q.Ref.RunID, v.StepID, v.Action))
}
func (p *temporalSingleTestProduct) Cleanup(ctx context.Context, q orchestration.CleanupRequest) error {
	if !stringInWorker(q.Reason, "terminal", "workflow_failed", "workflow_cancelled", "workflow_deadline") {
		return orchestration.ErrInvalid
	}
	// A known child can finish its proof after revocation. This operation reads
	// artifacts and settles journals only; it never obtains another send permit.
	v, err := p.inspect(ctx, q.Start, p.shared.compensation)
	if err != nil {
		return temporalProductError(ctx, err)
	}
	if v.PlanningState != nil && *v.PlanningState == "admitted" && v.Phase != "terminal" {
		scope, err := temporalScope(q.Start)
		if err != nil {
			return err
		}
		db := p.shared.compensation
		if p.shared.workerForward != nil {
			db = &workerSingleTestDatabase{base: db, forward: p.shared.workerForward, compensation: p.shared.workerCompensation, start: q.Start}
		}
		x, err := singleTestExecutionFor(db, scope, q.Start.Ref.RunID, v.StepID, v.Action)
		if err != nil {
			return err
		}
		state, err := x.state(ctx)
		if err != nil {
			return temporalProductError(ctx, err)
		}
		if p.shared.workerForward != nil && (state == "started" || state == "unknown") {
			raw, err := p.capturedLifecycle(ctx, "recovery_status", temporalStartFields(q.Start))
			if err != nil {
				return temporalProductError(ctx, err)
			}
			var status struct {
				Status string `json:"status"`
			}
			if len(raw) > 64 || decodeStrictWorkerJSON(raw, &status) != nil || !stringInWorker(status.Status, "complete", "pending") {
				return orchestration.ErrConflict
			}
			if status.Status == "complete" {
				if err := p.shared.runner.RunSingleTest(ctx, db, scope, q.Start.Ref.RunID, v.StepID, v.Action); err != nil {
					return temporalProductError(ctx, err)
				}
				state, err = x.state(ctx)
				if err != nil {
					return temporalProductError(ctx, err)
				}
			}
		}
		if state == "child" {
			settlement := p.shared.executor
			if p.shared.workerForward != nil {
				settlement = db
			}
			if err := p.shared.runner.SettleSingleTest(ctx, settlement, scope, q.Start.Ref.RunID, v.StepID, v.Action); err != nil {
				return temporalProductError(ctx, err)
			}
		}
	}
	fields := temporalStartFields(q.Start)
	fields["reason"] = q.Reason
	var raw json.RawMessage
	if p.shared.workerForward != nil {
		raw, err = p.capturedLifecycle(ctx, "cleanup", fields)
	} else {
		raw, err = temporalQuery(ctx, p.shared.compensation, `SELECT zasp_temporal74.cleanup($1::jsonb)`, fields)
	}
	if err != nil {
		return temporalProductError(ctx, err)
	}
	var receipt struct {
		WorkflowID string          `json:"workflow_id"`
		Pending    bool            `json:"pending"`
		Evidence   json.RawMessage `json:"evidence"`
	}
	id, err := orchestration.SingleTestWorkflowID(q.Start.Ref)
	if err != nil || len(raw) > 32768 || decodeStrictWorkerJSON(raw, &receipt) != nil || receipt.WorkflowID != id || len(receipt.Evidence) == 0 || string(receipt.Evidence) == "null" {
		return orchestration.ErrConflict
	}
	if receipt.Pending {
		return orchestration.ErrCleanupPending
	}
	return nil
}
