package apiserver

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The private admission repository also exposes the dormant transition
// boundary. There are no public handlers, worker routes, or adapter calls.
// The SQL entry point checks the API principal for decisions/cancellation and
// the worker principal for progression, inside the shared schema fence.
func (repository *securityAgentMultistepAdmissionRepository) transition(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var request struct {
		OrganizationID  string `json:"organization_id"`
		WorkspaceID     string `json:"workspace_id"`
		EnvironmentID   string `json:"environment_id"`
		RunID           string `json:"run_id"`
		StepID          string `json:"step_id"`
		Operation       string `json:"operation"`
		ActorID         string `json:"actor_id"`
		RunVersion      int64  `json:"run_version"`
		ApprovalVersion int64  `json:"approval_version"`
		FreshAuthAt     string `json:"fresh_auth_at"`
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 4096 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "actor_id", "run_version", "approval_version", "fresh_auth_at"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	for _, id := range []string{request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return nil, ErrRepositoryOperation
		}
	}
	if request.RunVersion < 1 || request.RunVersion > 999999 || request.ApprovalVersion < 1 || request.ApprovalVersion > 999999 || !validSecurityAgentText(request.ActorID, 128) {
		return nil, ErrRepositoryOperation
	}
	if _, err := time.Parse(time.RFC3339Nano, request.FreshAuthAt); err != nil {
		return nil, ErrRepositoryOperation
	}
	switch request.Operation {
	case "progress", "stop":
	case "approve", "reject", "cancel":
		if _, err := domain.ParseProductID(request.ActorID); err != nil {
			return nil, ErrRepositoryOperation
		}
	default:
		return nil, ErrRepositoryOperation
	}
	o, _ := domain.ParseProductID(request.OrganizationID)
	w, _ := domain.ParseProductID(request.WorkspaceID)
	e, _ := domain.ParseProductID(request.EnvironmentID)
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	index := -1
	for i := 0; i < 2; i++ {
		step, _ := CanonicalDiscoveryID(scope, "security_agent_step", request.RunID+"\x1f"+strconv.Itoa(i))
		if step == request.StepID {
			index = i
		}
	}
	if index < 0 || (request.Operation == "progress" || request.Operation == "stop") && index != 1 {
		return nil, ErrRepositoryOperation
	}
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.transition($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var receipt struct {
		ContractVersion int    `json:"contract_version"`
		OrganizationID  string `json:"organization_id"`
		WorkspaceID     string `json:"workspace_id"`
		EnvironmentID   string `json:"environment_id"`
		RunID           string `json:"run_id"`
		StepID          string `json:"step_id"`
		Outcome         string `json:"outcome"`
		RunState        string `json:"run_state"`
		StepState       string `json:"step_state"`
		RunVersion      int64  `json:"run_version"`
		ApprovalID      string `json:"approval_id"`
		ApprovalVersion int64  `json:"approval_version"`
	}
	if _, ok := securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "outcome", "run_state", "step_state", "run_version", "approval_id", "approval_version"); !ok || decodeStrictDiscovery(response, &receipt) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if receipt.ContractVersion != 61 || receipt.OrganizationID != request.OrganizationID || receipt.WorkspaceID != request.WorkspaceID || receipt.EnvironmentID != request.EnvironmentID || receipt.RunID != request.RunID || receipt.StepID != request.StepID {
		return nil, ErrRepositoryUnavailable
	}
	approval, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_approval", request.RunID+"\x1f"+request.StepID)
	// This dormant contract creates each approval at version 1 and decides or
	// cancels it once. A present approval cannot have an arbitrary SQL version.
	if receipt.ApprovalID != "" && (receipt.ApprovalID != approval || receipt.ApprovalVersion < 1 || receipt.ApprovalVersion > 2) || (receipt.ApprovalID == "") != (receipt.ApprovalVersion == 0) {
		return nil, ErrRepositoryUnavailable
	}
	valid := false
	switch receipt.Outcome {
	case "waiting":
		valid = request.Operation == "progress" && receipt.RunVersion == request.RunVersion && receipt.StepState == "queued" && receipt.ApprovalID == "" && (receipt.RunState == "waiting_approval" || receipt.RunState == "running" || receipt.RunState == "verifying")
	case "ready":
		valid = request.Operation == "progress" && receipt.RunVersion == request.RunVersion+1 && receipt.StepState == "waiting_approval" && receipt.RunState == "waiting_approval" && receipt.ApprovalID == approval && receipt.ApprovalVersion == 1
	case "approved":
		valid = request.Operation == "approve" && receipt.RunVersion == request.RunVersion+1 && receipt.StepState == "authorized" && receipt.RunState == "running" && receipt.ApprovalID == approval && receipt.ApprovalVersion == request.ApprovalVersion+1
	case "blocked":
		if request.Operation == "reject" {
			valid = receipt.RunVersion == request.RunVersion+1 && receipt.RunState == "needs_human" && receipt.StepState == "cancelled" && receipt.ApprovalID == approval && receipt.ApprovalVersion == 2 && receipt.ApprovalVersion == request.ApprovalVersion+1
		} else if receipt.StepState == "executing" {
			// Cancellation retains execution evidence for either canonical step
			// of the exact pair. SQL owns admission and preserves cleanup. This
			// response never authorizes descendants or asserts a test receipt.
			valid = ((request.Operation == "cancel" && (index == 0 || index == 1) && receipt.RunState == "cancelled" && receipt.RunVersion == request.RunVersion+1) ||
				(request.Operation == "stop" && index == 1 && receipt.RunState == "needs_human" && (receipt.RunVersion == request.RunVersion || receipt.RunVersion == request.RunVersion+1))) && receipt.ApprovalID == approval && receipt.ApprovalVersion == 2
		} else {
			// A never-ready successor can be cancelled without an approval. All
			// other blocked steps retain a single decided/cancelled approval.
			approvalValid := receipt.ApprovalID == approval && receipt.ApprovalVersion == 2 || index == 1 && receipt.StepState == "cancelled" && receipt.ApprovalID == "" && receipt.ApprovalVersion == 0
			valid = (request.Operation == "progress" || request.Operation == "stop" || request.Operation == "cancel") && approvalValid && (receipt.RunVersion == request.RunVersion || receipt.RunVersion == request.RunVersion+1) && (receipt.StepState == "cancelled" || receipt.StepState == "succeeded" || receipt.StepState == "failed" || receipt.StepState == "inconclusive") && (receipt.RunState == "cancelled" || receipt.RunState == "needs_human" || receipt.RunState == "failed" || receipt.RunState == "inconclusive" || receipt.RunState == "contained" || receipt.RunState == "remediated")
		}
	}
	if !valid || request.Operation == "stop" && (receipt.Outcome != "blocked" || receipt.RunState != "needs_human") {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}
