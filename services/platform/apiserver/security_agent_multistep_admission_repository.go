package apiserver

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const securityAgentMultistepAdmissionReadySQL = `SELECT zasp_sa_multistep_prior.ready($1,$2)`
const securityAgentMultistepAdmissionSQL = `SELECT zasp_sa_multistep_prior.admit($1,$2,$3::jsonb)`

// Intentionally private and unwired. This is admission, not an execution
// authority or an extension of the release60 worker repository.
type securityAgentMultistepAdmissionRepository struct{ database JSONDatabase }
type securityAgentMultistepAdmissionReceipt struct {
	ContractVersion       int      `json:"contract_version"`
	Outcome               string   `json:"outcome"`
	OrganizationID        string   `json:"organization_id"`
	WorkspaceID           string   `json:"workspace_id"`
	EnvironmentID         string   `json:"environment_id"`
	RunID                 string   `json:"run_id"`
	Version               int64    `json:"version"`
	PlanHash              string   `json:"plan_hash"`
	StepIDs               []string `json:"step_ids"`
	StepStates            []string `json:"step_states"`
	ApprovalID            string   `json:"approval_id"`
	DependencyID          string   `json:"dependency_id"`
	ProviderReservationID string   `json:"provider_reservation_id"`
}

func newSecurityAgentMultistepAdmissionRepository(database JSONDatabase) (*securityAgentMultistepAdmissionRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	repository := &securityAgentMultistepAdmissionRepository{database: database}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := repository.ready(ctx); err != nil {
		return nil, err
	}
	return repository, nil
}
func (repository *securityAgentMultistepAdmissionRepository) ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	raw, err := repository.database.QueryJSON(ctx, securityAgentMultistepAdmissionReadySQL, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
	var ready struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if err != nil {
		return ErrRepositoryUnavailable
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "release", "principal"); !ok || decodeStrictDiscovery(raw, &ready) != nil || !ready.Release || !ready.Principal {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (repository *securityAgentMultistepAdmissionRepository) admit(ctx context.Context, claim SecurityAgentRunClaim, worker, lease string, value securityAgentOrderedContext, submission securityAgentOrderedSubmission) (securityAgentMultistepAdmissionReceipt, error) {
	empty := securityAgentMultistepAdmissionReceipt{}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validSecurityAgentText(worker, 128) || !validSecurityAgentText(lease, 128) || len(lease) < 16 || !validSecurityAgentOrderedSubmission(submission, value, claim) {
		return empty, ErrRepositoryOperation
	}
	if err := repository.ready(ctx); err != nil {
		return empty, err
	}
	request, err := json.Marshal(map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "definition_id": claim.DefinitionID, "definition_version": claim.DefinitionVersion, "trigger_id": claim.TriggerID, "attempt": claim.Attempt, "run_version": claim.Version, "worker_id": worker, "lease_token": lease, "input_digest": submission.InputDigest, "output_digest": submission.OutputDigest, "model": submission.Model, "policy_version": submission.PolicyVersion, "candidate": submission.Candidate})
	if err != nil {
		return empty, ErrRepositoryOperation
	}
	raw, err := repository.database.QueryJSON(ctx, securityAgentMultistepAdmissionSQL, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), json.RawMessage(request))
	if err != nil {
		return empty, discoveryProviderError(err)
	}
	var receipt securityAgentMultistepAdmissionReceipt
	if _, ok := securityAgentOrderedClosedObject(raw, "contract_version", "outcome", "organization_id", "workspace_id", "environment_id", "run_id", "version", "plan_hash", "step_ids", "step_states", "approval_id", "dependency_id", "provider_reservation_id"); !ok || decodeStrictDiscovery(raw, &receipt) != nil {
		return empty, ErrRepositoryUnavailable
	}
	_, hashOK := decodeSecurityAgentDigest(receipt.PlanHash)
	if receipt.ContractVersion != 61 || receipt.Outcome != "admitted" || receipt.OrganizationID != claim.OrganizationID || receipt.WorkspaceID != claim.WorkspaceID || receipt.EnvironmentID != claim.EnvironmentID || receipt.RunID != claim.RunID || receipt.Version != claim.Version+1 || !hashOK || !validSecurityAgentMultistepAdmissionIDs(receipt, claim) || !slices.Equal(receipt.StepStates, []string{"waiting_approval", "dependency_blocked"}) || !validSecurityAgentText(receipt.ProviderReservationID, 128) {
		return empty, ErrRepositoryUnavailable
	}
	return receipt, nil
}

func validSecurityAgentMultistepAdmissionIDs(receipt securityAgentMultistepAdmissionReceipt, claim SecurityAgentRunClaim) bool {
	o, _ := domain.ParseProductID(claim.OrganizationID)
	w, _ := domain.ParseProductID(claim.WorkspaceID)
	e, _ := domain.ParseProductID(claim.EnvironmentID)
	scope, err := domain.NewScope(o, w, e)
	if err != nil || len(receipt.StepIDs) != 2 {
		return false
	}
	// Match the private admission function's kinds and native identity inputs.
	for index, suffix := range []string{"0", "1"} {
		id, err := CanonicalDiscoveryID(scope, "security_agent_step", claim.RunID+"\x1f"+suffix)
		if err != nil || receipt.StepIDs[index] != id {
			return false
		}
	}
	approval, err := CanonicalDiscoveryID(scope, "security_agent_ordered_approval", claim.RunID+"\x1f"+receipt.StepIDs[0])
	if err != nil || receipt.ApprovalID != approval {
		return false
	}
	dependency, err := CanonicalDiscoveryID(scope, "security_agent_ordered_dependency", claim.RunID+"\x1f"+receipt.StepIDs[1])
	return err == nil && receipt.DependencyID == dependency
}
