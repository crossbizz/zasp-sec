package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Deliberately not a PolicyDeploymentRepository constructor or worker route.
// This exact-source boundary is callable only by the deployment principal. The
// SQL boundary owns fencing, scoped claim/recovery and atomic legacy delegation.
func (repository *securityAgentMultistepAdmissionRepository) deployment(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	return repository.orderedDeployment(ctx, raw, keys, false)
}

func (repository *securityAgentMultistepAdmissionRepository) orderedDeployment(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys, cleanup bool) (json.RawMessage, error) {
	verifyEnvelope := orderedVerifiedEnvelope
	if cleanup {
		verifyEnvelope = orderedCleanupVerifiedEnvelope
	}
	var request struct {
		OrganizationID    string          `json:"organization_id"`
		WorkspaceID       string          `json:"workspace_id"`
		EnvironmentID     string          `json:"environment_id"`
		RunID             string          `json:"run_id"`
		StepID            string          `json:"step_id"`
		RunVersion        int64           `json:"run_version"`
		EffectVersion     int64           `json:"effect_version"`
		ActionWorkerID    string          `json:"action_worker_id"`
		ActionLeaseToken  string          `json:"action_lease_token"`
		DeviceID          string          `json:"device_id"`
		CredentialID      string          `json:"credential_id"`
		SourceSequence    int64           `json:"source_sequence"`
		SourceDigest      string          `json:"source_digest"`
		DesiredGeneration int64           `json:"desired_generation"`
		Operation         string          `json:"operation"`
		WorkerID          string          `json:"worker_id"`
		LeaseToken        string          `json:"lease_token"`
		LeaseSeconds      int             `json:"lease_seconds"`
		Sequence          int64           `json:"sequence"`
		InputDigest       string          `json:"input_digest"`
		Composition       json.RawMessage `json:"composition"`
		Envelope          json.RawMessage `json:"envelope"`
		Digest            string          `json:"digest"`
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > orderedDeploymentRequestBytes {
		return nil, ErrRepositoryOperation
	}
	if _, ok := orderedDeploymentClosedObject(raw, orderedDeploymentRequestBytes, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "run_version", "effect_version", "action_worker_id", "action_lease_token", "device_id", "credential_id", "source_sequence", "source_digest", "desired_generation", "operation", "worker_id", "lease_token", "lease_seconds", "sequence", "input_digest", "composition", "envelope", "digest"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedApplicationScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	_, sourceOK := decodeTemporaryPolicyDigest(request.SourceDigest)
	if !valid || !sourceOK || !validProductID(request.DeviceID) || !validProductID(request.CredentialID) || request.RunVersion < 1 || request.RunVersion > 999999 || request.EffectVersion < 1 || request.EffectVersion > 999999 || request.SourceSequence < 1 || request.SourceSequence > 999999999 || request.DesiredGeneration < 1 || request.DesiredGeneration > 999999999 || !validSecurityAgentWorkerLease(request.WorkerID, request.LeaseToken, request.LeaseSeconds) || !validSecurityAgentWorkerIdentity(request.ActionWorkerID, request.ActionLeaseToken) {
		return nil, ErrRepositoryOperation
	}
	binding := []string{request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID, request.DeviceID, request.CredentialID, strconv.FormatInt(request.DesiredGeneration, 10), strconv.FormatInt(request.SourceSequence, 10), request.SourceDigest}
	composition, compositionOK := orderedDeploymentCompositionModeValid(request.Composition, scope, request.RunID, request.StepID, request.DeviceID, request.CredentialID, request.SourceSequence, request.DesiredGeneration, request.SourceDigest, cleanup)
	if request.Operation == "claim" {
		if _, ok := securityAgentOrderedClosedObject(request.Composition); !ok || request.Sequence != 0 || request.InputDigest != "" || request.Digest != "" {
			return nil, ErrRepositoryOperation
		}
	} else if !compositionOK || request.Sequence < 1 || request.Sequence > 999999999 || request.InputDigest != orderedDeploymentInputDigest(binding, request.Composition) {
		return nil, ErrRepositoryOperation
	}
	switch request.Operation {
	case "claim", "read", "finish":
		if _, ok := securityAgentOrderedClosedObject(request.Envelope); !ok {
			return nil, ErrRepositoryOperation
		}
		if request.Operation == "finish" {
			if _, ok := decodeTemporaryPolicyDigest(request.Digest); !ok {
				return nil, ErrRepositoryOperation
			}
		} else if request.Digest != "" {
			return nil, ErrRepositoryOperation
		}
	case "store":
		var envelope policy.GatewayPolicyEnvelope
		expires, _ := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
		if !orderedDecodeEnvelope(request.Envelope, &envelope) || !verifyEnvelope(envelope, keys, request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.DeviceID, request.Sequence) || orderedEnvelopeDigest(envelope) != request.Digest || !reflect.DeepEqual(envelope.Policies, composition.Policies) || envelope.ExpiresAt.After(expires) {
			return nil, ErrRepositoryOperation
		}
	default:
		return nil, ErrRepositoryOperation
	}
	statement := `SELECT zasp_sa_multistep_prior.deployment($1,$2,$3::jsonb)`
	if cleanup {
		statement = `SELECT zasp_sa_multistep_prior.cleanup_deployment($1,$2,$3::jsonb)`
	}
	response, err := repository.database.QueryJSON(ctx, statement, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result struct {
		ContractVersion int             `json:"contract_version"`
		RunID           string          `json:"run_id"`
		StepID          string          `json:"step_id"`
		Operation       string          `json:"operation"`
		SourceID        string          `json:"source_id"`
		WorkID          string          `json:"work_id"`
		Result          json.RawMessage `json:"result"`
	}
	if _, ok := orderedDeploymentClosedObject(response, orderedDeploymentResponseBytes, "contract_version", "run_id", "step_id", "operation", "source_id", "work_id", "result"); !ok || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	sourceID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_source", strings.Join([]string{request.RunID, request.StepID, request.DeviceID, strconv.FormatInt(request.SourceSequence, 10), request.SourceDigest}, "\x1f"))
	workID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_work", strings.Join([]string{request.RunID, request.StepID, request.DeviceID, strconv.FormatInt(request.DesiredGeneration, 10)}, "\x1f"))
	if result.ContractVersion != 61 || result.RunID != request.RunID || result.StepID != request.StepID || result.Operation != request.Operation || result.SourceID != sourceID || result.WorkID != workID {
		return nil, ErrRepositoryUnavailable
	}
	switch request.Operation {
	case "claim":
		var claim orderedDeploymentClaim
		if _, ok := orderedDeploymentClosedObject(result.Result, orderedDeploymentResponseBytes, "organization_id", "workspace_id", "environment_id", "device_id", "credential_id", "desired_generation", "sequence", "policy_version", "input_digest", "lease_expires_at", "composition"); !ok || decodeStrictDiscovery(result.Result, &claim) != nil || claim.Sequence < 1 || claim.Sequence > 999999999 || claim.PolicyVersion != claim.Sequence || claim.OrganizationID != request.OrganizationID || claim.WorkspaceID != request.WorkspaceID || claim.EnvironmentID != request.EnvironmentID || claim.DeviceID != request.DeviceID || claim.CredentialID != request.CredentialID || claim.DesiredGeneration != request.DesiredGeneration || claim.InputDigest != orderedDeploymentInputDigest(binding, claim.Composition) || claim.LeaseExpiresAt.Location() != time.UTC || !claim.LeaseExpiresAt.After(time.Now()) {
			return nil, ErrRepositoryUnavailable
		}
		composition, valid := orderedDeploymentCompositionModeValid(claim.Composition, scope, request.RunID, request.StepID, request.DeviceID, request.CredentialID, request.SourceSequence, request.DesiredGeneration, request.SourceDigest, cleanup)
		if !valid || !orderedDeploymentSignable(scope, request.DeviceID, claim.Sequence, composition.Policies) {
			return nil, ErrRepositoryUnavailable
		}
	case "store":
		var stored struct {
			EnvelopeDigest string `json:"envelope_digest"`
		}
		if _, ok := securityAgentOrderedClosedObject(result.Result, "envelope_digest"); !ok || decodeStrictDiscovery(result.Result, &stored) != nil || stored.EnvelopeDigest != request.Digest {
			return nil, ErrRepositoryUnavailable
		}
	case "read":
		var envelope policy.GatewayPolicyEnvelope
		expires, _ := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
		if !orderedDecodeEnvelope(result.Result, &envelope) || !verifyEnvelope(envelope, keys, request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.DeviceID, request.Sequence) || !reflect.DeepEqual(envelope.Policies, composition.Policies) || envelope.ExpiresAt.After(expires) {
			return nil, ErrRepositoryUnavailable
		}
	case "finish":
		var finished struct {
			DesiredGeneration int64  `json:"desired_generation"`
			AppliedGeneration int64  `json:"applied_generation"`
			State             string `json:"state"`
			EnvelopeDigest    string `json:"envelope_digest"`
		}
		if _, ok := securityAgentOrderedClosedObject(result.Result, "desired_generation", "applied_generation", "state", "envelope_digest"); !ok || decodeStrictDiscovery(result.Result, &finished) != nil || finished.DesiredGeneration != request.DesiredGeneration || finished.AppliedGeneration != request.DesiredGeneration || finished.State != "scheduled" || finished.EnvelopeDigest != request.Digest {
			return nil, ErrRepositoryUnavailable
		}
	}
	return response, nil
}

func orderedDecodeEnvelope(raw json.RawMessage, value *policy.GatewayPolicyEnvelope) bool {
	_, ok := orderedDeploymentClosedObject(raw, orderedDeploymentResponseBytes, "contract_version", "key_id", "algorithm", "audience", "organization_id", "workspace_id", "environment_id", "device_id", "sequence", "policy_version", "issued_at", "expires_at", "failure_mode", "payload_digest", "policies", "signature")
	return ok && decodeStrictDiscovery(raw, value) == nil
}
