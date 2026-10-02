package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// The reader is private composition, not a generic/public run detail route.
func (repository *securityAgentMultistepAdmissionRepository) orchestrationState(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var q struct {
		OrganizationID       string `json:"organization_id"`
		WorkspaceID          string `json:"workspace_id"`
		EnvironmentID        string `json:"environment_id"`
		RunID                string `json:"run_id"`
		WorkerID             string `json:"worker_id"`
		LeaseToken           string `json:"lease_token"`
		DeploymentWorkerID   string `json:"deployment_worker_id"`
		DeploymentLeaseToken string `json:"deployment_lease_token"`
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 4096 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "worker_id", "lease_token", "deployment_worker_id", "deployment_lease_token"); !ok || decodeStrictDiscovery(raw, &q) != nil || !validSecurityAgentWorkerIdentity(q.WorkerID, q.LeaseToken) || !validSecurityAgentWorkerIdentity(q.DeploymentWorkerID, q.DeploymentLeaseToken) {
		return nil, ErrRepositoryOperation
	}
	// Scope validation also checks the canonical step: derive it from trusted
	// scope/run identities rather than accepting a caller-supplied step selector.
	if !validProductID(q.OrganizationID) || !validProductID(q.WorkspaceID) || !validProductID(q.EnvironmentID) || !validProductID(q.RunID) {
		return nil, ErrRepositoryOperation
	}
	o, _ := domain.ParseProductID(q.OrganizationID)
	w, _ := domain.ParseProductID(q.WorkspaceID)
	e, _ := domain.ParseProductID(q.EnvironmentID)
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = repository.ready(bounded); err != nil {
		return nil, err
	}
	response, err := repository.database.QueryJSON(bounded, `SELECT zasp_sa_multistep_prior.orchestration_state($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result struct {
		ContractVersion int               `json:"contract_version"`
		OrganizationID  string            `json:"organization_id"`
		WorkspaceID     string            `json:"workspace_id"`
		EnvironmentID   string            `json:"environment_id"`
		RunID           string            `json:"run_id"`
		RunState        string            `json:"run_state"`
		RunVersion      int64             `json:"run_version"`
		Steps           []json.RawMessage `json:"steps"`
		Admitted        bool              `json:"admitted"`
		Planning        json.RawMessage   `json:"planning"`
		Application     json.RawMessage   `json:"application"`
		StopRequired    bool              `json:"stop_required"`
		Test            json.RawMessage   `json:"test"`
		Cleanup         json.RawMessage   `json:"cleanup"`
	}
	if _, ok := orderedDeploymentClosedObject(response, 9*1024*1024, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "run_state", "run_version", "steps", "admitted", "planning", "application", "stop_required", "test", "cleanup"); !ok || decodeStrictDiscovery(response, &result) != nil || result.ContractVersion != 61 || result.OrganizationID != q.OrganizationID || result.WorkspaceID != q.WorkspaceID || result.EnvironmentID != q.EnvironmentID || result.RunID != q.RunID || result.RunVersion < 1 || result.RunVersion > 999999 || (result.Admitted && len(result.Steps) != 2) || (!result.Admitted && len(result.Steps) != 0) {
		return nil, ErrRepositoryUnavailable
	}
	if _, empty := securityAgentOrderedClosedObject(result.Planning); !empty {
		var job struct {
			State          string    `json:"state"`
			Owned          bool      `json:"owned"`
			LeaseExpiresAt time.Time `json:"lease_expires_at"`
		}
		if _, ok := securityAgentOrderedClosedObject(result.Planning, "state", "owned", "lease_expires_at"); !ok || decodeStrictDiscovery(result.Planning, &job) != nil || job.LeaseExpiresAt.IsZero() {
			return nil, ErrRepositoryUnavailable
		}
		switch job.State {
		case "claimed", "prepared", "started", "completed", "settled", "artifacts", "admitted", "needs_human":
		default:
			return nil, ErrRepositoryUnavailable
		}
	} else if !result.Admitted && result.RunState != "queued" {
		return nil, ErrRepositoryUnavailable
	}
	for i, rawStep := range result.Steps {
		var step struct {
			StepID          string `json:"step_id"`
			StepIndex       int    `json:"step_index"`
			State           string `json:"state"`
			StepVersion     int64  `json:"step_version"`
			ApprovalState   string `json:"approval_state"`
			ApprovalVersion int64  `json:"approval_version"`
			EffectState     string `json:"effect_state"`
			EffectVersion   int64  `json:"effect_version"`
			Attempt         int    `json:"attempt"`
			LeaseExpiresAt  string `json:"lease_expires_at"`
			Owned           bool   `json:"owned"`
		}
		id, _ := CanonicalDiscoveryID(scope, "security_agent_step", q.RunID+"\x1f"+strconv.Itoa(i))
		if _, ok := securityAgentOrderedClosedObject(rawStep, "step_id", "step_index", "state", "step_version", "approval_state", "approval_version", "effect_state", "effect_version", "attempt", "lease_expires_at", "owned"); !ok || decodeStrictDiscovery(rawStep, &step) != nil || step.StepID != id || step.StepIndex != i || step.StepVersion < 1 || step.EffectVersion < 0 || step.ApprovalVersion < 0 || step.ApprovalVersion > 2 {
			return nil, ErrRepositoryUnavailable
		}
	}
	if !validRelease61ApplicationState(result.Application, scope, q.RunID, result.Admitted) {
		return nil, ErrRepositoryUnavailable
	}
	if !validRelease61TestState(result.Test, scope, q.RunID) {
		return nil, ErrRepositoryUnavailable
	}
	if !validRelease61CleanupState(result.Cleanup, scope, q.RunID) {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

func validRelease61CleanupState(raw json.RawMessage, scope domain.Scope, run string) bool {
	if _, empty := securityAgentOrderedClosedObject(raw); empty {
		return true
	}
	var c struct {
		State          string          `json:"state"`
		Version        int64           `json:"version"`
		Owned          bool            `json:"owned"`
		LeaseExpiresAt string          `json:"lease_expires_at"`
		Application    json.RawMessage `json:"application"`
		ReceiptKind    string          `json:"receipt_kind"`
		Receipt        json.RawMessage `json:"receipt"`
		ReceiptDigest  string          `json:"receipt_digest"`
	}
	if _, ok := orderedDeploymentClosedObject(raw, 9*1024*1024, "state", "version", "owned", "lease_expires_at", "application", "receipt_kind", "receipt", "receipt_digest"); !ok || decodeStrictDiscovery(raw, &c) != nil || c.Version < 1 || c.Version > 999999 || !validRelease61ApplicationState(c.Application, scope, run, true, true) {
		return false
	}
	if c.State == "leased" {
		if _, err := time.Parse(time.RFC3339Nano, c.LeaseExpiresAt); err != nil {
			return false
		}
	} else if c.Owned || c.LeaseExpiresAt != "" || (c.State != "retryable" && c.State != "cleaned") {
		return false
	}
	if c.State != "cleaned" {
		_, empty := securityAgentOrderedClosedObject(c.Receipt)
		return empty && c.ReceiptKind == "" && c.ReceiptDigest == ""
	}
	if c.ReceiptDigest != orderedCleanupDigest(c.Receipt) || (c.ReceiptKind != "temporary_policy_cleaned.v1" && c.ReceiptKind != "temporary_policy_partial_cleaned.v1") {
		return false
	}
	var app struct {
		Targets []orderedApplicationTarget `json:"targets"`
	}
	if json.Unmarshal(c.Application, &app) != nil {
		return false
	}
	targets := map[string]orderedApplicationTarget{}
	for _, t := range app.Targets {
		if t.State != "verified" {
			return false
		}
		targets[t.DeviceID] = t
	}
	var receipt struct {
		Attempts int `json:"attempts"`
	}
	if json.Unmarshal(c.Receipt, &receipt) != nil || receipt.Attempts < 1 || receipt.Attempts > 100 {
		return false
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", run+"\x1f0")
	cleanup, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_cleanup", run+"\x1f"+step)
	control, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_control", run+"\x1f"+step)
	return orderedCleanupReceiptValid(c.Receipt, scope, run, step, cleanup, control, receipt.Attempts, targets, c.ReceiptKind == "temporary_policy_partial_cleaned.v1")
}

func validRelease61TestState(raw json.RawMessage, scope domain.Scope, run string) bool {
	if _, empty := securityAgentOrderedClosedObject(raw); empty {
		return true
	}
	var test struct {
		TestRunID         string            `json:"test_run_id"`
		DefinitionID      string            `json:"test_definition_id"`
		DefinitionVersion int64             `json:"test_definition_version"`
		TargetID          string            `json:"target_id"`
		TargetKind        string            `json:"target_kind"`
		Categories        []string          `json:"categories"`
		InputDigest       string            `json:"input_digest"`
		State             string            `json:"child_state"`
		Attempt           int               `json:"attempt"`
		Owned             bool              `json:"owned"`
		LeaseExpiresAt    string            `json:"lease_expires_at"`
		InputManifest     json.RawMessage   `json:"input_manifest"`
		InputBody         string            `json:"input_body"`
		Observations      []json.RawMessage `json:"observations"`
	}
	if _, ok := orderedDeploymentClosedObject(raw, 262144, "test_run_id", "test_definition_id", "test_definition_version", "target_id", "target_kind", "categories", "input_digest", "child_state", "attempt", "owned", "lease_expires_at", "input_manifest", "input_body", "observations"); !ok || decodeStrictDiscovery(raw, &test) != nil || !validProductID(test.TestRunID) || !validProductID(test.DefinitionID) || !validProductID(test.TargetID) || test.DefinitionVersion < 1 || test.Attempt < 0 || test.Attempt > 5 || len(test.Categories) < 1 || len(test.Categories) > 16 || len(test.InputBody) > 65536 || len(test.Observations) > len(test.Categories) {
		return false
	}
	if _, ok := decodeTemporaryPolicyDigest("sha256:" + test.InputDigest); !ok {
		return false
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", run+"\x1f1")
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", run+"\x1f"+step+"\x1frun_test")
	if test.TestRunID != child {
		return false
	}
	if !stringIn(test.State, "queued", "leased", "retryable", "complete", "failed", "cancelled") || !stringIn(test.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || test.DefinitionVersion > 1000000 || len(test.Categories) > 6 || test.Owned && (test.State != "leased" || test.LeaseExpiresAt == "") {
		return false
	}
	categories := map[string]bool{}
	for _, category := range test.Categories {
		if !stringIn(category, "prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information") || categories[category] {
			return false
		}
		categories[category] = true
	}
	if test.LeaseExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, test.LeaseExpiresAt); err != nil {
			return false
		}
	}
	if test.InputBody == "" {
		if _, ok := securityAgentOrderedClosedObject(test.InputManifest); !ok {
			return false
		}
	} else {
		var manifest RedTeamArtifactReference
		input, valid := orderedTestDecodeInput([]byte(test.InputBody))
		digest := sha256.Sum256([]byte(test.InputBody))
		id, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", run+"\x1f"+step)
		if _, ok := securityAgentOrderedClosedObject(test.InputManifest, "reference", "version_id", "sha256", "size_bytes"); !ok || decodeStrictDiscovery(test.InputManifest, &manifest) != nil || !validRedTeamInputArtifact(scope, &manifest) || !strings.HasSuffix(manifest.Reference, "/"+id) || manifest.SHA256 != hex.EncodeToString(digest[:]) || manifest.SizeBytes != int64(len(test.InputBody)) || !valid || input.OrganizationID != scope.OrganizationID().String() || input.WorkspaceID != scope.WorkspaceID().String() || input.EnvironmentID != scope.EnvironmentID().String() || input.RunID != child || input.DefinitionID != test.DefinitionID || input.DefinitionVersion != test.DefinitionVersion || input.TargetID != test.TargetID || input.TargetKind != test.TargetKind || input.InputDigest != test.InputDigest || !reflect.DeepEqual(input.Categories, test.Categories) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, raw := range test.Observations {
		var item struct {
			Category    string          `json:"category"`
			State       string          `json:"state"`
			Observation json.RawMessage `json:"observation"`
		}
		if _, ok := securityAgentOrderedClosedObject(raw, "category", "state", "observation"); !ok || decodeStrictDiscovery(raw, &item) != nil || (item.State != "started" && item.State != "completed") || !categories[item.Category] || seen[item.Category] {
			return false
		}
		seen[item.Category] = true
		if item.State == "started" {
			if _, ok := securityAgentOrderedClosedObject(item.Observation); !ok {
				return false
			}
		} else {
			fields, ok := securityAgentOrderedClosedObject(item.Observation, "target_comparison", "schema_version", "run_id", "category", "credential_version_digest", "observation")
			var observation redteamadapter.LinkedObservationResponse
			if !ok || decodeStrictDiscovery(item.Observation, &observation) != nil || observation.SchemaVersion != "red-team-linked-observation-v1" || observation.RunID != child || observation.Category != item.Category || !validAttackLabDigest(observation.CredentialVersionDigest) || observation.TargetComparison == nil || observation.Observation.Protected == nil || observation.Observation.HTTPStatus < 100 || observation.Observation.HTTPStatus > 599 || !validAttackLabDigest(observation.Observation.ResponseDigest) {
				return false
			}
			if _, ok = securityAgentOrderedClosedObject(fields["observation"], "http_status", "response_digest", "protected"); !ok {
				return false
			}
			if _, ok = securityAgentOrderedClosedObject(fields["target_comparison"], "schema_version", "organization_id", "workspace_id", "environment_id", "test_definition_id", "test_definition_version", "target_id", "target_kind", "categories", "safety_digest", "endpoint_digest", "configuration_digest", "credential_binding_id", "credential_binding_version", "credential_binding_digest"); !ok {
				return false
			}
			c := observation.TargetComparison
			if c.Schema != "red-team-target-comparison-v1" || c.Organization != scope.OrganizationID().String() || c.Workspace != scope.WorkspaceID().String() || c.Environment != scope.EnvironmentID().String() || c.Definition != test.DefinitionID || c.DefinitionVersion != test.DefinitionVersion || c.Target != test.TargetID || c.Kind != test.TargetKind || !reflect.DeepEqual(c.Categories, test.Categories) || !validProductID(c.Credential) || c.CredentialVersion < 1 {
				return false
			}
			for _, digest := range []string{c.Safety, c.Endpoint, c.Configuration, c.CredentialDigest} {
				if !validAttackLabDigest(digest) {
					return false
				}
			}
		}
	}
	return true
}

func validRelease61ApplicationState(raw json.RawMessage, scope domain.Scope, run string, admitted bool, cleanupMode ...bool) bool {
	if !admitted {
		_, ok := securityAgentOrderedClosedObject(raw)
		return ok
	}
	var app struct {
		TTL      int               `json:"ttl_seconds"`
		Targets  []json.RawMessage `json:"targets"`
		Delivery json.RawMessage   `json:"delivery"`
	}
	if _, ok := orderedDeploymentClosedObject(raw, 9*1024*1024, "ttl_seconds", "targets", "delivery"); !ok || decodeStrictDiscovery(raw, &app) != nil || app.TTL < 60 || app.TTL > 3600 || app.Targets == nil || len(app.Targets) > 100 {
		return false
	}
	targets := map[string]orderedApplicationTarget{}
	previous := ""
	for _, raw := range app.Targets {
		var target orderedApplicationTarget
		if _, ok := securityAgentOrderedClosedObject(raw, "device_id", "credential_id", "sequence", "policy_version", "state", "desired_generation", "envelope_digest"); !ok || decodeStrictDiscovery(raw, &target) != nil || !validProductID(target.DeviceID) || !validProductID(target.CredentialID) || target.DeviceID <= previous || target.Sequence < 1 || target.Sequence > 999999999 || target.PolicyVersion != target.Sequence {
			return false
		}
		if target.State == "planned" {
			if target.DesiredGeneration != 0 || target.EnvelopeDigest != "" {
				return false
			}
		} else if _, ok := decodeTemporaryPolicyDigest(target.EnvelopeDigest); !ok || target.DesiredGeneration < 1 || (target.State != "stored" && target.State != "verified") {
			return false
		}
		targets[target.DeviceID] = target
		previous = target.DeviceID
	}
	if _, empty := securityAgentOrderedClosedObject(app.Delivery); empty {
		return true
	}
	var delivery struct {
		DeviceID       string          `json:"device_id"`
		Phase          string          `json:"phase"`
		Owned          bool            `json:"owned"`
		LeaseExpiresAt string          `json:"lease_expires_at"`
		Claim          json.RawMessage `json:"claim"`
		Digest         string          `json:"digest"`
	}
	if _, ok := orderedDeploymentClosedObject(app.Delivery, orderedDeploymentResponseBytes, "device_id", "phase", "owned", "lease_expires_at", "claim", "digest"); !ok || decodeStrictDiscovery(app.Delivery, &delivery) != nil {
		return false
	}
	target, ok := targets[delivery.DeviceID]
	if !ok || target.State != "stored" {
		return false
	}
	switch delivery.Phase {
	case "unclaimed", "claimed", "stored", "read":
	default:
		return false
	}
	if delivery.LeaseExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, delivery.LeaseExpiresAt); err != nil {
			return false
		}
	}
	if delivery.Digest != "" {
		if _, ok := decodeTemporaryPolicyDigest(delivery.Digest); !ok {
			return false
		}
	}
	if !delivery.Owned || delivery.Phase == "unclaimed" {
		_, ok := securityAgentOrderedClosedObject(delivery.Claim)
		return ok
	}
	var claim orderedDeploymentClaim
	if _, ok := orderedDeploymentClosedObject(delivery.Claim, orderedDeploymentResponseBytes, "organization_id", "workspace_id", "environment_id", "device_id", "credential_id", "desired_generation", "sequence", "policy_version", "input_digest", "lease_expires_at", "composition"); !ok || decodeStrictDiscovery(delivery.Claim, &claim) != nil || claim.OrganizationID != scope.OrganizationID().String() || claim.WorkspaceID != scope.WorkspaceID().String() || claim.EnvironmentID != scope.EnvironmentID().String() || claim.DeviceID != target.DeviceID || claim.CredentialID != target.CredentialID || claim.DesiredGeneration != target.DesiredGeneration || claim.Sequence < 1 || claim.PolicyVersion != claim.Sequence {
		return false
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", run+"\x1f0")
	_, ok = orderedDeploymentCompositionModeValid(claim.Composition, scope, run, step, target.DeviceID, target.CredentialID, target.Sequence, target.DesiredGeneration, target.EnvelopeDigest, len(cleanupMode) == 1 && cleanupMode[0])
	return ok
}
