package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Private methods on the dormant release61 repository. SQL takes the shared
// schema fence before checking exact readiness or acquiring any authority row.
// No action worker or public route constructs or calls this adapter.
func (repository *securityAgentMultistepAdmissionRepository) application(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	var request struct {
		OrganizationID string          `json:"organization_id"`
		WorkspaceID    string          `json:"workspace_id"`
		EnvironmentID  string          `json:"environment_id"`
		RunID          string          `json:"run_id"`
		StepID         string          `json:"step_id"`
		Operation      string          `json:"operation"`
		WorkerID       string          `json:"worker_id"`
		LeaseToken     string          `json:"lease_token"`
		RunVersion     int64           `json:"run_version"`
		EffectVersion  int64           `json:"effect_version"`
		LeaseSeconds   int             `json:"lease_seconds"`
		Envelope       json.RawMessage `json:"envelope"`
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 32768 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "lease_token", "run_version", "effect_version", "lease_seconds", "envelope"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedApplicationScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	if !valid || !validSecurityAgentWorkerLease(request.WorkerID, request.LeaseToken, request.LeaseSeconds) || request.RunVersion < 1 || request.RunVersion > 999999 || request.EffectVersion < 0 || request.EffectVersion > 999999 {
		return nil, ErrRepositoryOperation
	}
	var source orderedApplicationSource
	switch request.Operation {
	case "claim", "heartbeat", "complete":
		if _, ok := securityAgentOrderedClosedObject(request.Envelope); !ok {
			return nil, ErrRepositoryOperation
		}
	case "store":
		if _, ok := securityAgentOrderedClosedObject(request.Envelope, "device_id", "credential_id", "sequence", "policy_version", "key_id", "issued_at", "expires_at", "failure_mode", "payload_digest", "policies", "signature", "envelope_digest"); !ok || decodeStrictDiscovery(request.Envelope, &source) != nil || !validProductID(source.CredentialID) || source.Sequence < 1 || source.Sequence > 1_000_000_000 || source.PolicyVersion != source.Sequence || !orderedContainmentPolicies(source.Policies, true) {
			return nil, ErrRepositoryOperation
		}
		signature, err := base64.StdEncoding.DecodeString(source.Signature)
		envelope := policy.GatewayPolicyEnvelope{ContractVersion: 1, Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, DeviceID: source.DeviceID, Sequence: uint64(source.Sequence), PolicyVersion: uint64(source.PolicyVersion), KeyID: source.KeyID, IssuedAt: source.IssuedAt, ExpiresAt: source.ExpiresAt, FailureMode: source.FailureMode, PayloadDigest: strings.TrimPrefix(source.PayloadDigest, "sha256:"), Policies: source.Policies, Signature: base64.RawURLEncoding.EncodeToString(signature)}
		if err != nil || !strings.HasPrefix(source.PayloadDigest, "sha256:") || !orderedVerifiedEnvelope(envelope, keys, request.OrganizationID, request.WorkspaceID, request.EnvironmentID, source.DeviceID, source.Sequence) || orderedEnvelopeDigest(envelope) != source.EnvelopeDigest {
			return nil, ErrRepositoryOperation
		}
	default:
		return nil, ErrRepositoryOperation
	}
	if request.Operation != "claim" && request.EffectVersion < 1 {
		return nil, ErrRepositoryOperation
	}
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.application($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result orderedApplicationResult
	if _, ok := securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "run_version", "step_version", "effect_version", "effect_state", "attempt", "reservation_id", "plan_hash", "input_digest", "ttl_seconds", "lease_expires_at", "targets", "control_id", "deployment_id", "result_digest"); !ok || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	reservation, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_reservation", request.RunID+"\x1f"+request.StepID)
	_, planOK := decodeTemporaryPolicyDigest(result.PlanHash)
	input, inputOK := decodeTemporaryPolicyDigest(result.InputDigest)
	if result.ContractVersion != 61 || result.OrganizationID != request.OrganizationID || result.WorkspaceID != request.WorkspaceID || result.EnvironmentID != request.EnvironmentID || result.RunID != request.RunID || result.StepID != request.StepID || result.Operation != request.Operation || result.ReservationID != reservation || !planOK || !inputOK || result.EffectVersion != request.EffectVersion+1 || result.Attempt < 1 || result.Attempt > 100 || result.TTLSeconds < 60 || result.TTLSeconds > 3600 || !result.LeaseExpiresAt.After(time.Now()) || result.LeaseExpiresAt.Location() != time.UTC || len(result.Targets) < 1 || len(result.Targets) > 100 {
		return nil, ErrRepositoryUnavailable
	}
	runIncrement, stepVersion := int64(0), int64(3)
	if request.Operation == "claim" || request.Operation == "complete" {
		runIncrement = 1
	}
	if request.Operation == "complete" {
		stepVersion = 4
	}
	if result.RunVersion != request.RunVersion+runIncrement || result.StepVersion != stepVersion || request.Operation == "claim" && request.EffectVersion == 0 && result.Attempt != 1 {
		return nil, ErrRepositoryUnavailable
	}
	var digestParts []string
	stored := false
	lastDevice := ""
	for _, rawTarget := range result.Targets {
		var target orderedApplicationTarget
		if _, ok := securityAgentOrderedClosedObject(rawTarget, "device_id", "credential_id", "sequence", "policy_version", "state", "desired_generation", "envelope_digest"); !ok || decodeStrictDiscovery(rawTarget, &target) != nil || !validProductID(target.DeviceID) || !validProductID(target.CredentialID) || target.DeviceID <= lastDevice || target.Sequence < 1 || target.Sequence > 1_000_000_000 || target.PolicyVersion != target.Sequence {
			return nil, ErrRepositoryUnavailable
		}
		lastDevice = target.DeviceID
		if target.State == "planned" {
			if target.DesiredGeneration != 0 || target.EnvelopeDigest != "" || request.Operation == "complete" {
				return nil, ErrRepositoryUnavailable
			}
		} else {
			digest, ok := decodeTemporaryPolicyDigest(target.EnvelopeDigest)
			if !ok || target.DesiredGeneration < 1 || target.DesiredGeneration > 1_000_000_000 || target.State != "stored" && target.State != "verified" || request.Operation == "complete" && target.State != "verified" || request.Operation != "complete" && target.State != "stored" {
				return nil, ErrRepositoryUnavailable
			}
			input = append(input, digest...)
			digestParts = append(digestParts, fmt.Sprintf(`[%q, %q, %d, %d, %d, %q]`, target.DeviceID, target.CredentialID, target.Sequence, target.PolicyVersion, target.DesiredGeneration, hex.EncodeToString(digest)))
		}
		if request.Operation == "claim" && request.EffectVersion == 0 && target.State != "planned" {
			return nil, ErrRepositoryUnavailable
		}
		if request.Operation == "store" && target.DeviceID == source.DeviceID {
			stored = target.CredentialID == source.CredentialID && target.Sequence == source.Sequence && target.PolicyVersion == source.PolicyVersion && target.State == "stored" && target.EnvelopeDigest == source.EnvelopeDigest
		}
	}
	if request.Operation == "store" && (!stored || source.ExpiresAt.Sub(source.IssuedAt) != time.Duration(result.TTLSeconds)*time.Second) {
		return nil, ErrRepositoryUnavailable
	}
	if request.Operation == "complete" {
		control, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_control", request.RunID+"\x1f"+request.StepID)
		deploymentDigest := sha256.Sum256([]byte("[" + strings.Join(digestParts, ", ") + "]"))
		deployment, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_deployment", request.RunID+"\x1f"+request.StepID+"\x1f"+hex.EncodeToString(deploymentDigest[:]))
		resultDigest := sha256.Sum256(input)
		if result.EffectState != "cleanup_pending" || result.ControlID != control || result.DeploymentID != deployment || result.ResultDigest != "sha256:"+hex.EncodeToString(resultDigest[:]) {
			return nil, ErrRepositoryUnavailable
		}
	} else if result.EffectState != "leased" || result.ControlID != "" || result.DeploymentID != "" || result.ResultDigest != "" {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

type orderedApplicationSource struct {
	DeviceID       string                  `json:"device_id"`
	CredentialID   string                  `json:"credential_id"`
	Sequence       int64                   `json:"sequence"`
	PolicyVersion  int64                   `json:"policy_version"`
	KeyID          string                  `json:"key_id"`
	IssuedAt       time.Time               `json:"issued_at"`
	ExpiresAt      time.Time               `json:"expires_at"`
	FailureMode    string                  `json:"failure_mode"`
	PayloadDigest  string                  `json:"payload_digest"`
	Policies       []policy.CompiledPolicy `json:"policies"`
	Signature      string                  `json:"signature"`
	EnvelopeDigest string                  `json:"envelope_digest"`
}
type orderedApplicationTarget struct {
	DeviceID          string `json:"device_id"`
	CredentialID      string `json:"credential_id"`
	Sequence          int64  `json:"sequence"`
	PolicyVersion     int64  `json:"policy_version"`
	State             string `json:"state"`
	DesiredGeneration int64  `json:"desired_generation"`
	EnvelopeDigest    string `json:"envelope_digest"`
}
type orderedApplicationResult struct {
	ContractVersion int               `json:"contract_version"`
	OrganizationID  string            `json:"organization_id"`
	WorkspaceID     string            `json:"workspace_id"`
	EnvironmentID   string            `json:"environment_id"`
	RunID           string            `json:"run_id"`
	StepID          string            `json:"step_id"`
	Operation       string            `json:"operation"`
	RunVersion      int64             `json:"run_version"`
	StepVersion     int64             `json:"step_version"`
	EffectVersion   int64             `json:"effect_version"`
	EffectState     string            `json:"effect_state"`
	Attempt         int               `json:"attempt"`
	ReservationID   string            `json:"reservation_id"`
	PlanHash        string            `json:"plan_hash"`
	InputDigest     string            `json:"input_digest"`
	TTLSeconds      int               `json:"ttl_seconds"`
	LeaseExpiresAt  time.Time         `json:"lease_expires_at"`
	Targets         []json.RawMessage `json:"targets"`
	ControlID       string            `json:"control_id"`
	DeploymentID    string            `json:"deployment_id"`
	ResultDigest    string            `json:"result_digest"`
}

func orderedApplicationScope(o, w, e, r, s string) (domain.Scope, bool) {
	for _, id := range []string{o, w, e, r, s} {
		if !validProductID(id) {
			return domain.Scope{}, false
		}
	}
	org, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	scope, err := domain.NewScope(org, workspace, environment)
	if err != nil {
		return domain.Scope{}, false
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", r+"\x1f0")
	return scope, s == step
}

func orderedContainmentPolicies(values []policy.CompiledPolicy, exact bool) bool {
	if len(values) < 2 || len(values) > 100 || exact && len(values) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		compiled, err := policy.Compile(policy.Policy{ID: value.ID, Trigger: value.Trigger, Action: value.Action, Conditions: value.Conditions})
		if err != nil || !reflect.DeepEqual(value, compiled) || seen[value.ID] {
			return false
		}
		seen[value.ID] = true
		if value.ID == "temporary-containment-http-v1" || value.ID == "temporary-containment-mcp-v1" {
			trigger, field := "http_request", "http.method"
			if value.ID == "temporary-containment-mcp-v1" {
				trigger, field = "tool_call", "tool.name"
			}
			if value.Trigger != trigger || value.Action != policy.ActionBlock || !reflect.DeepEqual(value.Conditions, []policy.Condition{{Field: field, Operator: "present"}}) {
				return false
			}
		}
	}
	return seen["temporary-containment-http-v1"] && seen["temporary-containment-mcp-v1"]
}

func orderedVerifiedEnvelope(value policy.GatewayPolicyEnvelope, keys policy.GatewayPolicyKeys, o, w, e, d string, sequence int64) bool {
	if value.Sequence != uint64(sequence) || value.PolicyVersion != uint64(sequence) || value.FailureMode != "closed" || !orderedContainmentPolicies(value.Policies, false) {
		return false
	}
	_, err := policy.VerifyGatewayPolicyEnvelope(value, keys, policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: d}, time.Now().UTC().Truncate(time.Second))
	return err == nil
}
func orderedEnvelopeDigest(value policy.GatewayPolicyEnvelope) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
