package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Match cleanup_wire and the immutable evidence check in release61 SQL.
const orderedCleanupRequestBytes = 32768
const orderedCleanupResponseBytes = 262144
const orderedCleanupReceiptBytes = 131072

// Dormant retained cleanup only. No generic worker or public constructor calls
// this method. SQL fences schema before every authority read or replay.
func (repository *securityAgentMultistepAdmissionRepository) cleanup(ctx context.Context, raw json.RawMessage, keys policy.GatewayPolicyKeys) (json.RawMessage, error) {
	var q struct {
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
		Version        int64           `json:"version"`
		LeaseSeconds   int             `json:"lease_seconds"`
		Envelope       json.RawMessage `json:"envelope"`
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryOperation
	}
	if _, ok := orderedDeploymentClosedObject(raw, orderedCleanupRequestBytes, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "lease_token", "run_version", "effect_version", "version", "lease_seconds", "envelope"); !ok || decodeStrictDiscovery(raw, &q) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedApplicationScope(q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID)
	if !valid || !validSecurityAgentWorkerLease(q.WorkerID, q.LeaseToken, q.LeaseSeconds) || q.RunVersion < 1 || q.RunVersion > 999998 || q.EffectVersion < 1 || q.EffectVersion > 999998 || q.Version < 0 || q.Version > 999998 || q.Operation != "claim" && q.Version < 1 {
		return nil, ErrRepositoryOperation
	}
	var source orderedApplicationSource
	switch q.Operation {
	case "claim", "heartbeat", "complete", "reconcile":
		if _, ok := securityAgentOrderedClosedObject(q.Envelope); !ok {
			return nil, ErrRepositoryOperation
		}
	case "store":
		if _, ok := securityAgentOrderedClosedObject(q.Envelope, "device_id", "credential_id", "sequence", "policy_version", "key_id", "issued_at", "expires_at", "failure_mode", "payload_digest", "policies", "signature", "envelope_digest"); !ok || decodeStrictDiscovery(q.Envelope, &source) != nil || !validProductID(source.DeviceID) || !validProductID(source.CredentialID) || source.Sequence < 1 || source.Sequence > 999999999 || source.PolicyVersion != source.Sequence || source.Policies == nil || len(source.Policies) != 0 || source.ExpiresAt.Sub(source.IssuedAt) != 5*time.Minute {
			return nil, ErrRepositoryOperation
		}
		signature, err := base64.StdEncoding.DecodeString(source.Signature)
		envelope := policy.GatewayPolicyEnvelope{ContractVersion: 1, Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: q.OrganizationID, WorkspaceID: q.WorkspaceID, EnvironmentID: q.EnvironmentID, DeviceID: source.DeviceID, Sequence: uint64(source.Sequence), PolicyVersion: uint64(source.PolicyVersion), KeyID: source.KeyID, IssuedAt: source.IssuedAt, ExpiresAt: source.ExpiresAt, FailureMode: source.FailureMode, PayloadDigest: strings.TrimPrefix(source.PayloadDigest, "sha256:"), Policies: source.Policies, Signature: base64.RawURLEncoding.EncodeToString(signature)}
		if err != nil || !strings.HasPrefix(source.PayloadDigest, "sha256:") || !orderedCleanupVerifiedEnvelope(envelope, keys, q.OrganizationID, q.WorkspaceID, q.EnvironmentID, source.DeviceID, source.Sequence) || orderedEnvelopeDigest(envelope) != source.EnvelopeDigest {
			return nil, ErrRepositoryOperation
		}
	default:
		return nil, ErrRepositoryOperation
	}
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var got orderedCleanupResult
	if _, ok := orderedDeploymentClosedObject(response, orderedCleanupResponseBytes, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "cleanup_id", "reservation_id", "control_id", "state", "version", "attempt", "run_version", "run_state", "effect_version", "effect_state", "lease_expires_at", "reason", "targets", "receipt_kind", "receipt", "receipt_digest"); !ok || decodeStrictDiscovery(response, &got) != nil {
		return nil, ErrRepositoryUnavailable
	}
	canonical := func(kind string) string { v, _ := CanonicalDiscoveryID(scope, kind, q.RunID+"\x1f"+q.StepID); return v }
	runIncrement := int64(0)
	if q.Operation == "complete" || q.Operation == "reconcile" {
		runIncrement = 1
	}
	if got.ContractVersion != 61 || got.OrganizationID != q.OrganizationID || got.WorkspaceID != q.WorkspaceID || got.EnvironmentID != q.EnvironmentID || got.RunID != q.RunID || got.StepID != q.StepID || got.Operation != q.Operation || got.CleanupID != canonical("security_agent_ordered_cleanup") || got.ReservationID != canonical("security_agent_ordered_cleanup_reservation") || got.ControlID != canonical("security_agent_ordered_control") || got.Version != q.Version+1 || got.EffectVersion != q.EffectVersion+1 || got.RunVersion != q.RunVersion+runIncrement || got.Attempt < 1 || got.Attempt > 100 || got.Attempt > int(got.Version) || q.Version == 0 && got.Attempt != 1 || q.Operation != "reconcile" && got.Reason != "none" || len(got.Targets) < 1 || len(got.Targets) > 100 {
		return nil, ErrRepositoryUnavailable
	}
	previous := ""
	stored := false
	targets := make(map[string]orderedApplicationTarget, len(got.Targets))
	for _, rawTarget := range got.Targets {
		var target orderedApplicationTarget
		if _, ok := securityAgentOrderedClosedObject(rawTarget, "device_id", "credential_id", "sequence", "policy_version", "state", "desired_generation", "envelope_digest"); !ok || decodeStrictDiscovery(rawTarget, &target) != nil || !validProductID(target.DeviceID) || !validProductID(target.CredentialID) || target.DeviceID <= previous || target.Sequence < 1 || target.Sequence > 999999999 || target.PolicyVersion != target.Sequence {
			return nil, ErrRepositoryUnavailable
		}
		if target.State == "planned" {
			if target.DesiredGeneration != 0 || target.EnvelopeDigest != "" || q.Operation == "complete" {
				return nil, ErrRepositoryUnavailable
			}
		} else {
			_, ok := decodeTemporaryPolicyDigest(target.EnvelopeDigest)
			if !ok || target.DesiredGeneration < 1 || target.DesiredGeneration > 999999999 || target.State != "stored" && target.State != "verified" || q.Operation == "complete" && target.State != "verified" || q.Operation != "complete" && target.State != "stored" {
				return nil, ErrRepositoryUnavailable
			}
		}
		if q.Operation == "claim" && q.Version == 0 && target.State != "planned" {
			return nil, ErrRepositoryUnavailable
		}
		if q.Operation == "store" && target.DeviceID == source.DeviceID {
			stored = target.State == "stored" && target.CredentialID == source.CredentialID && target.Sequence == source.Sequence && target.EnvelopeDigest == source.EnvelopeDigest
		}
		previous = target.DeviceID
		targets[target.DeviceID] = target
	}
	if q.Operation == "store" && !stored {
		return nil, ErrRepositoryUnavailable
	}
	if q.Operation == "complete" {
		partial := got.ReceiptKind == "temporary_policy_partial_cleaned.v1"
		if partial && got.RunState != "cancelled" && got.RunState != "needs_human" || got.State != "cleaned" || got.EffectState != "cleaned" || got.LeaseExpiresAt != "" || got.RunState != "remediated" && got.RunState != "needs_human" && got.RunState != "cancelled" || !partial && got.ReceiptKind != "temporary_policy_cleaned.v1" || got.ReceiptDigest != orderedCleanupDigest(got.Receipt) || !orderedCleanupReceiptValid(got.Receipt, scope, q.RunID, q.StepID, got.CleanupID, got.ControlID, got.Attempt, targets, partial) {
			return nil, ErrRepositoryUnavailable
		}
	} else if q.Operation == "reconcile" {
		if got.State != "retryable" || got.EffectState != "cleanup_failed" || got.LeaseExpiresAt != "" || got.RunState != "needs_human" && got.RunState != "cancelled" || got.ReceiptKind != "" || got.ReceiptDigest != "" || got.Reason != "no_external_call" && got.Reason != "unknown_call" && got.Reason != "partial_acknowledgement" && got.Reason != "complete_unsettled" {
			return nil, ErrRepositoryUnavailable
		}
		if _, ok := securityAgentOrderedClosedObject(got.Receipt); !ok {
			return nil, ErrRepositoryUnavailable
		}
	} else {
		lease, err := time.Parse(time.RFC3339Nano, got.LeaseExpiresAt)
		if err != nil || got.LeaseExpiresAt != lease.UTC().Format("2006-01-02T15:04:05.000000Z") || !lease.After(time.Now()) || got.State != "leased" || got.EffectState != "leased" || got.ReceiptKind != "" || got.ReceiptDigest != "" || got.RunState != "contained" && got.RunState != "needs_human" && got.RunState != "cancelled" && got.RunState != "failed" && got.RunState != "inconclusive" {
			return nil, ErrRepositoryUnavailable
		}
		if _, ok := securityAgentOrderedClosedObject(got.Receipt); !ok {
			return nil, ErrRepositoryUnavailable
		}
	}
	return response, nil
}

type orderedCleanupResult struct {
	ContractVersion int               `json:"contract_version"`
	OrganizationID  string            `json:"organization_id"`
	WorkspaceID     string            `json:"workspace_id"`
	EnvironmentID   string            `json:"environment_id"`
	RunID           string            `json:"run_id"`
	StepID          string            `json:"step_id"`
	Operation       string            `json:"operation"`
	CleanupID       string            `json:"cleanup_id"`
	ReservationID   string            `json:"reservation_id"`
	ControlID       string            `json:"control_id"`
	State           string            `json:"state"`
	Version         int64             `json:"version"`
	Attempt         int               `json:"attempt"`
	RunVersion      int64             `json:"run_version"`
	RunState        string            `json:"run_state"`
	EffectVersion   int64             `json:"effect_version"`
	EffectState     string            `json:"effect_state"`
	LeaseExpiresAt  string            `json:"lease_expires_at"`
	Reason          string            `json:"reason"`
	Targets         []json.RawMessage `json:"targets"`
	ReceiptKind     string            `json:"receipt_kind"`
	Receipt         json.RawMessage   `json:"receipt"`
	ReceiptDigest   string            `json:"receipt_digest"`
}

func orderedCleanupDigest(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	canonical, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func orderedCleanupReceiptValid(raw json.RawMessage, scope domain.Scope, r, s, cleanup, control string, attempt int, targets map[string]orderedApplicationTarget, partialMode ...bool) bool {
	partial := len(partialMode) == 1 && partialMode[0]
	var v struct {
		CleanupID                string            `json:"cleanup_id"`
		ControlID                string            `json:"control_id"`
		ControlVersion           int64             `json:"control_version"`
		EffectID                 string            `json:"effect_id"`
		ApplicationReceiptDigest string            `json:"application_receipt_digest"`
		TestEvidenceDigest       string            `json:"test_evidence_digest"`
		PartialApplicationDigest string            `json:"partial_application_digest"`
		CancellationDigest       string            `json:"cancellation_evidence_digest"`
		RemovedSourceDigest      string            `json:"removed_source_digest"`
		CleanupDeploymentDigest  string            `json:"cleanup_deployment_digest"`
		Targets                  []json.RawMessage `json:"targets"`
		StartedAt                string            `json:"started_at"`
		CompletedAt              string            `json:"completed_at"`
		Attempts                 int               `json:"attempts"`
		Outcome                  string            `json:"outcome"`
	}
	fields := []string{"cleanup_id", "control_id", "control_version", "effect_id", "application_receipt_digest", "test_evidence_digest", "removed_source_digest", "cleanup_deployment_digest", "targets", "started_at", "completed_at", "attempts", "outcome"}
	if partial {
		fields = []string{"cleanup_id", "partial_application_digest", "cancellation_evidence_digest", "removed_source_digest", "cleanup_deployment_digest", "targets", "started_at", "completed_at", "attempts", "outcome"}
	}
	if _, ok := orderedDeploymentClosedObject(raw, orderedCleanupReceiptBytes, fields...); !ok || decodeStrictDiscovery(raw, &v) != nil {
		return false
	}
	fx, _ := CanonicalDiscoveryID(scope, "security_agent_effect", r+"\x1f"+s+"\x1fapply")
	start, err1 := time.Parse(time.RFC3339Nano, v.StartedAt)
	end, err2 := time.Parse(time.RFC3339Nano, v.CompletedAt)
	if v.CleanupID != cleanup || !partial && (v.ControlID != control || v.ControlVersion != 2 || v.EffectID != fx) || v.Attempts != attempt || v.Outcome != "cleaned" || err1 != nil || err2 != nil || v.StartedAt != start.UTC().Format("2006-01-02T15:04:05.000000Z") || v.CompletedAt != end.UTC().Format("2006-01-02T15:04:05.000000Z") || end.Before(start) || end.After(time.Now()) || len(v.Targets) != len(targets) {
		return false
	}
	digests := []string{v.ApplicationReceiptDigest, v.TestEvidenceDigest, v.RemovedSourceDigest, v.CleanupDeploymentDigest}
	if partial {
		digests[0], digests[1] = v.PartialApplicationDigest, v.CancellationDigest
	}
	for _, digest := range digests {
		if _, ok := decodeTemporaryPolicyDigest("sha256:" + digest); !ok {
			return false
		}
	}
	acks, _ := json.Marshal(v.Targets)
	if orderedCleanupDigest(acks) != "sha256:"+v.CleanupDeploymentDigest {
		return false
	}
	previous := ""
	for _, rawAck := range v.Targets {
		var a struct {
			DeviceID            string `json:"device_id"`
			CredentialID        string `json:"credential_id"`
			RemovedSourceID     string `json:"removed_source_id"`
			RemovedSourceDigest string `json:"removed_source_digest"`
			RemovedSequence     int64  `json:"removed_sequence"`
			CleanupSourceID     string `json:"cleanup_source_id"`
			CleanupSourceDigest string `json:"cleanup_source_digest"`
			CleanupSequence     int64  `json:"cleanup_sequence"`
			DesiredGeneration   int64  `json:"desired_generation"`
			DeploymentSequence  int64  `json:"deployment_sequence"`
			DeploymentDigest    string `json:"deployment_digest"`
			CompositionDigest   string `json:"composition_digest"`
			AcknowledgementID   string `json:"acknowledgement_id"`
		}
		if _, ok := orderedDeploymentClosedObject(rawAck, 120000, "device_id", "credential_id", "removed_source_id", "removed_source_digest", "removed_sequence", "cleanup_source_id", "cleanup_source_digest", "cleanup_sequence", "desired_generation", "deployment_sequence", "deployment_digest", "composition_digest", "acknowledgement_id"); !ok || decodeStrictDiscovery(rawAck, &a) != nil {
			return false
		}
		target, ok := targets[a.DeviceID]
		if !ok || a.DeviceID <= previous || a.CredentialID != target.CredentialID || a.CleanupSequence != target.Sequence || a.CleanupSourceDigest != target.EnvelopeDigest || a.DesiredGeneration != target.DesiredGeneration || a.RemovedSequence < 1 || a.RemovedSequence >= a.CleanupSequence || a.DeploymentSequence < 1 || a.DeploymentSequence > 999999999 || !validProductID(a.AcknowledgementID) {
			return false
		}
		for _, digest := range []string{a.RemovedSourceDigest, a.DeploymentDigest, a.CompositionDigest} {
			if _, ok := decodeTemporaryPolicyDigest(digest); !ok {
				return false
			}
		}
		sourceID := func(seq int64, digest string) string {
			x, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_source", strings.Join([]string{r, s, a.DeviceID, strconv.FormatInt(seq, 10), digest}, "\x1f"))
			return x
		}
		if a.RemovedSourceID != sourceID(a.RemovedSequence, a.RemovedSourceDigest) || a.CleanupSourceID != sourceID(a.CleanupSequence, a.CleanupSourceDigest) {
			return false
		}
		var ack map[string]json.RawMessage
		if json.Unmarshal(rawAck, &ack) != nil {
			return false
		}
		delete(ack, "acknowledgement_id")
		body, _ := json.Marshal(ack)
		ackID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_cleanup_acknowledgement", r+"\x1f"+s+"\x1f"+strings.TrimPrefix(orderedCleanupDigest(body), "sha256:"))
		if a.AcknowledgementID != ackID {
			return false
		}
		previous = a.DeviceID
	}
	return true
}
