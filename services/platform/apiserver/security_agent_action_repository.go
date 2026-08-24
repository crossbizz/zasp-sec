package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresSecurityAgentActionReadyV23SQL  = `SELECT jsonb_build_object('release',zasp_security_agent_connector_revocation_readiness($1,$2),'principal',zasp_security_agent_action_principal_ready())`
	postgresSecurityAgentActionReadySQL     = `SELECT jsonb_build_object('release',zasp_security_agent_temporary_policy_readiness($1,$2),'principal',zasp_security_agent_action_principal_ready())`
	postgresSecurityAgentActionReconcileSQL = `SELECT zasp_security_agent_reconcile_connector_revocations($1,$2)`
	postgresSecurityAgentActionClaimSQL     = `SELECT zasp_security_agent_claim_temporary_policy_effects($1,$2,$3,$4)`
	postgresSecurityAgentActionHeartbeatSQL = `SELECT zasp_security_agent_heartbeat_temporary_policy_effect($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresSecurityAgentActionStoreSQL     = `SELECT zasp_security_agent_store_temporary_policy_target($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`
	postgresSecurityAgentActionReadSQL      = `SELECT zasp_security_agent_read_temporary_policy_target($1,$2,$3,$4,$5,$6,$7)`
	postgresSecurityAgentActionFinishSQL    = `SELECT zasp_security_agent_finish_temporary_policy_effect($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
)

type TemporaryPolicyTarget struct {
	DeviceID      string `json:"device_id"`
	CredentialID  string `json:"credential_id"`
	Sequence      int64  `json:"sequence"`
	PolicyVersion int64  `json:"policy_version"`
}

type TemporaryPolicyEffectClaim struct {
	OrganizationID string                  `json:"organization_id"`
	WorkspaceID    string                  `json:"workspace_id"`
	EnvironmentID  string                  `json:"environment_id"`
	RunID          string                  `json:"run_id"`
	StepID         string                  `json:"step_id"`
	Phase          string                  `json:"phase"`
	InputDigest    string                  `json:"input_digest"`
	TTLSeconds     int                     `json:"ttl_seconds"`
	LeaseExpiresAt time.Time               `json:"lease_expires_at"`
	Targets        []TemporaryPolicyTarget `json:"targets"`
}

type TemporaryPolicyTargetEnvelope struct {
	Target         TemporaryPolicyTarget
	Phase          string
	State          string
	KeyID          string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	FailureMode    string
	PayloadDigest  string
	Policies       json.RawMessage
	Signature      []byte
	EnvelopeDigest string
}

type TemporaryPolicyFinishResult struct {
	RunID        string `json:"run_id"`
	StepID       string `json:"step_id"`
	Phase        string `json:"phase"`
	EffectState  string `json:"effect_state"`
	OutcomeID    string `json:"outcome_id"`
	ResultDigest string `json:"result_digest"`
}

type SecurityAgentActionAuthority interface {
	Ready(context.Context) error
	ClaimTemporaryPolicyEffects(context.Context, string, string, int, int) ([]TemporaryPolicyEffectClaim, error)
	HeartbeatTemporaryPolicyEffect(context.Context, TemporaryPolicyEffectClaim, string, string, int) error
	StoreTemporaryPolicyTarget(context.Context, TemporaryPolicyEffectClaim, string, string, TemporaryPolicyTargetEnvelope) error
	ReadTemporaryPolicyTarget(context.Context, TemporaryPolicyEffectClaim, TemporaryPolicyTarget) (TemporaryPolicyTargetEnvelope, error)
	FinishTemporaryPolicyEffect(context.Context, TemporaryPolicyEffectClaim, string, string, string, string, string) (TemporaryPolicyFinishResult, error)
}

type SecurityAgentConnectorRevocationAuthority interface {
	ReconcileConnectorRevocations(context.Context, string, int) (int, error)
}

type SecurityAgentActionRepository struct {
	database                  JSONDatabase
	readySQL, checksum        string
	fingerprint, reconcileSQL string
}

func NewSecurityAgentActionRepository(database JSONDatabase) (*SecurityAgentActionRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	configurations := []SecurityAgentActionRepository{
		{database: database, readySQL: postgresSecurityAgentActionReadyV23SQL, checksum: migrations.ProductionSecurityAgentConnectorRevocation().Checksum(), fingerprint: migrations.ProductionSecurityAgentConnectorRevocationSemanticFingerprint(), reconcileSQL: postgresSecurityAgentActionReconcileSQL},
		{database: database, readySQL: postgresSecurityAgentActionReadySQL, checksum: migrations.ProductionSecurityAgentTemporaryPolicy().Checksum(), fingerprint: migrations.ProductionSecurityAgentTemporaryPolicySemanticFingerprint()},
	}
	for index := range configurations {
		if configurations[index].Ready(ctx) == nil {
			return &configurations[index], nil
		}
	}
	return nil, ErrRepositoryConfiguration
}

func (repository *SecurityAgentActionRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	if repository.readySQL == "" || repository.checksum == "" || repository.fingerprint == "" {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, repository.readySQL, repository.checksum, repository.fingerprint)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	var result struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if !exactJSONFields(payload, "principal", "release") || decodeStrictDiscovery(payload, &result) != nil || !result.Release || !result.Principal {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SecurityAgentActionRepository) ReconcileConnectorRevocations(ctx context.Context, workerID string, limit int) (int, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentText(workerID, 128) || limit < 1 || limit > 25 {
		return 0, ErrRepositoryOperation
	}
	if repository.reconcileSQL == "" {
		return 0, nil
	}
	payload, err := repository.database.QueryJSON(ctx, repository.reconcileSQL, workerID, limit)
	if err != nil {
		return 0, discoveryProviderError(err)
	}
	var result struct {
		Reconciled int `json:"reconciled"`
	}
	if !exactJSONFields(payload, "reconciled") || decodeStrictDiscovery(payload, &result) != nil || result.Reconciled < 0 || result.Reconciled > limit {
		return 0, ErrRepositoryUnavailable
	}
	return result.Reconciled, nil
}

func (repository *SecurityAgentActionRepository) ClaimTemporaryPolicyEffects(ctx context.Context, workerID, leaseToken string, leaseSeconds, limit int) ([]TemporaryPolicyEffectClaim, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) || limit < 1 || limit > 25 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActionClaimSQL, workerID, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []json.RawMessage `json:"items"`
	}
	if !exactJSONFields(payload, "items") || decodeStrictDiscovery(payload, &envelope) != nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	claims := make([]TemporaryPolicyEffectClaim, len(envelope.Items))
	for index, raw := range envelope.Items {
		if !exactJSONFields(raw, "environment_id", "input_digest", "lease_expires_at", "organization_id", "phase", "run_id", "step_id", "targets", "ttl_seconds", "workspace_id") || decodeStrictDiscovery(raw, &claims[index]) != nil || !validTemporaryPolicyEffectClaim(claims[index]) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return claims, nil
}

func (repository *SecurityAgentActionRepository) HeartbeatTemporaryPolicyEffect(ctx context.Context, claim TemporaryPolicyEffectClaim, workerID, leaseToken string, leaseSeconds int) error {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validTemporaryPolicyEffectClaim(claim) || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActionHeartbeatSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, claim.StepID, workerID, leaseToken, leaseSeconds)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if !exactJSONFields(payload, "lease_expires_at") || decodeStrictDiscovery(payload, &result) != nil || result.LeaseExpiresAt.IsZero() || result.LeaseExpiresAt.Location() != time.UTC {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SecurityAgentActionRepository) StoreTemporaryPolicyTarget(ctx context.Context, claim TemporaryPolicyEffectClaim, workerID, leaseToken string, envelope TemporaryPolicyTargetEnvelope) error {
	payloadDigest, payloadOK := decodeTemporaryPolicyDigest(envelope.PayloadDigest)
	envelopeDigest, envelopeOK := decodeTemporaryPolicyDigest(envelope.EnvelopeDigest)
	if repository == nil || ctx == nil || ctx.Err() != nil || !validTemporaryPolicyEffectClaim(claim) || !validSecurityAgentWorkerIdentity(workerID, leaseToken) || !validTemporaryPolicyTargetEnvelope(claim, envelope) || !payloadOK || !envelopeOK {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActionStoreSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, claim.StepID, claim.Phase, workerID, leaseToken, envelope.Target.DeviceID, envelope.Target.CredentialID, envelope.Target.Sequence, envelope.Target.PolicyVersion, envelope.KeyID, envelope.IssuedAt, envelope.ExpiresAt, envelope.FailureMode, payloadDigest, envelope.Policies, envelope.Signature, envelopeDigest)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		DeviceID      string `json:"device_id"`
		Phase         string `json:"phase"`
		Sequence      int64  `json:"sequence"`
		PolicyVersion int64  `json:"policy_version"`
		Envelope      string `json:"envelope_digest"`
	}
	if !exactJSONFields(payload, "device_id", "envelope_digest", "phase", "policy_version", "sequence") || decodeStrictDiscovery(payload, &result) != nil || result.DeviceID != envelope.Target.DeviceID || result.Phase != claim.Phase || result.Sequence != envelope.Target.Sequence || result.PolicyVersion != envelope.Target.PolicyVersion || result.Envelope != envelope.EnvelopeDigest {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SecurityAgentActionRepository) ReadTemporaryPolicyTarget(ctx context.Context, claim TemporaryPolicyEffectClaim, target TemporaryPolicyTarget) (TemporaryPolicyTargetEnvelope, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validTemporaryPolicyEffectClaim(claim) || !validTemporaryPolicyTarget(target) || !containsTemporaryPolicyTarget(claim.Targets, target) {
		return TemporaryPolicyTargetEnvelope{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActionReadSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, claim.StepID, claim.Phase, target.DeviceID)
	if err != nil {
		return TemporaryPolicyTargetEnvelope{}, discoveryProviderError(err)
	}
	var result struct {
		DeviceID       string          `json:"device_id"`
		CredentialID   string          `json:"credential_id"`
		Phase          string          `json:"phase"`
		State          string          `json:"state"`
		Sequence       int64           `json:"sequence"`
		PolicyVersion  int64           `json:"policy_version"`
		KeyID          string          `json:"key_id"`
		IssuedAt       time.Time       `json:"issued_at"`
		ExpiresAt      time.Time       `json:"expires_at"`
		FailureMode    string          `json:"failure_mode"`
		PayloadDigest  string          `json:"payload_digest"`
		Policies       json.RawMessage `json:"policies"`
		Signature      []byte          `json:"signature"`
		EnvelopeDigest string          `json:"envelope_digest"`
	}
	if !exactJSONFields(payload, "credential_id", "device_id", "envelope_digest", "expires_at", "failure_mode", "issued_at", "key_id", "payload_digest", "phase", "policies", "policy_version", "sequence", "signature", "state") || decodeStrictDiscovery(payload, &result) != nil {
		return TemporaryPolicyTargetEnvelope{}, ErrRepositoryUnavailable
	}
	envelope := TemporaryPolicyTargetEnvelope{Target: TemporaryPolicyTarget{DeviceID: result.DeviceID, CredentialID: result.CredentialID, Sequence: result.Sequence, PolicyVersion: result.PolicyVersion}, Phase: result.Phase, State: result.State, KeyID: result.KeyID, IssuedAt: result.IssuedAt, ExpiresAt: result.ExpiresAt, FailureMode: result.FailureMode, PayloadDigest: result.PayloadDigest, Policies: result.Policies, Signature: result.Signature, EnvelopeDigest: result.EnvelopeDigest}
	if envelope.Target != target || !validTemporaryPolicyTargetEnvelope(claim, envelope) || result.State != "stored" && result.State != "verified" {
		return TemporaryPolicyTargetEnvelope{}, ErrRepositoryUnavailable
	}
	return envelope, nil
}

func (repository *SecurityAgentActionRepository) FinishTemporaryPolicyEffect(ctx context.Context, claim TemporaryPolicyEffectClaim, workerID, leaseToken, resultDigest, auditID, correlationID string) (TemporaryPolicyFinishResult, error) {
	digest, digestOK := decodeTemporaryPolicyDigest(resultDigest)
	if repository == nil || ctx == nil || ctx.Err() != nil || !validTemporaryPolicyEffectClaim(claim) || !validSecurityAgentWorkerIdentity(workerID, leaseToken) || !digestOK || !validProductID(auditID) || !validProductID(correlationID) {
		return TemporaryPolicyFinishResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActionFinishSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, claim.StepID, claim.Phase, workerID, leaseToken, digest, auditID, correlationID)
	if err != nil {
		return TemporaryPolicyFinishResult{}, discoveryProviderError(err)
	}
	var result TemporaryPolicyFinishResult
	if !exactJSONFields(payload, "effect_state", "outcome_id", "phase", "result_digest", "run_id", "step_id") || decodeStrictDiscovery(payload, &result) != nil || result.RunID != claim.RunID || result.StepID != claim.StepID || result.Phase != claim.Phase || !validProductID(result.OutcomeID) || result.ResultDigest != resultDigest || claim.Phase == "apply" && result.EffectState != "cleanup_pending" || claim.Phase == "cleanup" && result.EffectState != "cleaned" {
		return TemporaryPolicyFinishResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validTemporaryPolicyEffectClaim(claim TemporaryPolicyEffectClaim) bool {
	_, digestOK := decodeTemporaryPolicyDigest(claim.InputDigest)
	if !validProductID(claim.OrganizationID) || !validProductID(claim.WorkspaceID) || !validProductID(claim.EnvironmentID) || !validProductID(claim.RunID) || !validProductID(claim.StepID) || claim.Phase != "apply" && claim.Phase != "cleanup" || claim.TTLSeconds < 60 || claim.TTLSeconds > 3600 || claim.LeaseExpiresAt.IsZero() || claim.LeaseExpiresAt.Location() != time.UTC || !digestOK || len(claim.Targets) < 1 || len(claim.Targets) > 1000 {
		return false
	}
	seen := make(map[string]struct{}, len(claim.Targets))
	for _, target := range claim.Targets {
		if !validTemporaryPolicyTarget(target) {
			return false
		}
		if _, exists := seen[target.DeviceID]; exists {
			return false
		}
		seen[target.DeviceID] = struct{}{}
	}
	return true
}

func validTemporaryPolicyTarget(target TemporaryPolicyTarget) bool {
	return validProductID(target.DeviceID) && validProductID(target.CredentialID) && target.Sequence > 0 && target.Sequence <= 1_000_000_000 && target.PolicyVersion > 0 && target.PolicyVersion <= 1_000_000_000
}

func validTemporaryPolicyTargetEnvelope(claim TemporaryPolicyEffectClaim, envelope TemporaryPolicyTargetEnvelope) bool {
	if !validTemporaryPolicyTarget(envelope.Target) || !containsTemporaryPolicyTarget(claim.Targets, envelope.Target) || envelope.Phase != claim.Phase || len(envelope.KeyID) < 8 || len(envelope.KeyID) > 64 || envelope.IssuedAt.IsZero() || envelope.IssuedAt.Location() != time.UTC || envelope.ExpiresAt.IsZero() || envelope.ExpiresAt.Location() != time.UTC || !envelope.ExpiresAt.After(envelope.IssuedAt) || envelope.ExpiresAt.After(envelope.IssuedAt.Add(24*time.Hour)) || envelope.FailureMode != "closed" || len(envelope.Signature) != 64 || len(envelope.Policies) > 1<<20 {
		return false
	}
	var policies []json.RawMessage
	if decodeStrictDiscovery(envelope.Policies, &policies) != nil || len(policies) > 100 || claim.Phase == "apply" && len(policies) == 0 || claim.Phase == "cleanup" && len(policies) != 0 {
		return false
	}
	_, payloadOK := decodeTemporaryPolicyDigest(envelope.PayloadDigest)
	_, envelopeOK := decodeTemporaryPolicyDigest(envelope.EnvelopeDigest)
	return payloadOK && envelopeOK
}

func containsTemporaryPolicyTarget(targets []TemporaryPolicyTarget, expected TemporaryPolicyTarget) bool {
	for _, target := range targets {
		if target == expected {
			return true
		}
	}
	return false
}

func decodeTemporaryPolicyDigest(value string) ([]byte, bool) {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return nil, false
	}
	digest, err := hex.DecodeString(value[len("sha256:"):])
	return digest, err == nil && len(digest) == sha256.Size
}
