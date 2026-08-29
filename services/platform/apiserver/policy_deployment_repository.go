package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const (
	postgresPolicyDeploymentReadySQL     = `SELECT jsonb_build_object('release',zasp_policy_deployment_execution_readiness($1,$2),'principal',zasp_policy_deployment_principal_ready())`
	postgresPolicyDeploymentClaimSQL     = `SELECT zasp_policy_deployment_claim($1,$2,$3,$4)`
	postgresPolicyDeploymentHeartbeatSQL = `SELECT zasp_policy_deployment_heartbeat($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresPolicyDeploymentStoreSQL     = `SELECT zasp_policy_deployment_store($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	postgresPolicyDeploymentReadSQL      = `SELECT zasp_policy_deployment_read($1,$2,$3,$4,$5)`
	postgresPolicyDeploymentFinishSQL    = `SELECT zasp_policy_deployment_finish($1,$2,$3,$4,$5,$6,$7,$8)`
)

type PolicyDeploymentClaim struct {
	OrganizationID     string                  `json:"organization_id"`
	WorkspaceID        string                  `json:"workspace_id"`
	EnvironmentID      string                  `json:"environment_id"`
	DeviceID           string                  `json:"device_id"`
	CredentialID       string                  `json:"credential_id"`
	DesiredGeneration  int64                   `json:"desired_generation"`
	Sequence           int64                   `json:"sequence"`
	PolicyVersion      int64                   `json:"policy_version"`
	InputDigest        string                  `json:"input_digest"`
	LeaseExpiresAt     time.Time               `json:"lease_expires_at"`
	PersistentPolicies []policy.Policy         `json:"persistent_policies"`
	TemporaryPolicies  []policy.CompiledPolicy `json:"temporary_policies"`
	TemporaryExpiresAt *time.Time              `json:"temporary_expires_at"`
}

type PolicyDeploymentRepository struct {
	database              JSONDatabase
	checksum, fingerprint string
}

func NewPolicyDeploymentRepository(database JSONDatabase) (*PolicyDeploymentRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	metadata := migrations.ProductionPolicyDeployment()
	repository := &PolicyDeploymentRepository{database: database, checksum: metadata.Checksum(), fingerprint: migrations.ProductionPolicyDeploymentSemanticFingerprint()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *PolicyDeploymentRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || repository.checksum == "" || repository.fingerprint == "" {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresPolicyDeploymentReadySQL, repository.checksum, repository.fingerprint)
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

func (repository *PolicyDeploymentRepository) ClaimPolicyDeployments(ctx context.Context, workerID, leaseToken string, leaseSeconds, limit int) ([]PolicyDeploymentClaim, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) || limit < 1 || limit > 25 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresPolicyDeploymentClaimSQL, workerID, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []json.RawMessage `json:"items"`
	}
	if !exactJSONFields(payload, "items") || decodeStrictDiscovery(payload, &envelope) != nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	claims := make([]PolicyDeploymentClaim, len(envelope.Items))
	for index, raw := range envelope.Items {
		if !exactJSONFields(raw, "credential_id", "desired_generation", "device_id", "environment_id", "input_digest", "lease_expires_at", "organization_id", "persistent_policies", "policy_version", "sequence", "temporary_expires_at", "temporary_policies", "workspace_id") || decodeStrictDiscovery(raw, &claims[index]) != nil || !validPolicyDeploymentClaim(claims[index]) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return claims, nil
}

func (repository *PolicyDeploymentRepository) HeartbeatPolicyDeployment(ctx context.Context, claim PolicyDeploymentClaim, workerID, leaseToken string, leaseSeconds int) error {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validPolicyDeploymentClaim(claim) || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresPolicyDeploymentHeartbeatSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.DeviceID, claim.DesiredGeneration, workerID, leaseToken, leaseSeconds)
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

func (repository *PolicyDeploymentRepository) StorePolicyDeployment(ctx context.Context, claim PolicyDeploymentClaim, workerID, leaseToken string, envelope policy.GatewayPolicyEnvelope) (string, error) {
	payloadDigest, payloadErr := hex.DecodeString(envelope.PayloadDigest)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(envelope.Signature)
	raw, rawErr := json.Marshal(envelope)
	envelopeDigest := sha256.Sum256(raw)
	if repository == nil || ctx == nil || ctx.Err() != nil || !validPolicyDeploymentClaim(claim) || !validSecurityAgentWorkerIdentity(workerID, leaseToken) || payloadErr != nil || len(payloadDigest) != sha256.Size || signatureErr != nil || len(signature) != 64 || rawErr != nil || envelope.OrganizationID != claim.OrganizationID || envelope.WorkspaceID != claim.WorkspaceID || envelope.EnvironmentID != claim.EnvironmentID || envelope.DeviceID != claim.DeviceID || envelope.Sequence != uint64(claim.Sequence) || envelope.PolicyVersion != uint64(claim.PolicyVersion) {
		return "", ErrRepositoryOperation
	}
	policies, err := json.Marshal(envelope.Policies)
	if err != nil {
		return "", ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresPolicyDeploymentStoreSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.DeviceID, claim.DesiredGeneration, workerID, leaseToken, claim.CredentialID, claim.Sequence, claim.PolicyVersion, envelope.KeyID, envelope.IssuedAt, envelope.ExpiresAt, envelope.FailureMode, payloadDigest, json.RawMessage(policies), signature, envelopeDigest[:])
	if err != nil {
		return "", discoveryProviderError(err)
	}
	var result struct {
		EnvelopeDigest string `json:"envelope_digest"`
	}
	want := "sha256:" + hex.EncodeToString(envelopeDigest[:])
	if !exactJSONFields(payload, "envelope_digest") || decodeStrictDiscovery(payload, &result) != nil || result.EnvelopeDigest != want {
		return "", ErrRepositoryUnavailable
	}
	return result.EnvelopeDigest, nil
}

func (repository *PolicyDeploymentRepository) ReadPolicyDeployment(ctx context.Context, claim PolicyDeploymentClaim) (policy.GatewayPolicyEnvelope, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validPolicyDeploymentClaim(claim) {
		return policy.GatewayPolicyEnvelope{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresPolicyDeploymentReadSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.DeviceID, claim.Sequence)
	if err != nil {
		return policy.GatewayPolicyEnvelope{}, discoveryProviderError(err)
	}
	var result policy.GatewayPolicyEnvelope
	if !exactJSONFields(payload, "algorithm", "audience", "contract_version", "device_id", "environment_id", "expires_at", "failure_mode", "issued_at", "key_id", "organization_id", "payload_digest", "policies", "policy_version", "sequence", "signature", "workspace_id") || decodeStrictDiscovery(payload, &result) != nil || result.OrganizationID != claim.OrganizationID || result.WorkspaceID != claim.WorkspaceID || result.EnvironmentID != claim.EnvironmentID || result.DeviceID != claim.DeviceID || result.Sequence != uint64(claim.Sequence) || result.PolicyVersion != uint64(claim.PolicyVersion) {
		return policy.GatewayPolicyEnvelope{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PolicyDeploymentRepository) FinishPolicyDeployment(ctx context.Context, claim PolicyDeploymentClaim, workerID, leaseToken, envelopeDigest string) error {
	digest, ok := decodeTemporaryPolicyDigest(envelopeDigest)
	if repository == nil || ctx == nil || ctx.Err() != nil || !validPolicyDeploymentClaim(claim) || !validSecurityAgentWorkerIdentity(workerID, leaseToken) || !ok {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresPolicyDeploymentFinishSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.DeviceID, claim.DesiredGeneration, workerID, leaseToken, digest)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		DesiredGeneration int64  `json:"desired_generation"`
		AppliedGeneration int64  `json:"applied_generation"`
		State             string `json:"state"`
		EnvelopeDigest    string `json:"envelope_digest"`
	}
	if !exactJSONFields(payload, "applied_generation", "desired_generation", "envelope_digest", "state") || decodeStrictDiscovery(payload, &result) != nil || result.DesiredGeneration < claim.DesiredGeneration || result.AppliedGeneration != claim.DesiredGeneration || result.State != "pending" && result.State != "scheduled" || result.EnvelopeDigest != envelopeDigest {
		return ErrRepositoryUnavailable
	}
	return nil
}

func validPolicyDeploymentClaim(claim PolicyDeploymentClaim) bool {
	_, digestOK := decodeTemporaryPolicyDigest(claim.InputDigest)
	if !validProductID(claim.OrganizationID) || !validProductID(claim.WorkspaceID) || !validProductID(claim.EnvironmentID) || !validProductID(claim.DeviceID) || !validProductID(claim.CredentialID) || claim.DesiredGeneration < 1 || claim.DesiredGeneration > 1_000_000_000 || claim.Sequence < 1 || claim.Sequence > 1_000_000_000 || claim.PolicyVersion != claim.Sequence || !digestOK || claim.LeaseExpiresAt.IsZero() || claim.LeaseExpiresAt.Location() != time.UTC || len(claim.PersistentPolicies) > 100 || len(claim.TemporaryPolicies) > 100 || len(claim.PersistentPolicies)+len(claim.TemporaryPolicies) > 100 {
		return false
	}
	if len(claim.TemporaryPolicies) == 0 {
		return claim.TemporaryExpiresAt == nil
	}
	if claim.TemporaryExpiresAt == nil || claim.TemporaryExpiresAt.IsZero() || claim.TemporaryExpiresAt.Location() != time.UTC {
		return false
	}
	return true
}
