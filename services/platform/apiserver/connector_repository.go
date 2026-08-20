package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresConnectorReadySQL                  = `SELECT to_jsonb(zasp_connector_readiness($1,$2))`
	postgresConnectorStartOAuthSQL             = `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb)`
	postgresConnectorConsumeOAuthSQL           = `SELECT zasp_connector_consume_oauth($1,$2,$3,$4,$5,$6)`
	postgresConnectorBeginEffectSQL            = `SELECT zasp_connector_begin_effect($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresConnectorStagePKCECleanupSQL       = `SELECT zasp_connector_stage_pkce_cleanup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresConnectorActivatePKCECleanupSQL    = `SELECT zasp_connector_activate_pkce_cleanup($1,$2,$3,$4)`
	postgresConnectorCompletePKCECleanupSQL    = `SELECT zasp_connector_complete_pkce_cleanup($1,$2,$3,$4,$5,$6)`
	postgresConnectorResolveEffectSQL          = `SELECT zasp_connector_resolve_effect($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`
	postgresConnectorPutCredentialSQL          = `SELECT zasp_connector_put_credential($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`
	postgresConnectorCompleteOAuthSQL          = `SELECT zasp_connector_complete_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`
	postgresConnectorClaimReconciliationSQL    = `SELECT zasp_connector_claim_reconciliation($1,$2,$3)`
	postgresConnectorCompleteReconciliationSQL = `SELECT zasp_connector_complete_reconciliation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14)`
	postgresConnectorFailReconciliationSQL     = `SELECT zasp_connector_fail_reconciliation($1,$2,$3,$4,$5,$6,$7)`
	postgresConnectorCompleteRevocationSQL     = `SELECT zasp_connector_complete_revocation($1,$2,$3,$4,$5,$6)`
	postgresConnectorCompleteCleanupSQL        = `SELECT zasp_connector_complete_cleanup($1,$2,$3,$4)`
	postgresConnectorCompleteLeasedCleanupSQL  = `SELECT zasp_connector_complete_cleanup($1,$2,$3,$4,$5,$6)`
	postgresConnectorQuarantineSQL             = `SELECT zasp_connector_quarantine_reconciliation($1,$2,$3,$4,$5,$6,$7)`
	postgresConnectorGetQuarantineSQL          = `SELECT zasp_connector_get_quarantine($1,$2,$3,$4)`
	postgresConnectorRemediateQuarantineSQL    = `SELECT zasp_connector_remediate_quarantine($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`
)

var connectorScopePattern = regexp.MustCompile(`^[A-Za-z0-9:_./-]{1,128}$`)
var connectorProviderPattern = regexp.MustCompile(`^nango:[a-z0-9][a-z0-9_-]{1,62}$`)
var connectorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)

type ConnectorAuthorizationRepository interface {
	StartOAuth(context.Context, RequestIdentity, OAuthStart) (OAuthAttemptRecord, error)
	ConsumeOAuth(context.Context, RequestIdentity, []byte, []byte) (OAuthConsumption, error)
	BeginConnectorEffect(context.Context, domain.Scope, ConnectorEffectStart) (ConnectorEffectRecord, error)
	ResolveConnectorEffect(context.Context, domain.Scope, ConnectorEffectResolution) (ConnectorEffectRecord, error)
	PutConnectorCredential(context.Context, domain.Scope, ConnectorCredentialPut) (ConnectorCredentialRecord, error)
	CompleteOAuth(context.Context, domain.Scope, OAuthCompletion) (OAuthCompletionRecord, error)
	StagePKCECleanup(context.Context, domain.Scope, PKCECleanupStage) (ConnectorEffectRecord, error)
	ActivatePKCECleanup(context.Context, domain.Scope, string) (ConnectorEffectTransition, error)
	CompletePKCECleanup(context.Context, domain.Scope, string) (ConnectorEffectTransition, error)
	GetConnectorQuarantine(context.Context, domain.Scope, string) (ConnectorQuarantine, error)
	CompleteConnectorCleanup(context.Context, domain.Scope, string) (ConnectorEffectTransition, error)
	RemediateConnectorQuarantine(context.Context, RequestIdentity, ConnectorQuarantineRemediation) (WorkflowMutationResult, error)
}

type ConnectorRepository struct{ database JSONDatabase }

func NewConnectorRepository(database JSONDatabase) (*ConnectorRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	repository := &ConnectorRepository{database: database}
	if err := repository.ready(context.Background()); err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *ConnectorRepository) Ready(ctx context.Context) error {
	if err := repository.ready(ctx); err != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *ConnectorRepository) ready(ctx context.Context) error {
	if !validConnectorRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	version, err := repository.database.SchemaVersion(ctx)
	if err != nil || version != ConnectorSchemaVersion {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorReadySQL, migrations.ConnectorAuthorization().Checksum(), migrations.ConnectorAuthorizationSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	payload, err = repository.database.QueryJSON(ctx, postgresDiscoveryPrincipalReadySQL, DiscoveryDatabaseAuthorityAPI)
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

type OAuthStart struct {
	AttemptID, IntegrationID, Provider, PKCEVerifierReference string
	SessionDigest, StateDigest, RequestDigest                 []byte
	RequestedScopes                                           []string
	ExpiresAt                                                 time.Time
	IntegrationVersion                                        int64
	Configuration                                             json.RawMessage
}

type OAuthAttemptRecord struct {
	ID            string    `json:"id"`
	IntegrationID string    `json:"integration_id"`
	Provider      string    `json:"provider"`
	Status        string    `json:"status"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

func (repository *ConnectorRepository) StartOAuth(ctx context.Context, identity RequestIdentity, input OAuthStart) (OAuthAttemptRecord, error) {
	if !validConnectorRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validOAuthStart(input) {
		return OAuthAttemptRecord{}, ErrRepositoryOperation
	}
	scopes, _ := json.Marshal(input.RequestedScopes)
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorStartOAuthSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.AttemptID, input.IntegrationID, input.Provider, identity.PrincipalID.String(), input.SessionDigest, input.StateDigest, input.PKCEVerifierReference, input.RequestDigest, string(scopes), input.ExpiresAt, input.IntegrationVersion, input.Configuration)
	if err != nil {
		return OAuthAttemptRecord{}, discoveryProviderError(err)
	}
	var result OAuthAttemptRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.AttemptID || result.IntegrationID != input.IntegrationID || result.Provider != input.Provider || result.Status != "pending" || !validPastServerTime(result.CreatedAt) || !result.ExpiresAt.After(time.Now()) || result.ExpiresAt.After(input.ExpiresAt.Add(time.Second)) {
		return OAuthAttemptRecord{}, ErrRepositoryUnavailable
	}
	result.CreatedAt, result.ExpiresAt = result.CreatedAt.UTC(), result.ExpiresAt.UTC()
	return result, nil
}

type OAuthConsumption struct {
	ID                    string    `json:"id"`
	IntegrationID         string    `json:"integration_id"`
	Provider              string    `json:"provider"`
	PrincipalID           string    `json:"principal_id"`
	PKCEVerifierReference string    `json:"pkce_verifier_reference"`
	RequestDigest         string    `json:"request_digest"`
	ReturnPath            string    `json:"return_path"`
	RequestedScopes       []string  `json:"requested_scopes"`
	ExpiresAt             time.Time `json:"expires_at"`
	ConsumedAt            time.Time `json:"consumed_at"`
}

func (repository *ConnectorRepository) ConsumeOAuth(ctx context.Context, identity RequestIdentity, stateDigest, sessionDigest []byte) (OAuthConsumption, error) {
	if !validConnectorRepository(repository, ctx) || !validRequestIdentity(identity, false) || len(stateDigest) != 32 || len(sessionDigest) != 32 {
		return OAuthConsumption{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorConsumeOAuthSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), stateDigest, identity.PrincipalID.String(), sessionDigest)
	if err != nil {
		return OAuthConsumption{}, discoveryProviderError(err)
	}
	var result OAuthConsumption
	if decodeStrictDiscovery(payload, &result) != nil {
		return OAuthConsumption{}, ErrRepositoryUnavailable
	}
	decodedDigest, digestErr := hex.DecodeString(result.RequestDigest)
	if digestErr != nil || len(decodedDigest) != 32 || !validProductID(result.ID) || !validProductID(result.IntegrationID) || result.PrincipalID != identity.PrincipalID.String() || !validOAuthProvider(result.Provider) || !validOpaqueReference(result.PKCEVerifierReference) || result.ReturnPath != "/connectors" || !validConnectorScopes(result.RequestedScopes) || !result.ExpiresAt.After(time.Now()) || !validPastServerTime(result.ConsumedAt) {
		return OAuthConsumption{}, ErrRepositoryUnavailable
	}
	result.ExpiresAt, result.ConsumedAt = result.ExpiresAt.UTC(), result.ConsumedAt.UTC()
	return result, nil
}

type ConnectorEffectStart struct {
	ID, IntegrationID, OAuthAttemptID, Provider, Operation, IdempotencyKey string
	RequestDigest                                                          []byte
}
type ConnectorEffectRecord struct {
	ID            string    `json:"id"`
	IntegrationID string    `json:"integration_id"`
	Provider      string    `json:"provider"`
	Operation     string    `json:"operation"`
	Status        string    `json:"status"`
	Attempt       int       `json:"attempt"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (repository *ConnectorRepository) BeginConnectorEffect(ctx context.Context, scope domain.Scope, input ConnectorEffectStart) (ConnectorEffectRecord, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !validProductID(input.IntegrationID) || input.OAuthAttemptID != "" && !validProductID(input.OAuthAttemptID) || !validConnectorProvider(input.Provider) || !stringIn(input.Operation, "authorize", "bind", "test", "rotate", "revoke", "nango_connect") || len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 || len(input.RequestDigest) != 32 {
		return ConnectorEffectRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorBeginEffectSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ID, input.IntegrationID, input.OAuthAttemptID, input.Provider, input.Operation, input.IdempotencyKey, input.RequestDigest)
	if err != nil {
		return ConnectorEffectRecord{}, discoveryProviderError(err)
	}
	return decodeConnectorEffect(payload, input.ID, input.IntegrationID, input.Provider, input.Operation)
}

type ConnectorEffectResolution struct {
	ID, Status, ConnectionReference, ErrorCode string
	Metadata                                   json.RawMessage
}

type PKCECleanupStage struct {
	ID, IntegrationID, OAuthAttemptID, Provider, Reference, Reason string
	RequestDigest                                                  []byte
	AvailableAt                                                    time.Time
}

func (repository *ConnectorRepository) StagePKCECleanup(ctx context.Context, scope domain.Scope, input PKCECleanupStage) (ConnectorEffectRecord, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !validProductID(input.IntegrationID) || input.OAuthAttemptID != "" && !validProductID(input.OAuthAttemptID) || !validOAuthProvider(input.Provider) || !validOpaqueReference(input.Reference) || len(input.RequestDigest) != sha256.Size || !stringIn(input.Reason, "oauth_attempt_expiry", "oauth_start_rejected") || input.AvailableAt.Before(time.Now().Add(-time.Second)) || input.AvailableAt.After(time.Now().Add(10*time.Minute+time.Second)) {
		return ConnectorEffectRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorStagePKCECleanupSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ID, input.IntegrationID, input.OAuthAttemptID, input.Provider, input.Reference, input.RequestDigest, input.AvailableAt, input.Reason)
	if err != nil {
		return ConnectorEffectRecord{}, discoveryProviderError(err)
	}
	return decodeConnectorEffect(payload, input.ID, input.IntegrationID, input.Provider, "pkce_cleanup")
}

func (repository *ConnectorRepository) ActivatePKCECleanup(ctx context.Context, scope domain.Scope, effectID string) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(effectID) {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorActivatePKCECleanupSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), effectID)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, effectID, "unknown", 0)
}

func (repository *ConnectorRepository) CompletePKCECleanup(ctx context.Context, scope domain.Scope, effectID string) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(effectID) {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompletePKCECleanupSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), effectID, "", "")
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, effectID, "reconciled", 0)
}

func (repository *ConnectorRepository) CompletePKCECleanupReconciliation(ctx context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "pkce_cleanup" {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompletePKCECleanupSQL, lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, lease.ID, lease.LeaseOwner, lease.LeaseToken)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, lease.ID, "reconciled", lease.Attempt)
}

func (repository *ConnectorRepository) ResolveConnectorEffect(ctx context.Context, scope domain.Scope, input ConnectorEffectResolution) (ConnectorEffectRecord, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !stringIn(input.Status, "unknown", "failed") || input.ConnectionReference != "" && !validOpaqueReference(input.ConnectionReference) || input.ErrorCode != "" && !connectorCodePattern.MatchString(input.ErrorCode) || !validConnectorMetadata(input.Metadata) {
		return ConnectorEffectRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorResolveEffectSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ID, input.Status, input.ConnectionReference, input.Metadata, input.ErrorCode)
	if err != nil {
		return ConnectorEffectRecord{}, discoveryProviderError(err)
	}
	var result ConnectorEffectRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.Status != input.Status || result.Attempt < 0 || result.Attempt > 100 || !validPastServerTime(result.UpdatedAt) {
		return ConnectorEffectRecord{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

type ConnectorCredentialPut struct {
	ID, IntegrationID, Provider, CredentialClass, CredentialReference string
	Version                                                           int64
	Metadata                                                          json.RawMessage
}
type ConnectorCredentialRecord struct {
	ID              string     `json:"id"`
	IntegrationID   string     `json:"integration_id"`
	Provider        string     `json:"provider"`
	CredentialClass string     `json:"credential_class"`
	Status          string     `json:"status"`
	Version         int64      `json:"version"`
	ExpiresAt       *time.Time `json:"expires_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (repository *ConnectorRepository) PutConnectorCredential(ctx context.Context, scope domain.Scope, input ConnectorCredentialPut) (ConnectorCredentialRecord, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !validProductID(input.IntegrationID) || !validConnectorProvider(input.Provider) || !stringIn(input.CredentialClass, "aws_external_id", "kubernetes_cluster_reference", "github_app_reference", "github_installation_reference", "okta_refresh_reference", "nango_connection_reference") || !validOpaqueReference(input.CredentialReference) || input.Version < 1 || input.Version > 1000000 || !validConnectorMetadata(input.Metadata) {
		return ConnectorCredentialRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorPutCredentialSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ID, input.IntegrationID, input.Provider, input.CredentialClass, input.CredentialReference, input.Version, input.Metadata)
	if err != nil {
		return ConnectorCredentialRecord{}, discoveryProviderError(err)
	}
	var result ConnectorCredentialRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.IntegrationID != input.IntegrationID || result.Provider != input.Provider || result.CredentialClass != input.CredentialClass || result.Version != input.Version || !stringIn(result.Status, "active", "rotated", "revoked", "expired") || !validPastServerTime(result.CreatedAt) || result.UpdatedAt.Before(result.CreatedAt) {
		return ConnectorCredentialRecord{}, ErrRepositoryUnavailable
	}
	result.CreatedAt, result.UpdatedAt = result.CreatedAt.UTC(), result.UpdatedAt.UTC()
	if result.ExpiresAt != nil {
		value := result.ExpiresAt.UTC()
		result.ExpiresAt = &value
	}
	return result, nil
}

type OAuthCompletion struct {
	AttemptID, EffectID, ConnectionID, ConnectionReference, ProviderSubject, CredentialID, CredentialClass string
	Metadata                                                                                               json.RawMessage
}
type OAuthCompletionRecord struct {
	AttemptID    string    `json:"attempt_id"`
	ConnectionID string    `json:"connection_id"`
	Status       string    `json:"status"`
	CompletedAt  time.Time `json:"completed_at"`
}

func (repository *ConnectorRepository) CompleteOAuth(ctx context.Context, scope domain.Scope, input OAuthCompletion) (OAuthCompletionRecord, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.AttemptID) || !validProductID(input.EffectID) || !validProductID(input.ConnectionID) || !validOpaqueReference(input.ConnectionReference) || len(input.ProviderSubject) < 1 || len(input.ProviderSubject) > 256 || !validProductID(input.CredentialID) || len(input.CredentialClass) < 1 || len(input.CredentialClass) > 64 || !validConnectorMetadata(input.Metadata) {
		return OAuthCompletionRecord{}, ErrRepositoryOperation
	}
	canonicalMetadata, digest := connectorOAuthCompletionDigest(input)
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompleteOAuthSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.AttemptID, input.EffectID, input.ConnectionID, input.ConnectionReference, input.ProviderSubject, input.CredentialID, input.CredentialClass, canonicalMetadata, digest[:])
	if err != nil {
		return OAuthCompletionRecord{}, discoveryProviderError(err)
	}
	var result OAuthCompletionRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.AttemptID != input.AttemptID || result.ConnectionID != input.ConnectionID || result.Status != "succeeded" || !validPastServerTime(result.CompletedAt) {
		return OAuthCompletionRecord{}, ErrRepositoryUnavailable
	}
	result.CompletedAt = result.CompletedAt.UTC()
	return result, nil
}

func connectorOAuthCompletionDigest(input OAuthCompletion) (json.RawMessage, [sha256.Size]byte) {
	canonicalMetadata, _ := canonicalConnectorMetadata(input.Metadata)
	digest := sha256.Sum256([]byte(strings.Join([]string{input.AttemptID, input.EffectID, input.ConnectionID, input.ConnectionReference, input.ProviderSubject, input.CredentialID, input.CredentialClass, string(canonicalMetadata)}, "\x1f")))
	return canonicalMetadata, digest
}

func canonicalConnectorMetadata(value json.RawMessage) (json.RawMessage, error) {
	var object map[string]any
	if decodeStrictDiscovery(value, &object) != nil || object == nil {
		return nil, ErrRepositoryOperation
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	return canonical, nil
}

type ConnectorEffectLease struct {
	OrganizationID      string    `json:"organization_id"`
	WorkspaceID         string    `json:"workspace_id"`
	EnvironmentID       string    `json:"environment_id"`
	ID                  string    `json:"id"`
	IntegrationID       string    `json:"integration_id"`
	OAuthAttemptID      string    `json:"oauth_attempt_id"`
	PrincipalID         string    `json:"principal_id"`
	RequestedScopes     []string  `json:"requested_scopes"`
	ConnectionReference string    `json:"connection_reference"`
	Provider            string    `json:"provider"`
	Operation           string    `json:"operation"`
	IdempotencyKey      string    `json:"idempotency_key"`
	RequestDigest       string    `json:"request_digest"`
	LastErrorCode       string    `json:"last_error_code"`
	Attempt             int       `json:"attempt"`
	LeaseOwner          string    `json:"lease_owner"`
	LeaseToken          string    `json:"lease_token"`
	LeaseExpiresAt      time.Time `json:"lease_expires_at"`
}

type ConnectorEffectTransition struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Attempt   int       `json:"attempt"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (repository *ConnectorRepository) ClaimReconciliation(ctx context.Context, owner string, leaseSeconds, limit int) ([]ConnectorEffectLease, error) {
	if !validConnectorRepository(repository, ctx) || len(owner) < 3 || len(owner) > 128 || leaseSeconds < 5 || leaseSeconds > 300 || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorClaimReconciliationSQL, owner, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var page struct {
		Items []ConnectorEffectLease `json:"items"`
	}
	if decodeStrictDiscovery(payload, &page) != nil || page.Items == nil || len(page.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	now := time.Now()
	for index := range page.Items {
		item := &page.Items[index]
		digest, digestErr := hex.DecodeString(item.RequestDigest)
		if digestErr != nil || len(digest) != 32 || !validProductID(item.OrganizationID) || !validProductID(item.WorkspaceID) || !validProductID(item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.IntegrationID) || item.Operation == "authorize" && (!validProductID(item.OAuthAttemptID) || !validProductID(item.PrincipalID) || !validConnectorScopes(item.RequestedScopes)) || item.Operation != "authorize" && item.Operation != "pkce_cleanup" && (item.OAuthAttemptID != "" || item.PrincipalID != "" || item.RequestedScopes != nil) || item.Operation == "pkce_cleanup" && (item.OAuthAttemptID != "" && !validProductID(item.OAuthAttemptID) || item.PrincipalID != "" && !validProductID(item.PrincipalID) || item.RequestedScopes != nil && !validConnectorScopes(item.RequestedScopes)) || item.Operation == "revoke" && !validOpaqueReference(item.ConnectionReference) || item.Operation == "pkce_cleanup" && !validOpaqueReference(item.ConnectionReference) || item.Operation == "authorize" && item.LastErrorCode == "cleanup_pending" && !validOpaqueReference(item.ConnectionReference) || item.Operation == "authorize" && item.LastErrorCode != "cleanup_pending" && item.ConnectionReference != "" || !stringIn(item.Operation, "authorize", "revoke", "pkce_cleanup") && item.ConnectionReference != "" || !validConnectorProvider(item.Provider) || !stringIn(item.Operation, "authorize", "bind", "test", "rotate", "revoke", "pkce_cleanup", "nango_connect") || item.LastErrorCode != "" && !connectorCodePattern.MatchString(item.LastErrorCode) || len(item.IdempotencyKey) < 16 || len(item.IdempotencyKey) > 128 || item.Attempt < 1 || item.Attempt > 100 || item.LeaseOwner != owner || len(item.LeaseToken) != 64 || !item.LeaseExpiresAt.After(now) || item.LeaseExpiresAt.After(now.Add(time.Duration(leaseSeconds)*time.Second+time.Second)) {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return page.Items, nil
}

func (repository *ConnectorRepository) CompleteOAuthReconciliation(ctx context.Context, lease ConnectorEffectLease, input OAuthCompletion) (OAuthCompletionRecord, error) {
	if !validConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "authorize" || input.AttemptID != lease.OAuthAttemptID || input.EffectID != lease.ID || !validOAuthCompletion(input) {
		return OAuthCompletionRecord{}, ErrRepositoryOperation
	}
	canonicalMetadata, digest := connectorOAuthCompletionDigest(input)
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompleteReconciliationSQL, lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, input.AttemptID, input.EffectID, lease.LeaseOwner, lease.LeaseToken, input.ConnectionID, input.ConnectionReference, input.ProviderSubject, input.CredentialID, input.CredentialClass, canonicalMetadata, digest[:])
	if err != nil {
		return OAuthCompletionRecord{}, discoveryProviderError(err)
	}
	var result OAuthCompletionRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.AttemptID != input.AttemptID || result.ConnectionID != input.ConnectionID || result.Status != "succeeded" || !validPastServerTime(result.CompletedAt) {
		return OAuthCompletionRecord{}, ErrRepositoryUnavailable
	}
	result.CompletedAt = result.CompletedAt.UTC()
	return result, nil
}

func (repository *ConnectorRepository) FailConnectorReconciliation(ctx context.Context, lease ConnectorEffectLease, errorCode string) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || !validConnectorLease(lease) || !connectorCodePattern.MatchString(errorCode) {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorFailReconciliationSQL, lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, lease.ID, lease.LeaseOwner, lease.LeaseToken, errorCode)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	var result ConnectorEffectTransition
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != lease.ID || result.Status != "failed" || result.Attempt != lease.Attempt || !validPastServerTime(result.UpdatedAt) {
		return ConnectorEffectTransition{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func (repository *ConnectorRepository) CompleteConnectorRevocation(ctx context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "revoke" {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompleteRevocationSQL, lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, lease.ID, lease.LeaseOwner, lease.LeaseToken)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	var result ConnectorEffectTransition
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != lease.ID || result.Status != "reconciled" || result.Attempt != lease.Attempt || !validPastServerTime(result.UpdatedAt) {
		return ConnectorEffectTransition{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func (repository *ConnectorRepository) CompleteConnectorCleanup(ctx context.Context, scope domain.Scope, effectID string) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(effectID) {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompleteCleanupSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), effectID)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, effectID, "reconciled", 0)
}

func (repository *ConnectorRepository) CompleteConnectorCleanupReconciliation(ctx context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	if !validConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "authorize" {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorCompleteLeasedCleanupSQL, lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, lease.ID, lease.LeaseOwner, lease.LeaseToken)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, lease.ID, "reconciled", lease.Attempt)
}

func (repository *ConnectorRepository) QuarantineConnectorReconciliation(ctx context.Context, lease ConnectorEffectLease, errorCode string) (ConnectorEffectTransition, error) {
	validReason := lease.Operation == "authorize" && stringIn(errorCode, "provider_outcome_ambiguous", "provider_cleanup_ambiguous") || lease.Operation == "revoke" && errorCode == "provider_revocation_ambiguous" || lease.Operation == "pkce_cleanup" && errorCode == "pkce_cleanup_ambiguous"
	if !validConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Attempt != 100 || !validReason {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorQuarantineSQL, lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, lease.ID, lease.LeaseOwner, lease.LeaseToken, errorCode)
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, lease.ID, "unknown", lease.Attempt)
}

type ConnectorQuarantineRemediation struct {
	EffectID, IntegrationID, Acknowledgement, IdempotencyKey string
	ExpectedVersion                                          int64
	Intent, Body                                             json.RawMessage
	AuditID, CorrelationID, ReceiptID                        string
}

type ConnectorQuarantine struct {
	ID                  string `json:"id"`
	IntegrationID       string `json:"integration_id"`
	Provider            string `json:"provider"`
	Operation           string `json:"operation"`
	ConnectionReference string `json:"connection_reference"`
	Status              string `json:"status"`
	Reason              string `json:"reason"`
}

func (repository *ConnectorRepository) GetConnectorQuarantine(ctx context.Context, scope domain.Scope, integrationID string) (ConnectorQuarantine, error) {
	if !validConnectorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(integrationID) {
		return ConnectorQuarantine{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorGetQuarantineSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID)
	if err != nil {
		return ConnectorQuarantine{}, discoveryProviderError(err)
	}
	var result ConnectorQuarantine
	if decodeStrictDiscovery(payload, &result) != nil {
		return ConnectorQuarantine{}, ErrRepositoryUnavailable
	}
	validReason := stringIn(result.Reason, "provider_outcome_ambiguous", "provider_cleanup_ambiguous", "provider_revocation_ambiguous", "pkce_cleanup_ambiguous", "provider_outcome_remediated", "provider_cleanup_remediated", "provider_revocation_remediated", "pkce_cleanup_remediated")
	needsReference := result.Operation == "pkce_cleanup" || result.Operation == "revoke" || result.Operation == "authorize" && stringIn(result.Reason, "provider_cleanup_ambiguous", "provider_cleanup_remediated")
	validReference := needsReference && validOpaqueReference(result.ConnectionReference) || !needsReference && result.ConnectionReference == ""
	if !validProductID(result.ID) || result.IntegrationID != integrationID || !validOAuthProvider(result.Provider) || !stringIn(result.Operation, "authorize", "revoke", "pkce_cleanup") || !validReference || !stringIn(result.Status, "unknown", "failed") || !validReason {
		return ConnectorQuarantine{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *ConnectorRepository) RemediateConnectorQuarantine(ctx context.Context, identity RequestIdentity, input ConnectorQuarantineRemediation) (WorkflowMutationResult, error) {
	if !validConnectorRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validProductID(input.EffectID) || !validProductID(input.IntegrationID) || !stringIn(input.Acknowledgement, "provider_grant_revoked_manually", "provider_grant_verified_absent") || len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 || !workflowKeyPattern.MatchString(input.IdempotencyKey) || input.ExpectedVersion < 1 || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || !validJSONObjectBody(input.Intent) {
		return WorkflowMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorRemediateQuarantineSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.EffectID, input.IntegrationID, identity.PrincipalID.String(), input.Acknowledgement, input.IdempotencyKey, input.ExpectedVersion, input.Intent, input.Body, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return WorkflowMutationResult{}, discoveryProviderError(err)
	}
	var result WorkflowMutationResult
	mutation := WorkflowMutation{Action: "update", Kind: "integration", ID: input.IntegrationID, Operation: "remediateIntegrationAuthorization", IdempotencyKey: input.IdempotencyKey, ExpectedVersion: input.ExpectedVersion, Intent: input.Intent, Body: input.Body, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}
	if json.Unmarshal(payload, &result) != nil || result.Version < 1 || result.SecretGeneration < 0 || !validJSONObjectBody(result.Body) || !validMutationResultIDs(result, mutation) {
		return WorkflowMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validConnectorLease(lease ConnectorEffectLease) bool {
	digest, err := hex.DecodeString(lease.RequestDigest)
	validReference := lease.Operation == "revoke" && validOpaqueReference(lease.ConnectionReference) || lease.Operation == "pkce_cleanup" && validOpaqueReference(lease.ConnectionReference) || lease.Operation == "authorize" && lease.LastErrorCode == "cleanup_pending" && validOpaqueReference(lease.ConnectionReference) || !stringIn(lease.Operation, "revoke", "pkce_cleanup") && (lease.Operation != "authorize" || lease.LastErrorCode != "cleanup_pending") && lease.ConnectionReference == ""
	validParent := lease.Operation == "authorize" && validProductID(lease.OAuthAttemptID) && validProductID(lease.PrincipalID) && validConnectorScopes(lease.RequestedScopes) || lease.Operation == "pkce_cleanup" && (lease.OAuthAttemptID == "" || validProductID(lease.OAuthAttemptID)) && (lease.PrincipalID == "" || validProductID(lease.PrincipalID)) && (lease.RequestedScopes == nil || validConnectorScopes(lease.RequestedScopes)) || !stringIn(lease.Operation, "authorize", "pkce_cleanup") && lease.OAuthAttemptID == "" && lease.PrincipalID == "" && lease.RequestedScopes == nil
	return err == nil && len(digest) == sha256.Size && validProductID(lease.OrganizationID) && validProductID(lease.WorkspaceID) && validProductID(lease.EnvironmentID) && validProductID(lease.ID) && validProductID(lease.IntegrationID) && validConnectorProvider(lease.Provider) && stringIn(lease.Operation, "authorize", "bind", "test", "rotate", "revoke", "pkce_cleanup", "nango_connect") && validParent && validReference && (lease.LastErrorCode == "" || connectorCodePattern.MatchString(lease.LastErrorCode)) && len(lease.IdempotencyKey) >= 16 && len(lease.IdempotencyKey) <= 128 && lease.Attempt >= 1 && lease.Attempt <= 100 && len(lease.LeaseOwner) >= 3 && len(lease.LeaseOwner) <= 128 && len(lease.LeaseToken) == 64 && lease.LeaseExpiresAt.After(time.Now())
}

func decodeConnectorTransition(payload json.RawMessage, effectID, status string, minimumAttempt int) (ConnectorEffectTransition, error) {
	var result ConnectorEffectTransition
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != effectID || result.Status != status || result.Attempt < minimumAttempt || result.Attempt > 100 || !validPastServerTime(result.UpdatedAt) {
		return ConnectorEffectTransition{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func validOAuthCompletion(input OAuthCompletion) bool {
	return validProductID(input.AttemptID) && validProductID(input.EffectID) && validProductID(input.ConnectionID) && validOpaqueReference(input.ConnectionReference) && len(input.ProviderSubject) >= 1 && len(input.ProviderSubject) <= 256 && validProductID(input.CredentialID) && len(input.CredentialClass) >= 1 && len(input.CredentialClass) <= 64 && validConnectorMetadata(input.Metadata)
}

func decodeConnectorEffect(payload json.RawMessage, id, integrationID, provider, operation string) (ConnectorEffectRecord, error) {
	var result ConnectorEffectRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.IntegrationID != integrationID || result.Provider != provider || result.Operation != operation || !stringIn(result.Status, "pending", "unknown", "succeeded", "failed", "reconciled") || result.Attempt < 0 || result.Attempt > 100 || !validPastServerTime(result.CreatedAt) || result.UpdatedAt.Before(result.CreatedAt) {
		return ConnectorEffectRecord{}, ErrRepositoryUnavailable
	}
	result.CreatedAt, result.UpdatedAt = result.CreatedAt.UTC(), result.UpdatedAt.UTC()
	return result, nil
}

func validConnectorRepository(repository *ConnectorRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validOAuthStart(input OAuthStart) bool {
	return validProductID(input.AttemptID) && validProductID(input.IntegrationID) && validOAuthProvider(input.Provider) && len(input.SessionDigest) == 32 && len(input.StateDigest) == 32 && validOpaqueReference(input.PKCEVerifierReference) && len(input.RequestDigest) == 32 && validConnectorScopes(input.RequestedScopes) && input.ExpiresAt.After(time.Now()) && !input.ExpiresAt.After(time.Now().Add(10*time.Minute)) && input.IntegrationVersion >= 1 && input.IntegrationVersion <= 1000000 && len(input.Configuration) <= 16384 && validJSONObjectBody(input.Configuration)
}

func validOAuthProvider(provider string) bool {
	if provider == "github" || provider == "okta" {
		return true
	}
	if !connectorProviderPattern.MatchString(provider) {
		return false
	}
	key := strings.TrimPrefix(provider, "nango:")
	return !stringIn(key, "aws", "kubernetes", "github", "okta")
}

func validConnectorProvider(provider string) bool {
	return stringIn(provider, "aws", "kubernetes", "github", "okta") || validOAuthProvider(provider)
}

func validConnectorScopes(scopes []string) bool {
	if len(scopes) < 1 || len(scopes) > 32 || !sort.StringsAreSorted(scopes) {
		return false
	}
	for index, scope := range scopes {
		if !connectorScopePattern.MatchString(scope) || index > 0 && scope == scopes[index-1] {
			return false
		}
	}
	return true
}

func validConnectorMetadata(value json.RawMessage) bool {
	if len(value) < 2 || len(value) > 16384 || !json.Valid(value) {
		return false
	}
	var object map[string]any
	if decodeStrictDiscovery(value, &object) != nil || object == nil {
		return false
	}
	for key := range object {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "access_token") || strings.Contains(lower, "refresh_token") || strings.Contains(lower, "private_key") || strings.Contains(lower, "pkce_verifier") || strings.Contains(lower, "authorization_code") {
			return false
		}
	}
	return true
}
