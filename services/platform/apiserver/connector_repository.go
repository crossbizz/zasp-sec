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
	postgresConnectorReadySQL               = `SELECT to_jsonb(zasp_connector_readiness($1,$2))`
	postgresConnectorStartOAuthSQL          = `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`
	postgresConnectorConsumeOAuthSQL        = `SELECT zasp_connector_consume_oauth($1,$2,$3,$4,$5,$6)`
	postgresConnectorBeginEffectSQL         = `SELECT zasp_connector_begin_effect($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresConnectorResolveEffectSQL       = `SELECT zasp_connector_resolve_effect($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`
	postgresConnectorPutCredentialSQL       = `SELECT zasp_connector_put_credential($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`
	postgresConnectorCompleteOAuthSQL       = `SELECT zasp_connector_complete_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`
	postgresConnectorClaimReconciliationSQL = `SELECT zasp_connector_claim_reconciliation($1,$2,$3)`
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
	ClaimReconciliation(context.Context, string, int, int) ([]ConnectorEffectLease, error)
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
	payload, err := repository.database.QueryJSON(ctx, postgresConnectorStartOAuthSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.AttemptID, input.IntegrationID, input.Provider, identity.PrincipalID.String(), input.SessionDigest, input.StateDigest, input.PKCEVerifierReference, input.RequestDigest, string(scopes), input.ExpiresAt)
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
	canonicalMetadata, _ := canonicalConnectorMetadata(input.Metadata)
	digest := sha256.Sum256([]byte(strings.Join([]string{input.AttemptID, input.EffectID, input.ConnectionID, input.ConnectionReference, input.ProviderSubject, input.CredentialID, input.CredentialClass, string(canonicalMetadata)}, "\x1f")))
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
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	ID             string    `json:"id"`
	IntegrationID  string    `json:"integration_id"`
	Provider       string    `json:"provider"`
	Operation      string    `json:"operation"`
	IdempotencyKey string    `json:"idempotency_key"`
	RequestDigest  string    `json:"request_digest"`
	Attempt        int       `json:"attempt"`
	LeaseOwner     string    `json:"lease_owner"`
	LeaseToken     string    `json:"lease_token"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
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
		if digestErr != nil || len(digest) != 32 || !validProductID(item.OrganizationID) || !validProductID(item.WorkspaceID) || !validProductID(item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.IntegrationID) || !validConnectorProvider(item.Provider) || !stringIn(item.Operation, "authorize", "bind", "test", "rotate", "revoke", "nango_connect") || len(item.IdempotencyKey) < 16 || len(item.IdempotencyKey) > 128 || item.Attempt < 1 || item.Attempt > 100 || item.LeaseOwner != owner || len(item.LeaseToken) != 64 || !item.LeaseExpiresAt.After(now) || item.LeaseExpiresAt.After(now.Add(time.Duration(leaseSeconds)*time.Second+time.Second)) {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return page.Items, nil
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
	return validProductID(input.AttemptID) && validProductID(input.IntegrationID) && validOAuthProvider(input.Provider) && len(input.SessionDigest) == 32 && len(input.StateDigest) == 32 && validOpaqueReference(input.PKCEVerifierReference) && len(input.RequestDigest) == 32 && validConnectorScopes(input.RequestedScopes) && input.ExpiresAt.After(time.Now()) && !input.ExpiresAt.After(time.Now().Add(10*time.Minute))
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
