package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

const (
	postgresIdentityProviderOrganizationSQL = `SELECT to_jsonb(zasp_identity_admin_provider_organization($1,$2))`
	postgresIdentityReserveMutationSQL      = `SELECT zasp_identity_admin_reserve_mutation($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)`
	postgresIdentityMarkUnknownSQL          = `SELECT zasp_identity_admin_mark_unknown($1,$2,$3,$4,$5,$6)`
	postgresIdentityCompleteMutationSQL     = `SELECT zasp_identity_admin_complete_mutation($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)`
	postgresIdentityConnectionPageSQL       = `SELECT zasp_identity_admin_connection_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresIdentityRevealSecretSQL         = `SELECT zasp_identity_admin_reveal_secret($1,$2,$3)`
	postgresIdentityAcknowledgeSecretSQL    = `SELECT zasp_identity_admin_ack_secret($1,$2,$3)`
)

type identityProviderMutation struct {
	Operation, IdempotencyKey, MutationID, AuditID, CorrelationID, ReceiptID string
	Intent                                                                   json.RawMessage
	OwnerToken                                                               []byte
	LeaseSeconds                                                             int
}

type identityProviderCompletion struct {
	identityProviderMutation
	Connection                           json.RawMessage
	GrantID                              string
	Ciphertext, Nonce, AuthenticationTag []byte
	GrantExpiresAt                       time.Time
}

type identityMutationReservation struct {
	MutationID                    string          `json:"mutation_id"`
	State                         string          `json:"state"`
	ProviderOrganizationReference string          `json:"provider_organization_reference"`
	Version                       int64           `json:"version"`
	AuditID                       string          `json:"audit_id"`
	CorrelationID                 string          `json:"correlation_id"`
	ReceiptID                     string          `json:"receipt_id"`
	Replayed                      bool            `json:"replayed"`
	Body                          json.RawMessage `json:"body"`
	SecretGrantID                 *string         `json:"secret_grant_id"`
}

func (repository *PostgresRepository) identityProviderOrganization(ctx context.Context, identity RequestIdentity) (string, error) {
	if repository == nil || repository.schema != IdentityAdministrationSchemaVersion || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession {
		return "", ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresIdentityProviderOrganizationSQL, identity.Scope.OrganizationID().String(), identity.PrincipalID.String())
	if err != nil {
		return "", discoveryProviderError(err)
	}
	var reference string
	if json.Unmarshal(payload, &reference) != nil || !validStytchReference(reference, "organization-") {
		return "", ErrRepositoryNotFound
	}
	return reference, nil
}

func (repository *PostgresRepository) reserveIdentityProviderMutation(ctx context.Context, identity RequestIdentity, mutation identityProviderMutation) (identityMutationReservation, json.RawMessage, error) {
	if repository == nil || repository.schema != IdentityAdministrationSchemaVersion || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || !validIdentityProviderMutation(mutation) {
		return identityMutationReservation{}, nil, ErrRepositoryOperation
	}
	digest := sha256.Sum256(mutation.Intent)
	payload, err := repository.database.QueryJSON(ctx, postgresIdentityReserveMutationSQL,
		identity.Scope.OrganizationID().String(), identity.PrincipalID.String(), mutation.Operation, mutation.IdempotencyKey, mutation.MutationID, digest[:], mutation.Intent, mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID, mutation.OwnerToken, mutation.LeaseSeconds)
	if err != nil {
		return identityMutationReservation{}, nil, discoveryProviderError(err)
	}
	var reservation identityMutationReservation
	if decodeStrictIdentityAdministration(payload, &reservation) != nil || !validProductID(reservation.AuditID) || !validProductID(reservation.CorrelationID) || !validProductID(reservation.ReceiptID) || reservation.Replayed && reservation.State == "" && len(reservation.Body) == 0 {
		return identityMutationReservation{}, nil, ErrRepositoryUnavailable
	}
	if len(reservation.Body) == 0 && (!validProductID(reservation.MutationID) || !stringIn(reservation.State, "reserved", "provider_unknown") || reservation.Version < 1 || !validStytchReference(reservation.ProviderOrganizationReference, "organization-")) {
		return identityMutationReservation{}, nil, ErrRepositoryUnavailable
	}
	if !reservation.Replayed && (reservation.MutationID != mutation.MutationID || reservation.AuditID != mutation.AuditID || reservation.CorrelationID != mutation.CorrelationID || reservation.ReceiptID != mutation.ReceiptID) {
		return identityMutationReservation{}, nil, ErrRepositoryUnavailable
	}
	return reservation, payload, nil
}

func (repository *PostgresRepository) markIdentityProviderMutationUnknown(ctx context.Context, identity RequestIdentity, mutation identityProviderMutation) error {
	if repository == nil || repository.schema != IdentityAdministrationSchemaVersion || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || !validIdentityProviderMutation(mutation) {
		return ErrRepositoryOperation
	}
	_, err := repository.database.QueryJSON(ctx, postgresIdentityMarkUnknownSQL, identity.Scope.OrganizationID().String(), identity.PrincipalID.String(), mutation.Operation, mutation.IdempotencyKey, mutation.MutationID, mutation.OwnerToken)
	return discoveryProviderError(err)
}

func (repository *PostgresRepository) completeIdentityProviderMutation(ctx context.Context, identity RequestIdentity, completion identityProviderCompletion) (json.RawMessage, error) {
	if repository == nil || repository.schema != IdentityAdministrationSchemaVersion || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || !validIdentityProviderMutation(completion.identityProviderMutation) || !json.Valid(completion.Connection) {
		return nil, ErrRepositoryOperation
	}
	var grant any
	var expires any
	if completion.GrantID != "" {
		if !validProductID(completion.GrantID) || len(completion.Ciphertext) < 1 || len(completion.Ciphertext) > 8192 || len(completion.Nonce) != 12 || len(completion.AuthenticationTag) != 16 || completion.GrantExpiresAt.IsZero() || completion.GrantExpiresAt.Location() != time.UTC {
			return nil, ErrRepositoryOperation
		}
		grant, expires = completion.GrantID, completion.GrantExpiresAt
	}
	payload, err := repository.database.QueryJSON(ctx, postgresIdentityCompleteMutationSQL,
		identity.Scope.OrganizationID().String(), identity.PrincipalID.String(), completion.Operation, completion.IdempotencyKey, completion.MutationID, completion.OwnerToken, completion.Connection,
		grant, nullableIdentityBytes(completion.Ciphertext), nullableIdentityBytes(completion.Nonce), nullableIdentityBytes(completion.AuthenticationTag), expires)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	if !json.Valid(payload) {
		return nil, ErrRepositoryUnavailable
	}
	return payload, nil
}

func (repository *PostgresRepository) revealIdentityProviderSecret(ctx context.Context, identity RequestIdentity, grantID string) (json.RawMessage, error) {
	if repository == nil || repository.schema != IdentityAdministrationSchemaVersion || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || !validProductID(grantID) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresIdentityRevealSecretSQL, identity.Scope.OrganizationID().String(), identity.PrincipalID.String(), grantID)
	if err != nil || !json.Valid(payload) || string(payload) == "null" {
		return nil, ErrRepositoryNotFound
	}
	return payload, nil
}

func (repository *PostgresRepository) acknowledgeIdentityProviderSecret(ctx context.Context, identity RequestIdentity, grantID string) error {
	if repository == nil || repository.schema != IdentityAdministrationSchemaVersion || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || !validProductID(grantID) {
		return ErrRepositoryOperation
	}
	_, err := repository.database.QueryJSON(ctx, postgresIdentityAcknowledgeSecretSQL, identity.Scope.OrganizationID().String(), identity.PrincipalID.String(), grantID)
	return discoveryProviderError(err)
}

func validIdentityProviderMutation(mutation identityProviderMutation) bool {
	return stringIn(mutation.Operation, "createSSOConnection", "deleteSSOConnection", "testSSOConnection", "createSCIMConnection", "deleteSCIMConnection") &&
		validAdministrationIdempotencyKey(mutation.IdempotencyKey) && validProductID(mutation.MutationID) && validProductID(mutation.AuditID) && validProductID(mutation.CorrelationID) && validProductID(mutation.ReceiptID) &&
		mutation.AuditID != mutation.CorrelationID && mutation.AuditID != mutation.ReceiptID && mutation.CorrelationID != mutation.ReceiptID && json.Valid(mutation.Intent) && len(mutation.Intent) <= 4096 &&
		len(mutation.OwnerToken) == 32 && mutation.LeaseSeconds >= 5 && mutation.LeaseSeconds <= 120
}

func decodeStrictIdentityAdministration(payload json.RawMessage, target any) error {
	return decodeStrictDiscovery(payload, target)
}

func nullableIdentityBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
