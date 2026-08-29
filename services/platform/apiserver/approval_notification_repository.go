package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresApprovalNotificationClaimSQL          = `SELECT zasp_security_agent_claim_approval_notification($1,$2,$3)`
	postgresApprovalNotificationCompleteSQL       = `SELECT zasp_security_agent_complete_approval_notification($1,$2,$3,$4,$5,$6)`
	postgresApprovalNotificationFailSQL           = `SELECT zasp_security_agent_fail_approval_notification($1,$2,$3,$4,$5,$6)`
	postgresApprovalNotificationAuthorityReadySQL = `SELECT jsonb_build_object('release',zasp_production_approval_notification_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
)

func NewApprovalNotificationPostgresRepository(database JSONDatabase) (*PostgresRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	repository := &PostgresRepository{database: database, schema: ProductionApprovalNotificationSchemaVersion, securityAgentExecution: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if repository.ReadyApprovalNotifications(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *PostgresRepository) ReadyApprovalNotifications(ctx context.Context) error {
	if !validApprovalNotificationRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	metadata := migrations.ProductionApprovalNotification()
	payload, err := repository.database.QueryJSON(ctx, postgresApprovalNotificationAuthorityReadySQL, metadata.Checksum(), migrations.ProductionApprovalNotificationSemanticFingerprint())
	if err != nil {
		return ErrRepositoryUnavailable
	}
	var ready struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if !exactJSONFields(payload, "principal", "release") || decodeStrictDiscovery(payload, &ready) != nil || !ready.Release || !ready.Principal {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *PostgresRepository) ClaimApprovalNotification(ctx context.Context, owner, leaseToken string, leaseSeconds int) (ApprovalNotificationLease, error) {
	if !validApprovalNotificationRepository(repository, ctx) || len(owner) < 3 || len(owner) > 128 || strings.TrimSpace(owner) != owner || strings.ContainsAny(owner, "\x00\r\n") || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || leaseSeconds < 15 || leaseSeconds > 60 {
		return ApprovalNotificationLease{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresApprovalNotificationClaimSQL, owner, leaseToken, leaseSeconds)
	if err != nil {
		return ApprovalNotificationLease{}, discoveryProviderError(err)
	}
	var wire struct {
		Found           bool      `json:"found"`
		OrganizationID  string    `json:"organization_id"`
		WorkspaceID     string    `json:"workspace_id"`
		EnvironmentID   string    `json:"environment_id"`
		DeliveryID      string    `json:"delivery_id"`
		ApprovalID      string    `json:"approval_id"`
		RunID           string    `json:"run_id"`
		Payload         string    `json:"payload"`
		PayloadDigest   string    `json:"payload_digest"`
		DestinationURL  string    `json:"destination_url"`
		SecretReference string    `json:"secret_reference"`
		LeaseToken      string    `json:"lease_token"`
		LeaseExpiresAt  time.Time `json:"lease_expires_at"`
		Attempt         int       `json:"attempt"`
	}
	if decodeStrictDiscovery(payload, &wire) != nil {
		return ApprovalNotificationLease{}, ErrRepositoryUnavailable
	}
	if !wire.Found {
		if !exactJSONFields(payload, "found") {
			return ApprovalNotificationLease{}, ErrRepositoryUnavailable
		}
		return ApprovalNotificationLease{}, nil
	}
	if !exactJSONFields(payload, "approval_id", "attempt", "delivery_id", "destination_url", "environment_id", "found", "lease_expires_at", "lease_token", "organization_id", "payload", "payload_digest", "run_id", "secret_reference", "workspace_id") {
		return ApprovalNotificationLease{}, ErrRepositoryUnavailable
	}
	organization, organizationErr := domain.ParseProductID(wire.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(wire.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(wire.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	lease := ApprovalNotificationLease{Scope: scope, DeliveryID: wire.DeliveryID, ApprovalID: wire.ApprovalID, RunID: wire.RunID, Payload: wire.Payload, PayloadDigest: wire.PayloadDigest, DestinationURL: wire.DestinationURL, SecretReference: wire.SecretReference, LeaseToken: wire.LeaseToken, LeaseExpiresAt: wire.LeaseExpiresAt.UTC(), Attempt: wire.Attempt}
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || !validApprovalNotificationLease(lease, leaseToken, leaseSeconds) {
		return ApprovalNotificationLease{}, ErrRepositoryUnavailable
	}
	return lease, nil
}

func (repository *PostgresRepository) CompleteApprovalNotification(ctx context.Context, scope domain.Scope, deliveryID, leaseToken, payloadDigest string) error {
	return repository.transitionApprovalNotification(ctx, postgresApprovalNotificationCompleteSQL, "delivered", scope, deliveryID, leaseToken, payloadDigest)
}

func (repository *PostgresRepository) FailApprovalNotification(ctx context.Context, scope domain.Scope, deliveryID, leaseToken, payloadDigest string) error {
	return repository.transitionApprovalNotification(ctx, postgresApprovalNotificationFailSQL, "retryable|exhausted", scope, deliveryID, leaseToken, payloadDigest)
}

func (repository *PostgresRepository) transitionApprovalNotification(ctx context.Context, statement, expected string, scope domain.Scope, deliveryID, leaseToken, payloadDigest string) error {
	if !validApprovalNotificationRepository(repository, ctx) || scope.Validate() != nil || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || !findingTicketDigestPattern.MatchString(payloadDigest) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, statement, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deliveryID, leaseToken, payloadDigest)
	if err != nil {
		return discoveryProviderError(err)
	}
	var response struct {
		Transition string `json:"transition"`
	}
	if !exactJSONFields(payload, "transition") || json.Unmarshal(payload, &response) != nil || !stringIn(response.Transition, strings.Split(expected, "|")...) {
		return ErrRepositoryUnavailable
	}
	return nil
}

func validApprovalNotificationRepository(repository *PostgresRepository, ctx context.Context) bool {
	return repository != nil && repository.schema == ProductionApprovalNotificationSchemaVersion && repository.securityAgentExecution && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

var _ ApprovalNotificationRepository = (*PostgresRepository)(nil)
