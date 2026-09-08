package apiserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresIntegrationWebhookTestReserveSQL  = `SELECT zasp_integration_webhook_test_reserve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	postgresIntegrationWebhookTestCompleteSQL = `SELECT zasp_integration_webhook_test_complete($1,$2,$3,$4,$5,$6,$7)`
	postgresIntegrationWebhookTestStatusSQL   = `SELECT zasp_integration_webhook_test_status($1,$2,$3,$4)`
)

type IntegrationWebhookTestCommand struct {
	Identity        RequestIdentity
	IntegrationID   string
	ExpectedVersion int64
	IdempotencyKey  string
	AuditID         string
	CorrelationID   string
}

type IntegrationWebhookTestStatus struct {
	IntegrationID   string     `json:"integration_id"`
	DeliveryID      string     `json:"delivery_id"`
	DeliveryStatus  string     `json:"delivery_status"`
	SignatureStatus string     `json:"signature_status"`
	AttemptedAt     time.Time  `json:"attempted_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	ErrorCode       string     `json:"error_code"`
	AuditID         string     `json:"audit_id"`
}

type IntegrationWebhookTestReservation struct {
	State           string
	DeliveryID      string
	Payload         string
	PayloadDigest   string
	DestinationURL  string
	SecretReference string
	LeaseExpiresAt  time.Time
	Status          IntegrationWebhookTestStatus
}

type integrationWebhookTestRepository interface {
	ReserveIntegrationWebhookTest(context.Context, IntegrationWebhookTestCommand, string, string, int) (IntegrationWebhookTestReservation, error)
	CompleteIntegrationWebhookTest(context.Context, domain.Scope, string, string, string, bool) (IntegrationWebhookTestStatus, error)
	GetIntegrationWebhookTestStatus(context.Context, domain.Scope, string) (IntegrationWebhookTestStatus, error)
}

type IntegrationWebhookTestWebhook interface {
	DeliverIntegrationWebhookTest(context.Context, string, string, string, string, []byte) error
}

type IntegrationWebhookTester interface {
	TestIntegrationWebhook(context.Context, IntegrationWebhookTestCommand) (IntegrationWebhookTestStatus, error)
	GetIntegrationWebhookTestStatus(context.Context, domain.Scope, string) (IntegrationWebhookTestStatus, error)
}

type IntegrationWebhookTestServiceConfig struct {
	Repository    integrationWebhookTestRepository
	Secrets       FindingTicketSecretResolver
	Webhook       IntegrationWebhookTestWebhook
	LeaseSeconds  int
	NewDeliveryID func(domain.Scope, string) (string, error)
	NewLeaseToken func() (string, error)
}

type integrationWebhookTestService struct {
	repository    integrationWebhookTestRepository
	secrets       FindingTicketSecretResolver
	webhook       IntegrationWebhookTestWebhook
	leaseSeconds  int
	newDeliveryID func(domain.Scope, string) (string, error)
	newLeaseToken func() (string, error)
}

func (repository *PostgresRepository) ReserveIntegrationWebhookTest(ctx context.Context, command IntegrationWebhookTestCommand, deliveryID, leaseToken string, leaseSeconds int) (IntegrationWebhookTestReservation, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validIntegrationWebhookTestCommand(command) || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || leaseSeconds < 5 || leaseSeconds > 30 {
		return IntegrationWebhookTestReservation{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresIntegrationWebhookTestReserveSQL,
		command.Identity.Scope.OrganizationID().String(), command.Identity.Scope.WorkspaceID().String(), command.Identity.Scope.EnvironmentID().String(), command.Identity.PrincipalID.String(), command.IntegrationID, command.ExpectedVersion, command.IdempotencyKey, command.AuditID, command.CorrelationID, deliveryID, leaseToken, leaseSeconds,
	)
	if err != nil {
		return IntegrationWebhookTestReservation{}, riskProviderError(err)
	}
	var response struct {
		State           string                       `json:"state"`
		DeliveryID      string                       `json:"delivery_id"`
		Payload         string                       `json:"payload"`
		PayloadDigest   string                       `json:"payload_digest"`
		DestinationURL  string                       `json:"destination_url"`
		SecretReference string                       `json:"secret_reference"`
		LeaseExpiresAt  *time.Time                   `json:"lease_expires_at"`
		Status          IntegrationWebhookTestStatus `json:"status"`
	}
	if decodeStrictRisk(payload, &response) != nil || !validProductID(response.DeliveryID) {
		return IntegrationWebhookTestReservation{}, ErrRepositoryUnavailable
	}
	result := IntegrationWebhookTestReservation{State: response.State, DeliveryID: response.DeliveryID}
	switch response.State {
	case "dispatch":
		if response.LeaseExpiresAt == nil || !validLeaseExpiration(*response.LeaseExpiresAt, leaseSeconds) || !validIntegrationWebhookTestPayload(response.Payload, response.PayloadDigest, command, response.DeliveryID) || !validIntegrationWebhookDestination(response.DestinationURL) || !validIntegrationWebhookSecretReference(response.SecretReference) || response.Status.IntegrationID != "" {
			return IntegrationWebhookTestReservation{}, ErrRepositoryUnavailable
		}
		result.Payload, result.PayloadDigest, result.DestinationURL, result.SecretReference, result.LeaseExpiresAt = response.Payload, response.PayloadDigest, response.DestinationURL, response.SecretReference, response.LeaseExpiresAt.UTC()
	case "busy":
		if response.LeaseExpiresAt == nil || !validLeaseExpiration(*response.LeaseExpiresAt, leaseSeconds) || response.Payload != "" || response.PayloadDigest != "" || response.DestinationURL != "" || response.SecretReference != "" || response.Status.IntegrationID != "" {
			return IntegrationWebhookTestReservation{}, ErrRepositoryUnavailable
		}
		result.LeaseExpiresAt = response.LeaseExpiresAt.UTC()
	case "succeeded", "failed":
		if response.LeaseExpiresAt != nil || response.Payload != "" || response.PayloadDigest != "" || response.DestinationURL != "" || response.SecretReference != "" || !validIntegrationWebhookTestStatus(response.Status, command.IntegrationID) || response.Status.DeliveryID != response.DeliveryID || response.Status.DeliveryStatus != response.State {
			return IntegrationWebhookTestReservation{}, ErrRepositoryUnavailable
		}
		result.Status = response.Status
	default:
		return IntegrationWebhookTestReservation{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) CompleteIntegrationWebhookTest(ctx context.Context, scope domain.Scope, deliveryID, leaseToken, payloadDigest string, succeeded bool) (IntegrationWebhookTestStatus, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) || !findingTicketDigestPattern.MatchString(payloadDigest) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresIntegrationWebhookTestCompleteSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deliveryID, leaseToken, payloadDigest, succeeded)
	if err != nil {
		return IntegrationWebhookTestStatus{}, riskProviderError(err)
	}
	var result IntegrationWebhookTestStatus
	if decodeStrictRisk(payload, &result) != nil || !validIntegrationWebhookTestStatus(result, result.IntegrationID) || result.DeliveryID != deliveryID || result.DeliveryStatus != map[bool]string{true: "succeeded", false: "failed"}[succeeded] {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) GetIntegrationWebhookTestStatus(ctx context.Context, scope domain.Scope, integrationID string) (IntegrationWebhookTestStatus, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(integrationID) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresIntegrationWebhookTestStatusSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID)
	if err != nil {
		return IntegrationWebhookTestStatus{}, riskProviderError(err)
	}
	var result IntegrationWebhookTestStatus
	if decodeStrictRisk(payload, &result) != nil || !validIntegrationWebhookTestStatus(result, integrationID) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func NewIntegrationWebhookTestService(config IntegrationWebhookTestServiceConfig) (IntegrationWebhookTester, error) {
	if nilInterface(config.Repository) || nilInterface(config.Secrets) || nilInterface(config.Webhook) || config.LeaseSeconds < 5 || config.LeaseSeconds > 30 || config.NewDeliveryID == nil || config.NewLeaseToken == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &integrationWebhookTestService{repository: config.Repository, secrets: config.Secrets, webhook: config.Webhook, leaseSeconds: config.LeaseSeconds, newDeliveryID: config.NewDeliveryID, newLeaseToken: config.NewLeaseToken}, nil
}

func (service *integrationWebhookTestService) TestIntegrationWebhook(ctx context.Context, command IntegrationWebhookTestCommand) (IntegrationWebhookTestStatus, error) {
	if service == nil || ctx == nil || ctx.Err() != nil || !validIntegrationWebhookTestCommand(command) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryOperation
	}
	deliveryID, deliveryErr := service.newDeliveryID(command.Identity.Scope, command.IntegrationID)
	leaseToken, leaseErr := service.newLeaseToken()
	if deliveryErr != nil || leaseErr != nil || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	reservation, err := service.repository.ReserveIntegrationWebhookTest(ctx, command, deliveryID, leaseToken, service.leaseSeconds)
	if err != nil {
		return IntegrationWebhookTestStatus{}, err
	}
	switch reservation.State {
	case "succeeded", "failed":
		if !validIntegrationWebhookTestStatus(reservation.Status, command.IntegrationID) || reservation.Status.DeliveryStatus != reservation.State || reservation.Status.DeliveryID != reservation.DeliveryID {
			return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
		}
		return reservation.Status, nil
	case "busy":
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	case "dispatch":
	default:
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	if !validProductID(reservation.DeliveryID) || !validIntegrationWebhookTestPayload(reservation.Payload, reservation.PayloadDigest, command, reservation.DeliveryID) || !validIntegrationWebhookDestination(reservation.DestinationURL) || !validIntegrationWebhookSecretReference(reservation.SecretReference) || !validLeaseExpiration(reservation.LeaseExpiresAt, service.leaseSeconds) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	deadline := reservation.LeaseExpiresAt.Add(-100 * time.Millisecond)
	if !deadline.After(time.Now()) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	providerDeadline := deadline.Add(-2 * time.Second)
	if !providerDeadline.After(time.Now()) {
		providerDeadline = time.Now().Add(time.Until(deadline) / 2)
	}
	providerContext, cancelProvider := context.WithDeadline(ctx, providerDeadline)
	defer cancelProvider()
	finalizationContext, cancelFinalization := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancelFinalization()
	secret, secretErr := service.secrets.ResolveFindingTicketSecret(providerContext, reservation.SecretReference)
	succeeded := secretErr == nil && len(secret) >= 32 && len(secret) <= 4096
	if succeeded {
		succeeded = deliverIntegrationWebhookTestSafely(service.webhook, providerContext, reservation, secret) == nil
	}
	clear(secret)
	status, err := service.repository.CompleteIntegrationWebhookTest(finalizationContext, command.Identity.Scope, reservation.DeliveryID, leaseToken, reservation.PayloadDigest, succeeded)
	if err != nil || !validIntegrationWebhookTestStatus(status, command.IntegrationID) || status.DeliveryID != reservation.DeliveryID || status.DeliveryStatus != map[bool]string{true: "succeeded", false: "failed"}[succeeded] {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	return status, nil
}

func (service *integrationWebhookTestService) GetIntegrationWebhookTestStatus(ctx context.Context, scope domain.Scope, integrationID string) (IntegrationWebhookTestStatus, error) {
	if service == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validProductID(integrationID) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryOperation
	}
	status, err := service.repository.GetIntegrationWebhookTestStatus(ctx, scope, integrationID)
	if err != nil {
		return IntegrationWebhookTestStatus{}, err
	}
	if !validIntegrationWebhookTestStatus(status, integrationID) {
		return IntegrationWebhookTestStatus{}, ErrRepositoryUnavailable
	}
	return status, nil
}

func deliverIntegrationWebhookTestSafely(webhook IntegrationWebhookTestWebhook, ctx context.Context, reservation IntegrationWebhookTestReservation, secret []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrRepositoryUnavailable
		}
	}()
	return webhook.DeliverIntegrationWebhookTest(ctx, reservation.DestinationURL, reservation.Payload, reservation.PayloadDigest, reservation.DeliveryID, secret)
}

func validIntegrationWebhookTestCommand(command IntegrationWebhookTestCommand) bool {
	return validRequestIdentity(command.Identity, false) && validProductID(command.IntegrationID) && command.ExpectedVersion >= 1 && command.ExpectedVersion <= 1_000_000 && validPublicIdempotency(command.IdempotencyKey) && validProductID(command.AuditID) && validProductID(command.CorrelationID) && command.AuditID != command.CorrelationID
}

func validIntegrationWebhookDestination(raw string) bool {
	if strings.ContainsAny(raw, "?#\r\n\t ") || strings.Contains(raw, "..") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return validFindingTicketDestination(parsed.String())
}

func validIntegrationWebhookSecretReference(reference string) bool {
	return findingTicketReferencePattern.MatchString(reference) && !strings.Contains(reference, "..") && !strings.Contains(reference, "//")
}

func validIntegrationWebhookTestStatus(status IntegrationWebhookTestStatus, integrationID string) bool {
	if status.IntegrationID != integrationID || !validProductID(status.IntegrationID) || !validProductID(status.DeliveryID) || !validProductID(status.AuditID) || status.AttemptedAt.IsZero() || status.AttemptedAt.Location() != time.UTC {
		return false
	}
	if status.DeliveryStatus == "pending" {
		return status.SignatureStatus == "unconfirmed" && status.CompletedAt == nil && status.ErrorCode == ""
	}
	if status.CompletedAt == nil || status.CompletedAt.IsZero() || status.CompletedAt.Location() != time.UTC || status.CompletedAt.Before(status.AttemptedAt) {
		return false
	}
	return status.DeliveryStatus == "succeeded" && status.SignatureStatus == "signed" && status.ErrorCode == "" || status.DeliveryStatus == "failed" && status.SignatureStatus == "unconfirmed" && status.ErrorCode == "delivery_failed"
}

func validIntegrationWebhookTestPayload(payload, encodedDigest string, command IntegrationWebhookTestCommand, deliveryID string) bool {
	if len(payload) < 2 || len(payload) > 16<<10 || !findingTicketDigestPattern.MatchString(encodedDigest) {
		return false
	}
	decodedDigest, err := hex.DecodeString(strings.TrimPrefix(encodedDigest, "sha256:"))
	if err != nil || len(decodedDigest) != sha256.Size {
		return false
	}
	actualDigest := sha256.Sum256([]byte(payload))
	if subtle.ConstantTimeCompare(actualDigest[:], decodedDigest) != 1 {
		return false
	}
	var body struct {
		DeliveryID  string `json:"delivery_id"`
		Event       string `json:"event"`
		Integration struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
		} `json:"integration"`
		Scope struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
		} `json:"scope"`
		SentAt  time.Time `json:"sent_at"`
		Version int       `json:"version"`
	}
	return decodeStrictRisk([]byte(payload), &body) == nil && body.DeliveryID == deliveryID && body.Event == "integration.webhook.test" && body.Integration.ID == command.IntegrationID && body.Integration.Version == command.ExpectedVersion && body.Scope.OrganizationID == command.Identity.Scope.OrganizationID().String() && body.Scope.WorkspaceID == command.Identity.Scope.WorkspaceID().String() && body.Scope.EnvironmentID == command.Identity.Scope.EnvironmentID().String() && body.SentAt.Location() == time.UTC && !body.SentAt.IsZero() && body.Version == 1
}

var _ IntegrationWebhookTester = (*integrationWebhookTestService)(nil)
