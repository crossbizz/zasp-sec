package apiserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ApprovalNotificationLease struct {
	Scope           domain.Scope
	DeliveryID      string
	ApprovalID      string
	RunID           string
	Payload         string
	PayloadDigest   string
	DestinationURL  string
	SecretReference string
	LeaseToken      string
	LeaseExpiresAt  time.Time
	Attempt         int
}

type ApprovalNotificationRepository interface {
	ClaimApprovalNotification(context.Context, string, string, int) (ApprovalNotificationLease, error)
	CompleteApprovalNotification(context.Context, domain.Scope, string, string, string) error
	FailApprovalNotification(context.Context, domain.Scope, string, string, string) error
}

type ApprovalNotificationWebhook interface {
	DeliverApprovalNotification(context.Context, string, string, string, string, []byte) error
}

type ApprovalNotificationReconcilerConfig struct {
	Repository    ApprovalNotificationRepository
	Secrets       FindingTicketSecretResolver
	Webhook       ApprovalNotificationWebhook
	Owner         string
	LeaseSeconds  int
	Interval      time.Duration
	NewLeaseToken func() (string, error)
}

type ApprovalNotificationReconciler struct {
	repository    ApprovalNotificationRepository
	secrets       FindingTicketSecretResolver
	webhook       ApprovalNotificationWebhook
	owner         string
	leaseSeconds  int
	interval      time.Duration
	newLeaseToken func() (string, error)
	ready         atomic.Bool
}

func NewApprovalNotificationReconciler(config ApprovalNotificationReconcilerConfig) (*ApprovalNotificationReconciler, error) {
	if nilInterface(config.Repository) || nilInterface(config.Secrets) || nilInterface(config.Webhook) || len(config.Owner) < 3 || len(config.Owner) > 128 || strings.TrimSpace(config.Owner) != config.Owner || strings.ContainsAny(config.Owner, "\x00\r\n") || config.LeaseSeconds < 15 || config.LeaseSeconds > 60 || config.NewLeaseToken == nil {
		return nil, ErrRepositoryConfiguration
	}
	interval := config.Interval
	if interval == 0 {
		interval = time.Second
	}
	if interval < 10*time.Millisecond || interval > time.Minute {
		return nil, ErrRepositoryConfiguration
	}
	return &ApprovalNotificationReconciler{repository: config.Repository, secrets: config.Secrets, webhook: config.Webhook, owner: config.Owner, leaseSeconds: config.LeaseSeconds, interval: interval, newLeaseToken: config.NewLeaseToken}, nil
}

func (reconciler *ApprovalNotificationReconciler) Ready() bool {
	return reconciler != nil && reconciler.ready.Load()
}

func (reconciler *ApprovalNotificationReconciler) Run(ctx context.Context) error {
	if reconciler == nil || ctx == nil {
		return ErrRepositoryConfiguration
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			err := reconciler.ReconcileOnce(ctx)
			delay := reconciler.interval
			if err != nil {
				delay = 5 * reconciler.interval
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
			timer.Reset(delay)
		}
	}
}

func (reconciler *ApprovalNotificationReconciler) ReconcileOnce(ctx context.Context) error {
	if reconciler == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	token, err := reconciler.newLeaseToken()
	if err != nil || !findingTicketLeaseTokenPattern.MatchString(token) {
		reconciler.ready.Store(false)
		return ErrRepositoryUnavailable
	}
	lease, err := reconciler.repository.ClaimApprovalNotification(ctx, reconciler.owner, token, reconciler.leaseSeconds)
	if err != nil {
		reconciler.ready.Store(false)
		return ErrRepositoryUnavailable
	}
	if lease.DeliveryID == "" {
		if !emptyApprovalNotificationLease(lease) {
			reconciler.ready.Store(false)
			return ErrRepositoryUnavailable
		}
		reconciler.ready.Store(true)
		return nil
	}
	if !validApprovalNotificationLease(lease, token, reconciler.leaseSeconds) {
		reconciler.ready.Store(false)
		return ErrRepositoryUnavailable
	}
	providerDeadline := lease.LeaseExpiresAt.Add(-2 * time.Second)
	if !providerDeadline.After(time.Now()) {
		reconciler.ready.Store(false)
		return ErrRepositoryUnavailable
	}
	providerContext, cancelProvider := context.WithDeadline(ctx, providerDeadline)
	defer cancelProvider()
	finalizationContext, cancelFinalization := context.WithDeadline(context.WithoutCancel(ctx), lease.LeaseExpiresAt.Add(-100*time.Millisecond))
	defer cancelFinalization()
	secret, err := reconciler.secrets.ResolveFindingTicketSecret(providerContext, lease.SecretReference)
	if err != nil || len(secret) < 32 || len(secret) > 4096 {
		clear(secret)
		return reconciler.finishFailedTenantDelivery(finalizationContext, lease)
	}
	defer clear(secret)
	if err := deliverApprovalNotificationSafely(reconciler.webhook, providerContext, lease, secret); err != nil {
		return reconciler.finishFailedTenantDelivery(finalizationContext, lease)
	}
	if err := reconciler.repository.CompleteApprovalNotification(finalizationContext, lease.Scope, lease.DeliveryID, lease.LeaseToken, lease.PayloadDigest); err != nil {
		reconciler.ready.Store(false)
		return ErrRepositoryUnavailable
	}
	reconciler.ready.Store(true)
	return nil
}

func (reconciler *ApprovalNotificationReconciler) finishFailedTenantDelivery(ctx context.Context, lease ApprovalNotificationLease) error {
	if err := reconciler.repository.FailApprovalNotification(ctx, lease.Scope, lease.DeliveryID, lease.LeaseToken, lease.PayloadDigest); err != nil {
		reconciler.ready.Store(false)
		return ErrRepositoryUnavailable
	}
	reconciler.ready.Store(true)
	return nil
}

func deliverApprovalNotificationSafely(webhook ApprovalNotificationWebhook, ctx context.Context, lease ApprovalNotificationLease, secret []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrRepositoryUnavailable
		}
	}()
	return webhook.DeliverApprovalNotification(ctx, lease.DestinationURL, lease.Payload, lease.PayloadDigest, lease.DeliveryID, secret)
}

func emptyApprovalNotificationLease(lease ApprovalNotificationLease) bool {
	return lease.Scope == (domain.Scope{}) && lease.ApprovalID == "" && lease.RunID == "" && lease.Payload == "" && lease.PayloadDigest == "" && lease.DestinationURL == "" && lease.SecretReference == "" && lease.LeaseToken == "" && lease.LeaseExpiresAt.IsZero() && lease.Attempt == 0
}

func validApprovalNotificationLease(lease ApprovalNotificationLease, token string, leaseSeconds int) bool {
	if lease.Scope.Validate() != nil || !validProductID(lease.DeliveryID) || !validProductID(lease.ApprovalID) || !validProductID(lease.RunID) || lease.LeaseToken != token || !findingTicketLeaseTokenPattern.MatchString(lease.LeaseToken) || lease.Attempt < 1 || lease.Attempt > 10 || len(lease.Payload) < 2 || len(lease.Payload) > 16<<10 || !findingTicketDigestPattern.MatchString(lease.PayloadDigest) || !validFindingTicketDestination(lease.DestinationURL) || !findingTicketReferencePattern.MatchString(lease.SecretReference) || !validLeaseExpiration(lease.LeaseExpiresAt, leaseSeconds) {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(lease.PayloadDigest, "sha256:"))
	actual := sha256.Sum256([]byte(lease.Payload))
	if err != nil || len(digest) != sha256.Size || subtle.ConstantTimeCompare(digest, actual[:]) != 1 {
		return false
	}
	var payload struct {
		DeliveryID string `json:"delivery_id"`
		Event      string `json:"event"`
		Version    int    `json:"version"`
		Scope      struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
		} `json:"scope"`
		Approval struct {
			ID    string `json:"id"`
			RunID string `json:"run_id"`
		} `json:"approval"`
	}
	raw := json.RawMessage(lease.Payload)
	return exactJSONFields(raw, "approval", "delivery_id", "event", "scope", "version") && decodeStrictRisk(raw, &payload) == nil && payload.DeliveryID == lease.DeliveryID && payload.Event == "security_agent.approval_required" && payload.Version == 1 && payload.Approval.ID == lease.ApprovalID && payload.Approval.RunID == lease.RunID && payload.Scope.OrganizationID == lease.Scope.OrganizationID().String() && payload.Scope.WorkspaceID == lease.Scope.WorkspaceID().String() && payload.Scope.EnvironmentID == lease.Scope.EnvironmentID().String()
}
