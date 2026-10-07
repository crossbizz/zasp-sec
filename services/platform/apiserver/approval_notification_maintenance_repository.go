package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This explicit constructor is guarded off until a real registered executor is
// supplied. It preserves the old constructor and never fabricates API identity.
type AuthorizedApprovalNotificationConfig struct {
	Native        *approvalmaintenance.Executor
	Secrets       FindingTicketSecretResolver
	Webhook       ApprovalNotificationWebhook
	Owner         string
	LeaseSeconds  int
	Interval      time.Duration
	NewLeaseToken func() (string, error)
}
type AuthorizedApprovalNotificationReconciler struct {
	cfg    AuthorizedApprovalNotificationConfig
	ready  atomic.Bool
	serial chan struct{}
}

func NewAuthorizedApprovalNotificationReconciler(ctx context.Context, c AuthorizedApprovalNotificationConfig) (*AuthorizedApprovalNotificationReconciler, error) {
	if ctx == nil || c.Native == nil || nilInterface(c.Secrets) || nilInterface(c.Webhook) || len(c.Owner) < 3 || len(c.Owner) > 128 || strings.TrimSpace(c.Owner) != c.Owner || strings.ContainsAny(c.Owner, "\x00\r\n") || c.LeaseSeconds < 15 || c.LeaseSeconds > 60 || c.NewLeaseToken == nil {
		return nil, ErrRepositoryConfiguration
	}
	if c.Interval == 0 {
		c.Interval = time.Second
	}
	if c.Interval < 10*time.Millisecond || c.Interval > time.Minute {
		return nil, ErrRepositoryConfiguration
	}
	if c.Native.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &AuthorizedApprovalNotificationReconciler{cfg: c, serial: make(chan struct{}, 1)}, nil
}
func (r *AuthorizedApprovalNotificationReconciler) Ready() bool { return r != nil && r.ready.Load() }
func (r *AuthorizedApprovalNotificationReconciler) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrRepositoryConfiguration
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			r.ready.Store(false)
			return ctx.Err()
		case <-timer.C:
			err := r.ReconcileOnce(ctx)
			delay := r.cfg.Interval
			if err != nil && !errors.Is(err, approvalmaintenance.ErrDenied) {
				delay *= 5
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
			timer.Reset(delay)
		}
	}
}
func (r *AuthorizedApprovalNotificationReconciler) ReconcileOnce(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	select {
	case r.serial <- struct{}{}:
		defer func() { <-r.serial }()
	case <-ctx.Done():
		return ErrRepositoryUnavailable
	}
	if ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	boundary := &authorizedApprovalBoundary{native: r.cfg.Native, secrets: r.cfg.Secrets, webhook: r.cfg.Webhook}
	defer func() { boundary.payload = approvalmaintenance.DeliveryPayload{}; boundary.reference = "" }()
	adapter := approvalmaintenance.NativeAdapter{Caller: r.cfg.Native, Owner: r.cfg.Owner, LeaseSeconds: r.cfg.LeaseSeconds, Token: r.cfg.NewLeaseToken}
	coordinator := approvalmaintenance.Coordinator{Repository: adapter, Gate: adapter, Secrets: boundary, Provider: boundary, Now: time.Now}
	err := coordinator.RunOnce(ctx)
	r.ready.Store(err == nil || errors.Is(err, approvalmaintenance.ErrDenied))
	return err
}

type authorizedApprovalBoundary struct {
	native    *approvalmaintenance.Executor
	secrets   FindingTicketSecretResolver
	webhook   ApprovalNotificationWebhook
	payload   approvalmaintenance.DeliveryPayload
	reference string
}

func (b *authorizedApprovalBoundary) Resolve(ctx context.Context, r approvalmaintenance.Reservation) ([]byte, error) {
	payload, err := b.native.LoadDelivery(ctx, r)
	if err != nil {
		if errors.Is(err, approvalmaintenance.ErrDenied) {
			return nil, approvalmaintenance.ErrDenied
		}
		return nil, approvalmaintenance.ErrUnavailable
	}
	if !validMaintenanceDeliveryPayload(payload) {
		return nil, approvalmaintenance.ErrUnavailable
	}
	b.payload = payload
	b.reference = r.Reference
	return b.secrets.ResolveFindingTicketSecret(ctx, payload.SecretReference)
}
func (b *authorizedApprovalBoundary) Deliver(ctx context.Context, r approvalmaintenance.Reservation, secret []byte) error {
	if ctx == nil || ctx.Err() != nil || b.reference != r.Reference || !validMaintenanceDeliveryPayload(b.payload) {
		return approvalmaintenance.ErrUnavailable
	}
	return b.webhook.DeliverApprovalNotification(ctx, b.payload.DestinationURL, b.payload.DeliveryID, b.payload.PayloadDigest, b.payload.Payload, secret)
}
func validMaintenanceDeliveryPayload(p approvalmaintenance.DeliveryPayload) bool {
	// Lease-only reservation has not consumed attempt1. All original payload,
	// destination, scope, idempotency and secret-reference checks remain required.
	org, err := domain.ParseProductID(p.Organization)
	if err != nil {
		return false
	}
	workspace, err := domain.ParseProductID(p.Workspace)
	if err != nil {
		return false
	}
	env, err := domain.ParseProductID(p.Environment)
	if err != nil {
		return false
	}
	scope, err := domain.NewScope(org, workspace, env)
	if err != nil {
		return false
	}
	if p.Attempt < 0 || p.Attempt >= 10 || len(p.Payload) == 0 || len(p.Payload) > 16384 || !findingTicketLeaseTokenPattern.MatchString(p.LeaseToken) || !p.LeaseExpiresAt.Add(-2*time.Second).After(time.Now()) {
		return false
	}
	hash := sha256.Sum256([]byte(p.Payload))
	if p.PayloadDigest != "sha256:"+hex.EncodeToString(hash[:]) {
		return false
	}
	// Reuse the ORIGINAL payload/security validator. Its attempt is a validation
	// precondition only, not a persisted/invoked attempt; native Begin owns count.
	lease := ApprovalNotificationLease{Scope: scope, DeliveryID: p.DeliveryID, ApprovalID: p.ApprovalID, RunID: p.RunID, Payload: p.Payload, PayloadDigest: p.PayloadDigest, DestinationURL: p.DestinationURL, SecretReference: p.SecretReference, LeaseToken: p.LeaseToken, LeaseExpiresAt: p.LeaseExpiresAt, Attempt: p.Attempt + 1}
	return validApprovalNotificationLease(lease, p.LeaseToken, 60)
}
