package apiserver

import (
	"context"
	"crypto/sha256"
	"net/http"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

type stytchWebhookRepository interface {
	ReconcileStytchWebhook(context.Context, platformidentity.WebhookEvent, []byte, string) (bool, error)
}

type durableStytchWebhookReconciler struct {
	repository stytchWebhookRepository
	verifier   *platformidentity.WebhookVerifier
	newAuditID func() (string, error)
}

func NewProductionStytchWebhookHandler(repository *PostgresRepository, projectID, secret string, now func() time.Time) (http.Handler, error) {
	return newProductionStytchWebhookHandler(repository, projectID, secret, now, newWorkflowProductID)
}

func newProductionStytchWebhookHandler(repository stytchWebhookRepository, projectID, secret string, now func() time.Time, newAuditID func() (string, error)) (http.Handler, error) {
	if nilInterface(repository) || newAuditID == nil {
		return nil, ErrRepositoryConfiguration
	}
	verifier, err := platformidentity.NewWebhookVerifier(projectID, secret, now, 5*time.Minute)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	reconciler := &durableStytchWebhookReconciler{repository: repository, verifier: verifier, newAuditID: newAuditID}
	handler, err := platformidentity.NewWebhookHTTPHandlerForPath(reconciler, "/api/v1/webhooks/stytch")
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return handler, nil
}

func (reconciler *durableStytchWebhookReconciler) Handle(ctx context.Context, body []byte, headers platformidentity.WebhookHeaders) (bool, error) {
	if reconciler == nil || nilInterface(reconciler.repository) || reconciler.verifier == nil || reconciler.newAuditID == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryOperation
	}
	event, replay, err := reconciler.verifier.Verify(body, headers)
	if err != nil {
		return false, err
	}
	if replay {
		return false, nil
	}
	release := true
	defer func() {
		if release {
			reconciler.verifier.Release(event.EventID)
		}
	}()
	if event.Kind() != "scim.member.delete" {
		release = false
		return false, nil
	}
	auditID, err := reconciler.newAuditID()
	if err != nil || !validProductID(auditID) {
		return false, ErrRepositoryUnavailable
	}
	digest := sha256.Sum256(body)
	processed, err := reconciler.repository.ReconcileStytchWebhook(ctx, event, digest[:], auditID)
	if err != nil {
		return false, ErrRepositoryUnavailable
	}
	release = false
	return processed, nil
}
