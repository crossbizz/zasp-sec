package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type stytchWebhookRepository interface {
	ReconcileStytchWebhook(context.Context, platformidentity.WebhookEvent, []byte, string) (bool, error)
}

type durableStytchWebhookReconciler struct {
	repository stytchWebhookRepository
	verifier   *platformidentity.WebhookVerifier
	newAuditID func() (string, error)
	native     *identityWebhookIssuer
}

type identityWebhookIssuer struct {
	key            *authorization.IdentityWebhookKey
	sessionVersion string
	deployment     authorization.IdentityDeployment
	repository     *PostgresRepository
}

// The purpose key lives in the verified delivery handler, not the repository's
// public event-shaped method. Only successful Svix verification reaches it.
func NewProductionNativeStytchWebhookHandler(repository *PostgresRepository, secret string, now func() time.Time, seed []byte, deployment authorization.IdentityDeployment) (http.Handler, error) {
	if repository == nil || !repository.currentAuthorization {
		return nil, ErrRepositoryConfiguration
	}
	if _, err := deployment.Audience(); err != nil {
		return nil, ErrRepositoryConfiguration
	}
	key, err := authorization.NewIdentityWebhookKey(seed)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	session, err := authorization.NewIdentitySessionKey(seed)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	verifier, err := platformidentity.NewWebhookVerifier(deployment.ProjectID, secret, now, 5*time.Minute)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	r := &durableStytchWebhookReconciler{repository: repository, verifier: verifier, newAuditID: newWorkflowProductID, native: &identityWebhookIssuer{key: key, sessionVersion: session.Version(), deployment: deployment, repository: repository}}
	return platformidentity.NewWebhookHTTPHandlerForPath(r, "/api/v1/webhooks/stytch")
}

func (i *identityWebhookIssuer) applyVerified(ctx context.Context, event platformidentity.WebhookEvent, digest [32]byte, audit string) (bool, error) {
	m, err := readyIdentityRegistrations(ctx, i.repository, i.deployment, i.sessionVersion, i.key.Version())
	if err != nil {
		return false, err
	}
	proof, err := i.key.SignDeprovision(event, authorization.IdentityWebhookAdmission{Registration: m.Webhook, Profile: migrations.AuthorizationIdentityProfileChecksum(), BodyDigest: hex.EncodeToString(digest[:]), AuditID: audit, VerifiedAt: time.Now().UTC().Truncate(time.Millisecond)})
	if err != nil {
		return false, ErrRepositoryUnavailable
	}
	d, err := i.repository.nativeIdentityDatabase()
	if err != nil {
		return false, err
	}
	var result struct {
		Processed       bool `json:"processed"`
		Replayed        bool `json:"replayed"`
		RevokedSessions int  `json:"revoked_sessions"`
		RevokedTokens   int  `json:"revoked_tokens"`
	}
	_, err = d.identityTransaction(ctx, identityDeprovision, []any{string(proof)}, func(b json.RawMessage) error {
		if decodeStrictIdentityAdministration(b, &result) != nil || result.Processed == result.Replayed || result.RevokedSessions < 0 || result.RevokedTokens < 0 {
			return ErrRepositoryUnavailable
		}
		return nil
	})
	return result.Processed, err
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
	var processed bool
	if reconciler.native != nil {
		processed, err = reconciler.native.applyVerified(ctx, event, digest, auditID)
	} else {
		processed, err = reconciler.repository.ReconcileStytchWebhook(ctx, event, digest[:], auditID)
	}
	if err != nil {
		return false, ErrRepositoryUnavailable
	}
	release = false
	return processed, nil
}
