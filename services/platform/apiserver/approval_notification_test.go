package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type approvalNotificationRepositoryStub struct {
	lease       ApprovalNotificationLease
	claimErr    error
	completeErr error
	failErr     error
	claims      int
	completes   int
	fails       int
}

func (repository *approvalNotificationRepositoryStub) ClaimApprovalNotification(context.Context, string, string, int) (ApprovalNotificationLease, error) {
	repository.claims++
	return repository.lease, repository.claimErr
}

func (repository *approvalNotificationRepositoryStub) CompleteApprovalNotification(context.Context, domain.Scope, string, string, string) error {
	repository.completes++
	return repository.completeErr
}

func (repository *approvalNotificationRepositoryStub) FailApprovalNotification(context.Context, domain.Scope, string, string, string) error {
	repository.fails++
	return repository.failErr
}

type approvalNotificationWebhookStub struct {
	calls       int
	destination string
	payload     string
	digest      string
	deliveryID  string
	secret      []byte
	err         error
}

func (webhook *approvalNotificationWebhookStub) DeliverApprovalNotification(_ context.Context, destination, payload, digest, deliveryID string, secret []byte) error {
	webhook.calls++
	webhook.destination = destination
	webhook.payload = payload
	webhook.digest = digest
	webhook.deliveryID = deliveryID
	webhook.secret = append([]byte(nil), secret...)
	return webhook.err
}

func approvalNotificationFixture(t *testing.T) ApprovalNotificationLease {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	lease := ApprovalNotificationLease{
		Scope:           identity.Scope,
		DeliveryID:      "pid_76000001-0000-4000-8000-000000000001",
		ApprovalID:      "pid_76000002-0000-4000-8000-000000000002",
		RunID:           "pid_76000003-0000-4000-8000-000000000003",
		Payload:         `{"approval":{"id":"pid_76000002-0000-4000-8000-000000000002","run_id":"pid_76000003-0000-4000-8000-000000000003"},"delivery_id":"pid_76000001-0000-4000-8000-000000000001","event":"security_agent.approval_required","scope":{"environment_id":"` + identity.Scope.EnvironmentID().String() + `","organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `"},"version":1}`,
		DestinationURL:  "https://hooks.example.test/zasp",
		SecretReference: "secret_ref_approval_prod",
		LeaseToken:      strings.Repeat("b", 64),
		LeaseExpiresAt:  time.Now().UTC().Add(20 * time.Second),
		Attempt:         1,
	}
	digest := sha256.Sum256([]byte(lease.Payload))
	lease.PayloadDigest = "sha256:" + hex.EncodeToString(digest[:])
	return lease
}

func TestApprovalNotificationReconcilerSignsOneMinimalTenantScopedDelivery(t *testing.T) {
	lease := approvalNotificationFixture(t)
	repository := &approvalNotificationRepositoryStub{lease: lease}
	secrets := &findingTicketSecretResolverStub{material: []byte(strings.Repeat("s", 32))}
	webhook := &approvalNotificationWebhookStub{}
	reconciler, err := NewApprovalNotificationReconciler(ApprovalNotificationReconcilerConfig{
		Repository: repository, Secrets: secrets, Webhook: webhook, Owner: "agentsec-api:test", LeaseSeconds: 30,
		NewLeaseToken: func() (string, error) { return lease.LeaseToken, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.claims != 1 || repository.completes != 1 || repository.fails != 0 || secrets.calls != 1 || webhook.calls != 1 {
		t.Fatalf("calls claim/complete/fail/secret/webhook=%d/%d/%d/%d/%d", repository.claims, repository.completes, repository.fails, secrets.calls, webhook.calls)
	}
	if webhook.destination != lease.DestinationURL || webhook.payload != lease.Payload || webhook.digest != lease.PayloadDigest || webhook.deliveryID != lease.DeliveryID || string(webhook.secret) != strings.Repeat("s", 32) {
		t.Fatalf("webhook authority drift: %#v", webhook)
	}
	for _, forbidden := range []string{"evidence", "credential", "lease_token", "signing_secret", "plan_hash"} {
		if strings.Contains(webhook.payload, forbidden) {
			t.Fatalf("payload leaked %q: %s", forbidden, webhook.payload)
		}
	}
}

func TestApprovalNotificationReconcilerReleasesFailedDeliveryWithoutEchoingProviderError(t *testing.T) {
	lease := approvalNotificationFixture(t)
	repository := &approvalNotificationRepositoryStub{lease: lease}
	secrets := &findingTicketSecretResolverStub{material: []byte(strings.Repeat("s", 32))}
	webhook := &approvalNotificationWebhookStub{err: errors.New("provider-secret-shaped-error")}
	reconciler, err := NewApprovalNotificationReconciler(ApprovalNotificationReconcilerConfig{
		Repository: repository, Secrets: secrets, Webhook: webhook, Owner: "agentsec-api:test", LeaseSeconds: 30,
		NewLeaseToken: func() (string, error) { return lease.LeaseToken, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.lease = ApprovalNotificationLease{}
	if err := reconciler.ReconcileOnce(context.Background()); err != nil || !reconciler.Ready() {
		t.Fatalf("empty warmup err=%v ready=%t", err, reconciler.Ready())
	}
	repository.lease = lease
	if err := reconciler.ReconcileOnce(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) || strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("error=%v", err)
	}
	if reconciler.Ready() {
		t.Fatal("provider failure left approval notification reconciler ready")
	}
	if repository.fails != 1 || repository.completes != 0 || webhook.calls != 1 {
		t.Fatalf("calls fail/complete/webhook=%d/%d/%d", repository.fails, repository.completes, webhook.calls)
	}
}

func TestApprovalNotificationReconcilerTreatsEmptyQueueAsHealthy(t *testing.T) {
	repository := &approvalNotificationRepositoryStub{}
	reconciler, err := NewApprovalNotificationReconciler(ApprovalNotificationReconcilerConfig{
		Repository: repository, Secrets: &findingTicketSecretResolverStub{}, Webhook: &approvalNotificationWebhookStub{}, Owner: "agentsec-api:test", LeaseSeconds: 30,
		NewLeaseToken: func() (string, error) { return strings.Repeat("b", 64), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.ReconcileOnce(context.Background()); err != nil || !reconciler.Ready() {
		t.Fatalf("empty queue err=%v ready=%t", err, reconciler.Ready())
	}
}
