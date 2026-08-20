package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type connectorConcurrentRepositoryStub struct {
	leases    []ConnectorEffectLease
	completed chan string
	mu        sync.Mutex
}

func (stub *connectorConcurrentRepositoryStub) ClaimReconciliation(context.Context, string, int, int) ([]ConnectorEffectLease, error) {
	return append([]ConnectorEffectLease(nil), stub.leases...), nil
}
func (*connectorConcurrentRepositoryStub) CompleteOAuthReconciliation(context.Context, ConnectorEffectLease, OAuthCompletion) (OAuthCompletionRecord, error) {
	return OAuthCompletionRecord{}, nil
}
func (*connectorConcurrentRepositoryStub) CompleteConnectorCleanupReconciliation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error) {
	return ConnectorEffectTransition{}, nil
}
func (stub *connectorConcurrentRepositoryStub) CompletePKCECleanupReconciliation(_ context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	stub.completed <- lease.ID
	return ConnectorEffectTransition{ID: lease.ID, Status: "reconciled", Attempt: lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}
func (*connectorConcurrentRepositoryStub) QuarantineConnectorReconciliation(context.Context, ConnectorEffectLease, string) (ConnectorEffectTransition, error) {
	return ConnectorEffectTransition{}, nil
}
func (*connectorConcurrentRepositoryStub) FailConnectorReconciliation(context.Context, ConnectorEffectLease, string) (ConnectorEffectTransition, error) {
	return ConnectorEffectTransition{}, nil
}
func (stub *connectorConcurrentRepositoryStub) CompleteConnectorRevocation(_ context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	stub.completed <- lease.ID
	return ConnectorEffectTransition{ID: lease.ID, Status: "reconciled", Attempt: lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}

type connectorWorkflowMapStub map[string]WorkflowValue

func (stub connectorWorkflowMapStub) GetWorkflow(_ context.Context, _ domain.Scope, _ string, id string) (WorkflowValue, error) {
	value, ok := stub[id]
	if !ok {
		return WorkflowValue{}, ErrRepositoryNotFound
	}
	return value, nil
}

type connectorDelayedRevocationProvider struct{ delay time.Duration }

func (*connectorDelayedRevocationProvider) AuthorizationURL(string, string) (string, error) {
	return "", nil
}
func (*connectorDelayedRevocationProvider) Complete(context.Context, string, string, []byte) (ConnectorOAuthGrant, error) {
	return ConnectorOAuthGrant{}, errors.New("unexpected complete")
}
func (*connectorDelayedRevocationProvider) Recover(context.Context, string) (ConnectorOAuthGrant, error) {
	return ConnectorOAuthGrant{}, errors.New("unexpected recover")
}
func (*connectorDelayedRevocationProvider) Discard(context.Context, string, bool) error {
	return errors.New("unexpected discard")
}
func (provider *connectorDelayedRevocationProvider) Revoke(ctx context.Context, _ string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(provider.delay):
		return nil
	}
}

type connectorReconciliationRepositoryStub struct {
	mu               sync.Mutex
	lease            ConnectorEffectLease
	leases           []ConnectorEffectLease
	completed        OAuthCompletion
	completeCount    int
	revoked          bool
	failedCode       string
	cleanupCount     int
	quarantined      string
	claimCount       int
	completeOAuthErr error
	cleanupErr       error
	pkceCleanupErr   error
	revocationErr    error
}

func (stub *connectorReconciliationRepositoryStub) CompleteConnectorCleanupReconciliation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.cleanupCount++
	if stub.cleanupErr != nil {
		return ConnectorEffectTransition{}, stub.cleanupErr
	}
	return ConnectorEffectTransition{ID: stub.lease.ID, Status: "reconciled", Attempt: stub.lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}
func (stub *connectorReconciliationRepositoryStub) CompletePKCECleanupReconciliation(_ context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.cleanupCount++
	if stub.pkceCleanupErr != nil {
		return ConnectorEffectTransition{}, stub.pkceCleanupErr
	}
	return ConnectorEffectTransition{ID: lease.ID, Status: "reconciled", Attempt: lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}
func (stub *connectorReconciliationRepositoryStub) QuarantineConnectorReconciliation(_ context.Context, _ ConnectorEffectLease, code string) (ConnectorEffectTransition, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.quarantined = code
	return ConnectorEffectTransition{ID: stub.lease.ID, Status: "unknown", Attempt: stub.lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}

func (stub *connectorReconciliationRepositoryStub) CompleteConnectorRevocation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.revoked = true
	if stub.revocationErr != nil {
		return ConnectorEffectTransition{}, stub.revocationErr
	}
	return ConnectorEffectTransition{ID: stub.lease.ID, Status: "reconciled", Attempt: stub.lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}

func (stub *connectorReconciliationRepositoryStub) ClaimReconciliation(context.Context, string, int, int) ([]ConnectorEffectLease, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.claimCount++
	if stub.leases != nil {
		return append([]ConnectorEffectLease(nil), stub.leases...), nil
	}
	if stub.lease.ID == "" {
		return []ConnectorEffectLease{}, nil
	}
	return []ConnectorEffectLease{stub.lease}, nil
}

func TestConnectorReconcilerProviderFailuresDoNotBackOffGlobalClaims(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	workflow := connectorWorkflowValue(integrationID, "github")
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	digest := connectorAuthorizationIntentDigestValues(identity.Scope, identity.PrincipalID.String(), workflow, integrationID, attemptID, "github", map[string]string{}, []string{"read:org", "repo"})
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: integrationID, OAuthAttemptID: attemptID, PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:" + attemptID, RequestDigest: hex.EncodeToString(digest[:]), Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}}
	provider := &connectorRecoveryProvider{recoverErr: errors.New("github unavailable")}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, _ := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: 10 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 78*time.Millisecond)
	defer cancel()
	_ = reconciler.Run(ctx)
	if repository.claimCount < 6 {
		t.Fatalf("provider errors backed off global claim cadence: claims=%d", repository.claimCount)
	}
}
func (stub *connectorReconciliationRepositoryStub) CompleteOAuthReconciliation(_ context.Context, _ ConnectorEffectLease, completion OAuthCompletion) (OAuthCompletionRecord, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.completed = completion
	stub.completeCount++
	if stub.completeOAuthErr != nil {
		return OAuthCompletionRecord{}, stub.completeOAuthErr
	}
	return OAuthCompletionRecord{AttemptID: completion.AttemptID, ConnectionID: completion.ConnectionID, Status: "succeeded", CompletedAt: time.Now().UTC()}, nil
}
func (stub *connectorReconciliationRepositoryStub) FailConnectorReconciliation(_ context.Context, _ ConnectorEffectLease, code string) (ConnectorEffectTransition, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.failedCode = code
	return ConnectorEffectTransition{ID: stub.lease.ID, Status: "failed", Attempt: stub.lease.Attempt, UpdatedAt: time.Now().UTC()}, nil
}

type connectorRecoveryProvider struct {
	mu                     sync.Mutex
	grant                  ConnectorOAuthGrant
	recoverErr             error
	recoverErrors          []error
	completeCalls          int
	recoverCalls           int
	discardCalls           int
	discardRequestedRevoke bool
	revokeCalls            int
	revokeErr              error
}

func (*connectorRecoveryProvider) AuthorizationURL(string, string) (string, error) { return "", nil }
func (provider *connectorRecoveryProvider) Complete(context.Context, string, string, []byte) (ConnectorOAuthGrant, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.completeCalls++
	return ConnectorOAuthGrant{}, errors.New("exchange must not repeat")
}
func (provider *connectorRecoveryProvider) Recover(context.Context, string) (ConnectorOAuthGrant, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.recoverCalls++
	if provider.recoverCalls <= len(provider.recoverErrors) {
		return provider.grant, provider.recoverErrors[provider.recoverCalls-1]
	}
	return provider.grant, provider.recoverErr
}
func (provider *connectorRecoveryProvider) Discard(_ context.Context, _ string, revoke bool) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.discardCalls++
	provider.discardRequestedRevoke = revoke
	return nil
}
func (provider *connectorRecoveryProvider) Revoke(context.Context, string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.revokeCalls++
	return provider.revokeErr
}

func TestConnectorReconcilerRecoversDurableOutcomeWithoutRepeatingProviderEffect(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	effectID := "pid_70000003-0000-4000-8000-000000000003"
	workflow := connectorWorkflowValue(integrationID, "github")
	digest := connectorAuthorizationIntentDigestValues(identity.Scope, identity.PrincipalID.String(), workflow, integrationID, attemptID, "github", map[string]string{}, []string{"read:org", "repo"})
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{
		OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(),
		ID: effectID, IntegrationID: integrationID, OAuthAttemptID: attemptID, PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:" + attemptID,
		RequestDigest: hex.EncodeToString(digest[:]), Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute),
	}}
	provider := &connectorRecoveryProvider{grant: ConnectorOAuthGrant{ConnectionReference: "ref:github/install/123456", ProviderSubject: "installation:123456", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":123456}`)}}
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.completeCalls != 0 || provider.recoverCalls != 1 || provider.discardCalls != 1 || provider.discardRequestedRevoke || repository.completed.AttemptID != attemptID || repository.failedCode != "" {
		t.Fatalf("recovery calls provider=%#v completed=%#v failed=%q", provider, repository.completed, repository.failedCode)
	}

	provider.grant = ConnectorOAuthGrant{}
	provider.recoverErr = ErrConnectorOutcomeNotFound
	repository.completed = OAuthCompletion{}
	repository.lease.Attempt = 100
	if err := reconciler.reconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.completeCalls != 0 || provider.discardCalls != 1 || provider.discardRequestedRevoke || repository.failedCode != "" || repository.quarantined != "provider_outcome_ambiguous" || repository.completed.AttemptID != "" {
		t.Fatalf("missing outcome quarantine provider=%#v completed=%#v failed=%q quarantined=%q", provider, repository.completed, repository.failedCode, repository.quarantined)
	}
}

func TestConnectorReconcilerRetriesPostCompletionCleanupWithoutRecoveringOrExchanging(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	effectID := "pid_70000003-0000-4000-8000-000000000003"
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: effectID, IntegrationID: integrationID, OAuthAttemptID: attemptID, PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:" + attemptID, RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), LastErrorCode: "cleanup_pending", Attempt: 2, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}}
	provider := &connectorRecoveryProvider{}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, _ := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue(integrationID, "github")}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err := reconciler.reconcileOnce(context.Background()); err != nil || provider.completeCalls != 0 || provider.recoverCalls != 0 || provider.discardCalls != 1 || provider.discardRequestedRevoke || repository.cleanupCount != 1 || repository.completeCount != 0 {
		t.Fatalf("cleanup reconciliation err=%v provider=%#v repository=%#v", err, provider, repository)
	}
}

func TestConnectorReconcilerQuarantinesFinalAttemptCleanupAndRevocationFailures(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	workflow := connectorWorkflowValue(integrationID, "github")
	provider := &connectorRecoveryProvider{revokeErr: errors.New("provider unavailable")}
	provider.discardCalls = 0
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: integrationID, OAuthAttemptID: "pid_70000002-0000-4000-8000-000000000002", PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:pid_70000002-0000-4000-8000-000000000002", RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), LastErrorCode: "cleanup_pending", ConnectionReference: "ref:github/installation/123456", Attempt: 100, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}}
	provider.discardRequestedRevoke = false
	reconciler, _ := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	provider.recoverErr = errors.New("unused")
	providerDiscardError := errors.New("secret cleanup unavailable")
	provider.revokeErr = providerDiscardError
	// Use a provider wrapper whose completed-effect cleanup fails.
	providerForCleanup := &connectorRecoveryProviderWithDiscardError{connectorRecoveryProvider: provider, discardErr: providerDiscardError}
	registry, _ = NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: providerForCleanup, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, _ = NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err := reconciler.reconcileOnce(context.Background()); err != nil || repository.quarantined != "provider_cleanup_ambiguous" {
		t.Fatalf("final authorization cleanup err=%v quarantine=%q", err, repository.quarantined)
	}

	var workflowBody map[string]any
	_ = json.Unmarshal(workflow.Body, &workflowBody)
	workflowBody["status"] = "revoking"
	workflow.Body, _ = json.Marshal(workflowBody)
	repository.quarantined = ""
	repository.lease = ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000004-0000-4000-8000-000000000004", IntegrationID: integrationID, Provider: "github", Operation: "revoke", IdempotencyKey: "delete-integration-0001", RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), ConnectionReference: "ref:github/installation/123456", Attempt: 100, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	provider.revokeErr = errors.New("provider unavailable")
	reconciler.workflows = connectorWorkflowStub{value: workflow}
	if err := reconciler.reconcileOnce(context.Background()); err != nil || repository.quarantined != "provider_revocation_ambiguous" || repository.failedCode != "" {
		t.Fatalf("final revocation err=%v quarantine=%q failed=%q", err, repository.quarantined, repository.failedCode)
	}

	repository.quarantined = ""
	repository.lease = ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000005-0000-4000-8000-000000000005", IntegrationID: integrationID, Provider: "github", Operation: "pkce_cleanup", IdempotencyKey: "pkce-cleanup:pid_70000005-0000-4000-8000-000000000005", RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), LastErrorCode: "oauth_attempt_expiry", ConnectionReference: "ref:oauth/pkce/70000005-0000-4000-8000-000000000005", Attempt: 100, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	reconciler.secrets = &connectorSecretStub{deleteErr: errors.New("secrets manager unavailable")}
	if err := reconciler.reconcileOnce(context.Background()); err != nil || repository.quarantined != "pkce_cleanup_ambiguous" {
		t.Fatalf("final PKCE cleanup err=%v quarantine=%q", err, repository.quarantined)
	}
}

func TestConnectorReconcilerQuarantinesEveryFinalAttemptFinalizationFailure(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	workflow := connectorWorkflowValue(integrationID, "github")
	digest := connectorAuthorizationIntentDigestValues(identity.Scope, identity.PrincipalID.String(), workflow, integrationID, attemptID, "github", map[string]string{}, []string{"read:org", "repo"})
	base := ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: integrationID, OAuthAttemptID: attemptID, PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:" + attemptID, RequestDigest: hex.EncodeToString(digest[:]), Attempt: 100, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	grant := ConnectorOAuthGrant{ConnectionReference: "ref:github/installation/123456", ProviderSubject: "installation:123456", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":123456}`)}
	run := func(t *testing.T, repository *connectorReconciliationRepositoryStub, provider ConnectorOAuthProvider, lease ConnectorEffectLease, workflow WorkflowValue, want string) {
		t.Helper()
		repository.lease = lease
		registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if err := reconciler.reconcileOnce(context.Background()); err != nil || repository.quarantined != want {
			t.Fatalf("finalization err=%v quarantine=%q want=%q", err, repository.quarantined, want)
		}
	}

	t.Run("oauth completion", func(t *testing.T) {
		repository := &connectorReconciliationRepositoryStub{completeOAuthErr: errors.New("completion unavailable")}
		run(t, repository, &connectorRecoveryProvider{grant: grant}, base, workflow, "provider_outcome_ambiguous")
	})
	t.Run("post completion discard", func(t *testing.T) {
		repository := &connectorReconciliationRepositoryStub{}
		provider := &connectorRecoveryProviderWithDiscardError{connectorRecoveryProvider: &connectorRecoveryProvider{grant: grant}, discardErr: errors.New("discard unavailable")}
		run(t, repository, provider, base, workflow, "provider_cleanup_ambiguous")
	})
	t.Run("cleanup completion", func(t *testing.T) {
		lease := base
		lease.LastErrorCode = "cleanup_pending"
		lease.ConnectionReference = grant.ConnectionReference
		repository := &connectorReconciliationRepositoryStub{cleanupErr: errors.New("cleanup completion unavailable")}
		run(t, repository, &connectorRecoveryProvider{}, lease, workflow, "provider_cleanup_ambiguous")
	})
	t.Run("revocation completion", func(t *testing.T) {
		lease := base
		lease.OAuthAttemptID = ""
		lease.Operation = "revoke"
		lease.ConnectionReference = grant.ConnectionReference
		var body map[string]any
		_ = json.Unmarshal(workflow.Body, &body)
		body["status"] = "revoking"
		revoking := workflow
		revoking.Body, _ = json.Marshal(body)
		repository := &connectorReconciliationRepositoryStub{revocationErr: errors.New("revocation completion unavailable")}
		run(t, repository, &connectorRecoveryProvider{}, lease, revoking, "provider_revocation_ambiguous")
	})
	t.Run("PKCE cleanup completion", func(t *testing.T) {
		lease := base
		lease.Operation = "pkce_cleanup"
		lease.ConnectionReference = "ref:oauth/pkce/70000002-0000-4000-8000-000000000002"
		repository := &connectorReconciliationRepositoryStub{pkceCleanupErr: errors.New("PKCE completion unavailable")}
		run(t, repository, &connectorRecoveryProvider{}, lease, workflow, "pkce_cleanup_ambiguous")
	})
}

type connectorRecoveryProviderWithDiscardError struct {
	*connectorRecoveryProvider
	discardErr error
}

func (provider *connectorRecoveryProviderWithDiscardError) Discard(context.Context, string, bool) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.discardCalls++
	return provider.discardErr
}

func TestConnectorReconcilerDeletesExpiredPKCEUnderLiveLease(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	reference := "ref:oauth/pkce/70000002-0000-4000-8000-000000000002"
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", OAuthAttemptID: "pid_70000002-0000-4000-8000-000000000002", PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org"}, Provider: "github", Operation: "pkce_cleanup", IdempotencyKey: "pkce-cleanup:pid_70000003-0000-4000-8000-000000000003", RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), LastErrorCode: "oauth_attempt_expiry", ConnectionReference: reference, Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}}
	secrets := &connectorSecretStub{}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: &connectorRecoveryProvider{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue(repository.lease.IntegrationID, "github")}, Registry: registry, Secrets: secrets, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileOnce(context.Background()); err != nil || len(secrets.deleted) != 1 || secrets.deleted[0] != reference || repository.cleanupCount != 1 {
		t.Fatalf("pkce cleanup err=%v deleted=%#v completed=%d", err, secrets.deleted, repository.cleanupCount)
	}
}

func TestConnectorReconcilerDrainsClaimAfterOneProviderFailure(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	workflow := connectorWorkflowValue(integrationID, "github")
	makeLease := func(attemptID, effectID string) ConnectorEffectLease {
		digest := connectorAuthorizationIntentDigestValues(identity.Scope, identity.PrincipalID.String(), workflow, integrationID, attemptID, "github", map[string]string{}, []string{"read:org", "repo"})
		return ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: effectID, IntegrationID: integrationID, OAuthAttemptID: attemptID, PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:" + attemptID, RequestDigest: hex.EncodeToString(digest[:]), Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	}
	repository := &connectorReconciliationRepositoryStub{leases: []ConnectorEffectLease{
		makeLease("pid_70000002-0000-4000-8000-000000000002", "pid_70000003-0000-4000-8000-000000000003"),
		makeLease("pid_70000004-0000-4000-8000-000000000004", "pid_70000005-0000-4000-8000-000000000005"),
	}}
	provider := &connectorRecoveryProvider{grant: ConnectorOAuthGrant{ConnectionReference: "ref:github/install/123456", ProviderSubject: "installation:123456", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":123456}`)}, recoverErrors: []error{errors.New("first provider unavailable"), nil}}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, _ := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err := reconciler.reconcileOnce(context.Background()); err == nil || provider.recoverCalls != 2 || repository.completeCount != 1 || repository.completed.AttemptID != "pid_70000004-0000-4000-8000-000000000004" {
		t.Fatalf("drained claim err=%v recover_calls=%d completions=%d last=%#v", err, provider.recoverCalls, repository.completeCount, repository.completed)
	}
}

func TestConnectorReconcilerProcessesSlowProvidersWithoutStarvingOtherLeases(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	githubID := "pid_70000001-0000-4000-8000-000000000001"
	oktaID := "pid_70000002-0000-4000-8000-000000000002"
	githubWorkflow := connectorWorkflowValue(githubID, "github")
	oktaWorkflow := connectorWorkflowValue(oktaID, "okta")
	for _, workflow := range []*WorkflowValue{&githubWorkflow, &oktaWorkflow} {
		var body map[string]any
		if err := json.Unmarshal(workflow.Body, &body); err != nil {
			t.Fatal(err)
		}
		body["status"] = "revoking"
		workflow.Body, _ = json.Marshal(body)
	}
	lease := func(id, integrationID, provider, reference string) ConnectorEffectLease {
		return ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: id, IntegrationID: integrationID, Provider: provider, Operation: "revoke", IdempotencyKey: "delete-" + id, RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), ConnectionReference: reference, Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}
	}
	leases := make([]ConnectorEffectLease, 0, 10)
	for ordinal := 3; ordinal <= 10; ordinal++ {
		id := fmt.Sprintf("pid_700000%02d-0000-4000-8000-%012d", ordinal, ordinal)
		leases = append(leases, lease(id, githubID, "github", "ref:github/installation/123456"))
	}
	oktaEffectID := "pid_70000011-0000-4000-8000-000000000011"
	pkceEffectID := "pid_70000012-0000-4000-8000-000000000012"
	leases = append(leases,
		lease(oktaEffectID, oktaID, "okta", "ref:okta/refresh/70000004-0000-4000-8000-000000000004"),
		ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: pkceEffectID, IntegrationID: githubID, Provider: "github", Operation: "pkce_cleanup", IdempotencyKey: "pkce-cleanup:" + pkceEffectID, RequestDigest: hex.EncodeToString(make([]byte, sha256.Size)), ConnectionReference: "ref:oauth/pkce/70000012-0000-4000-8000-000000000012", Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)},
	)
	repository := &connectorConcurrentRepositoryStub{leases: leases, completed: make(chan string, len(leases))}
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"github": {Provider: &connectorDelayedRevocationProvider{delay: 250 * time.Millisecond}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"},
		"okta":   {Provider: &connectorDelayedRevocationProvider{}, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowMapStub{githubID: githubWorkflow, oktaID: oktaWorkflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- reconciler.reconcileOnce(context.Background()) }()
	quick := map[string]bool{}
	deadline := time.After(100 * time.Millisecond)
	for len(quick) < 2 {
		select {
		case completed := <-repository.completed:
			if completed == oktaEffectID || completed == pkceEffectID {
				quick[completed] = true
			}
		case <-deadline:
			t.Fatalf("Okta/PKCE lanes starved behind saturated GitHub leases: completed=%v", quick)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type connectorDeadlineRepositoryStub struct {
	connectorReconciliationRepositoryStub
	quarantineContextErr error
}

func (stub *connectorDeadlineRepositoryStub) QuarantineConnectorReconciliation(ctx context.Context, lease ConnectorEffectLease, code string) (ConnectorEffectTransition, error) {
	stub.quarantineContextErr = ctx.Err()
	return stub.connectorReconciliationRepositoryStub.QuarantineConnectorReconciliation(ctx, lease, code)
}

type connectorDeadlineProvider struct{}

func (*connectorDeadlineProvider) AuthorizationURL(string, string) (string, error) { return "", nil }
func (*connectorDeadlineProvider) Complete(context.Context, string, string, []byte) (ConnectorOAuthGrant, error) {
	return ConnectorOAuthGrant{}, errors.New("unexpected complete")
}
func (*connectorDeadlineProvider) Recover(ctx context.Context, _ string) (ConnectorOAuthGrant, error) {
	<-ctx.Done()
	return ConnectorOAuthGrant{}, ErrConnectorOutcomeNotFound
}
func (*connectorDeadlineProvider) Discard(context.Context, string, bool) error { return nil }
func (*connectorDeadlineProvider) Revoke(context.Context, string) error        { return nil }

func TestConnectorReconcilerReservesLiveLeaseTimeForFinalAttemptQuarantine(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	workflow := connectorWorkflowValue(integrationID, "github")
	digest := connectorAuthorizationIntentDigestValues(identity.Scope, identity.PrincipalID.String(), workflow, integrationID, attemptID, "github", map[string]string{}, []string{"read:org", "repo"})
	repository := &connectorDeadlineRepositoryStub{connectorReconciliationRepositoryStub: connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: integrationID, OAuthAttemptID: attemptID, PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:" + attemptID, RequestDigest: hex.EncodeToString(digest[:]), Attempt: 100, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Second)}}}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: &connectorDeadlineProvider{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, _ := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err := reconciler.reconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.quarantined != "provider_outcome_ambiguous" || repository.quarantineContextErr != nil {
		t.Fatalf("finalization used expired provider context: quarantine=%q context_err=%v", repository.quarantined, repository.quarantineContextErr)
	}
}

func TestConnectorReconcilerConfirmsProviderRevocationBeforeLocalTerminalState(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	workflow := connectorWorkflowValue(integrationID, "okta")
	var body map[string]any
	_ = json.Unmarshal(workflow.Body, &body)
	body["status"] = "revoking"
	workflow.Body, _ = json.Marshal(body)
	digest := sha256.Sum256([]byte("revoke-intent"))
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: integrationID, Provider: "okta", Operation: "revoke", IdempotencyKey: "delete-integration-0001", RequestDigest: hex.EncodeToString(digest[:]), ConnectionReference: "ref:okta/refresh/70000002-0000-4000-8000-000000000002", Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}}
	provider := &connectorRecoveryProvider{}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"okta": {Provider: provider, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"}}, nil)
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileOnce(context.Background()); err != nil || provider.revokeCalls != 1 || !repository.revoked || repository.failedCode != "" {
		t.Fatalf("confirmed revocation err=%v provider=%#v repository=%#v", err, provider, repository)
	}
	repository.revoked = false
	provider.revokeErr = errors.New("provider unavailable")
	if err := reconciler.reconcileOnce(context.Background()); err == nil || repository.revoked || repository.failedCode != "" {
		t.Fatalf("unconfirmed revocation err=%v repository=%#v", err, repository)
	}
}

func TestConnectorReconcilerRejectsChangedAuthorizationIntentAndRunCancels(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	workflow := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	digest := sha256.Sum256([]byte("stale-intent"))
	repository := &connectorReconciliationRepositoryStub{lease: ConnectorEffectLease{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", OAuthAttemptID: "pid_70000002-0000-4000-8000-000000000002", PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org", "repo"}, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-authorize:pid_70000002-0000-4000-8000-000000000002", RequestDigest: hex.EncodeToString(digest[:]), Attempt: 1, LeaseOwner: "connector-worker-a", LeaseToken: hex.EncodeToString(make([]byte, sha256.Size)), LeaseExpiresAt: time.Now().Add(time.Minute)}}
	provider := &connectorRecoveryProvider{grant: ConnectorOAuthGrant{ConnectionReference: "ref:github/install/123456", ProviderSubject: "installation:123456", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":123456}`)}}
	registry, _ := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "connector-worker-a", LeaseSeconds: 30, Limit: 10, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileOnce(context.Background()); err != nil || repository.failedCode != "authorization_intent_changed" || !provider.discardRequestedRevoke || provider.recoverCalls != 0 {
		t.Fatalf("stale intent result err=%v failed=%q provider=%#v", err, repository.failedCode, provider)
	}
	contextValue, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(contextValue) }()
	deadline := time.Now().Add(time.Second)
	for !reconciler.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || !reconciler.Ready() {
		t.Fatalf("cancelled worker err=%v ready=%v", err, reconciler.Ready())
	}
}
