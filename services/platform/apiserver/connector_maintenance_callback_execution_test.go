package apiserver

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This group checks our handler's boundary selection. The stub does not prove
// PostgreSQL receipt validation or an actual OpenFGA permission decision.
type connectorNativeCallbackBoundaryStub struct {
	*connectorAuthorizationStub
	phases          []string
	deniedPhase     string
	pkceSettlements int
}

func (*connectorNativeCallbackBoundaryStub) ConnectorOAuthCallbackAuthorityRequired() bool {
	return true
}
func (s *connectorNativeCallbackBoundaryStub) PrepareConnectorOAuthCallback(_ context.Context, phase string, _ OAuthConsumption) error {
	s.phases = append(s.phases, phase)
	if phase == s.deniedPhase {
		return ErrAuthorizationDenied
	}
	return nil
}

func (s *connectorNativeCallbackBoundaryStub) CompletePKCECleanup(ctx context.Context, scope domain.Scope, id string) (ConnectorEffectTransition, error) {
	s.pkceSettlements++
	return s.connectorAuthorizationStub.CompletePKCECleanup(ctx, scope, id)
}

type connectorNativeCallbackMarkerOnlyStub struct{ *connectorAuthorizationStub }

func (*connectorNativeCallbackMarkerOnlyStub) ConnectorOAuthCallbackAuthorityRequired() bool {
	return true
}

type connectorNativeCallbackSecrets struct {
	*connectorSecretStub
	consumeUnavailable bool
}

func (s *connectorNativeCallbackSecrets) Consume(ctx context.Context, reference string) ([]byte, error) {
	if s.consumeUnavailable {
		return nil, ErrRepositoryUnavailable
	}
	return s.connectorSecretStub.Consume(ctx, reference)
}

func TestConnectorMaintenanceCallbackExecutionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, denied                         string
		changed                              bool
		missingHook                          bool
		secretUnavailable                    bool
		consumeUnavailable                   bool
		status                               int
		taken, provider, completed, resolved bool
		deleted                              bool
		phases                               string
	}{
		{name: "uncertain_forward_consumption_keeps_cleanup_pending", consumeUnavailable: true, status: http.StatusServiceUnavailable, phases: "secret"},
		{name: "completion_and_captured_cleanup", status: http.StatusSeeOther, taken: true, provider: true, completed: true, phases: "secret,provider,cleanup"},
		{name: "revoked_before_secret_has_no_external_access", denied: "secret", status: http.StatusForbidden, phases: "secret"},
		{name: "revoked_before_provider_has_no_exchange", denied: "provider", status: http.StatusForbidden, taken: true, phases: "secret,provider"},
		{name: "changed_intent_uses_only_captured_rejection_cleanup", changed: true, denied: "secret", status: http.StatusConflict, deleted: true, resolved: true, phases: "reject_secret"},
		{name: "unavailable_rejection_secret_keeps_cleanup_pending", changed: true, secretUnavailable: true, deleted: true, status: http.StatusServiceUnavailable, phases: "reject_secret"},
		{name: "native_marker_without_hook_fails_closed", changed: true, missingHook: true, status: http.StatusServiceUnavailable},
		{name: "rejection_receipt_refusal_has_no_secret_access", changed: true, denied: "reject_secret", status: http.StatusForbidden, phases: "reject_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			now := time.Now().UTC()
			original := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
			current := original
			if tc.changed {
				current.Version++
			}
			base := &connectorAuthorizationStub{consumed: OAuthConsumption{ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now}}
			digest := connectorAuthorizationIntentDigest(identity, original, base.consumed.IntegrationID, base.consumed.ID, "github", map[string]string{}, base.consumed.RequestedScopes)
			base.consumed.RequestDigest = jsonDigest(digest[:])
			repository := &connectorNativeCallbackBoundaryStub{connectorAuthorizationStub: base, deniedPhase: tc.denied}
			secrets := &connectorSecretStub{reference: base.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: strings.Repeat("s", 43), Verifier: []byte(strings.Repeat("v", 43))}}
			if tc.secretUnavailable {
				secrets.deleteErr = ErrRepositoryUnavailable
			}
			provider := &connectorProviderStub{}
			var selected ConnectorAuthorizationRepository = repository
			if tc.missingHook {
				selected = &connectorNativeCallbackMarkerOnlyStub{base}
			}
			handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: selected, Workflows: connectorWorkflowStub{value: current}, Secrets: &connectorNativeCallbackSecrets{connectorSecretStub: secrets, consumeUnavailable: tc.consumeUnavailable}, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+strings.Repeat("s", 43), nil)
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if (len(secrets.deleted) > 0) != tc.deleted {
				t.Fatal("captured PKCE deletion mismatch")
			}
			if tc.deleted && (len(secrets.deleted) != 1 || secrets.deleted[0] != base.consumed.PKCEVerifierReference) {
				t.Fatal("captured cleanup targeted a different PKCE reference")
			}
			if response.Code != tc.status || secrets.taken != tc.taken || (provider.code != "") != tc.provider || (base.completed.AttemptID != "") != tc.completed || (base.resolved.Status == "failed") != tc.resolved || strings.Join(repository.phases, ",") != tc.phases {
				t.Fatalf("callback boundary mismatch: status=%d secret=%v provider=%v completion=%v resolution=%v phases=%v", response.Code, secrets.taken, provider.code != "", base.completed.AttemptID != "", base.resolved.Status == "failed", repository.phases)
			}
			if (tc.secretUnavailable || tc.consumeUnavailable) && repository.pkceSettlements != 0 {
				t.Fatal("failed secret removal was recorded as durable cleanup")
			}
			if tc.changed && base.activatedID != "" {
				t.Fatal("native rejection used forward PKCE activation")
			}
			if tc.completed && (provider.discardCalls != 1 || base.cleanupCount != 1) {
				t.Fatal("successful callback omitted cleanup settlement")
			}
		})
	}
}

func TestConnectorMaintenanceCallbackAdmissionReservesBeforeConsume(t *testing.T) {
	d := &ConnectorMaintenanceEnqueueDatabase{callbacks: make(map[[32]byte]connectorCallbackPermit)}
	const requests = 1024
	var accepted [requests]bool
	var group sync.WaitGroup
	for i := 0; i < requests; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			var key [32]byte
			binary.BigEndian.PutUint64(key[:8], uint64(i))
			accepted[i] = d.reserveCallback(key)
		}(i)
	}
	group.Wait()
	count := 0
	for _, ok := range accepted {
		if ok {
			count++
		}
	}
	if count != 512 || len(d.callbackPending) != 512 {
		t.Fatalf("concurrent admission=%d pending=%d", count, len(d.callbackPending))
	}
	// A consumed request cannot overwrite its still-pending reservation, and a
	// failed request returns its capacity without evicting any issued permit.
	var released [32]byte
	for i, ok := range accepted {
		if ok {
			binary.BigEndian.PutUint64(released[:8], uint64(i))
			break
		}
	}
	if d.reserveCallback(released) {
		t.Fatal("duplicate in-flight callback was admitted")
	}
	d.releaseCallbackReservation(released)
	var next [32]byte
	binary.BigEndian.PutUint64(next[:8], requests+1)
	if !d.reserveCallback(next) {
		t.Fatal("failed request did not return callback capacity")
	}
	d.callbackMu.Lock()
	delete(d.callbackPending, next)
	d.callbacks[next] = connectorCallbackPermit{Token: "private-permit", Expires: time.Now().Add(time.Minute)}
	d.callbackMu.Unlock()
	if d.reserveCallback(next) {
		t.Fatal("issued callback permit was overwritten")
	}
}
