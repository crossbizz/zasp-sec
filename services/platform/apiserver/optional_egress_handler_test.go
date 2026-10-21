package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

type optionalCheckedAuthorizer struct {
	grant RequestAuthorization
	calls []RoutedOperation
}

func (a *optionalCheckedAuthorizer) Authorize(_ context.Context, _ RequestIdentity, _ CredentialBinding, route RoutedOperation) (RequestAuthorization, error) {
	a.calls = append(a.calls, route)
	return a.grant, nil
}

type optionalNeverSender struct{ calls int }

func (s *optionalNeverSender) Send(context.Context, *optionalegress.Prepared, optionalegress.Claim) optionalegress.SendOutcome {
	s.calls++
	return optionalegress.SendOutcome{State: optionalegress.Unknown}
}

func TestOptionalEgressHTTPRejectsUntrustedInputsBeforeStorageOrSend(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	sender := &optionalNeverSender{}
	h := &optionalEgressHTTPHandler{config: &OptionalEgressHTTPConfig{Repository: &OptionalEgressRepository{}, Authorizer: &optionalCheckedAuthorizer{}, Sender: sender, Clock: time.Now}, next: handlerResponse("retained")}
	for _, body := range []string{
		`{"finding_id":"pid_88008001-0000-4000-8000-000000000001","finding_version":1,"idempotency_key":"owned-request-key-0001","model":"client-choice"}`,
		`{"finding_id":"pid_88008001-0000-4000-8000-000000000001","finding_version":1,"idempotency_key":"owned-request-key-0001","organization_id":"foreign"}`,
		`{"finding_id":"pid_88008001-0000-4000-8000-000000000001","finding_version":1,"idempotency_key":"owned-request-key-0001","idempotency_key":"different-request-key"}`,
		`{"finding_id":"pid_88008001-0000-4000-8000-000000000001","finding_version":1,"idempotency_key":"owned-request-key-0001"} {}`,
	} {
		r := workflowRequest(t, identity, testCorrelationID, "createAIExplanation", nil, http.MethodPost, "/api/v1/ai/explanations", body)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "owned-request-key-0001")
		grant := RequestAuthorization{Identity: identity, OperationID: "createAIExplanation", Credential: CredentialBinding{Kind: CredentialBrowserSession}}
		r = r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, grant))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || sender.calls != 0 {
			t.Fatalf("untrusted input reached execution: status=%d sends=%d", w.Code, sender.calls)
		}
	}
	for _, operation := range []string{"createAIExplanation", "updateExternalDataFlows"} {
		r := workflowRequest(t, identity, testCorrelationID, operation, nil, http.MethodPost, "/api/v1/ai/explanations", `{}`)
		w := httptest.NewRecorder()
		(&optionalEgressHTTPHandler{next: handlerResponse("retained")}).ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("unconfigured optional route %s=%d", operation, w.Code)
		}
	}
}

func TestOptionalEgressChecksCurrentExactFindingAtEveryPhase(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	finding := "pid_88008001-0000-4000-8000-000000000001"
	target := AuthorizationTarget{Scope: identity.Scope, Kind: "finding", ID: finding, Version: 7}
	grant := RequestAuthorization{OperationID: "getFinding", Identity: identity, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "owned-session", Digest: [32]byte{1}}, Allowed: []AuthorizationTarget{target}}
	body, err := authorizationDecisionJSON(grant)
	if err != nil {
		t.Fatal(err)
	}
	grant.decisionDigest = sha256.Sum256(body)
	grant.attestation = json.RawMessage(`{"component-only":"opaque proof preserved"}`)
	checked := &optionalCheckedAuthorizer{grant: grant}
	authorizer := &optionalFindingAuthorizer{authorizer: checked, original: grant}
	intent := optionalegress.Intent{OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ActorID: identity.PrincipalID.String(), FindingID: finding, FindingVersion: 7}
	for _, phase := range []optionalegress.Phase{optionalegress.ReplayPhase, optionalegress.SourcePhase, optionalegress.ReservePhase, optionalegress.DispatchPhase} {
		if _, err := authorizer.Authorize(context.Background(), intent, phase); err != nil {
			t.Fatal("fresh exact check rejected", err)
		}
	}
	if len(checked.calls) != 4 {
		t.Fatal("phase reused a cached finding grant")
	}
	for _, route := range checked.calls {
		if route.OperationID != "getFinding" || route.PathParameters["id"] != finding {
			t.Fatal("phase checked another target")
		}
	}
	checked.grant.Allowed[0].Version = 8
	if _, err := authorizer.Authorize(context.Background(), intent, optionalegress.DispatchPhase); err == nil {
		t.Fatal("stale finding version authorized dispatch")
	}
	intent.OrganizationID = "foreign"
	before := len(checked.calls)
	if _, err := authorizer.Authorize(context.Background(), intent, optionalegress.DispatchPhase); err == nil || len(checked.calls) != before {
		t.Fatal("foreign scope reached authorization")
	}
	if strings.Contains(string(grant.attestation), "token") {
		t.Fatal("invalid component fixture")
	}
}
