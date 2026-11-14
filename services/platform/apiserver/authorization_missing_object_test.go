package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// A read of one object by ID whose object is not in the caller's scope
// answers "not found" only to a caller that holds the operation's permission
// on the Environment itself. Everyone else and every other operation keep the
// refusal; a check that cannot be decided is reported as undecided.
func TestMissingObjectAnswersNotFoundOnlyToAnEnvironmentReader(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	i.Permissions = []string{"view"}
	environment := i.Scope.EnvironmentID().String()
	rev := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-test", Digest: [32]byte{1}}
	missing := authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{}}}
	route := func(operation string) RoutedOperation {
		return RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": "pid_84000009-0000-4000-8000-000000000009"}}
	}
	for _, test := range []struct {
		name, operation string
		reader          authorization.Revision
		allowed         bool
		checkErr        error
		want            error
	}{
		{"policy, environment reader", "getPolicy", rev, true, nil, ErrRepositoryNotFound},
		{"integration, environment reader", "getIntegration", rev, true, nil, ErrRepositoryNotFound},
		{"agent, environment reader", "getSecurityAgent", rev, true, nil, ErrRepositoryNotFound},
		{"finding, environment reader", "getFinding", rev, true, nil, ErrRepositoryNotFound},
		{"inventory agent, environment reader", "getAgent", rev, true, nil, ErrRepositoryNotFound},
		{"inventory tool, environment reader", "getTool", rev, true, nil, ErrRepositoryNotFound},
		{"inventory identity, environment reader", "getIdentity", rev, true, nil, ErrRepositoryNotFound},
		{"inventory runtime, environment reader", "getRuntime", rev, true, nil, ErrRepositoryNotFound},
		{"inventory asset, environment reader", "getAsset", rev, true, nil, ErrRepositoryNotFound},
		{"inventory agent, no environment permission", "getAgent", rev, false, nil, ErrAuthorizationDenied},
		{"an agent sub-read keeps the refusal", "getAgentCapabilities", rev, true, nil, ErrAuthorizationDenied},
		{"finding, no environment permission", "getFinding", rev, false, nil, ErrAuthorizationDenied},
		// An undecided check is neither "not found" nor "forbidden".
		{"finding, check failed", "getFinding", rev, true, authorization.ErrUnavailable, authorization.ErrUnavailable},
		{"finding, projection pending", "getFinding", authorization.Revision{OrganizationID: rev.OrganizationID, Desired: 2, Applied: 1, Generation: 1, StoreID: rev.StoreID, ModelID: rev.ModelID}, true, nil, authorization.ErrPending},
		{"a write keeps the refusal", "updateFinding", rev, true, nil, ErrAuthorizationDenied},
		{"another read keeps the refusal", "getIntegrationSetupStatus", rev, true, nil, ErrAuthorizationDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			var checked []authorization.CheckRequest
			checker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
				checked = append(checked, q)
				return authorization.Decision{Allowed: test.allowed, ModelID: rev.ModelID}, test.checkErr
			})
			a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{test.reader}, Checker: checker, Resolver: missing, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
			_, err := a.Authorize(context.Background(), i, credential, route(test.operation))
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v want %v", err, test.want)
			}
			// Only the caller's own Environment is ever asked about.
			for _, q := range checked {
				if q.ResourceType != "environment" || q.ResourceID != environment || q.EnvironmentID != environment || q.PrincipalID != i.PrincipalID.String() || q.OrganizationID != i.Scope.OrganizationID().String() {
					t.Fatalf("unexpected check %+v", q)
				}
			}
			if errors.Is(test.want, ErrRepositoryNotFound) && len(checked) != 1 {
				t.Fatalf("checks=%d", len(checked))
			}
		})
	}
	// A bearer token whose ceiling lacks the permission is refused before
	// anything is resolved.
	token := i
	token.CredentialKind = CredentialBearerToken
	a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: true, ModelID: rev.ModelID}, nil
	}), Resolver: missing, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	if _, err := a.Authorize(context.Background(), token, CredentialBinding{Kind: CredentialBearerToken, ID: "token-test", Digest: [32]byte{2}, PATCeiling: []string{"manage_workflows"}}, route("getFinding")); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("ceiling err=%v", err)
	}
}
