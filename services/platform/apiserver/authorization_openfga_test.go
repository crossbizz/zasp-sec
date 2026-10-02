package apiserver

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"net/http"
	"net/http/httptest"
	"testing"
)

type authorizationTargetFixture struct{ targets AuthorizationTargets }

type authorizationTargetFunc func(context.Context, RequestIdentity, RoutedOperation) (AuthorizationTargets, error)

func (f authorizationTargetFunc) ResolveAuthorization(ctx context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
	return f(ctx, identity, route)
}

func TestP7AuthorizationScopeMetadata(t *testing.T) {
	for _, test := range []struct {
		name                               string
		environmentAllow, pat, ceilingView bool
	}{
		{"resource only", false, false, false},
		{"separate environment grant", true, false, false},
		{"PAT ceiling excludes view", true, true, false},
		{"PAT ceiling includes view", true, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			if test.pat {
				identity.CredentialKind = CredentialBearerToken
			}
			binding := CredentialBinding{Kind: identity.CredentialKind, ID: "metadata-credential", Digest: [32]byte{1}, PATCeiling: []string{"investigate_sessions"}}
			if test.ceilingView {
				binding.PATCeiling = append(binding.PATCeiling, "view")
			}
			revision := authorization.Revision{OrganizationID: identity.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
			session := AuthorizationTarget{Scope: identity.Scope, Kind: "session", ID: "pid_86000001-0000-4000-8000-000000000001", SourceID: "unattributed", Version: 1}
			environment := AuthorizationTarget{Scope: identity.Scope, Kind: "environment", ID: identity.Scope.EnvironmentID().String(), Version: 4}
			environmentChecks := 0
			a := &OpenFGAAuthorizer{AttestationKey: authorizationFixtureAttestor(t), StoreID: revision.StoreID, ModelID: revision.ModelID, Reader: authorizationRevisionFixture{revision},
				Resolver: authorizationTargetFunc(func(_ context.Context, _ RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
					if route.OperationID == "getEnvironment" && route.PathParameters["id"] == environment.ID {
						return AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{environment}}, nil
					}
					return AuthorizationTargets{Complete: true, Collection: true, Targets: []AuthorizationTarget{session}}, nil
				}),
				Checker: authorizationDecisionFunc(func(_ context.Context, request authorization.CheckRequest) (authorization.Decision, error) {
					allow := true
					if request.ResourceType == "environment" {
						environmentChecks++
						allow = test.environmentAllow
						if request.Permission != "view" {
							t.Fatal("wrong metadata permission")
						}
					}
					return authorization.Decision{Allowed: allow, ModelID: revision.ModelID}, nil
				}),
			}
			grant, err := a.Authorize(context.Background(), identity, binding, RoutedOperation{OperationID: "listSessions"})
			want := test.environmentAllow && (!test.pat || test.ceilingView)
			if err != nil || grant.EnvironmentView != want || len(grant.Allowed) != 1 || grant.Allowed[0] != session {
				t.Fatalf("scope metadata grant=%+v error=%v", grant, err)
			}
			if want && (len(grant.Targets) != 2 || grant.Targets[1] != environment) {
				t.Fatal("metadata environment version missing from commit fence")
			}
			if test.pat && !test.ceilingView && environmentChecks != 0 {
				t.Fatal("PAT view ceiling was bypassed")
			}
		})
	}
}

func (f authorizationTargetFixture) ResolveAuthorization(context.Context, RequestIdentity, RoutedOperation) (AuthorizationTargets, error) {
	return f.targets, nil
}

type requestAuthorizerFixture struct{ err error }

func (f requestAuthorizerFixture) Authorize(context.Context, RequestIdentity, CredentialBinding, RoutedOperation) (RequestAuthorization, error) {
	return RequestAuthorization{}, f.err
}

func TestP7AuthorizationRouterBoundary(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	identity.Permissions = []string{"view"}
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"current deny", ErrAuthorizationDenied, http.StatusForbidden},
		{"unavailable", authorization.ErrUnavailable, http.StatusServiceUnavailable},
		{"revision conflict", authorization.ErrConflict, http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler, err := NewRouter([]Operation{{Method: "GET", Pattern: "/api/v1/findings/{id}", OperationID: "getFinding", Permission: "view", Security: []CredentialKind{CredentialBearerToken}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })}})
			if err != nil {
				t.Fatal(err)
			}
			handler.(*operationRouter).authorizer = requestAuthorizerFixture{test.err}
			request := httptest.NewRequest("GET", "/api/v1/findings/pid_80000001-0000-4000-8000-000000000001", nil)
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if called || response.Code != test.status {
				t.Fatalf("old permission bypassed current boundary: called=%v status=%d", called, response.Code)
			}
		})
	}
}

type authorizationRevisionFixture struct{ revision authorization.Revision }

func (f authorizationRevisionFixture) Revision(context.Context, string) (authorization.Revision, error) {
	return f.revision, nil
}

type authorizationDecisionFixture struct {
	allow map[string]bool
	err   error
	model string
}

type authorizationDecisionFunc func(context.Context, authorization.CheckRequest) (authorization.Decision, error)

func (f authorizationDecisionFunc) Check(ctx context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	return f(ctx, q)
}

func TestP7AuthorizationCompliancePermissions(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	i.Permissions = []string{"view", "view_audit", "view_compliance"}
	first, second := "pid_84000001-0000-4000-8000-000000000001", "pid_84000002-0000-4000-8000-000000000002"
	rev := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	resolver := authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: i.Scope, Kind: "finding", ID: first}, {Scope: i.Scope, Kind: "finding", ID: second}}}}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-test", Digest: [32]byte{1}}
	for _, denied := range []string{"view", "view_audit", "view_compliance"} {
		t.Run(denied, func(t *testing.T) {
			checker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
				return authorization.Decision{Allowed: q.Permission != denied || q.ResourceID == first, ModelID: rev.ModelID}, nil
			})
			a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
			if _, err := a.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: "getComplianceEvidence"}); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("missing %s on second parent allowed disclosure: %v", denied, err)
			}
			collection := resolver
			collection.targets.Collection = true
			a.Resolver = collection
			g, err := a.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: "listComplianceEvidence"})
			if err != nil || len(g.Allowed) != 1 || g.Allowed[0].ID != first {
				t.Fatalf("mixed-parent collection not restricted: %+v %v", g.Allowed, err)
			}
		})
	}
}

func (f authorizationDecisionFixture) Check(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	return authorization.Decision{Allowed: f.allow[q.ResourceID], ModelID: f.model}, f.err
}

// Fails if current policy is replaced by old identity permissions, PAT ceiling
// is discarded, or an environment deny blocks a separately granted resource.
func TestP7AuthorizationCurrentPolicy(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.Permissions = []string{"view", "manage_findings"}
	resource := "pid_80000001-0000-4000-8000-000000000001"
	denied := "pid_80000002-0000-4000-8000-000000000002"
	revision := authorization.Revision{OrganizationID: identity.Scope.OrganizationID().String(), Desired: 5, Applied: 5, Generation: 2, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	target := AuthorizationTarget{Scope: identity.Scope, Kind: "finding", ID: resource, Version: 1}
	resolver := authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{target}}}
	checker := authorizationDecisionFixture{map[string]bool{resource: true}, nil, revision.ModelID}
	authorizer := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, Checker: checker, Resolver: resolver, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-test", Digest: [32]byte{1}}
	route := RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": resource}}
	grant, err := authorizer.Authorize(context.Background(), identity, credential, route)
	if err != nil || len(grant.Allowed) != 1 || grant.Allowed[0].ID != resource || grant.Revision != revision {
		t.Fatalf("current object grant missing: %#v %v", grant, err)
	}
	checker.allow = map[string]bool{}
	authorizer.Checker = checker
	if _, err := authorizer.Authorize(context.Background(), identity, credential, route); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatal("old permission allowed denied object", err)
	}
	checker.err = authorization.ErrUnavailable
	authorizer.Checker = checker
	if _, err := authorizer.Authorize(context.Background(), identity, credential, route); !errors.Is(err, authorization.ErrUnavailable) {
		t.Fatal("dependency failure did not fail closed", err)
	}
	checker.err = nil
	checker.allow = map[string]bool{resource: true}
	authorizer.Checker = checker
	identity.CredentialKind = CredentialBearerToken
	credential.Kind = CredentialBearerToken
	credential.PATCeiling = []string{"view"}
	route.OperationID = "updateFinding"
	if _, err := authorizer.Authorize(context.Background(), identity, credential, route); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatal("current allow expanded PAT", err)
	}
	identity.CredentialKind = CredentialBrowserSession
	credential.Kind = CredentialBrowserSession
	credential.PATCeiling = nil
	route = RoutedOperation{OperationID: "listFindings", PathParameters: map[string]string{}}
	resolver.targets.Collection = true
	resolver.targets.Targets = append(resolver.targets.Targets, AuthorizationTarget{Scope: identity.Scope, Kind: "finding", ID: denied, Version: 1})
	authorizer.Resolver = resolver
	grant, err = authorizer.Authorize(context.Background(), identity, credential, route)
	if err != nil || !grant.Collection || len(grant.Allowed) != 1 || grant.Allowed[0].ID != resource {
		t.Fatalf("resource-only collection authorization: %#v %v", grant, err)
	}
	resolver.targets.Complete = false
	authorizer.Resolver = resolver
	if _, err := authorizer.Authorize(context.Background(), identity, credential, route); !errors.Is(err, authorization.ErrUnavailable) {
		t.Fatal("incomplete candidate set returned as complete", err)
	}
	// Evidence may disclose more than one authoritative target. An object
	// response requires every disclosed target, never the union of permissions.
	resolver.targets.Complete = true
	resolver.targets.Collection = false
	authorizer.Resolver = resolver
	route.OperationID = "getComplianceEvidence"
	checker.allow = map[string]bool{resource: true, denied: true}
	authorizer.Checker = checker
	if grant, err = authorizer.Authorize(context.Background(), identity, credential, route); err != nil || len(grant.Allowed) != 2 {
		t.Fatalf("fully authorized multi-parent evidence rejected: %v", err)
	}
	checker.allow = map[string]bool{resource: true}
	authorizer.Checker = checker
	if _, err = authorizer.Authorize(context.Background(), identity, credential, route); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("one parent exposed another target: %v", err)
	}
}

func TestP7AuthorizationOperationTargets(t *testing.T) {
	for _, operation := range authorization.Operations() {
		policy, err := authorizationTargetPolicy(operation.ID)
		if err != nil || policy.Mode == "" {
			t.Errorf("operation has no explicit target policy: %s", operation.ID)
		}
		if operation.Permission != "" && policy.Mode == "credential" {
			t.Errorf("protected operation classified as credential: %s", operation.ID)
		}
	}
	if _, err := authorizationTargetPolicy("getUnknownResource"); err == nil {
		t.Fatal("unmapped resource borrowed scope permission")
	}
}
