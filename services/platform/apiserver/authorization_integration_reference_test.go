package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func referenceStatementGrant(t *testing.T) RequestAuthorization {
	t.Helper()
	i := fixtureRequestIdentity(t)
	i.FreshAuthenticated = true
	i.Permissions = nil
	id := integrationClientExisting
	target := AuthorizationTarget{Scope: i.Scope, Kind: "integration", ID: id, Version: 4}
	revision := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-reference", Digest: sha256.Sum256([]byte("reference-current"))}
	a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, Checker: authorizationDecisionFixture{allow: map[string]bool{id: true}, model: revision.ModelID}, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{target}}}, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	g, err := a.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: "authorizeIntegrationReference", PathParameters: map[string]string{"id": id}})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestP7IntegrationReferenceStatementBoundary(t *testing.T) {
	g := referenceStatementGrant(t)
	i := g.Identity
	f := &integrationClientFixture{browser: i}
	args := f.referenceNativeArgs(integrationClientExisting, "reference-statement-key", 2)
	for _, tc := range []struct {
		query string
		args  []any
	}{
		{postgresCurrentReferenceValueSQL, []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), integrationClientExisting}},
		{postgresCurrentReferenceReplaySQL, []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), integrationClientExisting, "reference-statement-key", int64(2)}},
		{postgresCurrentReferenceCompleteSQL, args},
	} {
		if !authorizationStatementAllowed(g, tc.query, tc.args) {
			t.Fatalf("valid original-operation query denied: %s", tc.query)
		}
		for index := range tc.args {
			if index > 4 {
				continue
			}
			changed := append([]any(nil), tc.args...)
			changed[index] = "foreign"
			if authorizationStatementAllowed(g, tc.query, changed) {
				t.Errorf("scope/actor/path substitution %d admitted by %s", index, tc.query)
			}
		}
	}
	for _, change := range []struct {
		index int
		value any
	}{
		{5, "github"}, {6, integrationClientExisting}, {9, int64(0)},
		{11, json.RawMessage(`{"expected_version":2}`)},
		{10, json.RawMessage(`{"role_arn":"substituted"}`)},
		{8, "different-reference-key"},
	} {
		bad := append([]any(nil), args...)
		bad[change.index] = change.value
		if authorizationStatementAllowed(g, postgresCurrentReferenceCompleteSQL, bad) {
			t.Errorf("completion substitution %d admitted", change.index)
		}
	}
	for _, query := range []string{postgresReplayReferenceAuthorizationSQL, postgresExecutionCompleteReferenceSQL, postgresCompleteReferenceAuthorizationSQL, postgresWorkflowGetSQL} {
		if authorizationStatementAllowed(g, query, args) {
			t.Errorf("legacy query admitted: %s", query)
		}
	}
}

func TestP7IntegrationReferenceReadRouting(t *testing.T) {
	g := referenceStatementGrant(t)
	i := g.Identity
	ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
	db := &workflowCallDatabase{response: json.RawMessage(`{"found":false,"result":null}`)}
	reference := &ReferenceAuthorizationRepository{database: db}
	_, found, err := reference.Replay(ctx, i, ReferenceAuthorizationReplay{IntegrationID: integrationClientExisting, IdempotencyKey: "reference-routing-key", ExpectedVersion: 2})
	if err != nil || found || db.query != postgresCurrentReferenceReplaySQL {
		t.Fatalf("original replay query=%s found=%t %v", db.query, found, err)
	}
	db.response = json.RawMessage(`{"body":{"id":"` + integrationClientExisting + `"},"version":2,"secret_generation":0}`)
	workflows := &PostgresRepository{database: db, currentAuthorization: true}
	_, err = workflows.GetWorkflow(ctx, i.Scope, "integration", integrationClientExisting)
	if err != nil || db.query != postgresCurrentReferenceValueSQL {
		t.Fatalf("manage-only preparation query=%s %v", db.query, err)
	}
}
