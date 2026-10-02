package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func integrationRejectionGrant(t *testing.T, operation string, kind CredentialKind) RequestAuthorization {
	t.Helper()
	i := fixtureRequestIdentity(t)
	i.Permissions = nil
	i.CredentialKind = kind
	id, targetKind := i.Scope.EnvironmentID().String(), "environment"
	parameters := map[string]string{}
	if operation == "updateIntegration" {
		id, targetKind = "pid_78100001-0000-4000-8000-000000000001", "integration"
		parameters["id"] = id
	}
	target := AuthorizationTarget{Scope: i.Scope, Kind: targetKind, ID: id, Version: 1}
	revision := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: kind, ID: "session-rejection", Digest: sha256.Sum256([]byte("rejection-current")), PATCeiling: []string{"manage_workflows"}}
	a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, Checker: authorizationDecisionFixture{allow: map[string]bool{id: true}, model: revision.ModelID}, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{target}}}, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	g, err := a.Authorize(context.Background(), i, credential, RoutedOperation{OperationID: operation, PathParameters: parameters})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The current caller must select purpose-bound reads, never generic legacy
// replay/get SQL or a made-up view permission for update preparation.
func TestP7IntegrationRejectionReadRouting(t *testing.T) {
	for _, operation := range []string{"createIntegration", "updateIntegration"} {
		for _, kind := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
			g := integrationRejectionGrant(t, operation, kind)
			i := g.Identity
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			db := &workflowCallDatabase{response: json.RawMessage(`{"found":false}`)}
			r := &PostgresRepository{database: db, currentAuthorization: true}
			intent := json.RawMessage(`{"body":{"name":"Rejected","connector_key":"github","configuration":{"provider_url":"https://private.invalid"}},"resource_id":"","expected_version":0}`)
			_, replayed, err := r.ReplayWorkflow(ctx, i, operation, "rejection-routing-0001", intent)
			want := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), operation, "rejection-routing-0001", intent}
			if err != nil || replayed || db.query != `SELECT zasp_authorization80.integration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)` || !reflect.DeepEqual(db.args, want) {
				t.Errorf("%s/%d replay query=%q args=%v replayed=%v error=%v", operation, kind, db.query, db.args, replayed, err)
			}
			if operation == "updateIntegration" {
				db.response = json.RawMessage(`{"body":{"connector_key":"github"},"version":1,"secret_generation":0}`)
				id := g.PathParameters["id"]
				_, err = r.GetWorkflow(ctx, i.Scope, "integration", id)
				want = []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), id}
				if err != nil || db.query != `SELECT zasp_authorization80.integration_update_value($1,$2,$3,$4)` || !reflect.DeepEqual(db.args, want) {
					t.Errorf("update/%d auxiliary read query=%q args=%v error=%v", kind, db.query, db.args, err)
				}
			}
		}
	}
}

type rejectionRoutingDatabase struct {
	workflowCallDatabase
	command IntegrationRejection
	calls   int
}

func (db *rejectionRoutingDatabase) AuditIntegrationRejection(_ context.Context, _ RequestIdentity, command IntegrationRejection) error {
	db.command = command
	db.calls++
	return nil
}

// Empty legacy identity permissions are deliberate. Only an intact original
// private grant can take this branch; a context-free legacy array cannot.
func TestP7IntegrationRejectionCurrentAdmission(t *testing.T) {
	for _, operation := range []string{"createIntegration", "updateIntegration"} {
		for _, kind := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
			g := integrationRejectionGrant(t, operation, kind)
			i := g.Identity
			command := IntegrationRejection{CredentialDigest: append([]byte(nil), g.Credential.Digest[:]...), Operation: operation, TargetID: g.Allowed[0].ID, AuditID: "pid_78100002-0000-4000-8000-000000000002", CorrelationID: "pid_78100003-0000-4000-8000-000000000003"}
			db := &rejectionRoutingDatabase{}
			r := &PostgresRepository{database: db, currentAuthorization: true}
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			if err := r.AuditIntegrationRejection(ctx, i, command); err != nil || db.calls != 1 || !reflect.DeepEqual(db.command, command) {
				t.Errorf("%s/%d current safe append admission error=%v calls=%d", operation, kind, err, db.calls)
			}
			before := db.calls
			legacy := i
			legacy.Permissions = []string{"manage_workflows"}
			if err := r.AuditIntegrationRejection(context.Background(), legacy, command); err == nil || db.calls != before {
				t.Error("enforcing repository fell back to legacy array without private proof")
			}
			before = db.calls
			bad := command
			bad.CredentialDigest = make([]byte, sha256.Size)
			if err := r.AuditIntegrationRejection(ctx, i, bad); err == nil || db.calls != before {
				t.Error("wrong digest reached auditor")
			}
			before = db.calls
			otherOperation := "createIntegration"
			if operation == otherOperation {
				otherOperation = "updateIntegration"
			}
			other := integrationRejectionGrant(t, otherOperation, kind)
			if err := r.AuditIntegrationRejection(context.WithValue(context.Background(), requestAuthorizationContextKey{}, other), i, command); err == nil || db.calls != before {
				t.Error("another original signed operation reached auditor")
			}
		}
	}
}

// Keep existing replay conflict propagation separate from rejection persistence.
func TestP7IntegrationRejectionReplayConflict(t *testing.T) {
	g := integrationRejectionGrant(t, "createIntegration", CredentialBrowserSession)
	db := &workflowCallDatabase{err: ErrRepositoryConflict}
	r := &PostgresRepository{database: db, currentAuthorization: true}
	_, found, err := r.ReplayWorkflow(context.WithValue(context.Background(), requestAuthorizationContextKey{}, g), g.Identity, g.OperationID, "rejection-conflict-0001", json.RawMessage(`{"body":{}}`))
	if found || !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("conflict found=%v error=%v", found, err)
	}
}

type checkedRejectionHTTPRepository struct {
	workflowRepositoryStub
	command IntegrationRejection
}

func (r *checkedRejectionHTTPRepository) GetWorkflow(context.Context, domain.Scope, string, string) (WorkflowValue, error) {
	return WorkflowValue{}, ErrRepositoryUnavailable
}
func (r *checkedRejectionHTTPRepository) AuditIntegrationRejection(_ context.Context, _ RequestIdentity, command IntegrationRejection) error {
	r.command = command
	return ErrRepositoryAuthentication
}

// A checked replay/preparation failure must reach the dedicated native append
// validator, which distinguishes expired credentials from hidden targets. A
// second generic GetWorkflow would hide that error behind its own fence result.
func TestP7IntegrationRejectionCheckedUpdateErrorPath(t *testing.T) {
	g := integrationRejectionGrant(t, "updateIntegration", CredentialBrowserSession)
	repository := &checkedRejectionHTTPRepository{}
	handler, _ := newWorkflowHTTPHandler(repository, []byte(strings.Repeat("k", 32)), nil)
	r := workflowRequest(t, g.Identity, testCorrelationID, g.OperationID, g.PathParameters, "PATCH", "/api/v1/integrations/"+g.PathParameters["id"], "")
	r = r.WithContext(context.WithValue(r.Context(), requestAuthorizationContextKey{}, g))
	r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "rejection-current"})
	w := httptest.NewRecorder()
	handler.writeIntegrationRejection(w, r, g.Identity, RoutedOperation{OperationID: g.OperationID, PathParameters: g.PathParameters}, json.RawMessage(`{"body":{"name":"Rejected","configuration":{"provider_url":"https://private.invalid"}}}`), ErrRepositoryConflict)
	if w.Code != 401 || repository.command.Operation != g.OperationID || repository.command.TargetID != g.PathParameters["id"] {
		t.Fatalf("checked update rejection lost native classification: status=%d command=%+v", w.Code, repository.command)
	}
}

func TestP7IntegrationRejectionPreparationWaitError(t *testing.T) {
	g := integrationRejectionGrant(t, "updateIntegration", CredentialBearerToken)
	ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
	db := &workflowCallDatabase{err: errors.Join(ErrRepositoryUnavailable, &pgconn.PgError{Code: "28000", Message: "integration rejection credential unavailable"})}
	r := &PostgresRepository{database: db, currentAuthorization: true}
	if _, _, err := r.ReplayWorkflow(ctx, g.Identity, g.OperationID, "rejection-wait-error-01", json.RawMessage(`{"body":{}}`)); !errors.Is(err, ErrRepositoryAuthentication) {
		t.Errorf("replay wait credential error=%v", err)
	}
	if _, err := r.GetWorkflow(ctx, g.Identity.Scope, "integration", g.PathParameters["id"]); !errors.Is(err, ErrRepositoryAuthentication) {
		t.Errorf("update wait credential error=%v", err)
	}
}

func TestP7IntegrationRejectionStatementBoundary(t *testing.T) {
	for _, operation := range []string{"createIntegration", "updateIntegration"} {
		g := integrationRejectionGrant(t, operation, CredentialBearerToken)
		i := g.Identity
		query := `SELECT zasp_authorization80.integration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`
		args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), operation, "rejection-classifier-key", json.RawMessage(`{"body":{}}`)}
		if !authorizationStatementAllowed(g, query, args) {
			t.Errorf("original %s replay refused", operation)
		}
		for _, index := range []int{0, 1, 2, 3, 4} {
			wrong := append([]any(nil), args...)
			wrong[index] = "other-purpose-or-scope"
			if authorizationStatementAllowed(g, query, wrong) {
				t.Errorf("replay admitted wrong argument%d", index+1)
			}
		}
		read := `SELECT zasp_authorization80.integration_update_value($1,$2,$3,$4)`
		readArgs := []any{args[0], args[1], args[2], "pid_78100001-0000-4000-8000-000000000001"}
		if authorizationStatementAllowed(g, read, readArgs) != (operation == "updateIntegration") {
			t.Errorf("auxiliary read purpose=%s", operation)
		}
		readArgs[3] = "pid_78100009-0000-4000-8000-000000000009"
		if authorizationStatementAllowed(g, read, readArgs) {
			t.Error("auxiliary read admitted other target")
		}
		if authorizationStatementAllowed(g, postgresWorkflowGetSQL, readArgs) || authorizationStatementAllowed(g, postgresWorkflowReplaySQL, args) {
			t.Error("legacy SQL was admitted")
		}
	}
}
