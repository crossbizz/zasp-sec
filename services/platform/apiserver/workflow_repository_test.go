package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type workflowCallDatabase struct {
	response json.RawMessage
	err      error
	query    string
	args     []any
}

func (database *workflowCallDatabase) SchemaVersion(context.Context) (string, error) {
	return CoreSchemaVersion, nil
}
func (database *workflowCallDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	database.query, database.args = query, append([]any(nil), args...)
	return database.response, database.err
}
func (*workflowCallDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected exec")
}
func (*workflowCallDatabase) Close() error { return nil }

func TestWorkflowRepositoryListsAndGetsOnlyTheExactAuthorizedScope(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[]}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)

	page, err := repository.ListWorkflows(context.Background(), identity.Scope, "policy", "", "")
	if err != nil || string(page) != `{"items":[]}` {
		t.Fatalf("ListWorkflows = (%s, %v)", page, err)
	}
	want := []any{"policy", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), "", ""}
	if database.query != postgresWorkflowListSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("list query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresWorkflowListSQL, want)
	}

	database.response = json.RawMessage(`{"body":{"id":"policy-one"},"version":2,"secret_generation":0}`)
	value, err := repository.GetWorkflow(context.Background(), identity.Scope, "policy", "policy-one")
	if err != nil || value.Version != 2 || string(value.Body) != `{"id":"policy-one"}` {
		t.Fatalf("GetWorkflow = (%#v, %v)", value, err)
	}
	want = []any{"policy", "policy-one", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}
	if database.query != postgresWorkflowGetSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("get args = %#v, want %#v", database.args, want)
	}
}

func TestWorkflowRepositoryPagesSecurityAgentDefinitionsByStableID(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[{"id":"pid_40000001-0000-4000-8000-000000000001"}],"next_id":"pid_40000001-0000-4000-8000-000000000001"}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	after := "pid_40000000-0000-4000-8000-000000000000"

	page, err := repository.ListWorkflowPage(context.Background(), identity.Scope, "security_agent", after, 1)
	if err != nil || len(page.Items) != 1 || page.NextID != "pid_40000001-0000-4000-8000-000000000001" {
		t.Fatalf("ListWorkflowPage = (%#v, %v)", page, err)
	}
	want := []any{"security_agent", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), after, 1}
	if database.query != postgresWorkflowPageSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("page query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresWorkflowPageSQL, want)
	}
}

func TestWorkflowRepositoryMutationCarriesIdempotencyVersionAndAtomicAuditIdentity(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"body":{"id":"policy-one"},"version":3,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","replayed":false}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	mutation := WorkflowMutation{
		Action: "update", Kind: "policy", ID: "policy-one", Operation: "updatePolicy",
		IdempotencyKey: "idem-exact-request-1", ExpectedVersion: 2,
		Intent: json.RawMessage(`{"body":{"id":"policy-one"},"expected_version":2,"resource_id":"policy-one"}`), Body: json.RawMessage(`{"id":"policy-one"}`),
		AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}
	result, err := repository.MutateWorkflow(context.Background(), identity, mutation)
	if err != nil || result.Version != 3 || result.Replayed || result.AuditID != mutation.AuditID || result.CorrelationID != mutation.CorrelationID {
		t.Fatalf("MutateWorkflow = (%#v, %v)", result, err)
	}
	want := []any{
		"update", "policy", "policy-one", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(),
		identity.PrincipalID.String(), "updatePolicy", "idem-exact-request-1", int64(2), mutation.Intent, json.RawMessage(`{"id":"policy-one"}`), mutation.AuditID, mutation.CorrelationID,
	}
	if database.query != postgresWorkflowMutateSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("mutation query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresWorkflowMutateSQL, want)
	}
}

func TestWorkflowRepositoryAcceptsExactReplayWithOriginalAuditCorrelation(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"body":{"id":"policy-one"},"version":1,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","replayed":true}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	result, err := repository.MutateWorkflow(context.Background(), identity, WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-one", Operation: "createPolicy", IdempotencyKey: "idem-exact-request-1", Intent: json.RawMessage(`{"body":{"id":"policy-one"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"policy-one"}`), AuditID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc", CorrelationID: "pid_dddddddd-dddd-4ddd-8ddd-dddddddddddd"})
	if err != nil || !result.Replayed || result.AuditID != "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || result.CorrelationID != "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" {
		t.Fatalf("replay = (%#v, %v)", result, err)
	}
}

func TestWorkflowRepositoryRejectsMalformedMutationBeforeDatabaseAccess(t *testing.T) {
	database := &workflowCallDatabase{}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	for _, mutation := range []WorkflowMutation{
		{},
		{Action: "create", Kind: "policy", ID: "policy-one", Operation: "createPolicy", IdempotencyKey: "short", Body: json.RawMessage(`{}`), AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
		{Action: "update", Kind: "policy", ID: "policy-one", Operation: "updatePolicy", IdempotencyKey: "idem-exact-request-1", Body: json.RawMessage(`{}`), AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
	} {
		if _, err := repository.MutateWorkflow(context.Background(), identity, mutation); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("mutation %#v error = %v", mutation, err)
		}
	}
	if database.query != "" {
		t.Fatalf("malformed mutation reached database: %q", database.query)
	}
}

func TestWorkflowSecretFilterAllowsOpaqueReferencesButRejectsReadableValues(t *testing.T) {
	if containsSensitiveWorkflowField(json.RawMessage(`{"configuration":{"signing_secret_reference":"secret_ref_prod"}}`)) {
		t.Fatal("opaque secret reference was rejected")
	}
	for _, payload := range []json.RawMessage{
		json.RawMessage(`{"token":"readable"}`),
		json.RawMessage(`{"configuration":{"password":"readable"}}`),
		json.RawMessage(`{"provider_secret":"readable"}`),
	} {
		if !containsSensitiveWorkflowField(payload) {
			t.Fatalf("readable secret accepted: %s", payload)
		}
	}
}
