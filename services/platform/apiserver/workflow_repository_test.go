package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
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
	database := &workflowCallDatabase{response: json.RawMessage(`{"body":{"id":"policy-one"},"version":3,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","receipt_id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","replayed":false}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	mutation := WorkflowMutation{
		Action: "update", Kind: "policy", ID: "policy-one", Operation: "updatePolicy",
		IdempotencyKey: "idem-exact-request-1", ExpectedVersion: 2,
		Intent: json.RawMessage(`{"body":{"id":"policy-one"},"expected_version":2,"resource_id":"policy-one"}`), Body: json.RawMessage(`{"id":"policy-one"}`),
		AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	}
	result, err := repository.MutateWorkflow(context.Background(), identity, mutation)
	if err != nil || result.Version != 3 || result.Replayed || result.AuditID != mutation.AuditID || result.CorrelationID != mutation.CorrelationID {
		t.Fatalf("MutateWorkflow = (%#v, %v)", result, err)
	}
	want := []any{
		"update", "policy", "policy-one", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(),
		identity.PrincipalID.String(), "updatePolicy", "idem-exact-request-1", int64(2), mutation.Intent, json.RawMessage(`{"id":"policy-one"}`), mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID,
	}
	if database.query != postgresWorkflowMutateSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("mutation query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresWorkflowMutateSQL, want)
	}
}

func TestWorkflowRepositoryPATMutationAndReplayRequireNoReceiptIdentity(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	response := json.RawMessage(`{"body":{"id":"policy-one"},"version":1,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","replayed":false}`)
	database := &workflowCallDatabase{response: response}
	repository, _ := NewPostgresRepository(database)
	mutation := WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-one", Operation: "createPolicy", IdempotencyKey: "idem-pat-request-0001", Intent: json.RawMessage(`{"body":{"id":"policy-one"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"policy-one"}`), AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
	result, err := repository.MutateWorkflow(context.Background(), identity, mutation)
	if err != nil || result.ReceiptID != "" {
		t.Fatalf("PAT mutation = (%#v, %v)", result, err)
	}
	if got := database.args[len(database.args)-1]; got != "" {
		t.Fatalf("PAT receipt argument = %#v", got)
	}

	database.response = json.RawMessage(`{"found":true,"result":{"body":{"id":"policy-one"},"version":1,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","replayed":true}}`)
	replayed, found, err := repository.ReplayWorkflow(context.Background(), identity, mutation.Operation, mutation.IdempotencyKey, mutation.Intent)
	if err != nil || !found || !replayed.Replayed || replayed.ReceiptID != "" {
		t.Fatalf("PAT replay = (%#v, %v, %v)", replayed, found, err)
	}
}

func TestWorkflowRepositoryCleansExpiredReceiptsWithAnExactBound(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"deleted":1000}`)}
	repository, _ := NewPostgresRepository(database)
	deleted, err := repository.CleanupExpiredWorkflowMutationReceipts(context.Background(), 1000)
	if err != nil || deleted != 1000 || database.query != postgresWorkflowReceiptCleanupSQL || !reflect.DeepEqual(database.args, []any{1000}) {
		t.Fatalf("cleanup = (%d, %v) query=%q args=%#v", deleted, err, database.query, database.args)
	}
	database.query = ""
	if _, err := repository.CleanupExpiredWorkflowMutationReceipts(context.Background(), 1001); !errors.Is(err, ErrRepositoryOperation) || database.query != "" {
		t.Fatalf("unbounded cleanup = %v query=%q", err, database.query)
	}
}

func TestWorkflowRepositoryReadinessRunsOneBoundedReceiptCleanup(t *testing.T) {
	database := &round4ReadinessDatabase{responses: map[string]json.RawMessage{
		postgresWorkflowReceiptCleanupSQL: json.RawMessage(`{"deleted":0}`),
		postgresRevealGrantCleanupSQL:     json.RawMessage(`{"cleaned":0}`),
	}, errors: map[string]error{}}
	repository, _ := NewPostgresRepository(database)
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if len(database.queries) != 2 || database.queries[0] != postgresWorkflowReceiptCleanupSQL {
		t.Fatalf("readiness cleanup queries=%#v", database.queries)
	}
	database.responses[postgresWorkflowReceiptCleanupSQL] = json.RawMessage(`{"deleted":1001}`)
	if err := repository.Ready(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unbounded readiness cleanup error = %v", err)
	}
}

func TestWorkflowRepositoryListsAndAcknowledgesOnlyExactPrincipalScopeReceipts(t *testing.T) {
	created := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	expires := created.Add(7 * 24 * time.Hour)
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[{"id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","operation":"createPolicy","idempotency_key":"idem-exact-request-1","intent":{"body":{"id":"policy-one"},"expected_version":0,"resource_id":""},"result":{"id":"policy-one"},"resource_kind":"policy","resource_id":"policy-one","resource_version":1,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","created_at":"2026-08-18T12:00:00Z","expires_at":"2026-08-25T12:00:00Z"}]}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)

	receipts, err := repository.ListWorkflowMutationReceipts(context.Background(), identity, 20)
	if err != nil || len(receipts) != 1 || receipts[0].CreatedAt != created || receipts[0].ExpiresAt != expires || receipts[0].Operation != "createPolicy" || string(receipts[0].Result) != `{"id":"policy-one"}` {
		t.Fatalf("ListWorkflowMutationReceipts = (%#v, %v)", receipts, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), 20}
	if database.query != postgresWorkflowReceiptListSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("receipt list query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresWorkflowReceiptListSQL, want)
	}

	database.response = json.RawMessage(`{"acknowledged":true}`)
	if err := repository.AcknowledgeWorkflowMutationReceipt(context.Background(), identity, "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"); err != nil {
		t.Fatalf("AcknowledgeWorkflowMutationReceipt: %v", err)
	}
	want = []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
	if database.query != postgresWorkflowReceiptAcknowledgeSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("receipt acknowledge query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresWorkflowReceiptAcknowledgeSQL, want)
	}
}

func TestWorkflowRepositoryListsExactFindingRecoveryReceipt(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[{"id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","operation":"updateFinding","idempotency_key":"idem-risk-recovery-0001","intent":{"body":{"status":"under_review"},"expected_version":1,"resource_id":"pid_30000001-0000-4000-8000-000000000001"},"result":{"id":"pid_30000001-0000-4000-8000-000000000001","source":"posture","title":"Recover me","severity":"high","status":"under_review","evidence_ids":["pid_30000002-0000-4000-8000-000000000002"],"risk_factors":[],"version":2,"created_at":"2026-08-18T05:00:00-07:00","updated_at":"2026-08-18T05:01:00-07:00"},"resource_kind":"finding","resource_id":"pid_30000001-0000-4000-8000-000000000001","resource_version":2,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","created_at":"2026-08-18T12:00:00Z","expires_at":"2026-08-25T12:00:00Z"}]}`)}
	repository, _ := NewPostgresRepository(database)
	receipts, err := repository.ListWorkflowMutationReceipts(context.Background(), fixtureRequestIdentity(t), 20)
	if err != nil || len(receipts) != 1 || receipts[0].ResourceKind != "finding" || receipts[0].Operation != "updateFinding" || !bytes.Contains(receipts[0].Result, []byte(`"created_at":"2026-08-18T12:00:00Z"`)) || bytes.Contains(receipts[0].Result, []byte(`-07:00`)) {
		t.Fatalf("finding recovery receipt = (%#v, %v)", receipts, err)
	}
}

func TestWorkflowRepositoryRejectsMalformedOrExpiredReceiptPayloads(t *testing.T) {
	for name, payload := range map[string]json.RawMessage{
		"expired":           json.RawMessage(`{"items":[{"id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","operation":"createPolicy","idempotency_key":"idem-exact-request-1","intent":{},"result":{},"resource_kind":"policy","resource_id":"policy-one","resource_version":1,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","created_at":"2026-08-25T12:00:00Z","expires_at":"2026-08-18T12:00:00Z"}]}`),
		"extra envelope":    json.RawMessage(`{"items":[],"unexpected":true}`),
		"foreign operation": json.RawMessage(`{"items":[{"id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","operation":"unexpectedMutation","idempotency_key":"idem-exact-request-1","intent":{},"result":{},"resource_kind":"policy","resource_id":"policy-one","resource_version":1,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","created_at":"2026-08-18T12:00:00Z","expires_at":"2026-08-25T12:00:00Z"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			repository, _ := NewPostgresRepository(&workflowCallDatabase{response: payload})
			if _, err := repository.ListWorkflowMutationReceipts(context.Background(), fixtureRequestIdentity(t), 20); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("malformed receipt error = %v", err)
			}
		})
	}
}

func TestWorkflowRepositoryRejectsReplayWithoutOriginalReceiptIdentity(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"found":true,"result":{"body":{"id":"policy-one"},"version":1,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","replayed":true}}`)}
	repository, _ := NewPostgresRepository(database)
	result, found, err := repository.ReplayWorkflow(context.Background(), fixtureRequestIdentity(t), "createPolicy", "idem-exact-request-1", json.RawMessage(`{"body":{"id":"policy-one"},"expected_version":0,"resource_id":""}`))
	if !errors.Is(err, ErrRepositoryUnavailable) || found || !reflect.DeepEqual(result, WorkflowMutationResult{}) {
		t.Fatalf("replay without receipt identity = (%#v, %v, %v)", result, found, err)
	}
}

func TestWorkflowRepositoryAcceptsExactReplayWithOriginalAuditCorrelation(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"body":{"id":"policy-one"},"version":1,"secret_generation":0,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","receipt_id":"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","replayed":true}`)}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	result, err := repository.MutateWorkflow(context.Background(), identity, WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-one", Operation: "createPolicy", IdempotencyKey: "idem-exact-request-1", Intent: json.RawMessage(`{"body":{"id":"policy-one"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"policy-one"}`), AuditID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc", CorrelationID: "pid_dddddddd-dddd-4ddd-8ddd-dddddddddddd", ReceiptID: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"})
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
