package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPostgresProductionBoundaryRunsMigrationsAndPersistsAcrossRestart(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDatabase := &integrationMigrationDatabase{connection: connection}
	runner, err := migrations.NewRunner(migrationDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(ctx); err != nil {
		t.Fatalf("baseline migration: %v", err)
	}
	if err := runner.UpCore(ctx); err != nil {
		t.Fatalf("core migration: %v", err)
	}
	if err := runner.UpWorkflows(ctx); err != nil {
		t.Fatalf("workflow migration: %v", err)
	}

	principal := integrationProductID(t, "pid_10000004-0000-4000-8000-000000000004")
	organization := integrationProductID(t, "pid_10000001-0000-4000-8000-000000000001")
	workspace := integrationProductID(t, "pid_10000002-0000-4000-8000-000000000002")
	environment := integrationProductID(t, "pid_10000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	workspace2 := integrationProductID(t, "pid_10000022-0000-4000-8000-000000000022")
	environment2 := integrationProductID(t, "pid_10000023-0000-4000-8000-000000000023")
	scope2, err := domain.NewScope(organization, workspace2, environment2)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := `{"capabilities":["inventory.read"],"principal":{"id":"pid_90000004-0000-4000-8000-000000000004","organization_id":"pid_90000001-0000-4000-8000-000000000001","organization_reference":"organization-attacker","member_reference":"member-attacker","role":"organization_admin","active":false}}`
	authoritativeBootstrap := `{"capabilities":["inventory.read"],"principal":{"id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","organization_reference":"organization-test-local","member_reference":"member-test-local","role":"security_admin","active":true}}`
	agents := `{"items":[]}`
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_core_payloads (organization_id, workspace_id, environment_id, operation, payload) VALUES ($1,$2,$3,$4,$5::jsonb),($1,$2,$3,$6,$7::jsonb)`, organization.String(), workspace.String(), environment.String(), "session_bootstrap:"+principal.String(), bootstrap, "agents", agents); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_core_payloads (organization_id, workspace_id, environment_id, operation, payload) VALUES ($1,$2,$3,'agents','{"items":[]}'::jsonb)`, organization.String(), workspace2.String(), environment2.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_authorized_scopes (principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES ($1,$2,$3,$4,'Production','["view","manage_workflows"]'::jsonb,true),($1,$2,$5,$6,'Staging','["view","manage_workflows"]'::jsonb,false)`, principal.String(), organization.String(), workspace.String(), environment.String(), workspace2.String(), environment2.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships (principal_id, organization_id, organization_reference, member_reference, role) VALUES ($1,$2,'organization-test-local','member-test-local','security_admin')`, principal.String(), organization.String()); err != nil {
		t.Fatal(err)
	}
	const pat = "production-api-token-with-at-least-32-bytes"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_product_api_tokens (token_digest, principal_id, organization_id, workspace_id, environment_id, permissions, expires_at) VALUES (digest($1, 'sha256'),$2,$3,$4,$5,'["view"]'::jsonb,$6)`, pat, principal.String(), organization.String(), workspace.String(), environment.String(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := repository.ResolveIdentity(ctx, stytchExternalPrincipal(t, time.Now().UTC().Add(time.Hour).Truncate(time.Second)))
	if err != nil || resolved.PrincipalID != principal || resolved.Scope != scope {
		t.Fatalf("resolved identity = (%#v, %v)", resolved, err)
	}
	identityState, err := repository.BeginIdentity(ctx, "/discovery/assets")
	if err != nil {
		t.Fatalf("begin identity: %v", err)
	}
	returnTo, err := repository.ConsumeIdentity(ctx, identityState)
	if err != nil || returnTo != "/discovery/assets" {
		t.Fatalf("consume identity = (%q, %v)", returnTo, err)
	}
	if _, err := repository.ConsumeIdentity(ctx, identityState); !errors.Is(err, ErrRepositoryAuthentication) {
		t.Fatalf("identity state replay = %v", err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("repository readiness: %v", err)
	}
	grant := SessionGrant{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_workflows"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	session, err := repository.CreateSession(ctx, grant)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err != nil || !identity.FreshAuthenticated {
		t.Fatalf("fresh session authenticate = (%#v, %v)", identity, err)
	}
	if identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: pat}); err != nil || identity.CSRFToken != "" || identity.FreshAuthenticated {
		t.Fatalf("PAT authenticate = (%#v, %v)", identity, err)
	}
	identity, _ := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session})
	if payload, err := repository.Bootstrap(ctx, identity); err != nil || !equalIntegrationJSON(payload, []byte(authoritativeBootstrap)) {
		t.Fatalf("bootstrap = (%s, %v)", payload, err)
	}
	if payload, err := repository.ListScopes(ctx, identity); err != nil || !strings.Contains(string(payload), workspace2.String()) {
		t.Fatalf("scope list = (%s, %v)", payload, err)
	}
	switched, err := repository.SwitchScope(ctx, identity, session, scope2)
	if err != nil || switched.Scope != scope2 || !switched.FreshAuthenticated {
		t.Fatalf("scope switch = (%#v, %v)", switched, err)
	}
	foreignOrganization := integrationProductID(t, "pid_20000001-0000-4000-8000-000000000001")
	foreignWorkspace := integrationProductID(t, "pid_20000002-0000-4000-8000-000000000002")
	foreignEnvironment := integrationProductID(t, "pid_20000003-0000-4000-8000-000000000003")
	foreignScope, _ := domain.NewScope(foreignOrganization, foreignWorkspace, foreignEnvironment)
	if _, err := repository.SwitchScope(ctx, switched, session, foreignScope); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("foreign scope switch = %v", err)
	}
	identity = switched
	if payload, err := repository.Read(ctx, scope, "agents"); err != nil || !equalIntegrationJSON(payload, []byte(agents)) {
		t.Fatalf("read = (%s, %v)", payload, err)
	}
	workflowIdentity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_workflows"}}
	workflowBody := json.RawMessage(`{"id":"policy-production","name":"Production boundary","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	workflowCreate := WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-production", Operation: "createPolicy", IdempotencyKey: "idem-production-policy-0001", Intent: json.RawMessage(`{"body":{"id":"policy-production"},"expected_version":0,"resource_id":""}`), Body: workflowBody, AuditID: "pid_30000001-0000-4000-8000-000000000001", CorrelationID: "pid_30000002-0000-4000-8000-000000000002"}
	createdWorkflow, err := repository.MutateWorkflow(ctx, workflowIdentity, workflowCreate)
	if err != nil || createdWorkflow.Version != 1 || createdWorkflow.Replayed {
		t.Fatalf("create workflow = (%#v, %v)", createdWorkflow, err)
	}
	replayMutation := workflowCreate
	replayMutation.AuditID = "pid_30000003-0000-4000-8000-000000000003"
	replayMutation.CorrelationID = "pid_30000004-0000-4000-8000-000000000004"
	replayedWorkflow, err := repository.MutateWorkflow(ctx, workflowIdentity, replayMutation)
	if err != nil || !replayedWorkflow.Replayed || replayedWorkflow.AuditID != workflowCreate.AuditID || replayedWorkflow.CorrelationID != workflowCreate.CorrelationID {
		t.Fatalf("replay workflow = (%#v, %v)", replayedWorkflow, err)
	}
	decisionID := "pid_30000005-0000-4000-8000-000000000005"
	decisionBody := json.RawMessage(`{"matches":1,"would_block":0,"example_session_ids":[],"_decision":{"id":"` + decisionID + `","policy_id":"policy-production","environment_id":"` + scope.EnvironmentID().String() + `","result":"monitor","correlation_id":"pid_30000006-0000-4000-8000-000000000006","at":"2026-08-18T12:00:00Z"}}`)
	decisionResult, err := repository.MutateWorkflow(ctx, workflowIdentity, WorkflowMutation{Action: "audit", Kind: "policy", ID: "policy-production", Operation: "simulatePolicy", IdempotencyKey: "idem-production-simulate-01", ExpectedVersion: 1, Intent: json.RawMessage(`{"body":{"events":[{"action":"write"}]},"expected_version":1,"resource_id":"policy-production"}`), Body: decisionBody, AuditID: "pid_30000007-0000-4000-8000-000000000007", CorrelationID: "pid_30000006-0000-4000-8000-000000000006"})
	if err != nil || bytes.Contains(decisionResult.Body, []byte(`"_decision"`)) {
		t.Fatalf("atomic policy simulation = (%s, %v)", decisionResult.Body, err)
	}
	decisionPage, err := repository.ListWorkflows(ctx, scope, "policy_decision", "policy_id", "policy-production")
	if err != nil || !bytes.Contains(decisionPage, []byte(decisionID)) || !bytes.Contains(decisionPage, []byte(`"result": "monitor"`)) {
		t.Fatalf("durable policy decision = (%s, %v)", decisionPage, err)
	}
	if payload, err := repository.ListWorkflows(ctx, foreignScope, "policy", "", ""); err != nil || !equalIntegrationJSON(payload, []byte(`{"items":[]}`)) {
		t.Fatalf("foreign workflow list = (%s, %v)", payload, err)
	}
	staleMutation := WorkflowMutation{Action: "update", Kind: "policy", ID: "policy-production", Operation: "updatePolicy", IdempotencyKey: "idem-stale-policy-000001", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"id":"policy-production"},"expected_version":2,"resource_id":"policy-production"}`), Body: workflowBody, AuditID: "pid_30000008-0000-4000-8000-000000000008", CorrelationID: "pid_30000009-0000-4000-8000-000000000009"}
	if _, err := repository.MutateWorkflow(ctx, workflowIdentity, staleMutation); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("stale workflow mutation = %v", err)
	}
	var auditCount, idempotencyCount int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE resource_id = 'policy-production'), (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation = 'createPolicy')`).Scan(&auditCount, &idempotencyCount); err != nil || auditCount != 2 || idempotencyCount != 1 {
		t.Fatalf("workflow ledger counts = (%d, %d, %v)", auditCount, idempotencyCount, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	restartedConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	restartedDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: restartedConnection})
	restartedRepository, _ := NewPostgresRepository(restartedDatabase)
	if persisted, err := restartedRepository.GetWorkflow(ctx, scope, "policy", "policy-production"); err != nil || persisted.Version != 1 || !equalIntegrationJSON(persisted.Body, workflowBody) {
		t.Fatalf("workflow did not survive repository restart = (%#v, %v)", persisted, err)
	}
	if _, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err != nil {
		t.Fatalf("session did not survive repository restart: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `UPDATE zasp_identity_memberships SET role = 'read_only_viewer' WHERE principal_id = $1 AND organization_id = $2`, principal.String(), organization.String()); err != nil {
		t.Fatalf("downgrade membership: %v", err)
	}
	if downgraded, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err != nil || !equalPermissionSets(downgraded.Permissions, []string{"view"}) {
		t.Fatalf("role-downgraded browser session = (%#v, %v)", downgraded, err)
	}
	if downgraded, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: pat}); err != nil || !equalPermissionSets(downgraded.Permissions, []string{"view"}) {
		t.Fatalf("role-downgraded PAT = (%#v, %v)", downgraded, err)
	}
	if _, err := restartedConnection.Exec(ctx, `UPDATE zasp_identity_memberships SET role = 'security_admin' WHERE principal_id = $1 AND organization_id = $2`, principal.String(), organization.String()); err != nil {
		t.Fatalf("restore membership for session revocation proof: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_workflow_records ADD COLUMN schema_drift text`); err != nil {
		t.Fatalf("introduce schema drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("schema drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_workflow_records DROP COLUMN schema_drift`); err != nil {
		t.Fatalf("remove schema drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); err != nil {
		t.Fatalf("restored schema readiness: %v", err)
	}
	if err := restartedRepository.Revoke(ctx, identity, session); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err == nil {
		t.Fatal("revoked session authenticated")
	}
	if err := restartedDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	rollbackConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rollbackConnection.Close(context.Background()) }()
	rollbackRunner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: rollbackConnection})
	if err := rollbackRunner.DownWorkflows(ctx); err != nil {
		t.Fatalf("workflow rollback: %v", err)
	}
	if err := rollbackRunner.DownCore(ctx); err != nil {
		t.Fatalf("core rollback: %v", err)
	}
	if err := rollbackRunner.Down(ctx); err != nil {
		t.Fatalf("baseline rollback: %v", err)
	}
	if state, err := rollbackRunner.State(ctx); err != nil || state.Applied() {
		t.Fatalf("rolled back state = (%#v, %v)", state, err)
	}
}

func TestWorkflowMigrationExpiresExistingSessionFreshness(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpCore(ctx); err != nil {
		t.Fatal(err)
	}
	const token = "old-live-session-with-at-least-32-bytes"
	principal := "pid_51000004-0000-4000-8000-000000000004"
	organization := "pid_51000001-0000-4000-8000-000000000001"
	workspace := "pid_51000002-0000-4000-8000-000000000002"
	environment := "pid_51000003-0000-4000-8000-000000000003"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships (principal_id,organization_id,organization_reference,member_reference,role) VALUES ($1,$2,'organization-old','member-old','security_admin')`, principal, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_authorized_scopes (principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES ($1,$2,$3,$4,'Old','["view","manage_workflows"]'::jsonb,true)`, principal, organization, workspace, environment); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_product_sessions (token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at) VALUES (digest($1,'sha256'),$2,$3,$4,$5,'["view","manage_workflows"]'::jsonb,$6,transaction_timestamp()+interval '1 hour')`, token, principal, organization, workspace, environment, strings.Repeat("c", 32)); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflows(ctx); err != nil {
		t.Fatal(err)
	}
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token})
	if err != nil || identity.FreshAuthenticated {
		t.Fatalf("pre-v3 session freshness = (%#v, %v)", identity, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedWorkflowMutationsReplayLostResponsesInPostgres(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpCore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflows(ctx); err != nil {
		t.Fatal(err)
	}
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	principal := integrationProductID(t, "pid_61000004-0000-4000-8000-000000000004")
	organization := integrationProductID(t, "pid_61000001-0000-4000-8000-000000000001")
	workspace := integrationProductID(t, "pid_61000002-0000-4000-8000-000000000002")
	environment := integrationProductID(t, "pid_61000003-0000-4000-8000-000000000003")
	scope, _ := domain.NewScope(organization, workspace, environment)
	identity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_workflows"}}
	sequence := 0
	assertReplay := func(mutation WorkflowMutation) WorkflowMutationResult {
		t.Helper()
		sequence++
		mutation.IdempotencyKey = fmt.Sprintf("idem-lost-response-%02d", sequence)
		mutation.AuditID = fmt.Sprintf("pid_62000001-0000-4000-8000-%012d", sequence)
		mutation.CorrelationID = fmt.Sprintf("pid_62000002-0000-4000-8000-%012d", sequence)
		created, err := repository.MutateWorkflow(ctx, identity, mutation)
		if err != nil {
			t.Fatalf("%s first result: %v", mutation.Operation, err)
		}
		replayed, found, err := repository.ReplayWorkflow(ctx, identity, mutation.Operation, mutation.IdempotencyKey, mutation.Intent)
		if err != nil || !found || !replayed.Replayed || replayed.AuditID != created.AuditID || replayed.CorrelationID != created.CorrelationID || replayed.Version != created.Version || !equalIntegrationJSON(replayed.Body, created.Body) {
			t.Fatalf("%s lost response = created %#v replay %#v found=%v err=%v", mutation.Operation, created, replayed, found, err)
		}
		return created
	}
	intent := func(id string, expected int64, body json.RawMessage) json.RawMessage {
		value, _ := json.Marshal(map[string]any{"resource_id": id, "expected_version": expected, "body": json.RawMessage(body)})
		return value
	}
	policyID := "policy-lost-response"
	policy := json.RawMessage(`{"id":"policy-lost-response","name":"Lost response","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	assertReplay(WorkflowMutation{Action: "create", Kind: "policy", ID: policyID, Operation: "createPolicy", Intent: intent("", 0, policy), Body: policy})
	updatedPolicy := json.RawMessage(`{"id":"policy-lost-response","name":"Updated","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	assertReplay(WorkflowMutation{Action: "update", Kind: "policy", ID: policyID, Operation: "updatePolicy", ExpectedVersion: 1, Intent: intent(policyID, 1, updatedPolicy), Body: updatedPolicy})
	decision := json.RawMessage(`{"matches":1,"would_block":0,"example_session_ids":[],"_decision":{"id":"pid_63000001-0000-4000-8000-000000000001","policy_id":"policy-lost-response","environment_id":"` + environment.String() + `","result":"monitor"}}`)
	assertReplay(WorkflowMutation{Action: "audit", Kind: "policy", ID: policyID, Operation: "simulatePolicy", ExpectedVersion: 2, Intent: intent(policyID, 2, json.RawMessage(`{"events":[{"action":"write"}]}`)), Body: decision})
	monitor := json.RawMessage(`{"id":"policy-lost-response","name":"Updated","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"monitor","failure_mode":"open","_target_environment_id":"` + environment.String() + `"}`)
	assertReplay(WorkflowMutation{Action: "update", Kind: "policy", ID: policyID, Operation: "rolloutPolicy", ExpectedVersion: 2, Intent: intent(policyID, 2, json.RawMessage(`{"state":"monitor","target_id":"`+environment.String()+`"}`)), Body: monitor})
	disabled := json.RawMessage(`{"id":"policy-lost-response","name":"Updated","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"disabled","failure_mode":"open","_target_environment_id":"` + environment.String() + `"}`)
	assertReplay(WorkflowMutation{Action: "update", Kind: "policy", ID: policyID, Operation: "disablePolicy", ExpectedVersion: 3, Intent: intent(policyID, 3, json.RawMessage(`{}`)), Body: disabled})
	assertReplay(WorkflowMutation{Action: "delete", Kind: "policy", ID: policyID, Operation: "deletePolicy", ExpectedVersion: 4, Intent: intent(policyID, 4, json.RawMessage(`{}`)), Body: json.RawMessage(`{}`)})

	integrationID := "pid_64000001-0000-4000-8000-000000000001"
	integration := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"generic-webhook","name":"Local","configuration":{"url":"https://example.invalid"},"status":"configured","created_at":"2026-08-18T12:00:00Z","updated_at":"2026-08-18T12:00:00Z"}`)
	assertReplay(WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", Intent: intent("", 0, json.RawMessage(`{"connector_key":"generic-webhook","name":"Local","configuration":{"url":"https://example.invalid"}}`)), Body: integration})
	assertReplay(WorkflowMutation{Action: "update", Kind: "integration", ID: integrationID, Operation: "updateIntegration", ExpectedVersion: 1, Intent: intent(integrationID, 1, json.RawMessage(`{"name":"Updated","configuration":{"url":"https://example.invalid"}}`)), Body: integration})
	assertReplay(WorkflowMutation{Action: "delete", Kind: "integration", ID: integrationID, Operation: "deleteIntegration", ExpectedVersion: 2, Intent: intent(integrationID, 2, json.RawMessage(`{}`)), Body: json.RawMessage(`{}`)})

	agentID := "pid_65000001-0000-4000-8000-000000000001"
	agent := json.RawMessage(`{"id":"` + agentID + `","name":"Definition","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + environment.String() + `"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":true}`)
	assertReplay(WorkflowMutation{Action: "create", Kind: "security_agent", ID: agentID, Operation: "createSecurityAgent", Intent: intent("", 0, agent), Body: agent})
	assertReplay(WorkflowMutation{Action: "update", Kind: "security_agent", ID: agentID, Operation: "updateSecurityAgent", ExpectedVersion: 1, Intent: intent(agentID, 1, agent), Body: agent})
	assertReplay(WorkflowMutation{Action: "delete", Kind: "security_agent", ID: agentID, Operation: "deleteSecurityAgent", ExpectedVersion: 2, Intent: intent(agentID, 2, json.RawMessage(`{}`)), Body: json.RawMessage(`{}`)})
	if sequence != 12 {
		t.Fatalf("replayed mutation count = %d", sequence)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func startDisposablePostgres(t *testing.T) string {
	t.Helper()
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	pgIsReady, readyErr := exec.LookPath("pg_isready")
	pgCtl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		t.Skip("local PostgreSQL binaries unavailable")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data).Run(); err != nil {
		t.Fatalf("initdb: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	var stderr bytes.Buffer
	command := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		stop := exec.Command(pgCtl, "-D", data, "-m", "fast", "-w", "stop")
		if err := stop.Run(); err != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		stopped = true
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if exec.Command(pgIsReady, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "zasp_test", "-d", "postgres").Run() == nil {
			return fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}

func integrationProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func equalIntegrationJSON(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

type integrationPostgresDriver struct{ connection *pgx.Conn }

func (driver *integrationPostgresDriver) QueryRow(ctx context.Context, statement string, arguments ...any) PostgresRow {
	return driver.connection.QueryRow(ctx, statement, arguments...)
}
func (driver *integrationPostgresDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := driver.connection.Exec(ctx, statement, arguments...)
	return err
}
func (driver *integrationPostgresDriver) Close() error {
	return driver.connection.Close(context.Background())
}

type integrationMigrationDatabase struct{ connection *pgx.Conn }

func (database *integrationMigrationDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return database.connection.QueryRow(ctx, statement, arguments...)
}
func (database *integrationMigrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	transaction, err := database.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &integrationMigrationTransaction{transaction: transaction}, nil
}

type integrationMigrationTransaction struct{ transaction pgx.Tx }

func (transaction *integrationMigrationTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return transaction.transaction.QueryRow(ctx, statement, arguments...)
}
func (transaction *integrationMigrationTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	_, err := transaction.transaction.Exec(ctx, statement, arguments...)
	return err
}
func (transaction *integrationMigrationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}
func (transaction *integrationMigrationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
