package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
	if err := runner.UpWorkflowReceipts(ctx); err != nil {
		t.Fatalf("workflow receipt migration: %v", err)
	}
	if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
		t.Fatalf("workflow receipt safety migration: %v", err)
	}
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatalf("workflow receipt provenance migration: %v", err)
	}
	if err := runner.UpProductionAdministration(ctx); err != nil {
		t.Fatalf("production administration migration: %v", err)
	}
	if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
		t.Fatalf("API token reveal grants migration: %v", err)
	}
	fingerprintQuery := postgresSchemaVersionSQL[:strings.Index(postgresSchemaVersionSQL, "SELECT metadata.value")] + "SELECT value FROM semantic_fingerprint"
	var actualFingerprint string
	if err := connection.QueryRow(ctx, fingerprintQuery).Scan(&actualFingerprint); err != nil {
		t.Fatalf("semantic fingerprint query: %v", err)
	}
	if actualFingerprint != expectedCoreSchemaFingerprint() {
		t.Fatalf("semantic fingerprint = %q, migration marker = %q", actualFingerprint, expectedCoreSchemaFingerprint())
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
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Test organization','test.invalid')`, []any{organization.String()}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Production'),($3,$1,'Staging')`, []any{organization.String(), workspace.String(), workspace2.String()}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($4,$1,$2,'Production','production'),($5,$1,$3,'Staging','staging')`, []any{organization.String(), workspace.String(), workspace2.String(), environment.String(), environment2.String()}},
		{`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$4,'production','metadata_only',30,true),($1,$3,$5,'staging','metadata_only',30,true)`, []any{organization.String(), workspace.String(), workspace2.String(), environment.String(), environment2.String()}},
		{`INSERT INTO zasp_compliance_controls(organization_id,id,framework,name,fresh_until) VALUES($1,'access-control','SOC 2','Logical access controls',transaction_timestamp()+interval '24 hours')`, []any{organization.String()}},
		{`INSERT INTO zasp_compliance_evidence(organization_id,control_id,id,asset_id,source,at) VALUES($1,'access-control','membership-test',$2,'product-membership',transaction_timestamp())`, []any{organization.String(), principal.String()}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatal(err)
		}
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
	patIdentity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: pat})
	if err != nil || patIdentity.CSRFToken != "" || patIdentity.FreshAuthenticated {
		t.Fatalf("PAT authenticate = (%#v, %v)", patIdentity, err)
	}
	identity, _ := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session})
	organizationPayload, err := repository.ReadAdministration(ctx, identity, "getOrganization", nil)
	if err != nil || !strings.Contains(string(organizationPayload), `"domain": "test.invalid"`) {
		t.Fatalf("durable organization = (%s, %v)", organizationPayload, err)
	}
	createdWorkspace, err := repository.MutateAdministration(ctx, identity, administrationMutation{Operation: "createWorkspace", ID: "pid_11000002-0000-4000-8000-000000000002", Name: "Engineering", AuditID: "pid_31000001-0000-4000-8000-000000000001"})
	if err != nil || !strings.Contains(string(createdWorkspace), `"Engineering"`) {
		t.Fatalf("create workspace = (%s, %v)", createdWorkspace, err)
	}
	if _, err := repository.MutateAdministration(ctx, identity, administrationMutation{Operation: "updateWorkspace", ID: "pid_11000002-0000-4000-8000-000000000002", Name: "Stale update", ExpectedVersion: 2, AuditID: "pid_31000009-0000-4000-8000-000000000009"}); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("stale workspace precondition = %v", err)
	}
	createdEnvironment, err := repository.MutateAdministration(ctx, identity, administrationMutation{Operation: "createEnvironment", ID: "pid_11000003-0000-4000-8000-000000000003", WorkspaceID: workspace.String(), Name: "Development", AuditID: "pid_31000002-0000-4000-8000-000000000002"})
	if err != nil || !strings.Contains(string(createdEnvironment), `"Development"`) {
		t.Fatalf("create environment = (%s, %v)", createdEnvironment, err)
	}
	const createdRawToken = "zasp_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	createdMutation := administrationMutation{Operation: "createAPIToken", ID: "pid_11000005-0000-4000-8000-000000000005", Name: "Automation", WorkspaceID: workspace.String(), EnvironmentID: environment.String(), Permissions: json.RawMessage(`["view"]`), ExpiresAt: time.Now().UTC().Add(time.Hour), IdempotencyKey: "idem-admin-token-0001", GrantID: "pid_41000003-0000-4000-8000-000000000003", AuditID: "pid_31000003-0000-4000-8000-000000000003", revealKey: []byte("0123456789abcdef0123456789abcdef")}
	if err := prepareAPITokenReveal(identity, &createdMutation, createdMutation.Operation, createdRawToken, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	createdToken, err := repository.MutateAdministration(ctx, identity, createdMutation)
	if err != nil || strings.Contains(string(createdToken), createdRawToken) {
		t.Fatalf("create token = (%s, %v)", createdToken, err)
	}
	if replayed, err := repository.MutateAdministration(ctx, identity, createdMutation); err != nil || !bytes.Equal(replayed, createdToken) {
		t.Fatalf("lost create response reconciliation = (%s, %v)", replayed, err)
	}
	createdEnvelopePayload, err := repository.ReadAdministration(ctx, identity, "revealAPIToken", map[string]string{"id": createdMutation.GrantID})
	var createdEnvelope apiTokenRevealEnvelope
	if err != nil || json.Unmarshal(createdEnvelopePayload, &createdEnvelope) != nil {
		t.Fatalf("created token reveal envelope = (%s, %v)", createdEnvelopePayload, err)
	}
	if revealed, err := decryptAPITokenReveal(createdMutation.revealKey, identity, createdEnvelope); err != nil || revealed != createdRawToken {
		t.Fatalf("lost reveal response reconciliation = (%q, %v, %#v)", revealed, err, createdEnvelope)
	}
	conflictingMutation := administrationMutation{Operation: "createAPIToken", ID: "pid_11000006-0000-4000-8000-000000000006", Name: "Automation replay", WorkspaceID: workspace.String(), EnvironmentID: environment.String(), Permissions: json.RawMessage(`["view"]`), ExpiresAt: time.Now().UTC().Add(time.Hour), IdempotencyKey: "idem-admin-token-0001", GrantID: "pid_41000004-0000-4000-8000-000000000004", AuditID: "pid_31000004-0000-4000-8000-000000000004", revealKey: []byte("0123456789abcdef0123456789abcdef")}
	if err := prepareAPITokenReveal(identity, &conflictingMutation, conflictingMutation.Operation, "zasp_pat_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.MutateAdministration(ctx, identity, conflictingMutation); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("one-time token replay = %v", err)
	}
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: createdRawToken}); err != nil {
		t.Fatalf("created token authentication: %v", err)
	}
	const rotatedRawToken = "zasp_pat_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	rotatedMutation := administrationMutation{Operation: "rotateAPIToken", ID: "pid_11000005-0000-4000-8000-000000000005", ReplacementID: "pid_11000007-0000-4000-8000-000000000007", ExpectedVersion: 1, IdempotencyKey: "idem-admin-rotate-0001", GrantID: "pid_41000005-0000-4000-8000-000000000005", AuditID: "pid_31000005-0000-4000-8000-000000000005", revealKey: []byte("0123456789abcdef0123456789abcdef")}
	if err := prepareAPITokenReveal(identity, &rotatedMutation, rotatedMutation.Operation, rotatedRawToken, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rotatedToken, err := repository.MutateAdministration(ctx, identity, rotatedMutation)
	if err != nil || strings.Contains(string(rotatedToken), rotatedRawToken) {
		t.Fatalf("rotate token = (%s, %v)", rotatedToken, err)
	}
	if _, err := repository.ReadAdministration(ctx, identity, "revealAPIToken", map[string]string{"id": createdMutation.GrantID}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("rotation left old reveal grant usable: %v", err)
	}
	rotatedEnvelopePayload, err := repository.ReadAdministration(ctx, identity, "revealAPIToken", map[string]string{"id": rotatedMutation.GrantID})
	var rotatedEnvelope apiTokenRevealEnvelope
	if err != nil || json.Unmarshal(rotatedEnvelopePayload, &rotatedEnvelope) != nil {
		t.Fatalf("rotated token reveal envelope = (%s, %v)", rotatedEnvelopePayload, err)
	}
	if revealed, err := decryptAPITokenReveal(rotatedMutation.revealKey, identity, rotatedEnvelope); err != nil || revealed != rotatedRawToken {
		t.Fatalf("rotated reveal = (%q, %v)", revealed, err)
	}
	tokenIdentity := identity
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: createdRawToken}); !errors.Is(err, ErrRepositoryAuthentication) {
		t.Fatalf("rotated old token authentication = %v", err)
	}
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: rotatedRawToken}); err != nil {
		t.Fatalf("replacement token authentication: %v", err)
	}
	dataControls, err := repository.MutateAdministration(ctx, identity, administrationMutation{Operation: "updateDataControls", EnvironmentID: environment.String(), EnvironmentClass: "production", CollectionMode: "metadata_only", RetentionDays: 60, DeletionEnabled: true, ExpectedVersion: 1, AuditID: "pid_31000006-0000-4000-8000-000000000006"})
	if err != nil || !strings.Contains(string(dataControls), `"retention_days": 60`) {
		t.Fatalf("update data controls = (%s, %v)", dataControls, err)
	}
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
	workflowIdentity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_workflows"}, CredentialKind: CredentialBrowserSession}
	patBody := json.RawMessage(`{"id":"policy-pat","name":"PAT boundary","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	patMutation := WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-pat", Operation: "createPolicy", IdempotencyKey: "idem-production-pat-0001", Intent: json.RawMessage(`{"body":{"id":"policy-pat"},"expected_version":0,"resource_id":""}`), Body: patBody, AuditID: "pid_30000007-0000-4000-8000-000000000007", CorrelationID: "pid_30000008-0000-4000-8000-000000000008"}
	createdPAT, err := repository.MutateWorkflow(ctx, patIdentity, patMutation)
	if err != nil || createdPAT.Version != 1 || createdPAT.Replayed || createdPAT.ReceiptID != "" {
		t.Fatalf("PAT workflow create = (%#v, %v)", createdPAT, err)
	}
	patReplay := patMutation
	patReplay.AuditID = "pid_30000009-0000-4000-8000-000000000009"
	patReplay.CorrelationID = "pid_30000010-0000-4000-8000-000000000010"
	replayedPAT, err := repository.MutateWorkflow(ctx, patIdentity, patReplay)
	if err != nil || !replayedPAT.Replayed || replayedPAT.ReceiptID != "" || replayedPAT.AuditID != patMutation.AuditID || replayedPAT.CorrelationID != patMutation.CorrelationID {
		t.Fatalf("PAT workflow replay = (%#v, %v)", replayedPAT, err)
	}
	if patReceipts, err := repository.ListWorkflowMutationReceipts(ctx, workflowIdentity, 20); err != nil || len(patReceipts) != 0 {
		t.Fatalf("PAT poisoned browser receipt queue = (%#v, %v)", patReceipts, err)
	}
	var patIdempotencyCount, patAuditCount, patReceiptCount int
	if err := connection.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation = $1 AND idempotency_key = $2),
  (SELECT count(*) FROM zasp_workflow_audit WHERE operation = $1 AND resource_id = $3),
  (SELECT count(*) FROM zasp_workflow_receipts WHERE operation = $1 AND idempotency_key = $2)`, patMutation.Operation, patMutation.IdempotencyKey, patMutation.ID).Scan(&patIdempotencyCount, &patAuditCount, &patReceiptCount); err != nil || patIdempotencyCount != 1 || patAuditCount != 1 || patReceiptCount != 0 {
		t.Fatalf("PAT persistence counts = (%d, %d, %d, %v)", patIdempotencyCount, patAuditCount, patReceiptCount, err)
	}
	workflowBody := json.RawMessage(`{"id":"policy-production","name":"Production boundary","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	workflowCreate := WorkflowMutation{Action: "create", Kind: "policy", ID: "policy-production", Operation: "createPolicy", IdempotencyKey: "idem-production-policy-0001", Intent: json.RawMessage(`{"body":{"id":"policy-production"},"expected_version":0,"resource_id":""}`), Body: workflowBody, AuditID: "pid_30000001-0000-4000-8000-000000000001", CorrelationID: "pid_30000002-0000-4000-8000-000000000002", ReceiptID: "pid_30000003-0000-4000-8000-000000000003"}
	createdWorkflow, err := repository.MutateWorkflow(ctx, workflowIdentity, workflowCreate)
	if err != nil || createdWorkflow.Version != 1 || createdWorkflow.Replayed {
		t.Fatalf("create workflow = (%#v, %v)", createdWorkflow, err)
	}
	replayMutation := workflowCreate
	replayMutation.AuditID = "pid_30000005-0000-4000-8000-000000000005"
	replayMutation.CorrelationID = "pid_30000004-0000-4000-8000-000000000004"
	replayMutation.ReceiptID = "pid_30000006-0000-4000-8000-000000000006"
	replayedWorkflow, err := repository.MutateWorkflow(ctx, workflowIdentity, replayMutation)
	if err != nil || !replayedWorkflow.Replayed || replayedWorkflow.AuditID != workflowCreate.AuditID || replayedWorkflow.CorrelationID != workflowCreate.CorrelationID || replayedWorkflow.ReceiptID != workflowCreate.ReceiptID {
		t.Fatalf("replay workflow = (%#v, %v)", replayedWorkflow, err)
	}
	receipts, err := repository.ListWorkflowMutationReceipts(ctx, workflowIdentity, 20)
	if err != nil || len(receipts) != 1 || receipts[0].ID != workflowCreate.ReceiptID || receipts[0].Operation != workflowCreate.Operation || receipts[0].IdempotencyKey != workflowCreate.IdempotencyKey || receipts[0].AuditID != workflowCreate.AuditID || receipts[0].CorrelationID != workflowCreate.CorrelationID || !equalIntegrationJSON(receipts[0].Intent, workflowCreate.Intent) || !equalIntegrationJSON(receipts[0].Result, workflowBody) {
		t.Fatalf("committed receipt = (%#v, %v)", receipts, err)
	}
	if payload, err := repository.ListWorkflows(ctx, foreignScope, "policy", "", ""); err != nil || !equalIntegrationJSON(payload, []byte(`{"items":[]}`)) {
		t.Fatalf("foreign workflow list = (%s, %v)", payload, err)
	}
	staleMutation := WorkflowMutation{Action: "update", Kind: "policy", ID: "policy-production", Operation: "updatePolicy", IdempotencyKey: "idem-stale-policy-000001", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"id":"policy-production"},"expected_version":2,"resource_id":"policy-production"}`), Body: workflowBody, AuditID: "pid_30000008-0000-4000-8000-000000000008", CorrelationID: "pid_30000009-0000-4000-8000-000000000009", ReceiptID: "pid_30000010-0000-4000-8000-000000000010"}
	if _, err := repository.MutateWorkflow(ctx, workflowIdentity, staleMutation); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("stale workflow mutation = %v", err)
	}
	var auditCount, idempotencyCount int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE resource_id = 'policy-production'), (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation = 'createPolicy')`).Scan(&auditCount, &idempotencyCount); err != nil || auditCount != 1 || idempotencyCount != 2 {
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
	restartedEnvelopePayload, err := restartedRepository.ReadAdministration(ctx, tokenIdentity, "revealAPIToken", map[string]string{"id": rotatedMutation.GrantID})
	if err != nil || !bytes.Equal(restartedEnvelopePayload, rotatedEnvelopePayload) {
		t.Fatalf("reveal grant restart reconciliation = (%s, %v)", restartedEnvelopePayload, err)
	}
	if _, err := restartedRepository.MutateAdministration(ctx, tokenIdentity, administrationMutation{Operation: "acknowledgeAPITokenRevealGrant", ID: rotatedMutation.GrantID, AuditID: "pid_31000015-0000-4000-8000-000000000015"}); err != nil {
		t.Fatalf("acknowledge reveal grant after restart: %v", err)
	}
	if _, err := restartedRepository.ReadAdministration(ctx, tokenIdentity, "revealAPIToken", map[string]string{"id": rotatedMutation.GrantID}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("acknowledged reveal grant remained usable: %v", err)
	}
	if persisted, err := restartedRepository.GetWorkflow(ctx, scope, "policy", "policy-production"); err != nil || persisted.Version != 1 || !equalIntegrationJSON(persisted.Body, workflowBody) {
		t.Fatalf("workflow did not survive repository restart = (%#v, %v)", persisted, err)
	}
	if _, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); err != nil {
		t.Fatalf("session did not survive repository restart: %v", err)
	}
	receipts, err = restartedRepository.ListWorkflowMutationReceipts(ctx, workflowIdentity, 20)
	if err != nil || len(receipts) != 1 || receipts[0].ID != workflowCreate.ReceiptID {
		t.Fatalf("receipt did not survive repository restart = (%#v, %v)", receipts, err)
	}
	if err := restartedRepository.AcknowledgeWorkflowMutationReceipt(ctx, workflowIdentity, "pid_39999999-0000-4999-8999-999999999999"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("forged receipt acknowledgement = %v", err)
	}
	foreignReceiptIdentity := workflowIdentity
	foreignReceiptIdentity.Scope = foreignScope
	if err := restartedRepository.AcknowledgeWorkflowMutationReceipt(ctx, foreignReceiptIdentity, workflowCreate.ReceiptID); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("foreign receipt acknowledgement = %v", err)
	}
	if err := restartedRepository.AcknowledgeWorkflowMutationReceipt(ctx, workflowIdentity, workflowCreate.ReceiptID); err != nil {
		t.Fatalf("receipt acknowledgement: %v", err)
	}
	if err := restartedRepository.AcknowledgeWorkflowMutationReceipt(ctx, workflowIdentity, workflowCreate.ReceiptID); err != nil {
		t.Fatalf("idempotent receipt acknowledgement: %v", err)
	}
	if receipts, err := restartedRepository.ListWorkflowMutationReceipts(ctx, workflowIdentity, 20); err != nil || len(receipts) != 0 {
		t.Fatalf("acknowledged receipts = (%#v, %v)", receipts, err)
	}
	if _, err := restartedConnection.Exec(ctx, `UPDATE zasp_workflow_receipts SET created_at = transaction_timestamp() - interval '8 days', expires_at = transaction_timestamp() - interval '1 day' WHERE receipt_id = $1`, workflowCreate.ReceiptID); err != nil {
		t.Fatalf("expire receipt: %v", err)
	}
	if expired, err := restartedRepository.ListWorkflowMutationReceipts(ctx, workflowIdentity, 20); err != nil || len(expired) != 0 {
		t.Fatalf("expired receipt visibility = (%#v, %v)", expired, err)
	}
	var receiptCount int
	if err := restartedConnection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE receipt_id = $1`, workflowCreate.ReceiptID).Scan(&receiptCount); err != nil || receiptCount != 1 {
		t.Fatalf("receipt list performed cleanup = (%d, %v)", receiptCount, err)
	}
	if err := restartedRepository.Ready(ctx); err != nil {
		t.Fatalf("readiness receipt cleanup: %v", err)
	}
	if err := restartedConnection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE receipt_id = $1`, workflowCreate.ReceiptID).Scan(&receiptCount); err != nil || receiptCount != 0 {
		t.Fatalf("expired receipt count = (%d, %v)", receiptCount, err)
	}
	if _, err := restartedConnection.Exec(ctx, `
WITH generated AS (SELECT generate_series(1, 1001) AS ordinal), idempotency AS (
	  INSERT INTO zasp_workflow_idempotency
	    (organization_id, workspace_id, environment_id, principal_id, operation, idempotency_key, request_digest, response, receipt_semantics)
	  SELECT $1, $2, $3, $4, 'cleanupExpired', 'cleanup-expired-' || lpad(ordinal::text, 4, '0'),
	         digest(ordinal::text, 'sha256'), jsonb_build_object('receipt_id', 'cleanup-receipt-' || lpad(ordinal::text, 4, '0')), 'receipt_backed'
  FROM generated
  RETURNING idempotency_key
)
INSERT INTO zasp_workflow_receipts
  (organization_id, workspace_id, environment_id, principal_id, receipt_id, operation, idempotency_key,
   intent, result, resource_kind, resource_id, resource_version, audit_id, correlation_id, created_at, expires_at)
SELECT $1, $2, $3, $4, 'cleanup-receipt-' || right(idempotency_key, 4), 'cleanupExpired', idempotency_key,
       '{}'::jsonb, '{}'::jsonb, 'policy', 'policy-production', 1,
       'cleanup-audit-' || right(idempotency_key, 4), 'cleanup-correlation-' || right(idempotency_key, 4),
       transaction_timestamp() - interval '8 days', transaction_timestamp() - interval '1 day'
FROM idempotency`, organization.String(), workspace.String(), environment.String(), principal.String()); err != nil {
		t.Fatalf("seed bounded receipt cleanup: %v", err)
	}
	if deleted, err := restartedRepository.CleanupExpiredWorkflowMutationReceipts(ctx, 1000); err != nil || deleted != 1000 {
		t.Fatalf("bounded receipt cleanup = (%d, %v)", deleted, err)
	}
	if err := restartedConnection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE operation = 'cleanupExpired'`).Scan(&receiptCount); err != nil || receiptCount != 1 {
		t.Fatalf("bounded receipt cleanup remainder = (%d, %v)", receiptCount, err)
	}
	if err := restartedRepository.Ready(ctx); err != nil {
		t.Fatalf("readiness cleanup remainder: %v", err)
	}
	if err := restartedConnection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE operation = 'cleanupExpired'`).Scan(&receiptCount); err != nil || receiptCount != 0 {
		t.Fatalf("readiness cleanup remainder count = (%d, %v)", receiptCount, err)
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
	roleAdministrator, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session})
	if err != nil {
		t.Fatalf("authenticate role administrator: %v", err)
	}
	roleResult, err := restartedRepository.MutateAdministration(ctx, roleAdministrator, administrationMutation{Operation: "updateMemberRole", ID: principal.String(), Role: "read_only_viewer", ExpectedVersion: 1, AuditID: "pid_31000007-0000-4000-8000-000000000007"})
	if err != nil || !strings.Contains(string(roleResult), `"role": "read_only_viewer"`) {
		t.Fatalf("atomic role update = (%s, %v)", roleResult, err)
	}
	if _, err := restartedRepository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: session}); !errors.Is(err, ErrRepositoryAuthentication) {
		t.Fatalf("role update did not revoke session: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `UPDATE zasp_identity_memberships SET role = 'security_admin' WHERE principal_id = $1 AND organization_id = $2`, principal.String(), organization.String()); err != nil {
		t.Fatalf("restore membership after atomic revocation proof: %v", err)
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
	var originalMutationFunction string
	if err := restartedConnection.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure)`).Scan(&originalMutationFunction); err != nil {
		t.Fatalf("capture mutation function: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `CREATE OR REPLACE FUNCTION public.zasp_workflow_mutate(mutation text, requested_kind text, requested_id text, requested_organization_id text, requested_workspace_id text, requested_environment_id text, requested_principal_id text, requested_operation text, requested_idempotency_key text, expected_version bigint, requested_intent jsonb, requested_body jsonb, requested_audit_id text, requested_correlation_id text, requested_receipt_id text) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN RETURN '{}'::jsonb; END $$`); err != nil {
		t.Fatalf("introduce mutation function drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("mutation function drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, originalMutationFunction); err != nil {
		t.Fatalf("restore mutation function: %v", err)
	}
	if err := restartedRepository.Ready(ctx); err != nil {
		t.Fatalf("restored mutation function readiness: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_authorized_scopes ALTER COLUMN permissions DROP NOT NULL`); err != nil {
		t.Fatalf("introduce authorization drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("authorization drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_authorized_scopes ALTER COLUMN permissions SET NOT NULL`); err != nil {
		t.Fatalf("restore authorization schema: %v", err)
	}
	if err := restartedRepository.Ready(ctx); err != nil {
		t.Fatalf("restored authorization readiness: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_authorized_scopes ALTER COLUMN label TYPE varchar(128)`); err != nil {
		t.Fatalf("introduce authorization type drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("authorization type drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_authorized_scopes ALTER COLUMN label TYPE text`); err != nil {
		t.Fatalf("restore authorization type: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_workflow_records ALTER COLUMN version SET DEFAULT 2`); err != nil {
		t.Fatalf("introduce workflow default drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("workflow default drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_workflow_records ALTER COLUMN version SET DEFAULT 1`); err != nil {
		t.Fatalf("restore workflow default: %v", err)
	}
	var constraintName, constraintDefinition string
	if err := restartedConnection.QueryRow(ctx, `SELECT conname, pg_get_constraintdef(oid, true) FROM pg_constraint WHERE conrelid = 'public.zasp_workflow_records'::regclass AND contype = 'c' AND pg_get_constraintdef(oid, true) LIKE '%kind%'`).Scan(&constraintName, &constraintDefinition); err != nil {
		t.Fatalf("capture workflow constraint: %v", err)
	}
	constraintIdentifier := pgx.Identifier{constraintName}.Sanitize()
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_workflow_records DROP CONSTRAINT `+constraintIdentifier); err != nil {
		t.Fatalf("introduce workflow constraint drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("workflow constraint drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `ALTER TABLE zasp_workflow_records ADD CONSTRAINT `+constraintIdentifier+` `+constraintDefinition); err != nil {
		t.Fatalf("restore workflow constraint: %v", err)
	}
	var indexDefinition string
	if err := restartedConnection.QueryRow(ctx, `SELECT pg_get_indexdef('public.zasp_workflow_records_list_idx'::regclass, 0, true)`).Scan(&indexDefinition); err != nil {
		t.Fatalf("capture workflow index: %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, `DROP INDEX zasp_workflow_records_list_idx`); err != nil {
		t.Fatalf("introduce workflow index drift: %v", err)
	}
	if err := restartedRepository.Ready(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("workflow index drift readiness = %v", err)
	}
	if _, err := restartedConnection.Exec(ctx, indexDefinition); err != nil {
		t.Fatalf("restore workflow index: %v", err)
	}
	if err := restartedRepository.Ready(ctx); err != nil {
		t.Fatalf("fully restored semantic readiness: %v", err)
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
	if _, err := rollbackConnection.Exec(ctx, `DELETE FROM zasp_product_api_tokens WHERE token_digest = digest($1, 'sha256')`, pat); err != nil {
		t.Fatalf("remove post-v7 PAT before administration rollback: %v", err)
	}
	for _, statement := range []string{
		`DELETE FROM zasp_api_token_reveal_grants`, `DELETE FROM zasp_admin_audit`, `DELETE FROM zasp_admin_idempotency`, `DELETE FROM zasp_session_events`,
		`DELETE FROM zasp_product_api_tokens`, `DELETE FROM zasp_compliance_evidence`, `DELETE FROM zasp_compliance_controls`,
		`DELETE FROM zasp_data_controls`, `DELETE FROM zasp_group_mappings`, `DELETE FROM zasp_environments`,
		`DELETE FROM zasp_workspaces`, `DELETE FROM zasp_organizations`,
	} {
		if _, err := rollbackConnection.Exec(ctx, statement); err != nil {
			t.Fatalf("remove administration fixture before rollback: %v", err)
		}
	}
	if err := rollbackRunner.DownAPITokenRevealGrants(ctx); err != nil {
		t.Fatalf("API token reveal grant rollback: %v", err)
	}
	if err := rollbackRunner.DownProductionAdministration(ctx); err != nil {
		t.Fatalf("production administration rollback: %v", err)
	}
	if err := rollbackRunner.DownWorkflowReceiptProvenance(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("receipt-less PAT rollback guard = %v", err)
	}
	if version, err := rollbackRunner.Version(ctx); err != nil || version != 6 {
		t.Fatalf("guarded rollback state = (%d, %v)", version, err)
	}
	cleanup, err := rollbackConnection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, deletion := range []struct {
		statement string
		args      []any
	}{
		{statement: `DELETE FROM zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$4 AND operation=$5 AND idempotency_key=$6`, args: []any{patIdentity.Scope.OrganizationID().String(), patIdentity.Scope.WorkspaceID().String(), patIdentity.Scope.EnvironmentID().String(), patIdentity.PrincipalID.String(), patMutation.Operation, patMutation.IdempotencyKey}},
		{statement: `DELETE FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, args: []any{patIdentity.Scope.OrganizationID().String(), patMutation.AuditID}},
		{statement: `DELETE FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind=$4 AND id=$5`, args: []any{patIdentity.Scope.OrganizationID().String(), patIdentity.Scope.WorkspaceID().String(), patIdentity.Scope.EnvironmentID().String(), patMutation.Kind, patMutation.ID}},
	} {
		result, err := cleanup.Exec(ctx, deletion.statement, deletion.args...)
		if err != nil || result.RowsAffected() != 1 {
			_ = cleanup.Rollback(ctx)
			t.Fatalf("exact PAT rollback cleanup = rows %d error %v", result.RowsAffected(), err)
		}
	}
	if err := cleanup.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rollbackRunner.DownWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatalf("workflow receipt provenance rollback: %v", err)
	}
	if err := rollbackRunner.DownWorkflowReceiptSafety(ctx); err != nil {
		t.Fatalf("workflow receipt safety rollback: %v", err)
	}
	if err := rollbackRunner.DownWorkflowReceipts(ctx); err != nil {
		t.Fatalf("workflow receipt rollback: %v", err)
	}
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
	if err := runner.UpWorkflowReceipts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionAdministration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
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
	if err := runner.UpWorkflowReceipts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionAdministration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
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
	identity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_workflows"}, CredentialKind: CredentialBrowserSession}
	sequence := 0
	assertReplay := func(mutation WorkflowMutation) WorkflowMutationResult {
		t.Helper()
		sequence++
		mutation.IdempotencyKey = fmt.Sprintf("idem-lost-response-%02d", sequence)
		mutation.AuditID = fmt.Sprintf("pid_62000001-0000-4000-8000-%012d", sequence)
		mutation.CorrelationID = fmt.Sprintf("pid_62000002-0000-4000-8000-%012d", sequence)
		mutation.ReceiptID = fmt.Sprintf("pid_62000003-0000-4000-8000-%012d", sequence)
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
	if sequence != 11 {
		t.Fatalf("replayed mutation count = %d", sequence)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowHandlerNonemptyDeletesLeavePostgresMutationAuditAndReceiptsUntouched(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	for _, migration := range []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "schema", run: runner.Up},
		{name: "core", run: runner.UpCore},
		{name: "workflows", run: runner.UpWorkflows},
		{name: "receipts", run: runner.UpWorkflowReceipts},
		{name: "receipt safety", run: runner.UpWorkflowReceiptSafety},
		{name: "receipt provenance", run: runner.UpWorkflowReceiptProvenance},
		{name: "production administration", run: runner.UpProductionAdministration},
		{name: "API token reveal grants", run: runner.UpAPITokenRevealGrants},
	} {
		if err := migration.run(ctx); err != nil {
			t.Fatalf("%s migration: %v", migration.name, err)
		}
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	principal := integrationProductID(t, "pid_66000004-0000-4000-8000-000000000004")
	organization := integrationProductID(t, "pid_66000001-0000-4000-8000-000000000001")
	workspace := integrationProductID(t, "pid_66000002-0000-4000-8000-000000000002")
	environment := integrationProductID(t, "pid_66000003-0000-4000-8000-000000000003")
	scope, _ := domain.NewScope(organization, workspace, environment)
	identity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_workflows"}, CredentialKind: CredentialBrowserSession}
	deletes := []struct {
		operation string
		kind      string
		id        string
		path      string
	}{
		{operation: "deletePolicy", kind: "policy", id: "policy-postgres-delete", path: "/api/v1/policies/policy-postgres-delete"},
		{operation: "deleteIntegration", kind: "integration", id: "pid_67000001-0000-4000-8000-000000000001", path: "/api/v1/integrations/pid_67000001-0000-4000-8000-000000000001"},
		{operation: "deleteSecurityAgent", kind: "security_agent", id: "pid_67000002-0000-4000-8000-000000000002", path: "/api/v1/security-agents/pid_67000002-0000-4000-8000-000000000002"},
	}
	for _, deletion := range deletes {
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records (organization_id,workspace_id,environment_id,kind,id,body) VALUES ($1,$2,$3,$4,$5,'{}'::jsonb)`, organization.String(), workspace.String(), environment.String(), deletion.kind, deletion.id); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for index, deletion := range deletes {
		request := workflowRequest(t, identity, testCorrelationID, deletion.operation, map[string]string{"id": deletion.id}, http.MethodDelete, deletion.path, `{"force":true}`)
		request.Header.Set("Idempotency-Key", fmt.Sprintf("idem-postgres-delete-%02d", index))
		request.Header.Set("If-Match", `"1"`)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s nonempty body = %d %s", deletion.operation, response.Code, response.Body.String())
		}
	}
	var recordCount, idempotencyCount, auditCount, receiptCount int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_workflow_records WHERE organization_id=$1 AND deleted_at IS NULL),
		(SELECT count(*) FROM zasp_workflow_idempotency WHERE organization_id=$1),
		(SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1),
		(SELECT count(*) FROM zasp_workflow_receipts WHERE organization_id=$1)`, organization.String()).Scan(&recordCount, &idempotencyCount, &auditCount, &receiptCount); err != nil {
		t.Fatal(err)
	}
	if recordCount != 3 || idempotencyCount != 0 || auditCount != 0 || receiptCount != 0 {
		t.Fatalf("rejected delete durable counts = records:%d idempotency:%d audit:%d receipts:%d", recordCount, idempotencyCount, auditCount, receiptCount)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityAgentPaginationExceedsOneHundredWithoutTenantDisclosure(t *testing.T) {
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
	if err := runner.UpWorkflowReceipts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionAdministration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_workflow_records (organization_id, workspace_id, environment_id, kind, id, body)
SELECT $1, $2, $3, 'security_agent', generated.id,
       jsonb_build_object('id', generated.id, 'name', 'Definition ' || generated.ordinal, 'trigger_kind', 'finding', 'trigger_source', 'credential',
         'environment_ids', jsonb_build_array($3::text), 'autonomy', 'supervised', 'max_steps', 10, 'max_duration_seconds', 900,
         'temporary_policy_seconds', 3600, 'ai_token_budget', 4000, 'concurrency_limit', 2, 'allowed_actions', jsonb_build_array('run_test'),
         'verification_kind', 'test_run', 'definition_version', 1, 'enabled', true)
FROM (
  SELECT ordinal, 'pid_' || lpad(ordinal::text, 8, '0') || '-0000-4000-8000-' || lpad(ordinal::text, 12, '0') AS id
  FROM generate_series(1, 101) AS ordinal
) AS generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, _ := NewPostgresRepository(database)
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgents", nil, http.MethodGet, "/api/v1/security-agents?limit=100", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var first struct {
		Items    []json.RawMessage `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &first) != nil || len(first.Items) != 100 || !first.PageInfo.HasMore || first.PageInfo.NextCursor == nil {
		t.Fatalf("first real page = %d items=%d body=%s", response.Code, len(first.Items), response.Body.String())
	}
	request = workflowRequest(t, identity, testCorrelationID, "listSecurityAgents", nil, http.MethodGet, "/api/v1/security-agents?limit=100&cursor="+*first.PageInfo.NextCursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var second struct {
		Items    []json.RawMessage `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &second) != nil || len(second.Items) != 1 || second.PageInfo.HasMore || second.PageInfo.NextCursor != nil {
		t.Fatalf("second real page = %d items=%d body=%s", response.Code, len(second.Items), response.Body.String())
	}
	foreign := identity
	foreignOrganization := integrationProductID(t, "pid_20000001-0000-4000-8000-000000000001")
	foreignWorkspace := integrationProductID(t, "pid_20000002-0000-4000-8000-000000000002")
	foreignEnvironment := integrationProductID(t, "pid_20000003-0000-4000-8000-000000000003")
	foreign.Scope, _ = domain.NewScope(foreignOrganization, foreignWorkspace, foreignEnvironment)
	request = workflowRequest(t, foreign, testCorrelationID, "listSecurityAgents", nil, http.MethodGet, "/api/v1/security-agents?cursor="+*first.PageInfo.NextCursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte(identity.Scope.OrganizationID().String())) {
		t.Fatalf("foreign real cursor = %d %s", response.Code, response.Body.String())
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyAndIntegrationPaginationTraversesOneThousandAndOneRowsExactly(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	if err := runner.UpWorkflowReceipts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpWorkflowReceiptProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionAdministration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpAPITokenRevealGrants(ctx); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	for _, kind := range []string{"policy", "integration"} {
		if _, err := connection.Exec(ctx, `
INSERT INTO zasp_workflow_records (organization_id, workspace_id, environment_id, kind, id, body)
SELECT $1, $2, $3, $4, generated.id, jsonb_build_object('id', generated.id)
FROM (
  SELECT CASE WHEN $4 = 'policy'
              THEN 'policy-' || lpad(ordinal::text, 4, '0')
              ELSE 'pid_' || lpad(ordinal::text, 8, '0') || '-0000-4000-8000-' || lpad(ordinal::text, 12, '0')
         END AS id
  FROM generate_series(1, 1001) AS ordinal
) AS generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), kind); err != nil {
			t.Fatal(err)
		}
	}
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, _ := NewPostgresRepository(database)
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	for _, test := range []struct {
		operation string
		path      string
	}{
		{operation: "listPolicies", path: "/api/v1/policies"},
		{operation: "listIntegrations", path: "/api/v1/integrations"},
	} {
		t.Run(test.operation, func(t *testing.T) {
			cursor := ""
			seen := make(map[string]struct{}, 1001)
			requests := 0
			for {
				target := test.path + "?limit=100"
				if cursor != "" {
					target += "&cursor=" + cursor
				}
				request := workflowRequest(t, identity, testCorrelationID, test.operation, nil, http.MethodGet, target, "")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				requests++
				var page struct {
					Items []struct {
						ID string `json:"id"`
					} `json:"items"`
					PageInfo struct {
						NextCursor *string `json:"next_cursor"`
						HasMore    bool    `json:"has_more"`
					} `json:"page_info"`
				}
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
					t.Fatalf("page %d = %d %s", requests, response.Code, response.Body.String())
				}
				for _, item := range page.Items {
					if _, duplicate := seen[item.ID]; duplicate {
						t.Fatalf("duplicate stable ID %q", item.ID)
					}
					seen[item.ID] = struct{}{}
				}
				if !page.PageInfo.HasMore {
					if page.PageInfo.NextCursor != nil {
						t.Fatal("final page returned a cursor")
					}
					break
				}
				if page.PageInfo.NextCursor == nil {
					t.Fatal("continuing page omitted cursor")
				}
				cursor = *page.PageInfo.NextCursor
			}
			if len(seen) != 1001 || requests != 11 {
				t.Fatalf("traversal = %d rows in %d requests, want 1001/11", len(seen), requests)
			}
		})
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
