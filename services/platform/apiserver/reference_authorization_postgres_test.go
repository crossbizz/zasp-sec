package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrateToReferenceAuthorization(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := migrateToConnectorAuthorization(t, ctx, connection)
	if err := runner.UpReferenceAuthorization(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ReferenceAuthorization().UpSQL())
		t.Fatalf("reference authorization migration: %v (%T: %#v)", err, detail, detail)
	}
	return runner
}

func TestReferenceAuthorizationPostgresAtomicallyActivatesAndReplaysWithoutChurn(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 12 {
		t.Fatalf("reference schema version=%d err=%v", version, versionErr)
	}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	connectionID := "pid_74000002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	body := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"aws","name":"AWS","configuration":` + string(configuration) + `,"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)
	createIntent := json.RawMessage(`{"body":{"connector_key":"aws"},"expected_version":0,"resource_id":""}`)
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_workflow_mutate('create','integration',$1,$2,$3,$4,$5,'createIntegration',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, integrationID, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), "reference-create-0001", createIntent, body, "pid_74000003-0000-4000-8000-000000000003", "pid_74000004-0000-4000-8000-000000000004", "pid_74000005-0000-4000-8000-000000000005").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	idempotencyKey := "reference-authorize-0001"
	intent := referenceAuthorizationIntent(identity, integrationID, "aws", idempotencyKey, 1, configuration)
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, "aws", connectionID, "ref:aws/external-id/customer-0001", idempotencyKey, int64(1), configuration, intent, "pid_74000006-0000-4000-8000-000000000006", "pid_74000007-0000-4000-8000-000000000007", "pid_74000008-0000-4000-8000-000000000008"}
	query := `SELECT zasp_complete_reference_authorization($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15)`
	foreign := append([]any(nil), args...)
	foreign[0] = "pid_74000009-0000-4000-8000-000000000009"
	if err := connection.QueryRow(ctx, query, foreign...).Scan(&payload); err == nil {
		t.Fatal("cross-scope reference completion succeeded")
	}
	var residue int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_integration_connections WHERE id=$1)+(SELECT count(*) FROM zasp_workflow_receipts WHERE operation='completeIntegrationReferenceAuthorization')`, connectionID).Scan(&residue); err != nil || residue != 0 {
		t.Fatalf("cross-scope reference residue=%d err=%v", residue, err)
	}
	secondConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConnection.Close(ctx)
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	if _, err := transaction.Exec(ctx, `SELECT 1 FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind='integration' AND id=$4 FOR UPDATE`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	var secondPID int
	if err := secondConnection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
		t.Fatal(err)
	}
	type completionResult struct {
		payload []byte
		err     error
	}
	blockedResult := make(chan completionResult, 1)
	go func() {
		var value []byte
		err := secondConnection.QueryRow(ctx, query, args...).Scan(&value)
		blockedResult <- completionResult{payload: value, err: err}
	}()
	blocked := false
	for attempt := 0; attempt < 50; attempt++ {
		var waitType *string
		if err := connection.QueryRow(ctx, `SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1`, secondPID).Scan(&waitType); err == nil && waitType != nil && *waitType == "Lock" {
			blocked = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("concurrent reference completion did not reach the workflow lock barrier")
	}
	var first []byte
	if err := transaction.QueryRow(ctx, query, args...).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	secondResult := <-blockedResult
	if secondResult.err != nil {
		t.Fatalf("concurrent exact reference replay error=%v payload=%s", secondResult.err, secondResult.payload)
	}
	var replay []byte
	if err := connection.QueryRow(ctx, query, args...).Scan(&replay); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{"first": first, "concurrent replay": secondResult.payload, "exact replay": replay} {
		var result struct {
			Body struct {
				UpdatedAt string `json:"updated_at"`
			} `json:"body"`
		}
		if err := json.Unmarshal(payload, &result); err != nil {
			t.Fatalf("%s reference result decode: %v payload=%s", name, err, payload)
		}
		updatedAt, err := time.Parse(time.RFC3339Nano, result.Body.UpdatedAt)
		if err != nil || !strings.HasSuffix(result.Body.UpdatedAt, "Z") || strings.Contains(result.Body.UpdatedAt, "+00:00") || updatedAt.Location() != time.UTC {
			t.Fatalf("%s reference updated_at=%q parsed=%v err=%v", name, result.Body.UpdatedAt, updatedAt, err)
		}
	}
	var replayed struct {
		Replayed  bool   `json:"replayed"`
		ReceiptID string `json:"receipt_id"`
		Version   int64  `json:"version"`
	}
	if json.Unmarshal(replay, &replayed) != nil || !replayed.Replayed || replayed.ReceiptID != "pid_74000008-0000-4000-8000-000000000008" || replayed.Version != 2 {
		t.Fatalf("reference replay=%s first=%s", replay, first)
	}
	var workflowStatus, typedState, connectionState string
	var workflowVersion, typedVersion, connectionVersion, receipts int64
	if err := connection.QueryRow(ctx, `SELECT w.body->>'status',w.version,i.state,i.version,c.state,c.version,(SELECT count(*) FROM zasp_workflow_receipts r WHERE r.operation='completeIntegrationReferenceAuthorization' AND r.resource_id=$4) FROM zasp_workflow_records w JOIN zasp_integrations i ON (i.organization_id,i.workspace_id,i.environment_id,i.id)=(w.organization_id,w.workspace_id,w.environment_id,w.id) JOIN zasp_integration_connections c ON (c.organization_id,c.workspace_id,c.environment_id,c.integration_id)=(i.organization_id,i.workspace_id,i.environment_id,i.id) WHERE (w.organization_id,w.workspace_id,w.environment_id,w.id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&workflowStatus, &workflowVersion, &typedState, &typedVersion, &connectionState, &connectionVersion, &receipts); err != nil {
		t.Fatal(err)
	}
	if workflowStatus != "active" || typedState != "active" || connectionState != "verified" || workflowVersion != 2 || typedVersion != 2 || connectionVersion != 2 || receipts != 1 {
		t.Fatalf("reference authority workflow=%s/v%d typed=%s/v%d connection=%s/v%d receipts=%d", workflowStatus, workflowVersion, typedState, typedVersion, connectionState, connectionVersion, receipts)
	}
	conflict := append([]any(nil), args...)
	conflict[7] = "ref:aws/external-id/customer-0002"
	if err := connection.QueryRow(ctx, query, conflict...).Scan(&payload); err == nil {
		t.Fatal("changed reference replay succeeded")
	}
	if err := runner.DownReferenceAuthorization(ctx); err == nil || !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("data-aware reference down=%v", err)
	}
}

func TestReferenceAuthorizationPostgresSecurityDriftFailsConstructorAndRollback(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if _, err := NewReferenceAuthorizationRepository(database); err != nil {
		t.Fatalf("ready reference constructor: %v", err)
	}
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_worker`); err != nil {
		t.Fatal(err)
	}
	var replayAllowed, completeAllowed bool
	if err := connection.QueryRow(ctx, `SELECT has_function_privilege(current_user,'zasp_reference_authorization_replay(text,text,text,text,text,text,bigint)','EXECUTE'),has_function_privilege(current_user,'zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','EXECUTE')`).Scan(&replayAllowed, &completeAllowed); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if replayAllowed || completeAllowed {
		t.Fatalf("worker reference authority replay=%t complete=%t", replayAllowed, completeAllowed)
	}
	if _, err := connection.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_complete_reference_authorization(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) TO zasp_discovery_worker`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_reference_authorization_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("reference privilege drift ready=%t err=%v", ready, err)
	}
	if repository, err := NewReferenceAuthorizationRepository(database); err == nil || repository != nil {
		t.Fatalf("reference drift constructor=%#v err=%v", repository, err)
	}
	if err := runner.DownReferenceAuthorization(ctx); err == nil {
		t.Fatal("reference privilege drift did not block rollback")
	}
}

func TestReferenceAuthorizationPostgresEmptyDownRestoresConnectorRelease(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	fingerprintQuery := postgresSchemaVersionSQL[:strings.Index(postgresSchemaVersionSQL, "SELECT metadata.value")] + "SELECT value FROM semantic_fingerprint"
	var fingerprint string
	if err := connection.QueryRow(ctx, fingerprintQuery).Scan(&fingerprint); err != nil || fingerprint != migrations.ReferenceAuthorizationSemanticFingerprint() {
		t.Fatalf("reference fingerprint=%q marker=%q err=%v", fingerprint, migrations.ReferenceAuthorizationSemanticFingerprint(), err)
	}
	if err := runner.DownReferenceAuthorization(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ReferenceAuthorization().DownSQL())
		t.Fatalf("reference authorization down: %v (%T: %#v)", err, detail, detail)
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 11 {
		t.Fatalf("down version=%d err=%v", version, versionErr)
	}
}
