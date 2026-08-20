package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrateToProductionDiscoveryExecution(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionDiscoveryExecution().UpSQL())
		var liveFingerprint string
		var securityReady bool
		_ = connection.QueryRow(ctx, `SELECT zasp_execution_live_fingerprint(),zasp_execution_security_ready()`).Scan(&liveFingerprint, &securityReady)
		t.Fatalf("production discovery execution migration: %v (%T: %#v) live=%q expected=%q security=%t", err, detail, detail, liveFingerprint, migrations.ProductionDiscoveryExecutionSemanticFingerprint(), securityReady)
	}
	return runner
}

func seedReferenceAuthorizedIntegration(t *testing.T, ctx context.Context, connection *pgx.Conn, provider, integrationID, connectionID, reference string, configuration json.RawMessage, sequence string) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	body := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"` + provider + `","name":"` + provider + `","configuration":` + string(configuration) + `,"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)
	createIntent := json.RawMessage(`{"body":{"connector_key":"` + provider + `"},"expected_version":0,"resource_id":""}`)
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_workflow_mutate('create','integration',$1,$2,$3,$4,$5,'createIntegration',$6,0,$7::jsonb,$8::jsonb,$9,$10,$11)`, integrationID, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), "execution-create-"+sequence, createIntent, body, "pid_7500000"+sequence+"-0000-4000-8000-000000000001", "pid_7500000"+sequence+"-0000-4000-8000-000000000002", "pid_7500000"+sequence+"-0000-4000-8000-000000000003").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	idempotencyKey := "execution-authorize-" + sequence
	intent := referenceAuthorizationIntent(identity, integrationID, provider, idempotencyKey, 1, configuration)
	if err := connection.QueryRow(ctx, `SELECT zasp_complete_reference_authorization($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10::jsonb,$11::jsonb,$12,$13,$14)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, provider, connectionID, reference, idempotencyKey, configuration, intent, "pid_7600000"+sequence+"-0000-4000-8000-000000000001", "pid_7600000"+sequence+"-0000-4000-8000-000000000002", "pid_7600000"+sequence+"-0000-4000-8000-000000000003").Scan(&payload); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDiscoveryExecutionPostgresInstallsExactAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)

	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 13 {
		t.Fatalf("execution schema version=%d err=%v", version, versionErr)
	}
	var liveFingerprint string
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_live_fingerprint()`).Scan(&liveFingerprint); err != nil {
		t.Fatal(err)
	}
	if liveFingerprint != migrations.ProductionDiscoveryExecutionSemanticFingerprint() {
		t.Fatalf("execution fingerprint live=%q expected=%q", liveFingerprint, migrations.ProductionDiscoveryExecutionSemanticFingerprint())
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), liveFingerprint).Scan(&ready); err != nil || !ready {
		var securityReady, referenceReady, discoveryReady bool
		_ = connection.QueryRow(ctx, `SELECT zasp_execution_security_ready(),zasp_reference_authorization_security_ready(),zasp_discovery_security_ready()`).Scan(&securityReady, &referenceReady, &discoveryReady)
		t.Fatalf("execution readiness=%t security=%t reference=%t discovery=%t err=%v", ready, securityReady, referenceReady, discoveryReady, err)
	}
	if _, err := connection.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea) TO zasp_projection_risk_worker`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), liveFingerprint).Scan(&ready); err != nil || ready {
		t.Fatalf("forbidden projection grant readiness=%t err=%v", ready, err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err == nil {
		t.Fatal("security drift did not block rollback")
	}
	if _, err := connection.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea) FROM zasp_projection_risk_worker`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE zasp_execution_rogue LOGIN; GRANT zasp_discovery_scheduler TO zasp_execution_rogue`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("rogue scheduler membership readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `REVOKE zasp_discovery_scheduler FROM zasp_execution_rogue; DROP ROLE zasp_execution_rogue`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE zasp_execution_rogue NOLOGIN NOINHERIT; GRANT zasp_execution_rogue TO zasp_discovery_scheduler`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("outbound scheduler membership readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `REVOKE zasp_execution_rogue FROM zasp_discovery_scheduler; DROP ROLE zasp_execution_rogue`); err != nil {
		t.Fatal(err)
	}
	var schedulerMarker string
	if err := connection.QueryRow(ctx, `SELECT shobj_description(oid,'pg_authid') FROM pg_roles WHERE rolname='zasp_discovery_scheduler'`).Scan(&schedulerMarker); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `COMMENT ON ROLE zasp_discovery_scheduler IS 'foreign-capability-role'`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("foreign scheduler marker readiness=%t err=%v", ready, err)
	}
	if !strings.HasPrefix(schedulerMarker, "zasp-managed:production-discovery-execution-v1:database:") || strings.Contains(schedulerMarker, "'") {
		t.Fatalf("unexpected scheduler marker=%q", schedulerMarker)
	}
	if _, err := connection.Exec(ctx, `COMMENT ON ROLE zasp_discovery_scheduler IS '`+schedulerMarker+`'`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), liveFingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("restored execution readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_discovery_syncs DISABLE TRIGGER zasp_execution_sync_version`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("disabled sync trigger security readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_discovery_syncs ENABLE TRIGGER zasp_execution_sync_version`); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDiscoveryExecutionPostgresRejectsUnsafePreexistingCapabilityRoles(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup string
	}{
		{name: "login", setup: `CREATE ROLE zasp_discovery_scheduler LOGIN NOINHERIT`},
		{name: "inbound membership", setup: `CREATE ROLE zasp_execution_rogue NOLOGIN NOINHERIT; CREATE ROLE zasp_discovery_scheduler NOLOGIN NOINHERIT; GRANT zasp_discovery_scheduler TO zasp_execution_rogue`},
		{name: "outbound membership", setup: `CREATE ROLE zasp_execution_rogue NOLOGIN NOINHERIT; CREATE ROLE zasp_discovery_scheduler NOLOGIN NOINHERIT; GRANT zasp_execution_rogue TO zasp_discovery_scheduler`},
	} {
		t.Run(test.name, func(t *testing.T) {
			dsn := startDisposablePostgres(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			connection, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close(ctx)
			runner := migrateToReferenceAuthorization(t, ctx, connection)
			if _, err := connection.Exec(ctx, test.setup); err != nil {
				t.Fatal(err)
			}
			if err := runner.UpProductionDiscoveryExecution(ctx); err == nil {
				t.Fatal("unsafe pre-existing capability role was accepted")
			}
			var version int64
			var executionTable *string
			if err := connection.QueryRow(ctx, `SELECT max(version),to_regclass('public.zasp_discovery_execution_principals')::text FROM zasp_schema_versions`).Scan(&version, &executionTable); err != nil || version != 12 || executionTable != nil {
				t.Fatalf("failed preflight residue version=%d table=%v err=%v", version, executionTable, err)
			}
		})
	}
}

func TestProductionDiscoveryExecutionPostgresRejectsLiveV12DriftBeforeMutation(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_connector_effects DISABLE TRIGGER zasp_connector_effect_lanes_insert`); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionDiscoveryExecution(ctx); err == nil {
		t.Fatal("v12 ACL drift was blessed by v13")
	}
	var version int64
	var executionTable *string
	if err := connection.QueryRow(ctx, `SELECT max(version),to_regclass('public.zasp_discovery_execution_principals')::text FROM zasp_schema_versions`).Scan(&version, &executionTable); err != nil || version != 12 || executionTable != nil {
		t.Fatalf("drift preflight residue version=%d table=%v err=%v", version, executionTable, err)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_connector_effects ENABLE TRIGGER zasp_connector_effect_lanes_insert`); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatalf("restored v12 readiness rejected: %v", err)
	}
}

func TestProductionDiscoveryExecutionPostgresBindsSafePreprovisionedCapabilityRoles(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	if _, err := connection.Exec(ctx, `CREATE ROLE zasp_discovery_scheduler NOLOGIN NOINHERIT; CREATE ROLE zasp_projection_risk_worker NOLOGIN NOINHERIT; CREATE ROLE zasp_projection_graph_worker NOLOGIN NOINHERIT; CREATE ROLE zasp_projection_search_worker NOLOGIN NOINHERIT`); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatalf("safe preprovisioned roles rejected: %v", err)
	}
	var bound int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker') AND shobj_description(oid,'pg_authid')=format('zasp-managed:production-discovery-execution-v1:database:%s:bound',(SELECT oid FROM pg_database WHERE datname=current_database()))`).Scan(&bound); err != nil || bound != 4 {
		t.Fatalf("bound capability roles=%d err=%v", bound, err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
		t.Fatalf("down with bound roles: %v", err)
	}
	var preserved, comments int
	if err := connection.QueryRow(ctx, `SELECT count(*),count(shobj_description(oid,'pg_authid')) FROM pg_roles WHERE rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker')`).Scan(&preserved, &comments); err != nil || preserved != 4 || comments != 0 {
		t.Fatalf("preprovisioned roles after down=%d comments=%d err=%v", preserved, comments, err)
	}
}

func TestProductionDiscoveryExecutionPostgresPATScheduleBlocksRollbackWithoutReceipt(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_77600001-0000-4000-8000-000000000001"
	connectionID := "pid_77600002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0076","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/customer-0076", configuration, "6")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_public_put_schedule($1,$2,$3,$4,$5,$6,0,300,'disabled',$7,$8,'')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, "pat-schedule-idem-0076", "pid_77600003-0000-4000-8000-000000000003", "pid_77600004-0000-4000-8000-000000000004").Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"receipt_id": ""`)) {
		t.Fatalf("PAT schedule=%s err=%v", payload, err)
	}
	var receipts int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE resource_kind='integration_schedule' AND resource_id=$1`, integrationID).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("PAT schedule receipts=%d err=%v", receipts, err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err == nil {
		t.Fatal("receiptless PAT schedule did not block rollback")
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 13 {
		t.Fatalf("blocked rollback version=%d err=%v", version, versionErr)
	}
}

func TestProductionDiscoveryExecutionPostgresBackfillsOnlyExactSubjects(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	awsIntegration := "pid_77000001-0000-4000-8000-000000000001"
	awsConnection := "pid_77000002-0000-4000-8000-000000000002"
	awsConfig := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", awsIntegration, awsConnection, "ref:aws/external-id/customer-0001", awsConfig, "1")
	k8Integration := "pid_77000003-0000-4000-8000-000000000003"
	k8Connection := "pid_77000004-0000-4000-8000-000000000004"
	k8Config := json.RawMessage(`{"connection_reference":"ref:kubernetes/connection/customer-0001"}`)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "kubernetes", k8Integration, k8Connection, "ref:kubernetes/connection/customer-0001", k8Config, "2")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	var subjectKind, subjectID, source string
	if err := connection.QueryRow(ctx, `SELECT subject_kind,subject_id,source FROM zasp_discovery_connection_subjects WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND connection_id=$5`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), awsIntegration, awsConnection).Scan(&subjectKind, &subjectID, &source); err != nil {
		t.Fatal(err)
	}
	if subjectKind != "aws_account" || subjectID != "123456789012" || source != "upgrade" {
		t.Fatalf("aws subject=%s/%s source=%s", subjectKind, subjectID, source)
	}
	var k8State, workflowState string
	var k8Version, workflowVersion int64
	var k8Subjects int
	if err := connection.QueryRow(ctx, `SELECT i.state,w.body->>'status',i.version,w.version,(SELECT count(*) FROM zasp_discovery_connection_subjects s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.integration_id)=(i.organization_id,i.workspace_id,i.environment_id,i.id)) FROM zasp_integrations i JOIN zasp_workflow_records w ON (w.organization_id,w.workspace_id,w.environment_id,w.id,w.kind)=(i.organization_id,i.workspace_id,i.environment_id,i.id,'integration') WHERE (i.organization_id,i.workspace_id,i.environment_id,i.id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), k8Integration).Scan(&k8State, &workflowState, &k8Version, &workflowVersion, &k8Subjects); err != nil {
		t.Fatal(err)
	}
	if k8State != "degraded" || workflowState != "degraded" || k8Version != workflowVersion || k8Version < 2 || k8Subjects != 0 {
		t.Fatalf("kubernetes upgrade state=%s/%d workflow=%s/%d subjects=%d", k8State, k8Version, workflowState, workflowVersion, k8Subjects)
	}
	var payload []byte
	query := `SELECT zasp_execution_bind_connection_subject($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), k8Integration, k8Connection, "kubernetes", "kubernetes_cluster", "customer.example/cluster-01", k8Version, k8Config, "reference"}
	wrong := append([]any(nil), args...)
	wrong[3] = awsIntegration
	if err := connection.QueryRow(ctx, query, wrong...).Scan(&payload); err == nil {
		t.Fatal("cross-integration subject binding succeeded")
	}
	idempotencyKey := "execution-reauthorize-0002"
	intent := referenceAuthorizationIntent(identity, k8Integration, "kubernetes", idempotencyKey, k8Version, k8Config)
	completionQuery := `SELECT zasp_execution_complete_reference_authorization($1,$2,$3,$4,$5,'kubernetes',$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,'kubernetes_cluster','customer.example/cluster-01')`
	completionArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), k8Integration, k8Connection, "ref:kubernetes/connection/customer-0001", idempotencyKey, k8Version, k8Config, intent, "pid_77000005-0000-4000-8000-000000000005", "pid_77000006-0000-4000-8000-000000000006", "pid_77000007-0000-4000-8000-000000000007"}
	if err := connection.QueryRow(ctx, completionQuery, completionArgs...).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, completionQuery, completionArgs...).Scan(&payload); err != nil {
		t.Fatalf("exact reference subject replay=%s err=%v", payload, err)
	}
	var replay struct {
		Version  int64  `json:"version"`
		Receipt  string `json:"receipt_id"`
		Replayed bool   `json:"replayed"`
	}
	if err := json.Unmarshal(payload, &replay); err != nil || replay.Version != k8Version+1 || replay.Receipt != "pid_77000007-0000-4000-8000-000000000007" || !replay.Replayed {
		t.Fatalf("exact reference subject replay=%s err=%v", payload, err)
	}
	var subjectCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_discovery_connection_subjects WHERE integration_id IN($1,$2)`, awsIntegration, k8Integration).Scan(&subjectCount); err != nil || subjectCount != 2 {
		t.Fatalf("subject count=%d err=%v", subjectCount, err)
	}
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_integrations WHERE id=$1`, k8Integration).Scan(&k8State); err != nil || k8State != "active" {
		t.Fatalf("kubernetes reauthorization state=%s err=%v", k8State, err)
	}
}

func TestProductionDiscoveryExecutionPostgresLegacyLastGoodIsReadableButNotClaimable(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_77400001-0000-4000-8000-000000000001"
	connectionID := "pid_77400002-0000-4000-8000-000000000002"
	syncID := "pid_77400003-0000-4000-8000-000000000003"
	snapshotID := "pid_77400004-0000-4000-8000-000000000004"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0074","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/customer-0074", configuration, "4")
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,attempt,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'legacy-sync-idempotency-0074',$6,'manual',$7,'queued',0,'parser-v1','tool-v1')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), syncID, integrationID, make([]byte, 32), identity.PrincipalID.String()); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	digest[0] = 74
	if _, err := tx.Exec(ctx, `INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,candidate_digest,state,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'aws','s3://zasp-evidence/legacy/manifest.json',$7,$7,'complete','{"discovered_count":1,"changed_count":1,"removed_count":0}',true,true,transaction_timestamp(),transaction_timestamp())`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, integrationID, syncID, digest); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE zasp_discovery_syncs SET state='succeeded',attempt=1,started_at=requested_at,completed_at=transaction_timestamp(),discovered_count=1,changed_count=1,snapshot_id=$1 WHERE id=$2`, snapshotID, syncID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version,input_digest) SELECT $1,$2,$3,$4,kind,'v1',$5 FROM unnest(ARRAY['risk','graph','search']) kind`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, digest); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || bytes.Count(payload, []byte(`"state": "unavailable"`)) != 3 || !bytes.Contains(payload, []byte(`"snapshot_id": "`+snapshotID+`"`)) {
		t.Fatalf("legacy freshness=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_projection_work('risk','risk-worker','risk-lease-token-0001',30,8)`).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"items": []`)) {
		t.Fatalf("legacy projection claim=%s err=%v", payload, err)
	}
	var pending, attempts int
	if err := connection.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='pending'),sum(attempt) FROM zasp_projection_work WHERE snapshot_id=$1`, snapshotID).Scan(&pending, &attempts); err != nil || pending != 3 || attempts != 0 {
		t.Fatalf("legacy projection churn pending=%d attempts=%d err=%v", pending, attempts, err)
	}
}

func TestProductionDiscoveryExecutionPublicMutationsReplayAndReceipts(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_77500001-0000-4000-8000-000000000001"
	connectionID := "pid_77500002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0075","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/customer-0075", configuration, "5")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	var integrationVersion int64
	if err := connection.QueryRow(ctx, `SELECT version FROM zasp_integrations WHERE id=$1`, integrationID).Scan(&integrationVersion); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	digest[0] = 75
	syncArgs := []any{
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID,
		"public-sync-idempotency-0075", integrationVersion,
		"pid_77500003-0000-4000-8000-000000000003", "pid_77500004-0000-4000-8000-000000000004", "pid_77500005-0000-4000-8000-000000000005",
		digest, "parser-v1", "tool-v1", "pid_77500006-0000-4000-8000-000000000006", "pid_77500007-0000-4000-8000-000000000007", "",
	}
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_public_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, syncArgs...).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"receipt_id": ""`)) || !bytes.Contains(payload, []byte(`"replayed": false`)) {
		t.Fatalf("PAT sync first response=%s err=%v", payload, err)
	}
	firstSync := string(payload)
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_public_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, syncArgs...).Scan(&payload); err != nil || string(payload) == firstSync || !bytes.Contains(payload, []byte(`"replayed": true`)) || !bytes.Contains(payload, []byte(`"receipt_id": ""`)) {
		t.Fatalf("PAT sync replay=%s err=%v first=%s", payload, err, firstSync)
	}
	var receiptCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE resource_kind='integration_sync' AND resource_id=$1`, syncArgs[7]).Scan(&receiptCount); err != nil || receiptCount != 0 {
		t.Fatalf("PAT sync receipts=%d err=%v", receiptCount, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_history($1,$2,$3,$4,NULL,NULL,20)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"items": [`)) {
		t.Fatalf("sync first history page=%s err=%v", payload, err)
	}
	scheduleArgs := []any{
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID,
		"public-schedule-idem-0075", int64(0), 300, "disabled", "pid_77500008-0000-4000-8000-000000000008", "pid_77500009-0000-4000-8000-000000000009", "pid_77500010-0000-4000-8000-000000000010",
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_public_put_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, scheduleArgs...).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"next_run_at": null`)) || !bytes.Contains(payload, []byte(`"replayed": false`)) {
		t.Fatalf("browser schedule first response=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_public_put_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, scheduleArgs...).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"replayed": true`)) {
		t.Fatalf("browser schedule replay=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_receipts WHERE resource_kind='integration_schedule' AND resource_id=$1 AND receipt_id=$2`, integrationID, scheduleArgs[11]).Scan(&receiptCount); err != nil || receiptCount != 1 {
		t.Fatalf("browser schedule receipts=%d err=%v", receiptCount, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_workflow_receipt_list($1,$2,$3,$4,20)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"operation": "putIntegrationSchedule"`)) || !bytes.Contains(payload, []byte(`"resource_id": "`+integrationID+`"`)) {
		t.Fatalf("browser schedule receipt list=%s err=%v", payload, err)
	}
}

func TestProductionDiscoveryExecutionPostgresHydratesAndFencesLeasedJob(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_78000001-0000-4000-8000-000000000001"
	connectionID := "pid_78000002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0002","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/customer-0002", configuration, "3")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	syncID := "pid_78000003-0000-4000-8000-000000000003"
	jobID := "pid_78000004-0000-4000-8000-000000000004"
	outboxID := "pid_78000005-0000-4000-8000-000000000005"
	requestDigest := make([]byte, 32)
	requestDigest[0] = 1
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, syncID, jobID, outboxID, "execution-sync-0001", requestDigest, "manual", "parser_v1", "tool_v1").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	worker := "discovery-worker-01"
	token := "lease-token-000000000001"
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_jobs($1,$2,30,1)`, worker, token).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var claimed struct {
		Items []DiscoveryJobLease `json:"items"`
	}
	if err := json.Unmarshal(payload, &claimed); err != nil || len(claimed.Items) != 1 || claimed.Items[0].ID != jobID {
		t.Fatalf("claimed=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var input struct {
		JobID         string          `json:"job_id"`
		IntegrationID string          `json:"integration_id"`
		ConnectionID  string          `json:"connection_id"`
		SnapshotID    string          `json:"snapshot_id"`
		Generation    int64           `json:"generation"`
		Provider      string          `json:"provider"`
		SubjectKind   string          `json:"subject_kind"`
		SubjectID     string          `json:"subject_id"`
		Configuration json.RawMessage `json:"configuration"`
	}
	var decodedConfiguration map[string]string
	if err := json.Unmarshal(payload, &input); err != nil {
		t.Fatalf("hydrated=%s err=%v", payload, err)
	}
	if err := json.Unmarshal(input.Configuration, &decodedConfiguration); err != nil || input.JobID != jobID || input.IntegrationID != integrationID || input.ConnectionID != connectionID || !validProductID(input.SnapshotID) || input.Generation != 1 || input.Provider != "aws" || input.SubjectKind != "aws_account" || input.SubjectID != "123456789012" || decodedConfiguration["role_arn"] != "arn:aws:iam::123456789012:role/zasp-discovery" || decodedConfiguration["external_id_reference"] != "ref:aws/external-id/customer-0002" {
		t.Fatalf("hydrated=%s err=%v", payload, err)
	}
	firstSnapshotID := input.SnapshotID
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token).Scan(&payload); err != nil || json.Unmarshal(payload, &input) != nil || input.SnapshotID != firstSnapshotID || input.Generation != 1 {
		t.Fatalf("reserved input replay=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_heartbeat_job($1,$2,$3,$4,$5,$6,30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_heartbeat_job($1,$2,$3,$4,$5,$6,30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, "wrong-lease-token-000001").Scan(&payload); err == nil {
		t.Fatal("wrong lease token heartbeat succeeded")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_connection_subjects SET subject_id='999999999999' WHERE integration_id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token).Scan(&payload); err == nil {
		t.Fatal("mismatched durable subject hydrated")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_connection_subjects SET subject_id='123456789012' WHERE integration_id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	resultDigest := make([]byte, 32)
	resultDigest[0] = 9
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_finish_job($1,$2,$3,$4,$5,$6,'failed',$7,'terminal','terminal collection failure',0)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token, resultDigest).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'redelivery-worker','redelivery-token-0000001',30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"disposition": "ack_terminal"`)) {
		t.Fatalf("terminal redelivery=%s err=%v", payload, err)
	}
}

func TestProductionDiscoveryExecutionPostgresBindsRequestIntentAndSerializesQuota(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_78500001-0000-4000-8000-000000000001"
	connectionID := "pid_78500002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0004","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/customer-0004", configuration, "8")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	request := func(sequence string) (string, string) {
		t.Helper()
		syncID := "pid_785000" + sequence + "-0000-4000-8000-0000000000" + sequence
		jobID := "pid_786000" + sequence + "-0000-4000-8000-0000000000" + sequence
		outboxID := "pid_787000" + sequence + "-0000-4000-8000-0000000000" + sequence
		digest := make([]byte, 32)
		digest[0] = sequence[0]
		var payload []byte
		if err := connection.QueryRow(ctx, `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'manual','parser_v1','tool_v1')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, syncID, jobID, outboxID, "execution-quota-"+sequence, digest).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		return syncID, jobID
	}
	_, driftJob := request("11")
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'intent-worker','intent-token-0000000001',30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), driftJob).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET version=version+1 WHERE id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,'intent-worker','intent-token-0000000001')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), driftJob).Scan(&payload); err == nil {
		t.Fatal("request-time integration version drift hydrated")
	}
	var reservations int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_discovery_generation_reservations WHERE sync_id=(SELECT authority_id FROM zasp_discovery_jobs WHERE id=$1)`, driftJob).Scan(&reservations); err != nil || reservations != 0 {
		t.Fatalf("drift reservation residue=%d err=%v", reservations, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET version=version-1 WHERE id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_finish_job($1,$2,$3,$4,'intent-worker','intent-token-0000000001','failed',NULL,'intent changed',0)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), driftJob).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	_, firstJob := request("12")
	_, secondJob := request("13")
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_execution_quotas(organization_id,max_active_jobs) VALUES($1,1)`, identity.Scope.OrganizationID().String()); err != nil {
		t.Fatal(err)
	}
	type result struct {
		disposition string
		jobID       string
		worker      string
		token       string
		err         error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, jobID := range []string{firstJob, secondJob} {
		wait.Add(1)
		go func(index int, jobID string) {
			defer wait.Done()
			worker := "quota-worker-" + string(rune('1'+index))
			token := "quota-token-000000000" + string(rune('1'+index))
			workerConnection, connectErr := pgx.Connect(ctx, dsn)
			if connectErr != nil {
				results <- result{jobID: jobID, worker: worker, token: token, err: connectErr}
				return
			}
			defer workerConnection.Close(ctx)
			<-start
			var response []byte
			queryErr := workerConnection.QueryRow(ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,$5,$6,30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token).Scan(&response)
			var claim struct {
				Disposition string `json:"disposition"`
			}
			if queryErr == nil {
				queryErr = json.Unmarshal(response, &claim)
			}
			results <- result{disposition: claim.Disposition, jobID: jobID, worker: worker, token: token, err: queryErr}
		}(index, jobID)
	}
	close(start)
	wait.Wait()
	close(results)
	claimed, busy := 0, 0
	var claimedResult, busyResult result
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		switch item.disposition {
		case "claimed":
			claimed++
			claimedResult = item
		case "busy":
			busy++
			busyResult = item
		default:
			t.Fatalf("unexpected quota disposition=%q", item.disposition)
		}
	}
	if claimed != 1 || busy != 1 {
		t.Fatalf("serialized quota claimed=%d busy=%d", claimed, busy)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_execution_quotas SET max_active_jobs=2,version=version+1 WHERE organization_id=$1`, identity.Scope.OrganizationID().String()); err != nil {
		t.Fatal(err)
	}
	busyResult.worker, busyResult.token = "quota-worker-reclaim", "quota-token-reclaim-0001"
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,$5,$6,30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), busyResult.jobID, busyResult.worker, busyResult.token).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"disposition": "claimed"`)) {
		t.Fatalf("second quota claim=%s err=%v", payload, err)
	}
	type reservation struct {
		snapshotID string
		generation int64
		err        error
	}
	reservationResults := make(chan reservation, 2)
	start = make(chan struct{})
	wait = sync.WaitGroup{}
	for _, item := range []result{claimedResult, busyResult} {
		wait.Add(1)
		go func(item result) {
			defer wait.Done()
			workerConnection, connectErr := pgx.Connect(ctx, dsn)
			if connectErr != nil {
				reservationResults <- reservation{err: connectErr}
				return
			}
			defer workerConnection.Close(ctx)
			<-start
			var response []byte
			queryErr := workerConnection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), item.jobID, item.worker, item.token).Scan(&response)
			var input struct {
				SnapshotID string `json:"snapshot_id"`
				Generation int64  `json:"generation"`
			}
			if queryErr == nil {
				queryErr = json.Unmarshal(response, &input)
			}
			reservationResults <- reservation{snapshotID: input.SnapshotID, generation: input.Generation, err: queryErr}
		}(item)
	}
	close(start)
	wait.Wait()
	close(reservationResults)
	generations := map[int64]string{}
	conflicts := 0
	for item := range reservationResults {
		if item.err != nil {
			var postgresError *pgconn.PgError
			if !errors.As(item.err, &postgresError) || postgresError.Code != "55P03" {
				t.Fatalf("concurrent generation reservation=%#v", item)
			}
			conflicts++
			continue
		}
		if !validProductID(item.snapshotID) {
			t.Fatalf("concurrent generation reservation=%#v", item)
		}
		generations[item.generation] = item.snapshotID
	}
	if len(generations) != 1 || generations[1] == "" || conflicts != 1 {
		t.Fatalf("serialized concurrent generations=%#v conflicts=%d", generations, conflicts)
	}
}

func TestProductionDiscoveryExecutionPostgresSchedulesSnapshotsAndMonotonicProjection(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_79000001-0000-4000-8000-000000000001"
	connectionID := "pid_79000002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0003","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "aws", integrationID, connectionID, "ref:aws/external-id/customer-0003", configuration, "4")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	scheduleID := "pid_79000003-0000-4000-8000-000000000003"
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_put_schedule($1,$2,$3,$4,$5,300,$6,0)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, integrationID, time.Now().UTC().Add(-time.Minute)).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_schedules($1,$2,30,1)`, "scheduler-01", "schedule-token-000000001").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var schedules struct {
		Items []DiscoveryScheduleLease `json:"items"`
	}
	if err := json.Unmarshal(payload, &schedules); err != nil || len(schedules.Items) != 1 || schedules.Items[0].ID != scheduleID {
		t.Fatalf("schedules=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_schedule_input($1,$2,$3,$4,$5,$6)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, "scheduler-01", "schedule-token-000000001").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_heartbeat_schedule($1,$2,$3,$4,$5,$6,30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, "scheduler-01", "schedule-token-000000001").Scan(&payload); err != nil {
		t.Fatal(err)
	}

	syncID := "pid_79000004-0000-4000-8000-000000000004"
	jobID := "pid_79000005-0000-4000-8000-000000000005"
	outboxID := "pid_79000006-0000-4000-8000-000000000006"
	requestDigest := make([]byte, 32)
	requestDigest[0] = 2
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_request_scheduled_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), scheduleID, "scheduler-01", "schedule-token-000000001", integrationID, syncID, jobID, outboxID, "execution-sync-0002", requestDigest, "parser_v1", "tool_v1").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"status": "queued"`)) || !bytes.Contains(payload, []byte(`"version": 1`)) {
		t.Fatalf("queued sync detail=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,'pid_79000009-0000-4000-8000-000000000009',$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), syncID).Scan(&payload); err == nil {
		t.Fatal("cross-integration sync detail succeeded")
	}
	nextRun := time.Now().UTC().Add(5 * time.Minute).Round(time.Microsecond)
	completeScheduleQuery := `SELECT zasp_execution_complete_schedule($1,$2,$3,$4,'scheduler-01','schedule-token-000000001','advanced',$5)`
	if err := connection.QueryRow(ctx, completeScheduleQuery, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, nextRun).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	firstScheduleCompletion := string(payload)
	if err := connection.QueryRow(ctx, completeScheduleQuery, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, nextRun).Scan(&payload); err != nil || string(payload) != firstScheduleCompletion {
		t.Fatalf("schedule completion replay=%s err=%v first=%s", payload, err, firstScheduleCompletion)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_schedules SET next_run_at=transaction_timestamp()-interval '1 minute' WHERE id=$1`, scheduleID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_schedules('scheduler-02','schedule-token-000000002',30,1)`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_complete_schedule($1,$2,$3,$4,'scheduler-02','schedule-token-000000002','released',$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, time.Now().UTC().Add(-time.Second)).Scan(&payload); err == nil {
		t.Fatal("expired schedule next-run succeeded")
	}
	disabledNextRun := time.Now().UTC().Add(time.Hour).Round(time.Microsecond)
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_complete_schedule($1,$2,$3,$4,'scheduler-02','schedule-token-000000002','disabled',$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), scheduleID, disabledNextRun).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"state": "disabled"`)) {
		t.Fatalf("disabled schedule completion=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_schedule_detail($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"state": "disabled"`)) || !bytes.Contains(payload, []byte(`"next_run_at": null`)) {
		t.Fatalf("disabled schedule detail=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'discovery-worker-02','delivery-token-0000000002',30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"status": "running"`)) || !bytes.Contains(payload, []byte(`"version": 2`)) {
		t.Fatalf("running sync detail=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_job_input($1,$2,$3,$4,'discovery-worker-02','delivery-token-0000000002')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var reserved struct {
		SnapshotID string `json:"snapshot_id"`
		Generation int64  `json:"generation"`
	}
	if err := json.Unmarshal(payload, &reserved); err != nil || !validProductID(reserved.SnapshotID) || reserved.Generation != 1 {
		t.Fatalf("reservation=%s err=%v", payload, err)
	}
	snapshotID := reserved.SnapshotID
	manifestKey := "organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/artifacts/pid_79000008-0000-4000-8000-000000000008"
	manifestReference := "s3://zasp-evidence-prod/" + manifestKey
	manifestChecksum := make([]byte, 32)
	manifestChecksum[0] = 3
	applyQuery := `SELECT zasp_execution_apply_complete_snapshot($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'aws',$11,$12,'version-0001',$13,128,'application/json','manifest_v1',$14,'cursor-0001','parser_v1','tool_v1','[]'::jsonb,'[]'::jsonb,'[]'::jsonb)`
	applyArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, "discovery-worker-02", "delivery-token-0000000002", integrationID, syncID, snapshotID, reserved.Generation, manifestReference, manifestKey, manifestChecksum, time.Now().UTC()}
	wrongManifestArgs := append([]any(nil), applyArgs...)
	wrongManifestArgs[11] = manifestKey + "-other"
	if err := connection.QueryRow(ctx, applyQuery, wrongManifestArgs...).Scan(&payload); err == nil {
		t.Fatal("mismatched manifest reference/key succeeded")
	}
	var snapshotResidue int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_discovery_snapshots WHERE id=$1)+(SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE snapshot_id=$1)`, snapshotID).Scan(&snapshotResidue); err != nil || snapshotResidue != 0 {
		t.Fatalf("mismatched manifest residue=%d err=%v", snapshotResidue, err)
	}
	staleLeaseArgs := append([]any(nil), applyArgs...)
	staleLeaseArgs[5] = "stale-delivery-token-0001"
	if err := connection.QueryRow(ctx, applyQuery, staleLeaseArgs...).Scan(&payload); err == nil {
		t.Fatal("stale delivery lease applied snapshot")
	}
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_discovery_snapshots WHERE id=$1)+(SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE snapshot_id=$1)`, snapshotID).Scan(&snapshotResidue); err != nil || snapshotResidue != 0 {
		t.Fatalf("stale delivery residue=%d err=%v", snapshotResidue, err)
	}
	if err := connection.QueryRow(ctx, applyQuery, applyArgs...).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var applied struct {
		SnapshotID      string `json:"snapshot_id"`
		CandidateDigest []byte `json:"candidate_digest"`
	}
	if err := json.Unmarshal(payload, &applied); err != nil || applied.SnapshotID != snapshotID || len(applied.CandidateDigest) != 32 {
		t.Fatalf("apply=%s err=%v", payload, err)
	}
	firstApply := string(payload)
	if err := connection.QueryRow(ctx, applyQuery, applyArgs...).Scan(&payload); err != nil || string(payload) != firstApply {
		t.Fatalf("snapshot exact replay=%s err=%v first=%s", payload, err, firstApply)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"status": "succeeded"`)) || !bytes.Contains(payload, []byte(`"version": 3`)) {
		t.Fatalf("succeeded sync detail=%s err=%v", payload, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_jobs SET attempt=5,updated_at=transaction_timestamp(),lease_expires_at=transaction_timestamp()+interval '10 milliseconds' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_jobs('recovery-worker','recovery-token-00000001',30,1)`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var recoveredState string
	var recoveredDigest []byte
	if err := connection.QueryRow(ctx, `SELECT state,result_digest FROM zasp_discovery_jobs WHERE id=$1`, jobID).Scan(&recoveredState, &recoveredDigest); err != nil || recoveredState != "succeeded" || !bytes.Equal(recoveredDigest, applied.CandidateDigest) {
		t.Fatalf("committed attempt-five recovery state=%q digest=%x err=%v", recoveredState, recoveredDigest, err)
	}
	historyOne := "pid_79000010-0000-4000-8000-000000000010"
	historyTwo := "pid_79000011-0000-4000-8000-000000000011"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,parser_version,tool_version,requested_at) VALUES($1,$2,$3,$4,$6,'execution-history-0010',digest('history-1','sha256'),'manual',$7,'queued','parser_v1','tool_v1',transaction_timestamp()+interval '1 second'),($1,$2,$3,$5,$6,'execution-history-0011',digest('history-2','sha256'),'manual',$7,'queued','parser_v1','tool_v1',transaction_timestamp()+interval '2 seconds')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), historyOne, historyTwo, integrationID, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_history($1,$2,$3,$4,NULL,NULL,2)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var history struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		NextRequestedAt *time.Time `json:"next_requested_at"`
		NextID          *string    `json:"next_id"`
	}
	if err := json.Unmarshal(payload, &history); err != nil || len(history.Items) != 2 || history.Items[0].ID != historyTwo || history.Items[1].ID != historyOne || history.NextRequestedAt == nil || history.NextID == nil || *history.NextID != historyOne {
		t.Fatalf("sync history first page=%s err=%v", payload, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_discovery_syncs WHERE id=$1`, historyTwo); err != nil {
		t.Fatal(err)
	}
	historyThree := "pid_79000012-0000-4000-8000-000000000012"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,parser_version,tool_version,requested_at) VALUES($1,$2,$3,$4,$5,'execution-history-0012',digest('history-3','sha256'),'manual',$6,'queued','parser_v1','tool_v1',transaction_timestamp()+interval '3 seconds')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), historyThree, integrationID, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_history($1,$2,$3,$4,$5,$6,2)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, *history.NextRequestedAt, *history.NextID).Scan(&payload); err != nil || json.Unmarshal(payload, &history) != nil || len(history.Items) != 1 || history.Items[0].ID != syncID {
		t.Fatalf("stable sync history continuation=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"graph": {"state": "pending"`)) || !bytes.Contains(payload, []byte(`"risk": {"state": "pending"`)) || !bytes.Contains(payload, []byte(`"search": {"state": "pending"`)) {
		t.Fatalf("initial freshness=%s err=%v", payload, err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_snapshot_projection_items(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,section,item_id,payload) SELECT $1,$2,$3,$4,$5,'aws','entities','pid_82000000-0000-4000-8000-'||lpad(value::text,12,'0'),jsonb_build_object('id','pid_82000000-0000-4000-8000-'||lpad(value::text,12,'0')) FROM generate_series(1,1000) value`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, integrationID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_snapshot_projection_page($1,$2,$3,$4,'entities',NULL,2)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var page struct {
		SnapshotID string            `json:"snapshot_id"`
		Generation int64             `json:"generation"`
		Items      []json.RawMessage `json:"items"`
		NextID     *string           `json:"next_id"`
	}
	if err := json.Unmarshal(payload, &page); err != nil || page.SnapshotID != snapshotID || page.Generation != reserved.Generation || len(page.Items) != 2 || page.NextID == nil || *page.NextID != "pid_82000000-0000-4000-8000-000000000002" {
		t.Fatalf("projection page=%s err=%v", payload, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_discovery_snapshot_projection_items WHERE snapshot_id=$1 AND item_id='pid_82000000-0000-4000-8000-000000000001'`, snapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_snapshot_projection_items(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,section,item_id,payload) VALUES($1,$2,$3,$4,$5,'aws','entities','pid_81000000-0000-4000-8000-000000000000','{"id":"pid_81000000-0000-4000-8000-000000000000"}'::jsonb)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, integrationID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_snapshot_projection_page($1,$2,$3,$4,'entities',$5,2)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, *page.NextID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &page); err != nil || len(page.Items) != 2 || !bytes.Contains(page.Items[0], []byte(`000000000003`)) || !bytes.Contains(page.Items[1], []byte(`000000000004`)) {
		t.Fatalf("stable projection keyset=%s err=%v", payload, err)
	}
	var plan []byte
	if err := connection.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT payload FROM zasp_discovery_snapshot_projection_items WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND snapshot_id=$4 AND section='entities' AND item_id>$5 ORDER BY item_id LIMIT 100`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, *page.NextID).Scan(&plan); err != nil || !bytes.Contains(plan, []byte(`zasp_discovery_snapshot_projection_items_pkey`)) || bytes.Contains(plan, []byte(`Sort Method`)) {
		t.Fatalf("projection keyset plan=%s err=%v", plan, err)
	}
	for range 3 {
		if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_projection_work('search','projection-worker-01','projection-token-00000001',30,3)`).Scan(&payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_heartbeat_projection($1,$2,$3,$4,'search','v1','projection-worker-01','projection-token-00000001',30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	driverDigest := make([]byte, 32)
	driverDigest[0] = 4
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_finish_projection($1,$2,$3,$4,'search','v1','projection-worker-01','projection-token-00000001','succeeded','projection-receipt-00000001',$5,'',0)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, driverDigest).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_projection_status($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var projectionStatus struct {
		IntegrationID string `json:"integration_id"`
		Source        string `json:"source"`
		Projections   []struct {
			Kind    string `json:"kind"`
			Current bool   `json:"current"`
		} `json:"projections"`
	}
	if err := json.Unmarshal(payload, &projectionStatus); err != nil || projectionStatus.IntegrationID != integrationID || projectionStatus.Source != "aws" || len(projectionStatus.Projections) != 3 || projectionStatus.Projections[0].Current || projectionStatus.Projections[1].Current || !projectionStatus.Projections[2].Current {
		t.Fatalf("projection status=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"search": {"state": "current"`)) || !bytes.Contains(payload, []byte(`"risk": {"state": "pending"`)) {
		t.Fatalf("partial projection freshness=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_advance_projection_cursor($1,$2,$3,'search',$4,0,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, applied.CandidateDigest).Scan(&payload); err == nil {
		t.Fatal("stale projection cursor succeeded")
	}
}

func TestProductionDiscoveryExecutionPostgresDownRestoresReferenceAuthorization(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_79500001-0000-4000-8000-000000000001"
	connectionID := "pid_79500002-0000-4000-8000-000000000002"
	configuration := json.RawMessage(`{"connection_reference":"ref:kubernetes/connection/customer-0095"}`)
	seedReferenceAuthorizedIntegration(t, ctx, connection, "kubernetes", integrationID, connectionID, "ref:kubernetes/connection/customer-0095", configuration, "9")
	var priorIntegrationState, priorConnectionState string
	var priorIntegrationVersion, priorConnectionVersion, priorWorkflowVersion int64
	var priorIntegrationUpdated, priorConnectionUpdated, priorWorkflowUpdated time.Time
	var priorConnectionVerified *time.Time
	var priorWorkflowBody []byte
	if err := connection.QueryRow(ctx, `SELECT integration.state,integration.version,integration.updated_at,connection.state,connection.version,connection.verified_at,connection.updated_at,workflow.body,workflow.version,workflow.updated_at FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id) JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id,workflow.kind)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,'integration') WHERE integration.id=$1`, integrationID).Scan(&priorIntegrationState, &priorIntegrationVersion, &priorIntegrationUpdated, &priorConnectionState, &priorConnectionVersion, &priorConnectionVerified, &priorConnectionUpdated, &priorWorkflowBody, &priorWorkflowVersion, &priorWorkflowUpdated); err != nil {
		t.Fatal(err)
	}
	var readinessDefinition string
	if err := connection.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_reference_authorization_readiness(text,text)'::regprocedure)`).Scan(&readinessDefinition); err != nil {
		t.Fatal(err)
	}
	semanticDefinition := strings.Replace(readinessDefinition, "public.zasp_reference_authorization_readiness(expected_checksum text, expected_fingerprint text)", "public.test_reference_semantic_objects()", 1)
	semanticDefinition = strings.Replace(semanticDefinition, "RETURNS boolean", "RETURNS jsonb", 1)
	finalSelect := strings.Index(semanticDefinition, " SELECT EXISTS(SELECT 1 FROM zasp_schema_versions")
	endBody := strings.LastIndex(semanticDefinition, "$function$")
	semanticDefinition = semanticDefinition[:finalSelect] + " SELECT jsonb_agg(jsonb_build_array(object_kind,object_identity,definition) ORDER BY object_kind,object_identity) FROM semantic_objects\n" + semanticDefinition[endBody:]
	if _, err := connection.Exec(ctx, semanticDefinition); err != nil {
		t.Fatal(err)
	}
	var beforeSemantic []byte
	if err := connection.QueryRow(ctx, `SELECT test_reference_semantic_objects()`).Scan(&beforeSemantic); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1 AND operation='degradeIntegrationForExecutionUpgrade' AND resource_id=$2`, identity.Scope.OrganizationID().String(), integrationID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("upgrade degradation audits=%d err=%v", auditCount, err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionDiscoveryExecution().DownSQL())
		t.Fatalf("execution down: %v detail=%#v", err, detail)
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 12 {
		t.Fatalf("down version=%d err=%v", version, versionErr)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if schema, schemaErr := database.SchemaVersion(ctx); schemaErr != nil || schema != ReferenceSchemaVersion {
		t.Fatalf("schema after v13 down=%q err=%v", schema, schemaErr)
	}
	var afterSemantic []byte
	if err := connection.QueryRow(ctx, `SELECT test_reference_semantic_objects()`).Scan(&afterSemantic); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeSemantic, afterSemantic) {
		t.Fatal("v13 down did not exactly restore v12 semantic objects")
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_reference_authorization_readiness($1,$2)`, migrations.ReferenceAuthorization().Checksum(), migrations.ReferenceAuthorizationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		var securityReady bool
		var marker, fingerprint string
		var version int
		_ = connection.QueryRow(ctx, `SELECT zasp_reference_authorization_security_ready(),(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema'),(SELECT value FROM zasp_schema_metadata WHERE key='reference_authorization_fingerprint'),(SELECT max(version) FROM zasp_schema_versions)`).Scan(&securityReady, &marker, &fingerprint, &version)
		var connectorReady bool
		var discoveryReady bool
		var apiFunctions []string
		_ = connection.QueryRow(ctx, `SELECT zasp_connector_security_ready(),zasp_discovery_security_ready(),ARRAY(SELECT p.proname||'('||replace(oidvectortypes(p.proargtypes),', ',',')||')' FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=ANY(ARRAY['zasp_complete_reference_authorization','zasp_reference_authorization_configuration_valid','zasp_reference_authorization_exact_replay','zasp_reference_authorization_readiness','zasp_reference_authorization_replay','zasp_reference_authorization_security_ready']) AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE') ORDER BY 1)`).Scan(&connectorReady, &discoveryReady, &apiFunctions)
		t.Fatalf("reference readiness after v13 down=%t security=%t connector=%t discovery=%t marker=%q fingerprint=%q expected=%q version=%d api_functions=%v err=%v", ready, securityReady, connectorReady, discoveryReady, marker, fingerprint, migrations.ReferenceAuthorizationSemanticFingerprint(), version, apiFunctions, err)
	}
	var executionRoleCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker')`).Scan(&executionRoleCount); err != nil || executionRoleCount != 0 {
		t.Fatalf("managed execution roles after down=%d err=%v", executionRoleCount, err)
	}
	var restoredIntegrationState, restoredConnectionState string
	var restoredIntegrationVersion, restoredConnectionVersion, restoredWorkflowVersion int64
	var restoredIntegrationUpdated, restoredConnectionUpdated, restoredWorkflowUpdated time.Time
	var restoredConnectionVerified *time.Time
	var restoredWorkflowBody []byte
	if err := connection.QueryRow(ctx, `SELECT integration.state,integration.version,integration.updated_at,connection.state,connection.version,connection.verified_at,connection.updated_at,workflow.body,workflow.version,workflow.updated_at FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id) JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.id,workflow.kind)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,'integration') WHERE integration.id=$1`, integrationID).Scan(&restoredIntegrationState, &restoredIntegrationVersion, &restoredIntegrationUpdated, &restoredConnectionState, &restoredConnectionVersion, &restoredConnectionVerified, &restoredConnectionUpdated, &restoredWorkflowBody, &restoredWorkflowVersion, &restoredWorkflowUpdated); err != nil {
		t.Fatal(err)
	}
	if restoredIntegrationState != priorIntegrationState || restoredIntegrationVersion != priorIntegrationVersion || !restoredIntegrationUpdated.Equal(priorIntegrationUpdated) || restoredConnectionState != priorConnectionState || restoredConnectionVersion != priorConnectionVersion || !restoredConnectionUpdated.Equal(priorConnectionUpdated) || (restoredConnectionVerified == nil) != (priorConnectionVerified == nil) || restoredConnectionVerified != nil && !restoredConnectionVerified.Equal(*priorConnectionVerified) || !bytes.Equal(restoredWorkflowBody, priorWorkflowBody) || restoredWorkflowVersion != priorWorkflowVersion || !restoredWorkflowUpdated.Equal(priorWorkflowUpdated) {
		t.Fatalf("down did not exactly restore kubernetes transition")
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1 AND operation='degradeIntegrationForExecutionUpgrade' AND resource_id=$2`, identity.Scope.OrganizationID().String(), integrationID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("down degradation audits=%d err=%v", auditCount, err)
	}
}

func TestProductionDiscoveryExecutionPostgresOAuthCredentialAtomicallyBindsSubject(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToProductionDiscoveryExecution(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_7a000001-0000-4000-8000-000000000001"
	connectionID := "pid_7a000002-0000-4000-8000-000000000002"
	credentialID := "pid_7a000003-0000-4000-8000-000000000003"
	var payload []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_create_integration($1,$2,$3,$4,'github','1.0.0','GitHub','{}'::jsonb,NULL)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_transition_integration($1,$2,$3,$4,1,'active')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_put_connection($1,$2,$3,$4,$5,'github','ref:github/installation/customer-0001')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), connectionID, integrationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_transition_connection($1,$2,$3,$4,$5,1,'verified')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), connectionID, integrationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_put_credential($1,$2,$3,$4,$5,'github','github_installation_reference','ref:github/installation/customer-0001',1,'{"installation_id":"9007199254740992"}'::jsonb)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), credentialID, integrationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var subject string
	if err := connection.QueryRow(ctx, `SELECT subject_id FROM zasp_discovery_connection_subjects WHERE integration_id=$1 AND connection_id=$2`, integrationID, connectionID).Scan(&subject); err != nil || subject != "9007199254740992" {
		t.Fatalf("oauth subject=%q err=%v", subject, err)
	}
	invalidIntegration := "pid_7a000004-0000-4000-8000-000000000004"
	invalidConnection := "pid_7a000005-0000-4000-8000-000000000005"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES($1,$2,$3,$4,'github','1.0.0','Invalid','{}'::jsonb,'active')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), invalidIntegration); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,id,integration_id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,$5,'github','ref:github/installation/customer-0002','verified',transaction_timestamp())`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), invalidConnection, invalidIntegration); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_put_credential($1,$2,$3,$4,$5,'github','github_installation_reference','ref:github/installation/customer-0002',1,'{"installation_id":"9007199254740993"}'::jsonb)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), "pid_7a000006-0000-4000-8000-000000000006", invalidIntegration).Scan(&payload); err == nil {
		t.Fatal("out-of-range OAuth subject succeeded")
	}
	var residue int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_connector_credentials WHERE integration_id=$1)+(SELECT count(*) FROM zasp_discovery_connection_subjects WHERE integration_id=$1)`, invalidIntegration).Scan(&residue); err != nil || residue != 0 {
		t.Fatalf("invalid OAuth subject residue=%d err=%v", residue, err)
	}
}
