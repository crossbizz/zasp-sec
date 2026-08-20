package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrateToProductionDiscoveryExecution(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := migrateToReferenceAuthorization(t, ctx, connection)
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionDiscoveryExecution().UpSQL())
		t.Fatalf("production discovery execution migration: %v (%T: %#v)", err, detail, detail)
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
		t.Fatalf("execution readiness=%t err=%v", ready, err)
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
	var k8Subjects int
	if err := connection.QueryRow(ctx, `SELECT i.state,w.body->>'status',(SELECT count(*) FROM zasp_discovery_connection_subjects s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.integration_id)=(i.organization_id,i.workspace_id,i.environment_id,i.id)) FROM zasp_integrations i JOIN zasp_workflow_records w ON (w.organization_id,w.workspace_id,w.environment_id,w.id,w.kind)=(i.organization_id,i.workspace_id,i.environment_id,i.id,'integration') WHERE (i.organization_id,i.workspace_id,i.environment_id,i.id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), k8Integration).Scan(&k8State, &workflowState, &k8Subjects); err != nil {
		t.Fatal(err)
	}
	if k8State != "degraded" || workflowState != "degraded" || k8Subjects != 0 {
		t.Fatalf("kubernetes upgrade state=%s workflow=%s subjects=%d", k8State, workflowState, k8Subjects)
	}
	var payload []byte
	query := `SELECT zasp_execution_bind_connection_subject($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), k8Integration, k8Connection, "kubernetes", "kubernetes_cluster", "customer.example/cluster-01", int64(2), k8Config, "reference"}
	wrong := append([]any(nil), args...)
	wrong[3] = awsIntegration
	if err := connection.QueryRow(ctx, query, wrong...).Scan(&payload); err == nil {
		t.Fatal("cross-integration subject binding succeeded")
	}
	idempotencyKey := "execution-reauthorize-0002"
	intent := referenceAuthorizationIntent(identity, k8Integration, "kubernetes", idempotencyKey, 2, k8Config)
	completionQuery := `SELECT zasp_execution_complete_reference_authorization($1,$2,$3,$4,$5,'kubernetes',$6,$7,$8,2,$9::jsonb,$10::jsonb,$11,$12,$13,'kubernetes_cluster','customer.example/cluster-01')`
	completionArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), k8Integration, k8Connection, "ref:kubernetes/connection/customer-0001", idempotencyKey, k8Config, intent, "pid_77000005-0000-4000-8000-000000000005", "pid_77000006-0000-4000-8000-000000000006", "pid_77000007-0000-4000-8000-000000000007"}
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
	if err := json.Unmarshal(payload, &replay); err != nil || replay.Version != 3 || replay.Receipt != "pid_77000007-0000-4000-8000-000000000007" || !replay.Replayed {
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
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, syncID, jobID, outboxID, "execution-sync-0001", requestDigest, "manual", "parser_v1", "tool_v1").Scan(&payload); err != nil {
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
		Provider      string          `json:"provider"`
		SubjectKind   string          `json:"subject_kind"`
		SubjectID     string          `json:"subject_id"`
		Configuration json.RawMessage `json:"configuration"`
	}
	var decodedConfiguration map[string]string
	if err := json.Unmarshal(payload, &input); err != nil {
		t.Fatalf("hydrated=%s err=%v", payload, err)
	}
	if err := json.Unmarshal(input.Configuration, &decodedConfiguration); err != nil || input.JobID != jobID || input.IntegrationID != integrationID || input.ConnectionID != connectionID || input.Provider != "aws" || input.SubjectKind != "aws_account" || input.SubjectID != "123456789012" || decodedConfiguration["role_arn"] != "arn:aws:iam::123456789012:role/zasp-discovery" || decodedConfiguration["external_id_reference"] != "ref:aws/external-id/customer-0002" {
		t.Fatalf("hydrated=%s err=%v", payload, err)
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
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, syncID, jobID, outboxID, "execution-sync-0002", requestDigest, "manual", "parser_v1", "tool_v1").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	snapshotID := "pid_79000007-0000-4000-8000-000000000007"
	manifestKey := "organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/artifacts/pid_79000008-0000-4000-8000-000000000008"
	manifestReference := "s3://zasp-evidence-prod/" + manifestKey
	manifestChecksum := make([]byte, 32)
	manifestChecksum[0] = 3
	applyQuery := `SELECT zasp_execution_apply_complete_snapshot($1,$2,$3,$4,$5,$6,1,'aws',$7,$8,'version-0001',$9,128,'application/json','manifest_v1',$10,'cursor-0001','parser_v1','tool_v1','[]'::jsonb,'[]'::jsonb,'[]'::jsonb)`
	applyArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID, snapshotID, manifestReference, manifestKey, manifestChecksum, time.Now().UTC()}
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_snapshot_projection_page($1,$2,$3,$4,'entities',NULL,100)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var page struct {
		SnapshotID string            `json:"snapshot_id"`
		Generation int64             `json:"generation"`
		Items      []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(payload, &page); err != nil || page.SnapshotID != snapshotID || page.Generation != 1 || page.Items == nil || len(page.Items) != 0 {
		t.Fatalf("projection page=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_advance_projection_cursor($1,$2,$3,'search',$4,1,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID, applied.CandidateDigest).Scan(&payload); err != nil {
		t.Fatal(err)
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
	runner := migrateToProductionDiscoveryExecution(t, ctx, connection)
	if err := runner.DownProductionDiscoveryExecution(ctx); err != nil {
		_, detail := connection.Exec(ctx, migrations.ProductionDiscoveryExecution().DownSQL())
		t.Fatalf("execution down: %v detail=%#v", err, detail)
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 12 {
		t.Fatalf("down version=%d err=%v", version, versionErr)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_reference_authorization_readiness($1,$2)`, migrations.ReferenceAuthorization().Checksum(), migrations.ReferenceAuthorizationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("reference readiness after v13 down=%t err=%v", ready, err)
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
