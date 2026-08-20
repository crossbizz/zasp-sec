package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
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
		var securityReady, referenceReady, discoveryReady bool
		_ = connection.QueryRow(ctx, `SELECT zasp_execution_security_ready(),zasp_reference_authorization_security_ready(),zasp_discovery_security_ready()`).Scan(&securityReady, &referenceReady, &discoveryReady)
		t.Fatalf("execution readiness=%t security=%t reference=%t discovery=%t err=%v", ready, securityReady, referenceReady, discoveryReady, err)
	}
	if _, err := connection.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea) TO zasp_projection_worker`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), liveFingerprint).Scan(&ready); err != nil || ready {
		t.Fatalf("forbidden projection grant readiness=%t err=%v", ready, err)
	}
	if err := runner.DownProductionDiscoveryExecution(ctx); err == nil {
		t.Fatal("security drift did not block rollback")
	}
	if _, err := connection.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_execution_advance_projection_cursor(text,text,text,text,text,bigint,bytea) FROM zasp_projection_worker`); err != nil {
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_readiness($1,$2)`, migrations.ProductionDiscoveryExecution().Checksum(), liveFingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("restored execution readiness=%t err=%v", ready, err)
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_finish_job($1,$2,$3,$4,$5,$6,'succeeded',$7,'',0)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID, worker, token, resultDigest).Scan(&payload); err != nil {
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
	for item := range reservationResults {
		if item.err != nil || !validProductID(item.snapshotID) {
			t.Fatalf("concurrent generation reservation=%#v", item)
		}
		generations[item.generation] = item.snapshotID
	}
	if len(generations) != 2 || generations[1] == "" || generations[2] == "" || generations[1] == generations[2] {
		t.Fatalf("concurrent generations=%#v", generations)
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"state": "queued"`)) || !bytes.Contains(payload, []byte(`"version": 1`)) {
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_schedule_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, scheduleID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"state": "disabled"`)) {
		t.Fatalf("disabled schedule detail=%s err=%v", payload, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,'discovery-worker-02','delivery-token-0000000002',30)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), jobID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"state": "running"`)) || !bytes.Contains(payload, []byte(`"version": 2`)) {
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
	applyQuery := `SELECT zasp_execution_apply_complete_snapshot($1,$2,$3,$4,$5,$6,$7,'aws',$8,$9,'version-0001',$10,128,'application/json','manifest_v1',$11,'cursor-0001','parser_v1','tool_v1','[]'::jsonb,'[]'::jsonb,'[]'::jsonb)`
	applyArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID, snapshotID, reserved.Generation, manifestReference, manifestKey, manifestChecksum, time.Now().UTC()}
	wrongManifestArgs := append([]any(nil), applyArgs...)
	wrongManifestArgs[8] = manifestKey + "-other"
	if err := connection.QueryRow(ctx, applyQuery, wrongManifestArgs...).Scan(&payload); err == nil {
		t.Fatal("mismatched manifest reference/key succeeded")
	}
	var snapshotResidue int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_discovery_snapshots WHERE id=$1)+(SELECT count(*) FROM zasp_discovery_snapshot_inputs WHERE snapshot_id=$1)`, snapshotID).Scan(&snapshotResidue); err != nil || snapshotResidue != 0 {
		t.Fatalf("mismatched manifest residue=%d err=%v", snapshotResidue, err)
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID, syncID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"state": "succeeded"`)) || !bytes.Contains(payload, []byte(`"version": 3`)) {
		t.Fatalf("succeeded sync detail=%s err=%v", payload, err)
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"fresh": false`)) || !bytes.Contains(payload, []byte(`"kind": "graph"`)) || !bytes.Contains(payload, []byte(`"kind": "risk"`)) || !bytes.Contains(payload, []byte(`"kind": "search"`)) {
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
		if err := connection.QueryRow(ctx, `SELECT zasp_execution_claim_projection_work('projection-worker-01','projection-token-00000001',30,3)`).Scan(&payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_finish_projection($1,$2,$3,$4,'search','v1','projection-worker-01','projection-token-00000001','succeeded','',0)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), snapshotID).Scan(&payload); err != nil {
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
	if err := connection.QueryRow(ctx, `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&payload); err != nil || !bytes.Contains(payload, []byte(`"fresh": false`)) || !bytes.Contains(payload, []byte(`"current": true`)) {
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
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_reference_authorization_readiness($1,$2)`, migrations.ReferenceAuthorization().Checksum(), migrations.ReferenceAuthorizationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("reference readiness after v13 down=%t err=%v", ready, err)
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
