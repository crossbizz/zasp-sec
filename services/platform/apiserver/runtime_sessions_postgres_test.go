package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

const sessionProjectionFinishSQL = `SELECT zasp_runtime_finish_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`

func TestRuntimeSessionProjectionCommitsConfidenceAndCompletionAtomically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, apply := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"session_coordinator", "session_archive", "session_index", "session_correlation", "session_projection", "session_gateway"} {
		if _, err := connection.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'session_coordinator','session_archive','session_index','session_correlation','session_projection','session_gateway')`); err != nil {
		t.Fatal(err)
	}
	connect := func(name string) *pgx.Conn {
		config := connection.Config().Copy()
		config.User = name
		result, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { result.Close(context.Background()) })
		return result
	}
	coordinator, other := connect("session_coordinator"), connect("session_projection")
	arguments, projected := seedSessionProjectionCompletion(t, ctx, connection)
	var output json.RawMessage
	for _, principal := range []*pgx.Conn{coordinator, other} {
		if _, err := principal.Exec(ctx, `SELECT * FROM zasp_runtime_session_events`); err == nil {
			t.Fatal("worker read session table directly")
		}
	}
	if err := other.QueryRow(ctx, sessionProjectionFinishSQL, arguments...).Scan(&output); err == nil {
		t.Fatal("projection principal completed coordinator work")
	}
	legacy := `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	if err := coordinator.QueryRow(ctx, legacy, arguments[:17]...).Scan(&output); err == nil {
		t.Fatal("legacy completion skipped session projection")
	}
	for _, statement := range []string{strings.Replace(legacy, "zasp_runtime_finish_stage(", "zasp_runtime_finish_stage_v39(", 1)} {
		if err := coordinator.QueryRow(ctx, statement, arguments[:17]...).Scan(&output); err == nil {
			t.Fatal("private completion remained callable")
		}
	}
	for index, value := range map[int]any{0: invocationTarget, 1: invocationTarget, 2: invocationTarget, 3: invocationTarget, 4: int64(2), 5: "wrong-worker", 6: "wrong-lease-token", 7: 2, 8: make([]byte, 32), 17: append(append([]byte(nil), arguments[17].([]byte)...), ' ')} {
		wrong := append([]any(nil), arguments...)
		wrong[index] = value
		if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, wrong...).Scan(&output); err == nil {
			t.Fatalf("wrong projection authority at index %d accepted", index)
		}
	}
	for _, index := range []int{0, 4, 5, 6, 7, 8, 10, 11, 14, 16, 17} {
		wrong := append([]any(nil), arguments...)
		wrong[index] = nil
		if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, wrong...).Scan(&output); err == nil {
			t.Fatalf("null projection authority at index %d accepted", index)
		}
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE batch_id=$1 AND stage='complete'`, arguments[3]); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, arguments...).Scan(&output); err == nil {
		t.Fatal("expired coordinator lease completed")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=transaction_timestamp()+interval '1 hour' WHERE batch_id=$1 AND stage='complete'`, arguments[3]); err != nil {
		t.Fatal(err)
	}

	// A conflicting existing event must roll back the terminal stage update too.
	item := projected.Items[0]
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,'conflicting-title',$11,$12)`, arguments[0], arguments[1], arguments[2], item.EventID.String(), item.SessionID.String(), item.AgentID.String(), item.Confidence.String(), item.Source, item.EventClass, item.Action, item.EvidenceID.String(), item.EventTime); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, arguments...).Scan(&output); err == nil {
		t.Fatal("conflicting event replay completed")
	}
	var state string
	var count, receipts int
	if err := connection.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_runtime_session_events),(SELECT count(*) FROM zasp_runtime_session_projection_receipts) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, arguments[3]).Scan(&state, &count, &receipts); err != nil || state != "leased" || count != 1 || receipts != 0 {
		t.Fatalf("non-atomic failure: state=%s events=%d receipts=%d err=%v", state, count, receipts, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_runtime_session_events WHERE event_id=$1`, item.EventID.String()); err != nil {
		t.Fatal(err)
	}
	completion, err := coordinator.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer completion.Rollback(context.Background())
	if err := completion.QueryRow(ctx, sessionProjectionFinishSQL, arguments...).Scan(&output); err != nil {
		t.Fatal(err)
	}
	observer := connect("zasp_e2e")
	downCtx, downCancel := context.WithTimeout(ctx, 10*time.Second)
	defer downCancel()
	downDone := make(chan error, 1)
	go func() { downDone <- runner.DownProductionRuntimeSessions(downCtx) }()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		var waitType *string
		if err := observer.QueryRow(ctx, `SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1`, connection.PgConn().PID()).Scan(&waitType); err != nil {
			t.Fatal(err)
		}
		if waitType != nil && *waitType == "Lock" {
			waiting = true
			break
		}
		select {
		case early := <-downDone:
			t.Fatalf("rollback did not wait for active completion: %v", early)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !waiting {
		t.Fatal("rollback never competed with the uncommitted completion")
	}
	if err := completion.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-downDone:
		if err == nil {
			t.Fatal("rollback raced past its empty-table guard and deleted committed session evidence")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rollback did not finish after completion committed")
	}
	var replay json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, arguments...).Scan(&replay); err != nil || string(replay) != string(output) {
		t.Fatalf("exact replay changed completion: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_runtime_session_events),(SELECT count(*) FROM zasp_runtime_session_projection_receipts) FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='complete'`, arguments[3]).Scan(&state, &count, &receipts); err != nil || state != "succeeded" || count != 3 || receipts != 1 {
		t.Fatalf("completion state=%s events=%d receipts=%d err=%v", state, count, receipts, err)
	}
	var confidence []string
	if err := connection.QueryRow(ctx, `SELECT array_agg(confidence ORDER BY event_time,event_id) FROM zasp_runtime_session_events`).Scan(&confidence); err != nil || !reflect.DeepEqual(confidence, []string{"strong", "unattributed", "exact"}) {
		t.Fatalf("confidence/time order=%v err=%v", confidence, err)
	}
	if err := runner.DownProductionRuntimeSessions(ctx); err == nil {
		t.Fatal("rollback discarded retained session events")
	}
}

func seedSessionProjectionCompletion(t *testing.T, ctx context.Context, connection *pgx.Conn) ([]any, runtimeprojection.ProjectedBatch) {
	t.Helper()
	scope := fixtureRequestIdentity(t).Scope
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	batchID := mustProductID(t, "pid_96000001-0000-4000-8000-000000000001")
	sensorID, tokenID := "pid_96000002-0000-4000-8000-000000000002", "pid_96000003-0000-4000-8000-000000000003"
	body := []byte(`{"source":"tetragon","events":[` + strings.Join([]string{
		`{"event_id":"late","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-09-09T10:00:03.000Z","evidence_id":"pid_96000004-0000-4000-8000-000000000004","content":{}}`,
		`{"event_id":"early","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-09-09T10:00:01.000Z","evidence_id":"pid_96000005-0000-4000-8000-000000000005","content":{}}`,
		`{"event_id":"unknown","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-09-09T10:00:02.000Z","evidence_id":"pid_96000006-0000-4000-8000-000000000006","content":{}}`,
	}, ",") + `]}`)
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, body)
	if err != nil {
		t.Fatal(err)
	}
	correlations := make([]runtimecorrelation.Result, len(decoded.Records))
	for index, record := range decoded.Records {
		confidence := domain.EvidenceConfidenceExact
		if record.SourceEventID == "early" {
			confidence = domain.EvidenceConfidenceStrong
		}
		correlations[index] = runtimecorrelation.Result{EventID: record.ID, SessionID: mustProductID(t, "pid_96000007-0000-4000-8000-000000000007"), AgentID: mustProductID(t, invocationTarget), Confidence: confidence}
		if record.SourceEventID == "unknown" {
			correlations[index] = runtimecorrelation.Result{EventID: record.ID, Confidence: domain.EvidenceConfidenceUnattributed}
		}
	}
	archiveDigest := sha256.Sum256(body)
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: scope, BatchID: batchID, Generation: 1, ArchiveReference: "s3://zasp-evidence/runtime/sessions.json", ArchiveVersionID: "archive-v1", ArchiveDigest: archiveDigest, Body: body, Correlations: correlations})
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, receiptDigest, _, err := runtimeprojection.EncodeReceipt(runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v1", Scope: scope, BatchID: batchID, Generation: 1, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-v1", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-evidence/runtime/sessions.json", ArchiveVersionID: "archive-v1", ArchiveDigest: archiveDigest, EffectDigest: projected.ContentDigest, Items: projected.Items})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,$4,'Session proof sensor','tetragon')`, []any{org, workspace, environment, sensorID}},
		{`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,decode(repeat('aa',16),'hex'),decode(repeat('96',32),'hex'),transaction_timestamp()+interval '1 day')`, []any{org, workspace, environment, tokenID, sensorID}},
		{`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,$4,$5,'session-projection-fixture',$6,3,'s3://zasp-evidence/runtime/sessions.json',100,'application/json','runtime-v1','processing')`, []any{org, workspace, environment, batchID.String(), sensorID, archiveDigest[:]}},
		{`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,$4,$5,$6,1,1,'session-projection-fixture',$7,$7,'tetragon','application/json','runtime-v1',100,3,'runtime/session-projection-fixture.json','s3://zasp-evidence/runtime/sessions.json','archive-v1',$7,100,'fixture-kms-reference',transaction_timestamp(),'processing')`, []any{org, workspace, environment, batchID.String(), sensorID, tokenID, archiveDigest[:]}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,1,'project',4,'runtime-projection-v1',$5,'succeeded',1,$6,'s3://zasp-evidence/projected.json','projected-v1',$7,transaction_timestamp())`, []any{org, workspace, environment, batchID.String(), archiveDigest[:], projected.ContentDigest[:], receiptDigest[:]}},
		{`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,1,'complete',5,'runtime-complete-v1',$5,$5,'leased',1,'session-worker','session-lease-token-0001',transaction_timestamp()+interval '1 hour')`, []any{org, workspace, environment, batchID.String(), projected.ContentDigest[:]}},
	} {
		if _, err := connection.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(fmt.Errorf("session completion fixture: %w", err))
		}
	}
	resultDigest := sha256.Sum256([]byte("completion"))
	return []any{org, workspace, environment, batchID.String(), int64(1), "session-worker", "session-lease-token-0001", 1, projected.ContentDigest[:], "runtime-complete-v1", "succeeded", projected.ContentDigest[:], "s3://zasp-evidence/completed.json", "completed-v1", resultDigest[:], nil, 0, receiptBytes}, projected
}

func TestRuntimeSessionsMigrationPinsAuthorityAndRestoresPreviousRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, apply := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, migrations.ProductionRuntimeSessions().UpSQL()); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_runtime_sessions_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionRuntimeSessionsSemanticFingerprint() {
		t.Fatalf("candidate v40 fingerprint=%s", fingerprint)
	}
	if err := runner.UpProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 40 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	var apiSchema string
	if err := connection.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint()).Scan(&apiSchema); err != nil || apiSchema != ProductionRecoverySchemaVersion {
		t.Fatalf("production API rejects installed schema40: schema=%s error=%v", apiSchema, err)
	}
	future, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(41,'unsupported_future_release',repeat('a',64))`); err != nil {
		_ = future.Rollback(ctx)
		t.Fatal(err)
	}
	err = future.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint()).Scan(&apiSchema)
	_ = future.Rollback(ctx)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("future schema41 admitted API: %v", err)
	}
	for _, statement := range []string{
		`ALTER TABLE zasp_runtime_session_events DISABLE ROW LEVEL SECURITY`,
		`GRANT SELECT ON zasp_runtime_session_events TO zasp_discovery_api`,
		`GRANT EXECUTE ON FUNCTION zasp_runtime_finish_stage_v39(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer) TO zasp_runtime_coordinator`,
	} {
		tx, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		var ready bool
		err = tx.QueryRow(ctx, `SELECT zasp_production_runtime_sessions_readiness($1,$2)`, migrations.ProductionRuntimeSessions().Checksum(), migrations.ProductionRuntimeSessionsSemanticFingerprint()).Scan(&ready)
		_ = tx.Rollback(ctx)
		if err == nil && ready {
			t.Fatal("runtime session authority drift admitted readiness")
		}
	}
	if err := runner.DownProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_red_team_artifacts_live_fingerprint()`).Scan(&fingerprint); err != nil || fingerprint != migrations.ProductionRedTeamArtifactsSemanticFingerprint() {
		t.Fatalf("rollback fingerprint=%s err=%v", fingerprint, err)
	}
	if err := runner.UpProductionRuntimeSessions(ctx); err != nil {
		t.Fatal(err)
	}
}
