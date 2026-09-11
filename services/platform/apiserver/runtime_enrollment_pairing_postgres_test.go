package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const pairedSensorCreateSQL = `SELECT zasp_runtime_public_create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
const legacySensorCreateSQL = `SELECT zasp_runtime_public_create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

func TestRuntimeEnrollmentPairingMigrationAndAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, migrations.ProductionRuntimeEnrollmentPairing().UpSQL()); err != nil {
		probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	err = probe.QueryRow(ctx, `SELECT zasp_production_runtime_enrollment_pairing_live_fingerprint()`).Scan(&fingerprint)
	probe.Rollback(ctx)
	if err != nil || fingerprint != migrations.ProductionRuntimeEnrollmentPairingSemanticFingerprint() {
		t.Fatalf("candidate45 fingerprint=%s error=%v", fingerprint, err)
	}
	if err := runner.UpProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal("empty rollback", err)
	}
	// This pre-migration batch gets an explicit, immutable historical binding.
	seedSessionProjectionCompletion(t, ctx, admin)
	// Historical OTLP authority is intentionally unpaired. Clone only component
	// fixture rows here; this does not claim an authenticated ingest or archive run.
	const historicalSensor = "pid_78200007-0000-4000-8000-000000000007"
	const historicalToken = "pid_78200008-0000-4000-8000-000000000008"
	const historicalBatch = "pid_78200009-0000-4000-8000-000000000009"
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_sensors SELECT (jsonb_populate_record(NULL::zasp_sensors,to_jsonb(original)||jsonb_build_object('id',$1::text,'kind','otlp'))).* FROM zasp_sensors original WHERE id='pid_96000002-0000-4000-8000-000000000002'`, []any{historicalSensor}},
		{`INSERT INTO zasp_sensor_tokens SELECT (jsonb_populate_record(NULL::zasp_sensor_tokens,to_jsonb(original)||jsonb_build_object('id',$1::text,'sensor_id',$2::text,'token_hash',decode(repeat('97',32),'hex')))).* FROM zasp_sensor_tokens original WHERE id='pid_96000003-0000-4000-8000-000000000003'`, []any{historicalToken, historicalSensor}},
		{`INSERT INTO zasp_runtime_batch_authorities SELECT (jsonb_populate_record(NULL::zasp_runtime_batch_authorities,to_jsonb(original)||jsonb_build_object('batch_id',$1::text,'sensor_id',$2::text,'sensor_token_id',$3::text,'source_kind','otlp'))).* FROM zasp_runtime_batch_authorities original WHERE batch_id='pid_96000001-0000-4000-8000-000000000001'`, []any{historicalBatch, historicalSensor, historicalToken}},
	} {
		if _, err := admin.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := runner.UpProductionRuntimeEnrollmentPairing(ctx); err != nil {
		t.Fatal(err)
	}
	var historicalUnpaired bool
	if err := admin.QueryRow(ctx, `SELECT source_kind='otlp' AND source_sensor_id=$2 AND runtime_sensor_id IS NULL FROM zasp_runtime_batch_domains WHERE batch_id=$1`, historicalBatch, historicalSensor).Scan(&historicalUnpaired); err != nil || !historicalUnpaired {
		t.Fatal("historical OTLP batch gained implicit pairing", err)
	}
	identity := fixtureRequestIdentity(t)
	org, workspace, environment, principal := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_identity_memberships(organization_id,principal_id,organization_reference,member_reference,role,active) VALUES($1,$2,'pairing-org','pairing-member','security_admin',true) ON CONFLICT(organization_id,principal_id) DO UPDATE SET role='security_admin',active=true`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($4,$1,$2,$3,'Pairing proof','["view","manage_workflows"]',true) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions='["view","manage_workflows"]'`, org, workspace, environment, principal); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_discovery_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	apiRepository, err := NewPostgresRepository(apiDatabase)
	if err != nil || apiRepository.Ready(ctx) != nil {
		t.Fatal("schema45 prevented API startup", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 45 {
		t.Fatalf("release catalog version=%d error=%v", version, err)
	}
	future, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(46,'future_release',repeat('0',64))`); err != nil {
		future.Rollback(ctx)
		t.Fatal(err)
	}
	var futureSchema string
	futureErr := future.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint()).Scan(&futureSchema)
	future.Rollback(ctx)
	if futureErr == nil {
		t.Fatal("API accepted unknown schema46")
	}
	const anchor = "pid_78200001-0000-4000-8000-000000000001"
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Pairing runtime anchor','tetragon','active')`, org, workspace, environment, anchor); err != nil {
		t.Fatal(err)
	}
	exercisePairedProductEnrollmentAndRuntimeIngest(t, ctx, admin, apiDatabase, identity, anchor)
	newArgs := func(seed int, runtimeSensor any) []any {
		id := fmt.Sprintf("pid_78200002-0000-4000-8000-%012d", seed)
		token := fmt.Sprintf("pid_78200003-0000-4000-8000-%012d", seed)
		digest := sha256.Sum256([]byte("pairing-fixture-" + id))
		return []any{org, workspace, environment, principal, id, "Paired semantic source", "otlp", "metadata_only", fmt.Sprintf("pairing-request-%012d", seed), digest[:], token, int64(1), digest[:], digest[:], digest[:], time.Now().UTC().Add(time.Hour), runtimeSensor}
	}
	create := func(query string, args []any) (json.RawMessage, error) {
		var value json.RawMessage
		err := api.QueryRow(ctx, query, args...).Scan(&value)
		return value, err
	}
	// Real same-looking anchors in another organization, workspace, or environment
	// must not authorize this enrollment. A missing ID alone is not isolation proof.
	const foreignAnchor = "pid_78200005-0000-4000-8000-000000000005"
	const foreignScope = "pid_78200006-0000-4000-8000-000000000006"
	for scopeIndex := 0; scopeIndex < 3; scopeIndex++ {
		foreign := []any{org, workspace, environment, foreignAnchor}
		foreign[scopeIndex] = foreignScope
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Pairing runtime anchor','tetragon','active')`, foreign...); err != nil {
			t.Fatal(err)
		}
		if _, err := create(pairedSensorCreateSQL, newArgs(30+scopeIndex, foreignAnchor)); err == nil {
			t.Fatalf("foreign scope dimension %d authorized pairing", scopeIndex)
		}
	}
	args := newArgs(10, anchor)
	created, err := create(pairedSensorCreateSQL, args)
	if err != nil {
		t.Fatal("paired create", err)
	}
	var receipt struct {
		Body struct {
			ID              string `json:"id"`
			RuntimeSensorID string `json:"runtime_sensor_id"`
		} `json:"body"`
		Replayed bool `json:"replayed"`
	}
	if json.Unmarshal(created, &receipt) != nil || receipt.Body.ID != args[4] || receipt.Body.RuntimeSensorID != anchor || receipt.Replayed {
		t.Fatalf("pair receipt=%s", created)
	}
	var stored string
	if err := admin.QueryRow(ctx, `SELECT runtime_sensor_id FROM zasp_runtime_sensor_pairings WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND sensor_id=$4`, org, workspace, environment, args[4]).Scan(&stored); err != nil || stored != anchor {
		t.Fatal("pair not durable", err)
	}
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	for _, scenario := range []string{"receipt permission revoked", "anchor revoked"} {
		t.Run(scenario, func(t *testing.T) {
			defer func() {
				if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
					t.Error(err)
				}
				if _, err := admin.Exec(ctx, `UPDATE zasp_sensors SET state='active',revoked_at=NULL WHERE id=$1`, anchor); err != nil {
					t.Error(err)
				}
			}()
			lock, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback(context.Background())
			input := args
			if scenario == "receipt permission revoked" {
				_, err = lock.Exec(ctx, `SELECT sensor_id FROM zasp_runtime_sensor_mutations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND principal_id=$4 AND operation='createSensorEnrollment' AND idempotency_key=$5 FOR UPDATE`, org, workspace, environment, principal, args[8])
			} else {
				_, err = lock.Exec(ctx, `SELECT id FROM zasp_sensors WHERE id=$1 FOR UPDATE`, anchor)
				input = newArgs(12, anchor)
			}
			if err != nil {
				t.Fatal(err)
			}
			callCtx, callCancel := context.WithTimeout(ctx, 10*time.Second)
			defer callCancel()
			done := make(chan error, 1)
			go func() {
				var result json.RawMessage
				done <- api.QueryRow(callCtx, pairedSensorCreateSQL, input...).Scan(&result)
			}()
			waiting := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, api.PgConn().PID()).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case early := <-done:
					t.Fatalf("pairing call didn't wait for %s: %v", scenario, early)
				case <-time.After(10 * time.Millisecond):
				}
			}
			if !waiting {
				t.Fatal("pairing lock contention was not observed")
			}
			if scenario == "receipt permission revoked" {
				_, err = lock.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, org, principal)
			} else {
				_, err = lock.Exec(ctx, `UPDATE zasp_sensors SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, anchor)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := lock.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatalf("pairing completed after %s while blocked", scenario)
			}
		})
	}
	if _, err := create(legacySensorCreateSQL, args[:16]); err == nil {
		t.Fatal("paired receipt replayed through unpaired legacy overload")
	}
	changed := append([]any(nil), args...)
	changed[16] = nil
	if _, err := create(pairedSensorCreateSQL, changed); err == nil {
		t.Fatal("forged same digest removed pairing")
	}
	unpaired := newArgs(11, nil)
	if _, err := create(legacySensorCreateSQL, unpaired[:16]); err != nil {
		t.Fatal("legacy create", err)
	}
	unpaired[16] = anchor
	if _, err := create(pairedSensorCreateSQL, unpaired); err == nil {
		t.Fatal("forged same digest paired an existing unpaired enrollment")
	}
	for _, mutate := range []func([]any){
		func(a []any) { a[16] = "pid_78200099-0000-4000-8000-000000000099" },
		func(a []any) { a[6] = "tetragon" },
		func(a []any) { a[16] = a[4] },
		func(a []any) { a[16] = args[4] },
	} {
		input := newArgs(20, anchor)
		mutate(input)
		if _, err := create(pairedSensorCreateSQL, input); err == nil {
			t.Fatal("invalid pairing admitted")
		}
	}
	if _, err := api.Exec(ctx, `SELECT * FROM zasp_runtime_sensor_pairings`); err == nil {
		t.Fatal("API directly read pairing authority")
	}
	if _, err := api.Exec(ctx, `UPDATE zasp_runtime_sensor_pairings SET runtime_sensor_id=sensor_id`); err == nil {
		t.Fatal("API directly rewrote pairing authority")
	}
	for _, query := range []string{`UPDATE zasp_runtime_sensor_pairings SET runtime_sensor_id=runtime_sensor_id`, `DELETE FROM zasp_runtime_sensor_pairings`} {
		if _, err := admin.Exec(ctx, query); err == nil {
			t.Fatal("pairing provenance was mutable")
		}
	}
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_sensors WHERE id=$1`, anchor); err == nil {
		t.Fatal("anchor identifier could be deleted and reused")
	}
	for _, sensorID := range []any{anchor, args[4]} {
		if _, err := admin.Exec(ctx, `UPDATE zasp_sensors SET kind=CASE kind WHEN 'otlp' THEN 'tetragon' ELSE 'otlp' END WHERE id=$1`, sensorID); err == nil {
			t.Fatal("paired enrollment kind could be rewritten")
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_sensors SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := create(pairedSensorCreateSQL, newArgs(21, anchor)); err == nil {
		t.Fatal("new pairing accepted revoked anchor")
	}
	replay, err := create(pairedSensorCreateSQL, args)
	if err != nil || json.Unmarshal(replay, &receipt) != nil || !receipt.Replayed || receipt.Body.RuntimeSensorID != anchor {
		t.Fatalf("historical replay drifted after revocation: %s %v", replay, err)
	}
	var tokens int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_sensor_tokens WHERE sensor_id=$1`, args[4]).Scan(&tokens); err != nil || tokens != 1 {
		t.Fatal("replay created another credential", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, org, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := create(pairedSensorCreateSQL, args); err == nil {
		t.Fatal("revoked permission replayed pairing authority")
	}
	var backfilledSource, backfilledAnchor string
	if err := admin.QueryRow(ctx, `SELECT source_sensor_id,runtime_sensor_id FROM zasp_runtime_batch_domains WHERE batch_id='pid_96000001-0000-4000-8000-000000000001'`).Scan(&backfilledSource, &backfilledAnchor); err != nil || backfilledSource != "pid_96000002-0000-4000-8000-000000000002" || backfilledSource != backfilledAnchor {
		t.Fatal("historical Tetragon binding lost", err)
	}
	const batch = "pid_78200004-0000-4000-8000-000000000004"
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key) VALUES($1,$2,$3,$4,$5,$6,1,1,'pairing-batch-fixture-0001',$7,$7,'otlp','application/json','runtime-event-v1',1,1,'runtime/v15/pairing-fixture-0001.json')`, org, workspace, environment, batch, args[4], args[10], args[9]); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT source_sensor_id,runtime_sensor_id FROM zasp_runtime_batch_domains WHERE batch_id=$1`, batch).Scan(&backfilledSource, &backfilledAnchor); err != nil || backfilledSource != args[4] || backfilledAnchor != anchor {
		t.Fatal("new batch didn't freeze source and pairing", err)
	}
	for _, query := range []string{`UPDATE zasp_runtime_batch_domains SET generation=generation`, `DELETE FROM zasp_runtime_batch_domains`, `UPDATE zasp_runtime_batch_authorities SET batch_generation=batch_generation+1`} {
		if _, err := admin.Exec(ctx, query); err == nil {
			t.Fatal("batch domain provenance was mutable")
		}
	}
	if err := runner.DownProductionRuntimeEnrollmentPairing(ctx); err == nil {
		t.Fatal("rollback discarded retained enrollment/domain provenance")
	}
}
