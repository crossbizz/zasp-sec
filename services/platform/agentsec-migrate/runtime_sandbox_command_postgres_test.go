package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The outer transaction owns deliberately retained evidence. The real runner's
// transaction becomes a PostgreSQL savepoint, so rejecting the migration cannot
// remove the evidence and the test can later roll back its fixture insertion.
type sandboxCommandTransactionDatabase struct{ transaction pgx.Tx }

func (database *sandboxCommandTransactionDatabase) QueryRow(ctx context.Context, query string, args ...any) migrations.Row {
	return database.transaction.QueryRow(ctx, query, args...)
}
func (database *sandboxCommandTransactionDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := database.transaction.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &migrationTransaction{transaction: tx}, nil
}

func TestRuntimeSandboxReleaseCommandPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer connection.Close(context.Background())
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	version := func(want int64) {
		t.Helper()
		if got, err := runner.Version(ctx); err != nil || got != want {
			t.Fatal("release command target", got, want, err)
		}
	}
	run := func(command string) {
		t.Helper()
		if err := runReleaseMigration(ctx, runner, []string{command}); err != nil {
			t.Fatal(command, err)
		}
	}
	run("up")
	version(49)

	registration := discoveryPrincipalRegistration{migration: "zasp_test"}
	for i, target := range []*string{&registration.api, &registration.discovery, &registration.ingest, &registration.runtime, &registration.outbox, &registration.gateway, &registration.scheduler, &registration.projectionRisk, &registration.projectionGraph, &registration.projectionSearch, &registration.runtimeCoordinator, &registration.runtimeArchive, &registration.runtimeIndex, &registration.runtimeCorrelation, &registration.runtimeProjection, &registration.gatewayControl, &registration.securityAgentAPI, &registration.securityAgentWorker, &registration.securityAgentAction, &registration.redTeamWorker, &registration.redTeamOutbox, &registration.redTeamAdapter, &registration.attackLabController, &registration.attackLabOutbox, &registration.attackLabProxy, &registration.recoveryWorker, &registration.recoveryOutbox, &registration.policyDeployment} {
		*target = fmt.Sprintf("zasp_cli50_login_%02d", i)
		if _, err := connection.Exec(ctx, `CREATE ROLE `+pgx.Identifier{*target}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	if err := registerReleasePrincipals(ctx, connection, registration); err != nil {
		t.Fatal("register predecessor principals", err)
	}
	var bindingsBefore string
	if err := connection.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY authority_role)::text FROM zasp_runtime_principal_bindings b`).Scan(&bindingsBefore); err != nil {
		t.Fatal(err)
	}
	run("up-to-50")
	version(50)
	if err := registerReleasePrincipals(ctx, connection, registration); err != nil {
		t.Fatal("CLI post-migration registration on50", err)
	}
	checkReady := func() {
		t.Helper()
		var ready bool
		if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2) AND zasp_runtime_principals_ready()`, migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("compiled release50 and registered runtime readiness", ready, err)
		}
		var bindings string
		if err := connection.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY authority_role)::text FROM zasp_runtime_principal_bindings b`).Scan(&bindings); err != nil || bindings != bindingsBefore {
			t.Fatal("registration changed existing runtime bindings", err)
		}
	}
	checkReady()
	run("up-to-50")
	version(50)
	checkReady()
	if err := runReleaseMigration(ctx, runner, []string{"up"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatal("plain up silently adopted release50", err)
	}
	version(50)

	// A seeded reservation isolates the installed SQL producer. It does not
	// claim authenticated ingest, archive publication, or worker execution.
	org, workspace, environment := "pid_79500001-0000-4000-8000-000000000001", "pid_79500002-0000-4000-8000-000000000002", "pid_79500003-0000-4000-8000-000000000003"
	sensor, batch := "pid_79500004-0000-4000-8000-000000000004", "pid_79500005-0000-4000-8000-000000000005"
	for _, seed := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Sandbox CLI fixture','sandbox-cli.invalid')`, []any{org}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Fixture')`, []any{org, workspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Fixture','production')`, []any{org, workspace, environment}},
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'CLI fixture','otlp','active')`, []any{org, workspace, environment, sensor}},
		{`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,decode(repeat('ab',16),'hex'),digest($4,'sha256'),clock_timestamp()+interval '1 day')`, []any{org, workspace, environment, sensor}},
		{`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key) VALUES($1,$2,$3,$4,$5,$5,1,1,'sandbox-cli-reservation-01',decode(repeat('ab',32),'hex'),decode(repeat('ab',32),'hex'),'otlp','application/json','runtime-event-v1',128,1,$6)`, []any{org, workspace, environment, batch, sensor, "runtime/" + batch + ".json"}},
	} {
		if _, err := connection.Exec(ctx, seed.query, seed.args...); err != nil {
			t.Fatal("seed SQL producer reservation", err)
		}
	}
	var committed json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_commit_reserved_batch($1,$2,$3,$4,1,decode(repeat('ab',32),'hex'),'pid_79500006-0000-4000-8000-000000000006','pid_79500007-0000-4000-8000-000000000007',$5,$6,'fixture-version',decode(repeat('ab',32),'hex'),128,'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012')`, org, workspace, environment, batch, "s3://zasp-evidence/runtime/"+batch+".json", "runtime/"+batch+".json").Scan(&committed); err != nil {
		t.Fatal("installed reservation producer", err)
	}
	assertStages := func() {
		t.Helper()
		var versions []string
		if err := connection.QueryRow(ctx, `SELECT array_agg(implementation_version ORDER BY stage_order) FROM zasp_runtime_stage_work WHERE batch_id=$1`, batch).Scan(&versions); err != nil || !reflect.DeepEqual(versions, []string{"runtime-archive-v1", "runtime-index-v1", "runtime-correlation-v2", "runtime-projection-v1", "runtime-complete-v1"}) {
			t.Fatal("compatibility release activated fresh sandbox routing", versions, err)
		}
	}
	assertStages()

	retained, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Rollback(context.Background())
	if _, err := retained.Exec(ctx, `INSERT INTO zasp_runtime_candidate_snapshots(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind,archive_digest,index_receipt_digest,snapshot_body,snapshot_digest) VALUES($1,$2,$3,$4,1,$5,'otlp',decode(repeat('ab',32),'hex'),decode(repeat('ab',32),'hex'),convert_to('{"schema":"runtime-candidate-snapshot-v2"}','UTF8'),digest(convert_to('{"schema":"runtime-candidate-snapshot-v2"}','UTF8'),'sha256'))`, org, workspace, environment, batch, sensor); err != nil {
		t.Fatal("retain new snapshot evidence", err)
	}
	guardRunner, err := migrations.NewRunner(&sandboxCommandTransactionDatabase{transaction: retained})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, guardRunner, []string{"down-to-49"}); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatal("CLI rollback did not reject retained new snapshot evidence", err)
	}
	var evidencePreserved bool
	if err := retained.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_runtime_candidate_snapshots WHERE batch_id=$1) AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=50) AND to_regprocedure('zasp_runtime_claim_correlation_v3(text,text,integer,integer)') IS NOT NULL`, batch).Scan(&evidencePreserved); err != nil || !evidencePreserved {
		t.Fatal("failed rollback changed retained evidence or release", evidencePreserved, err)
	}
	if err := retained.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkReady()
	run("down-to-49")
	version(49)
	var priorReady, removed bool
	if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_readiness($1,$2),to_regclass('zasp_runtime_sandbox_search_outbox') IS NULL AND to_regprocedure('zasp_runtime_claim_correlation_v3(text,text,integer,integer)') IS NULL`, migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&priorReady, &removed); err != nil || !priorReady || !removed {
		t.Fatal("rollback did not restore exact49", priorReady, removed, err)
	}
	assertStages()
	run("down-to-49")
	version(49)
	run("up-to-50")
	version(50)
	if err := registerReleasePrincipals(ctx, connection, registration); err != nil {
		t.Fatal("reinstall registration", err)
	}
	checkReady()
	assertStages()
	t.Log("actual PostgreSQL release command proven: plain up stops49; explicit50 install/retry, post-migration principal registration and compiled readiness; installed SQL producer retains correlation-v2/projection-v1/complete-v1; retained snapshot blocks rollback; clean49 rollback and50 reinstall. No authenticated ingest or fresh sandbox producer activation.")
}
