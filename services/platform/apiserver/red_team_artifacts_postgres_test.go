package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionRedTeamArtifactsBindInputAndRejectLegacyCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, runner, adapter, worker := redTeamInvocationFixture(t, ctx)
	if err := runner.UpProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, migrations.ProductionRedTeamArtifacts().UpSQL()); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_red_team_artifacts_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionRedTeamArtifactsSemanticFingerprint() {
		t.Fatalf("candidate v39 fingerprint=%s", fingerprint)
	}
	if err := runner.UpProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal("empty rollback", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_red_team_invocation_live_fingerprint()`).Scan(&fingerprint); err != nil || fingerprint != migrations.ProductionRedTeamInvocationSemanticFingerprint() {
		t.Fatalf("rollback fingerprint=%s err=%v", fingerprint, err)
	}
	if err := runner.UpProductionRedTeamArtifacts(ctx); err != nil {
		t.Fatal("reapply", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 39 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	for _, statement := range []string{
		`ALTER TABLE zasp_red_team_attempts DROP CONSTRAINT zasp_red_team_attempt_input_artifact`,
		`GRANT EXECUTE ON FUNCTION zasp_red_team_finish_run_v38(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) TO zasp_red_team_worker`,
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
		err = tx.QueryRow(ctx, `SELECT zasp_production_red_team_artifacts_readiness($1,$2)`, migrations.ProductionRedTeamArtifacts().Checksum(), migrations.ProductionRedTeamArtifactsSemanticFingerprint()).Scan(&ready)
		_ = tx.Rollback(ctx)
		if err == nil && ready {
			t.Fatal("drift admitted readiness")
		}
	}
	scope := fixtureRequestIdentity(t).Scope
	var digest []byte
	if err := connection.QueryRow(ctx, `SELECT input_digest FROM zasp_red_team_runs WHERE run_id=$1`, invocationRun).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	key := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + invocationRun
	arguments := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), invocationRun, "invocation-worker", []byte(strings.Repeat("a", 32)), digest, "pass", "Evaluate curated categories: prompt_injection", "1 of 1 curated security checks passed; 0 exposed unsafe behavior.", nil, json.RawMessage(`["prompt_injection: protected"]`), "s3://zasp-evidence/" + key, key, "evidence-version-1", []byte(strings.Repeat("x", 32)), int64(1024)}
	var result json.RawMessage
	const legacy = `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17)`
	if err := worker.QueryRow(ctx, legacy, arguments...).Scan(&result); err == nil {
		t.Fatal("legacy worker completed without an input reference")
	}
	input := RedTeamArtifactReference{Reference: strings.TrimSuffix("s3://zasp-evidence/"+key, invocationRun) + "pid_95000007-0000-4000-8000-000000000007", VersionID: "input-version-1", SHA256: strings.Repeat("b", 64), SizeBytes: 512}
	encoded, _ := json.Marshal(input)
	arguments = append(arguments, encoded)
	const finish = `SELECT zasp_red_team_finish_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb)`
	if err := adapter.QueryRow(ctx, finish, arguments...).Scan(&result); err == nil {
		t.Fatal("adapter principal finished worker run")
	}
	if err := worker.QueryRow(ctx, strings.Replace(legacy, "zasp_red_team_finish_run(", "zasp_red_team_finish_run_v38(", 1), arguments[:17]...).Scan(&result); err == nil {
		t.Fatal("worker used private legacy completion")
	}
	for index, value := range map[int]any{0: "pid_95ffffff-0000-4000-8000-000000000001", 1: "pid_95ffffff-0000-4000-8000-000000000002", 2: "pid_95ffffff-0000-4000-8000-000000000003", 3: "pid_95ffffff-0000-4000-8000-000000000004", 4: "wrong-worker", 5: []byte(strings.Repeat("b", 32)), 6: []byte(strings.Repeat("z", 32)), 17: json.RawMessage(strings.Replace(string(encoded), scope.OrganizationID().String(), "pid_95ffffff-0000-4000-8000-000000000001", 1))} {
		wrong := append([]any(nil), arguments...)
		wrong[index] = value
		if err := worker.QueryRow(ctx, finish, wrong...).Scan(&result); err == nil {
			t.Fatalf("invalid authority index %d admitted", index)
		}
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE run_id=$1`, invocationRun); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, finish, arguments...).Scan(&result); err == nil {
		t.Fatal("expired lease finished")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=transaction_timestamp()+interval '1 hour',started_at=queued_at WHERE run_id=$1`, invocationRun); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, finish, arguments...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	var retained json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT input_artifact FROM zasp_red_team_attempts WHERE run_id=$1`, invocationRun).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	var actual RedTeamArtifactReference
	if json.Unmarshal(retained, &actual) != nil || actual != input {
		t.Fatal("attempt lost exact immutable input binding")
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE artifact_api LOGIN INHERIT; CREATE ROLE artifact_agent_worker LOGIN INHERIT; SELECT zasp_security_agent_register_principals('zasp_e2e','artifact_api','artifact_agent_worker')`); err != nil {
		t.Fatal(err)
	}
	apiConfig := connection.Config().Copy()
	apiConfig.User = "artifact_api"
	apiConnection, err := pgx.ConnectConfig(ctx, apiConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer apiConnection.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: apiConnection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := repository.GetRedTeamRun(ctx, fixtureRequestIdentity(t), invocationRun)
	if err != nil || len(detail.Attempts) != 1 || detail.Attempts[0].InputArtifact == nil || *detail.Attempts[0].InputArtifact != input {
		t.Fatalf("public repository lost input receipt: %v", err)
	}
	if err := runner.DownProductionRedTeamArtifacts(ctx); err == nil {
		t.Fatal("rollback discarded retained input references")
	}
}
