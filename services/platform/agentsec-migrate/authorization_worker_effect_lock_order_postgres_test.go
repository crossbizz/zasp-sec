package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuthorizationWorkerEffectSourceLockOrderPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	setup, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Close(context.Background())

	if _, err := setup.Exec(ctx, authorizationWorkerEffectLockFixtureSQL); err != nil {
		t.Fatalf("install controlled effect dependencies: %v", err)
	}
	if _, err := setup.Exec(ctx, authorizationWorkerEffectSourceStatement(t)); err != nil {
		t.Fatalf("install actual test74_effect_source: %v", err)
	}
	if _, err := setup.Exec(ctx, authorizationWorkerEffectLockFixtureRowsSQL); err != nil {
		t.Fatalf("install controlled effect rows: %v", err)
	}

	for _, test := range []struct {
		name  string
		phase string
	}{
		{name: "state", phase: "state"},
		{name: "effect", phase: "effect.read"},
		{name: "linked", phase: "linked.read"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertAuthorizationWorkerEffectLockOrder(t, ctx, dsn, test.phase)
		})
	}
}

func authorizationWorkerEffectSourceStatement(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../migrations/sql/0080_authorization_worker_test_effects.sql")
	if err != nil {
		t.Fatal(err)
	}
	const start = "CREATE FUNCTION zasp_authorization80_worker.test74_effect_source("
	const finish = "END $effect_source$;"
	begin := strings.Index(string(raw), start)
	if begin < 0 {
		t.Fatal("actual test74_effect_source statement absent")
	}
	endOffset := strings.Index(string(raw[begin:]), finish)
	if endOffset < 0 {
		t.Fatal("actual test74_effect_source terminator absent")
	}
	return string(raw[begin : begin+endOffset+len(finish)])
}

func assertAuthorizationWorkerEffectLockOrder(t *testing.T, ctx context.Context, dsn, phase string) {
	t.Helper()
	holder := connectAuthorizationWorkerEffectLockTest(t, ctx, dsn)
	source := connectAuthorizationWorkerEffectLockTest(t, ctx, dsn)
	observer := connectAuthorizationWorkerEffectLockTest(t, ctx, dsn)
	defer holder.Close(context.Background())
	defer source.Close(context.Background())
	defer observer.Close(context.Background())

	holderTx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	holderReleased := false
	defer func() {
		if !holderReleased {
			_ = rollbackAuthorizationWorkerEffectLockTest(holderTx)
		}
	}()
	if _, err := holderTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:organization-1',0))`); err != nil {
		t.Fatal(err)
	}

	sourceTx, err := source.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAuthorizationWorkerEffectLockTest(sourceTx)
	var sourcePID int
	if err := sourceTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&sourcePID); err != nil {
		t.Fatal(err)
	}
	query := map[string]any{
		"organization_id": "organization-1",
		"workspace_id":    "workspace-1",
		"environment_id":  "environment-1",
		"run_id":          "run-1",
		"step_id":         "step-1",
		"generation":      1,
		"operation":       "read",
		"payload":         map[string]any{},
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	queryResult := make(chan error, 1)
	allowCommit := make(chan struct{})
	sourceDone := make(chan error, 1)
	sourceCtx, cancelSource := context.WithCancel(ctx)
	go func() {
		var result []byte
		queryErr := sourceTx.QueryRow(sourceCtx, `SELECT zasp_authorization80_worker.test74_effect_source($1,$2::jsonb)`, phase, queryJSON).Scan(&result)
		queryResult <- queryErr
		if queryErr == nil {
			<-allowCommit
			queryErr = sourceTx.Commit(sourceCtx)
		} else {
			_ = rollbackAuthorizationWorkerEffectLockTest(sourceTx)
		}
		sourceDone <- queryErr
	}()
	commitAllowed := false
	sourceFinished := false
	defer func() {
		if !holderReleased {
			_ = rollbackAuthorizationWorkerEffectLockTest(holderTx)
			holderReleased = true
		}
		cancelSource()
		if !commitAllowed {
			close(allowCommit)
			commitAllowed = true
		}
		if !sourceFinished {
			<-sourceDone
			sourceFinished = true
		}
	}()

	returnedEarly, queryErr := awaitEffectSourceAdvisoryWait(t, ctx, observer, sourcePID, queryResult)
	if !returnedEarly && queryErr != nil {
		t.Fatal(queryErr)
	}
	probeTx, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	probeReleased := false
	defer func() {
		if !probeReleased {
			_ = rollbackAuthorizationWorkerEffectLockTest(probeTx)
		}
	}()
	var acquiredSchemaExclusive bool
	if err := probeTx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`).Scan(&acquiredSchemaExclusive); err != nil {
		t.Fatal(err)
	}
	var parent int
	parentErr := probeTx.QueryRow(ctx, `SELECT 1 FROM public.zasp_security_agent_runs WHERE organization_id='organization-1' AND workspace_id='workspace-1' AND environment_id='environment-1' AND run_id='run-1' FOR UPDATE NOWAIT`).Scan(&parent)
	if err := rollbackAuthorizationWorkerEffectLockTest(probeTx); err != nil {
		t.Fatal(err)
	}
	probeReleased = true
	if err := rollbackAuthorizationWorkerEffectLockTest(holderTx); err != nil {
		t.Fatal(err)
	}
	holderReleased = true
	if !returnedEarly {
		select {
		case queryErr = <-queryResult:
		case <-time.After(5 * time.Second):
			t.Fatal("effect source did not finish after organization advisory release")
		}
	}
	close(allowCommit)
	commitAllowed = true
	select {
	case doneErr := <-sourceDone:
		sourceFinished = true
		if queryErr == nil {
			queryErr = doneErr
		}
	case <-time.After(5 * time.Second):
		t.Fatal("effect source transaction did not finish")
	}

	parentWasLocked := false
	if parentErr != nil {
		var pgErr *pgconn.PgError
		if !errors.As(parentErr, &pgErr) || pgErr.Code != "55P03" {
			t.Fatalf("probe parent run lock: %v", parentErr)
		}
		parentWasLocked = true
	} else if parent != 1 {
		t.Fatalf("probe parent run returned %d", parent)
	}
	if queryErr != nil {
		t.Fatalf("effect source %s: %v", phase, queryErr)
	}
	if returnedEarly || parentWasLocked {
		t.Fatalf("effect source %s acquired the parent row before the organization advisory: returned=%t parent_locked=%t", phase, returnedEarly, parentWasLocked)
	}
	if acquiredSchemaExclusive {
		t.Fatalf("effect source %s did not hold the shared schema advisory before waiting for the organization advisory", phase)
	}
}

func awaitEffectSourceAdvisoryWait(t *testing.T, ctx context.Context, observer *pgx.Conn, pid int, result <-chan error) (bool, error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-result:
			return true, err
		default:
		}
		var waiting bool
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock' AND wait_event='advisory',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			return false, fmt.Errorf("observe effect source lock wait: %w", err)
		}
		if waiting {
			return false, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false, errors.New("effect source did not return or enter the organization advisory wait")
}

func connectAuthorizationWorkerEffectLockTest(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func rollbackAuthorizationWorkerEffectLockTest(tx pgx.Tx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}

const authorizationWorkerEffectLockFixtureSQL = `
CREATE EXTENSION pgcrypto;
CREATE SCHEMA zasp_temporal74;
CREATE SCHEMA zasp_authorization80_worker;
CREATE SCHEMA zasp_sa_multistep_prior;
CREATE TABLE public.zasp_security_agent_runs(organization_id text,workspace_id text,environment_id text,run_id text,state text,version bigint,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE public.zasp_security_agent_plans(organization_id text,workspace_id text,environment_id text,run_id text,plan_hash bytea,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE public.zasp_security_agent_steps(organization_id text,workspace_id text,environment_id text,run_id text,step_id text,action_key text,input_digest bytea,state text,version bigint,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id));
CREATE TABLE zasp_temporal74.run_owners(organization_id text,workspace_id text,environment_id text,run_id text,step_id text,definition_id text,definition_version bigint,input_digest text,test_run_id text,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id));
CREATE TABLE zasp_temporal74.effects(organization_id text,workspace_id text,environment_id text,run_id text,step_id text,generation bigint,effect_key text,snapshot_digest bytea,input_digest bytea,plan_hash bytea,state text,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,generation));
CREATE TABLE zasp_temporal74.test_inputs(organization_id text,workspace_id text,environment_id text,run_id text,step_id text,manifest jsonb,body bytea,PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id));
CREATE TABLE zasp_authorization80_worker.test_associations(organization_id text,workspace_id text,environment_id text,run_id text,definition_id text,definition_version bigint);
CREATE TABLE zasp_authorization80_worker.test_state(organization_id text,workspace_id text,environment_id text,run_id text,definition_id text,definition_version bigint,state text,run_version bigint,present boolean,target_current boolean,fresh_until timestamptz);
CREATE FUNCTION zasp_sa_multistep_prior.closed(jsonb,text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$SELECT true$$;
CREATE FUNCTION zasp_temporal74.start_identity(q jsonb) RETURNS zasp_temporal74.run_owners LANGUAGE sql STABLE AS $$SELECT r FROM zasp_temporal74.run_owners r WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id')$$;
CREATE FUNCTION zasp_authorization80_worker.test74_native_facts(boolean,jsonb,boolean) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE r public.zasp_security_agent_runs%ROWTYPE;
BEGIN
 SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($2->>'organization_id',$2->>'workspace_id',$2->>'environment_id',$2->>'run_id') FOR SHARE;
 RETURN jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.run_id,'definition_id','definition-1','definition_version',1,'run_state',r.state,'run_version',r.version);
END $$;
`

const authorizationWorkerEffectLockFixtureRowsSQL = `
INSERT INTO public.zasp_security_agent_runs VALUES('organization-1','workspace-1','environment-1','run-1','running',1);
INSERT INTO public.zasp_security_agent_plans VALUES('organization-1','workspace-1','environment-1','run-1',decode(repeat('11',32),'hex'));
INSERT INTO public.zasp_security_agent_steps VALUES('organization-1','workspace-1','environment-1','run-1','step-1','action-1',decode(repeat('22',32),'hex'),'running',1);
INSERT INTO zasp_temporal74.run_owners VALUES('organization-1','workspace-1','environment-1','run-1','step-1','definition-1',1,repeat('33',32),'test-run-1');
INSERT INTO zasp_temporal74.effects VALUES('organization-1','workspace-1','environment-1','run-1','step-1',1,'effect-1',decode(repeat('44',32),'hex'),decode(repeat('55',32),'hex'),decode(repeat('11',32),'hex'),'started');
INSERT INTO zasp_temporal74.test_inputs VALUES('organization-1','workspace-1','environment-1','run-1','step-1','{}'::jsonb,decode('00','hex'));
INSERT INTO zasp_authorization80_worker.test_associations VALUES('organization-1','workspace-1','environment-1','run-1','definition-1',1);
INSERT INTO zasp_authorization80_worker.test_state VALUES('organization-1','workspace-1','environment-1','run-1','definition-1',1,'running',1,true,true,clock_timestamp()+interval '1 hour');
`
