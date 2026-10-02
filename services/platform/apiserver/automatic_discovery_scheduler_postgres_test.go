package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Diagnostic regression at the registered execution boundary, not the public
// 300-second cadence acceptance test. No job, receipt or lease is owner-seeded.
// The break this catches is refusing an unchanged occurrence solely because a
// verified replacement claimant has a different lease owner/token.
func TestAutomaticDiscoveryScheduledOccurrenceRebindPostgres(t *testing.T) {
	t.Run("scheduled_decoder_cannot_accept_normalized_manual_replay_IDs", testScheduledOccurrenceResponseIdentity)
	for index, name := range []string{"exact_reclaim", "different_key_same_digest", "different_key_changed_digest", "distinct_due_time", "expired_legacy_preinstall", "unsupported_old_first_after_install"} {
		t.Run(name, func(t *testing.T) { testScheduledOccurrencePostgres(t, index) })
	}
}

func testScheduledOccurrencePostgres(t *testing.T, provisionalCase int) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	runner := migrateToReferenceAuthorization(t, ctx, owner)
	identity := fixtureRequestIdentity(t)
	const integration = "pid_79000001-0000-4000-8000-000000000001"
	const schedule = "pid_79000003-0000-4000-8000-000000000003"
	const syncID = "pid_79000004-0000-4000-8000-000000000004"
	const jobID = "pid_79000005-0000-4000-8000-000000000005"
	const outboxID = "pid_79000006-0000-4000-8000-000000000006"
	configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0003","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
	seedReferenceAuthorizedIntegration(t, ctx, owner, "aws", integration, "pid_79000002-0000-4000-8000-000000000002", "ref:aws/external-id/customer-0003", configuration, "4")
	if err := runner.UpProductionDiscoveryExecution(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `
CREATE ROLE occurrence_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_discovery LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_ingest LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_gateway LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_scheduler LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_risk LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_graph LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE occurrence_search LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
SELECT zasp_discovery_register_principals(session_user,'occurrence_api','occurrence_discovery','occurrence_ingest','occurrence_runtime','occurrence_outbox','occurrence_gateway');
SELECT zasp_execution_register_principals(session_user,'occurrence_scheduler','occurrence_discovery','occurrence_risk','occurrence_graph','occurrence_search');`); err != nil {
		t.Fatal(err)
	}
	installOccurrenceRelease59(t, ctx, owner, runner)
	if provisionalCase >= 4 {
		testOccurrenceLegacyFence(t, ctx, owner, runner, integration, schedule, provisionalCase == 5)
		return
	}
	if provisionalCase == 0 {
		cfg := owner.Config().Copy()
		cfg.User = "occurrence_scheduler"
		legacy, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: legacy})
		if err != nil {
			t.Fatal(err)
		}
		if repo, err := NewDiscoveryExecutionRepository(db, DiscoveryExecutionAuthorityScheduler); err != ErrRepositoryConfiguration || repo != nil {
			t.Errorf("release59-only scheduler started: %v", err)
		}
		if err := legacy.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := runner.UpProductionDiscoveryScheduleReplay(ctx); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_discovery_schedule_replay_readiness($1,$2)`, migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("release60 readiness=%t: %v", ready, err)
	}
	t.Logf("registered release60 checksum=%s fingerprint=%s ready=true", migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint())
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	var raw json.RawMessage
	// Production schedule admission, with a due time of now for this isolated
	// SQL regression. The connected proof must still wait a real public cadence.
	if err := owner.QueryRow(ctx, postgresDiscoveryPutScheduleSQL, o, w, e, schedule, integration, 300, time.Now().UTC(), 0).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	connectScheduler := func() (*pgx.Conn, *DiscoveryExecutionRepository) {
		t.Helper()
		config := owner.Config().Copy()
		config.User = "occurrence_scheduler"
		conn, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: conn})
		if err != nil {
			t.Fatal(err)
		}
		repo, err := NewDiscoveryExecutionRepository(db, DiscoveryExecutionAuthorityScheduler)
		if err != nil {
			t.Fatalf("registered scheduler constructor: %v", err)
		}
		return conn, repo
	}
	first, firstRepo := connectScheduler()
	second, secondRepo := connectScheduler()
	if provisionalCase == 0 {
		testOccurrenceRepositoryReadiness(t, ctx, owner, first, firstRepo)
	}
	claim := func(repo *DiscoveryExecutionRepository, worker, token string) ExecutionScheduleInput {
		t.Helper()
		leases, err := repo.ClaimDiscoverySchedules(ctx, worker, token, 5, 1)
		if err != nil || len(leases) != 1 || leases[0].ID != schedule {
			t.Fatalf("claim: %+v %v", leases, err)
		}
		input, err := repo.GetDiscoveryScheduleInput(ctx, identity.Scope, schedule, worker, token)
		if err != nil {
			t.Fatal(err)
		}
		return input
	}
	const firstWorker, firstToken = "scheduler-before-restart", "schedule-before-token-0001"
	const secondWorker, secondToken = "scheduler-after-restart", "schedule-after-token-00002"
	initial := claim(firstRepo, firstWorker, firstToken)
	digest := sha256.Sum256([]byte("one exact scheduled occurrence"))
	baseRequest := SyncRequest{IntegrationID: integration, SyncID: syncID, JobID: jobID, OutboxID: outboxID, IdempotencyKey: "occurrence-restart-0001", RequestDigest: digest[:], TriggerKind: "schedule", ParserVersion: "parser_v1", ToolVersion: "tool_v1"}
	request := func(conn *pgx.Conn, worker, token string, input SyncRequest) (SyncRequestResult, error) {
		var result SyncRequestResult
		var raw json.RawMessage
		err := conn.QueryRow(ctx, postgresExecutionScheduledSyncSQL, o, w, e, identity.PrincipalID.String(), schedule, worker, token, input.IntegrationID, input.SyncID, input.JobID, input.OutboxID, input.IdempotencyKey, input.RequestDigest, input.ParserVersion, input.ToolVersion).Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	admit := func(repo *DiscoveryExecutionRepository, worker, token string, input SyncRequest) (SyncRequestResult, error) {
		return repo.RequestScheduledSync(ctx, identity, ScheduledSyncRequest{ScheduleID: schedule, Worker: worker, LeaseToken: token, SyncRequest: input})
	}
	t.Run("lease_expiring_inside_sync_admission_rolls_back_every_provisional_write", func(t *testing.T) {
		const delayedSync = "pid_79000007-0000-4000-8000-000000000001"
		const delayedJob = "pid_79000007-0000-4000-8000-000000000002"
		const delayedOutbox = "pid_79000007-0000-4000-8000-000000000003"
		if _, err := owner.Exec(ctx, `
			CREATE SEQUENCE test_delay_scheduled_admission_entry;
CREATE FUNCTION test_delay_scheduled_admission() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $$BEGIN
	IF NEW.job_id='pid_79000007-0000-4000-8000-000000000002' THEN
		PERFORM nextval('public.test_delay_scheduled_admission_entry');
		PERFORM pg_sleep(1.5);
	END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER test_delay_scheduled_admission BEFORE INSERT ON zasp_discovery_job_authorities FOR EACH ROW EXECUTE FUNCTION test_delay_scheduled_admission()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = owner.Exec(context.Background(), `DROP TRIGGER IF EXISTS test_delay_scheduled_admission ON zasp_discovery_job_authorities;DROP FUNCTION IF EXISTS test_delay_scheduled_admission();DROP SEQUENCE IF EXISTS test_delay_scheduled_admission_entry`)
		}()
		before := occurrenceSnapshot(t, ctx, owner, o, w, e, integration)
		if _, err := owner.Exec(ctx, `UPDATE zasp_discovery_schedules SET lease_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1 AND lease_owner=$2 AND lease_token=$3`, schedule, firstWorker, firstToken); err != nil {
			t.Fatal(err)
		}
		var shortenedSchedule string
		if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM zasp_discovery_schedules r WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&shortenedSchedule); err != nil {
			t.Fatal(err)
		}
		before["zasp_discovery_schedules"] = shortenedSchedule
		delayedDigest := sha256.Sum256([]byte("lease expires inside scheduled admission"))
		_, err := request(first, firstWorker, firstToken, SyncRequest{IntegrationID: integration, SyncID: delayedSync, JobID: delayedJob, OutboxID: delayedOutbox, IdempotencyKey: "occurrence-expiring-0001", RequestDigest: delayedDigest[:], TriggerKind: "schedule", ParserVersion: "parser_v1", ToolVersion: "tool_v1"})
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "P0002" || pg.Message != "schedule lease missing" {
			t.Fatalf("expired inner admission result: %v", err)
		}
		var triggerEntered bool
		if err := owner.QueryRow(ctx, `SELECT is_called FROM test_delay_scheduled_admission_entry`).Scan(&triggerEntered); err != nil || !triggerEntered {
			t.Fatalf("inner admission delay trigger was not entered: entered=%t err=%v", triggerEntered, err)
		}
		for table, after := range occurrenceSnapshot(t, ctx, owner, o, w, e, integration) {
			if after != before[table] {
				t.Errorf("expired inner admission changed %s: before=%s after=%s", table, before[table], after)
			}
		}
		if err := owner.QueryRow(ctx, `UPDATE zasp_discovery_schedules SET lease_expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 RETURNING lease_expires_at`, schedule, firstWorker, firstToken).Scan(&initial.LeaseExpiresAt); err != nil {
			t.Fatal(err)
		}
	})
	created, err := admit(firstRepo, firstWorker, firstToken, baseRequest)
	if err != nil {
		t.Fatalf("initial committed admission: %v", err)
	}
	if created.SyncID != syncID || created.JobID != jobID || created.OutboxID != outboxID || created.Replayed {
		t.Fatalf("initial result: %+v", created)
	}
	assertOne := func(t *testing.T) {
		t.Helper()
		var syncs, jobs, outboxes, receipts int
		if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM zasp_discovery_syncs WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)),
 (SELECT count(*) FROM zasp_discovery_jobs WHERE (organization_id,workspace_id,environment_id,authority_id)=($1,$2,$3,$5)),
 (SELECT count(*) FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$6)),
 (SELECT count(*) FROM zasp_discovery_schedule_runs WHERE (organization_id,workspace_id,environment_id,schedule_id,sync_id,job_id,request_digest,scheduled_for)=($1,$2,$3,$7,$5,$8,$9,$10))`, o, w, e, integration, syncID, outboxID, schedule, jobID, digest[:], initial.NextRunAt).Scan(&syncs, &jobs, &outboxes, &receipts); err != nil {
			t.Fatal(err)
		}
		if syncs != 1 || jobs != 1 || outboxes != 1 || receipts != 1 {
			t.Fatalf("durable occurrence counts sync/job/outbox/receipt=%d/%d/%d/%d", syncs, jobs, outboxes, receipts)
		}
	}
	assertOne(t)
	snapshot := func(t *testing.T) map[string]string {
		return occurrenceSnapshot(t, ctx, owner, o, w, e, integration)
	}
	assertUnchanged := func(t *testing.T, before map[string]string) {
		t.Helper()
		for table, after := range snapshot(t) {
			if after != before[table] {
				t.Errorf("refused occurrence changed full %s values/versions: before=%s after=%s", table, before[table], after)
			}
		}
	}
	assertProposedAbsent := func(t *testing.T, input SyncRequest) {
		t.Helper()
		for _, item := range []struct{ table, proposed, original string }{
			{"zasp_discovery_syncs", input.SyncID, syncID},
			{"zasp_discovery_jobs", input.JobID, jobID},
			{"zasp_discovery_outbox", input.OutboxID, outboxID},
		} {
			if item.proposed == item.original {
				continue
			}
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{item.table}.Sanitize()+` WHERE id=$1`, item.proposed).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Errorf("proposed %s ID %s persisted: count=%d", item.table, item.proposed, count)
			}
		}
	}
	// A wrong registered capability or direct table grant must not confer
	// occurrence authority. These calls use real LOGIN sessions, not SET ROLE.
	t.Run("direct_table_writes_and_reads_cannot_bypass_scheduler_RLS", func(t *testing.T) {
		before := snapshot(t)
		for _, query := range []string{
			`SELECT * FROM zasp_discovery_schedule_runs`,
			`UPDATE zasp_discovery_schedule_runs SET lease_owner='forged'`,
			`DELETE FROM zasp_discovery_schedule_runs`,
			`INSERT INTO zasp_discovery_schedule_runs SELECT * FROM zasp_discovery_schedule_runs`,
		} {
			_, err := second.Exec(ctx, query)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Errorf("direct receipt access escaped grants/RLS: %s: %v", query, err)
			}
		}
		var forced bool
		if err := owner.QueryRow(ctx, `SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='zasp_discovery_schedule_runs'::regclass`).Scan(&forced); err != nil || !forced {
			t.Errorf("receipt RLS not forced: %t %v", forced, err)
		}
		assertUnchanged(t, before)
	})
	t.Run("wrong_registered_principal_cannot_borrow_live_lease", func(t *testing.T) {
		before := snapshot(t)
		cfg := owner.Config().Copy()
		cfg.User = "occurrence_api"
		wrong, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer wrong.Close(context.Background())
		_, err = request(wrong, firstWorker, firstToken, baseRequest)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Errorf("API borrowed scheduler occurrence authority: %v", err)
		}
		assertUnchanged(t, before)
	})
	t.Run("same_live_token_replay_does_not_mutate_receipt_or_freshness", func(t *testing.T) {
		before := snapshot(t)
		got, err := admit(firstRepo, firstWorker, firstToken, baseRequest)
		if err != nil || !got.Replayed || got.SyncID != syncID || got.JobID != jobID || got.OutboxID != outboxID {
			t.Errorf("same-token replay=%+v err=%v", got, err)
		}
		assertUnchanged(t, before)
	})
	if provisionalCase == 3 {
		// A new due instant is a new occurrence, not permission to reuse the old
		// receipt. Public cadence is not under test: the real schedule API edits
		// its next due to now, just as the initial diagnostic fixture does.
		completed, err := firstRepo.CompleteDiscoverySchedule(ctx, identity.Scope, DiscoveryScheduleCompletion{ID: schedule, Worker: firstWorker, LeaseToken: firstToken, Outcome: "advanced", NextRunAt: initial.NextRunAt.Add(300 * time.Second).UTC()})
		if err != nil {
			t.Fatalf("registered completion before distinct due: %v", err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "occurrence_api"
		api, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		if err := api.QueryRow(ctx, postgresDiscoveryPutScheduleSQL, o, w, e, schedule, integration, 300, time.Now().UTC(), completed.Version).Scan(&raw); err != nil {
			t.Fatalf("registered diagnostic due-time edit: %v", err)
		}
		next := claim(secondRepo, secondWorker, secondToken)
		if !next.NextRunAt.After(initial.NextRunAt) {
			t.Fatalf("due instant not distinct: initial=%s next=%s", initial.NextRunAt, next.NextRunAt)
		}
		before := snapshot(t)
		_, err = request(second, secondWorker, secondToken, baseRequest)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23505" {
			t.Errorf("different due reused old occurrence: %v", err)
		}
		assertUnchanged(t, before)
		nextRequest := baseRequest
		nextRequest.SyncID = "pid_79200001-0000-4000-8000-000000000001"
		nextRequest.JobID = "pid_79200002-0000-4000-8000-000000000002"
		nextRequest.OutboxID = "pid_79200003-0000-4000-8000-000000000003"
		nextRequest.IdempotencyKey = "distinct-due-occurrence-0001"
		got, err := admit(secondRepo, secondWorker, secondToken, nextRequest)
		if err != nil || got.Replayed || got.SyncID != nextRequest.SyncID || got.JobID != nextRequest.JobID || got.OutboxID != nextRequest.OutboxID {
			t.Fatalf("fresh distinct-due occurrence=%+v err=%v", got, err)
		}
		var total, dueTimes int
		if err := owner.QueryRow(ctx, `SELECT count(*),count(DISTINCT scheduled_for) FROM zasp_discovery_schedule_runs WHERE schedule_id=$1`, schedule).Scan(&total, &dueTimes); err != nil || total != 2 || dueTimes != 2 {
			t.Fatalf("distinct due receipts=%d distinct_due=%d err=%v", total, dueTimes, err)
		}
		return
	}
	// Wall-clock expiry, no UPDATE or pg_sleep backdating. Separate connections
	// reproduce a replacement process retaining only the durable database state.
	started := time.Now()
	timer := time.NewTimer(time.Until(initial.LeaseExpiresAt) + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// The old process can still submit while its replacement reclaims. Both
	// registered connections start together; no owner mutates lease timestamps.
	var reclaimed ExecutionScheduleInput
	t.Run("simultaneous_expired_admission_and_reclaim_fences_old_process", func(t *testing.T) {
		before := snapshot(t)
		start := make(chan struct{})
		oldDone := make(chan error, 1)
		type claimResult struct {
			input ExecutionScheduleInput
			err   error
		}
		newDone := make(chan claimResult, 1)
		go func() { <-start; _, err := request(first, firstWorker, firstToken, baseRequest); oldDone <- err }()
		go func() {
			<-start
			leases, err := secondRepo.ClaimDiscoverySchedules(ctx, secondWorker, secondToken, 5, 1)
			if err == nil && (len(leases) != 1 || leases[0].ID != schedule) {
				err = fmt.Errorf("replacement claims=%+v", leases)
			}
			var input ExecutionScheduleInput
			if err == nil {
				input, err = secondRepo.GetDiscoveryScheduleInput(ctx, identity.Scope, schedule, secondWorker, secondToken)
			}
			newDone <- claimResult{input, err}
		}()
		close(start)
		oldErr, current := <-oldDone, <-newDone
		var pg *pgconn.PgError
		if !errors.As(oldErr, &pg) || pg.Code != "P0002" {
			t.Errorf("expired process admitted during reclaim: %v", oldErr)
		}
		if current.err != nil {
			t.Fatalf("concurrent registered reclaim: %v", current.err)
		}
		reclaimed = current.input
		for table, after := range snapshot(t) {
			if table != "zasp_discovery_schedules" && after != before[table] {
				t.Errorf("reclaim/expired admission changed %s: before=%s after=%s", table, before[table], after)
			}
		}
	})
	if reclaimed.ScheduleID != schedule {
		t.Fatal("replacement fixture did not acquire schedule")
	}
	if !reclaimed.NextRunAt.Equal(initial.NextRunAt) || reclaimed.Version <= initial.Version || !reclaimed.LeaseExpiresAt.After(time.Now()) {
		t.Fatalf("invalid replacement lease: first=%+v second=%+v", initial, reclaimed)
	}
	t.Logf("real lease wait=%s claim version=%d→%d same due=%s", time.Since(started), initial.Version, reclaimed.Version, initial.NextRunAt.Format(time.RFC3339Nano))
	for _, field := range []string{"organization", "workspace", "environment", "schedule", "integration"} {
		t.Run("changed_"+field+"_cannot_borrow_replacement_lease", func(t *testing.T) {
			args := []any{o, w, e, identity.PrincipalID.String(), schedule, secondWorker, secondToken, integration, syncID, jobID, outboxID, baseRequest.IdempotencyKey, digest[:], "parser_v1", "tool_v1"}
			position := map[string]int{"organization": 0, "workspace": 1, "environment": 2, "schedule": 4, "integration": 7}[field]
			args[position] = "pid_79900002-0000-4000-8000-000000000002"
			before := snapshot(t)
			var ignored json.RawMessage
			err := second.QueryRow(ctx, postgresExecutionScheduledSyncSQL, args...).Scan(&ignored)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "P0002" {
				t.Errorf("changed %s borrowed lease: %v", field, err)
			}
			assertUnchanged(t, before)
		})
	}
	// Same key/digest makes manual sync admission normalize each proposed ID
	// back to the stored ID. None may authorize a receipt transfer.
	for _, field := range []string{"sync", "job", "outbox"} {
		t.Run("normalized_"+field+"_ID_must_not_authorize_rebind", func(t *testing.T) {
			input := baseRequest
			const changed = "pid_79000007-0000-4000-8000-000000000007"
			switch field {
			case "sync":
				input.SyncID = changed
			case "job":
				input.JobID = changed
			case "outbox":
				input.OutboxID = changed
			}
			before := snapshot(t)
			_, err := request(second, secondWorker, secondToken, input)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23505" {
				t.Errorf("normalized %s ID authorized occurrence: %v", field, err)
			}
			assertUnchanged(t, before)
			assertProposedAbsent(t, input)
		})
	}
	t.Run("exact_occurrence_rebinds_to_verified_replacement", func(t *testing.T) {
		before := snapshot(t)
		replayed, replayErr := admit(secondRepo, secondWorker, secondToken, baseRequest)
		assertOne(t)
		if replayErr != nil {
			assertUnchanged(t, before)
			var pg *pgconn.PgError
			if errors.As(replayErr, &pg) {
				t.Fatalf("exact occurrence replay under verified new live lease must succeed: SQLSTATE=%s message=%s", pg.Code, pg.Message)
			}
			t.Fatalf("exact occurrence replay: %v", replayErr)
		}
		if !replayed.Replayed || replayed.SyncID != syncID || replayed.JobID != jobID || replayed.OutboxID != outboxID {
			t.Fatalf("replay changed occurrence: %+v", replayed)
		}
		var generation int
		if err := owner.QueryRow(ctx, `SELECT COALESCE((to_jsonb(r)->>'rebind_generation')::integer,0) FROM zasp_discovery_schedule_runs r WHERE schedule_id=$1`, schedule).Scan(&generation); err != nil || generation != 1 {
			t.Fatalf("replacement generation=%d err=%v", generation, err)
		}
		var receipt []map[string]any
		if err := json.Unmarshal([]byte(before["zasp_discovery_schedule_runs"]), &receipt); err != nil || len(receipt) != 1 {
			t.Fatalf("receipt before transfer: %v", err)
		}
		receipt[0]["lease_owner"], receipt[0]["lease_token"], receipt[0]["rebind_generation"] = secondWorker, secondToken, 1
		wantReceipt, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if after := snapshot(t)["zasp_discovery_schedule_runs"]; !equalIntegrationJSON(wantReceipt, []byte(after)) {
			t.Errorf("rebind changed immutable receipt fields: want=%s got=%s", wantReceipt, after)
		}
		for table, after := range snapshot(t) {
			if table != "zasp_discovery_schedule_runs" && after != before[table] {
				t.Errorf("rebind changed %s: before=%s after=%s", table, before[table], after)
			}
		}
		before = snapshot(t)
		if retry, err := admit(secondRepo, secondWorker, secondToken, baseRequest); err != nil || retry != replayed {
			t.Fatalf("replacement retry=%+v: %v", retry, err)
		}
		assertUnchanged(t, before)
	})
	// Different keys force actual provisional sync/job/outbox and freshness
	// writes. Each call is autocommit: no test transaction can hide residue.
	for index, changeDigest := range []bool{false, true} {
		if provisionalCase != index+1 {
			continue
		}
		t.Run(fmt.Sprintf("different_key_provisional_writes_rollback_changed_digest_%t", changeDigest), func(t *testing.T) {
			input := baseRequest
			input.SyncID = fmt.Sprintf("pid_7910000%d-0000-4000-8000-000000000001", index+1)
			input.JobID = fmt.Sprintf("pid_7910000%d-0000-4000-8000-000000000002", index+1)
			input.OutboxID = fmt.Sprintf("pid_7910000%d-0000-4000-8000-000000000003", index+1)
			input.IdempotencyKey = fmt.Sprintf("occurrence-changed-key-%04d", index+1)
			if changeDigest {
				changed := sha256.Sum256([]byte("changed scheduled occurrence intent"))
				input.RequestDigest = changed[:]
			}
			before := snapshot(t)
			_, err := request(second, secondWorker, secondToken, input)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23505" || pg.Message != "schedule run conflict" {
				t.Errorf("different-key occurrence must fail at occurrence conflict after provisional writes: %v", err)
			}
			assertProposedAbsent(t, input)
			assertUnchanged(t, before)
		})
	}
	if provisionalCase == 0 {
		t.Run("replacement_completion_is_occurrence_durable", func(t *testing.T) {
			// A second real expiry proves generation2, not one increment per retry.
			timer := time.NewTimer(time.Until(reclaimed.LeaseExpiresAt) + 50*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			const thirdWorker, thirdToken = "scheduler-third", "schedule-third-token-0003"
			third := claim(firstRepo, thirdWorker, thirdToken)
			if !third.NextRunAt.Equal(initial.NextRunAt) {
				t.Fatal("replacement changed due instant")
			}
			if got, err := admit(firstRepo, thirdWorker, thirdToken, baseRequest); err != nil || !got.Replayed || got.SyncID != syncID || got.JobID != jobID || got.OutboxID != outboxID {
				t.Fatalf("second replacement=%+v: %v", got, err)
			}
			var generation int
			if err := owner.QueryRow(ctx, `SELECT rebind_generation FROM zasp_discovery_schedule_runs WHERE schedule_id=$1`, schedule).Scan(&generation); err != nil || generation != 2 {
				t.Fatalf("second replacement generation=%d: %v", generation, err)
			}
			before := snapshot(t)
			if got, err := admit(firstRepo, thirdWorker, thirdToken, baseRequest); err != nil || !got.Replayed {
				t.Fatalf("second replacement retry=%+v: %v", got, err)
			}
			assertUnchanged(t, before)
			next := time.Now().UTC().Add(1500 * time.Millisecond).Truncate(time.Microsecond)
			completion := DiscoveryScheduleCompletion{ID: schedule, Worker: thirdWorker, LeaseToken: thirdToken, Outcome: "advanced", NextRunAt: next}
			for _, old := range []struct{ worker, token string }{{firstWorker, firstToken}, {secondWorker, secondToken}} {
				stale := completion
				stale.Worker, stale.LeaseToken = old.worker, old.token
				if _, err := secondRepo.CompleteDiscoverySchedule(ctx, identity.Scope, stale); !errors.Is(err, ErrRepositoryNotFound) {
					t.Fatalf("old token completed: %v", err)
				}
				assertUnchanged(t, before)
			}
			result, err := firstRepo.CompleteDiscoverySchedule(ctx, identity.Scope, completion)
			if err != nil || result.Version != third.Version+1 || !result.NextRunAt.Equal(next) {
				t.Fatalf("current completion=%+v: %v", result, err)
			}
			var stored json.RawMessage
			var durable bool
			if err := owner.QueryRow(ctx, `SELECT completion_result,completed_at IS NOT NULL AND octet_length(completion_digest)=32 AND rebind_generation=2 FROM zasp_discovery_schedule_runs WHERE schedule_id=$1`, schedule).Scan(&stored, &durable); err != nil || !durable {
				t.Fatalf("missing durable occurrence completion: %t %v", durable, err)
			}
			var saved DiscoveryScheduleCompletionResult
			if err := json.Unmarshal(stored, &saved); err != nil || saved.ID != result.ID || saved.State != result.State || saved.Version != result.Version || !saved.NextRunAt.Equal(result.NextRunAt) {
				t.Fatalf("stored completion=%+v result=%+v err=%v", saved, result, err)
			}
			assertOne(t)
			before = snapshot(t)
			retry := func() {
				t.Helper()
				got, err := secondRepo.CompleteDiscoverySchedule(ctx, identity.Scope, completion)
				if err != nil || got != result {
					t.Fatalf("lost response replay=%+v want=%+v err=%v", got, result, err)
				}
				assertUnchanged(t, before)
			}
			retry()
			timer.Reset(time.Until(next) + 50*time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			retry()
			const laterWorker, laterToken = "scheduler-later", "schedule-later-token-0004"
			later := claim(secondRepo, laterWorker, laterToken)
			if !later.NextRunAt.Equal(next) {
				t.Fatal("later occurrence due mismatch")
			}
			before = snapshot(t)
			retry()
			changed := completion
			changed.NextRunAt = next.Add(time.Second)
			if _, err := secondRepo.CompleteDiscoverySchedule(ctx, identity.Scope, changed); !errors.Is(err, ErrRepositoryConflict) {
				t.Fatalf("changed completion digest accepted: %v", err)
			}
			assertUnchanged(t, before)
			if _, err := admit(secondRepo, laterWorker, laterToken, baseRequest); !errors.Is(err, ErrRepositoryConflict) {
				t.Fatalf("completed receipt rebound: %v", err)
			}
			assertUnchanged(t, before)
			laterRequest := baseRequest
			laterRequest.SyncID, laterRequest.JobID, laterRequest.OutboxID, laterRequest.IdempotencyKey = "pid_79300001-0000-4000-8000-000000000001", "pid_79300002-0000-4000-8000-000000000002", "pid_79300003-0000-4000-8000-000000000003", "later-occurrence-0004"
			if got, err := admit(secondRepo, laterWorker, laterToken, laterRequest); err != nil || got.Replayed {
				t.Fatalf("later admission=%+v: %v", got, err)
			}
			before = snapshot(t)
			retry()
			// Complete the later occurrence normally, then use the registered API
			// to revisit the original diagnostic due instant. This isolates the
			// completed-receipt fence from the different-due identity fence.
			laterResult, err := secondRepo.CompleteDiscoverySchedule(ctx, identity.Scope, DiscoveryScheduleCompletion{ID: schedule, Worker: laterWorker, LeaseToken: laterToken, Outcome: "advanced", NextRunAt: next.Add(300 * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			cfg := owner.Config().Copy()
			cfg.User = "occurrence_api"
			api, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close(context.Background())
			if err := api.QueryRow(ctx, postgresDiscoveryPutScheduleSQL, o, w, e, schedule, integration, 300, initial.NextRunAt, laterResult.Version).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			const revisitingWorker, revisitingToken = "scheduler-revisiting", "schedule-revisiting-token-0005"
			if got := claim(secondRepo, revisitingWorker, revisitingToken); !got.NextRunAt.Equal(initial.NextRunAt) {
				t.Fatal("diagnostic same-due edit failed")
			}
			before = snapshot(t)
			if _, err := admit(secondRepo, revisitingWorker, revisitingToken, baseRequest); !errors.Is(err, ErrRepositoryConflict) {
				t.Fatalf("completed exact occurrence rebound: %v", err)
			}
			assertUnchanged(t, before)
		})
	}
}

// A resumed predecessor body after installation is intentionally unsupported.
// Current code must refuse its version-derived identities without rewriting it.
func testOccurrenceLegacyFence(t *testing.T, ctx context.Context, owner *pgx.Conn, runner *migrations.Runner, integration, schedule string, postInstall bool) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	var raw json.RawMessage
	if err := owner.QueryRow(ctx, postgresDiscoveryPutScheduleSQL, o, w, e, schedule, integration, 300, time.Now().UTC(), 0).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	cfg := owner.Config().Copy()
	cfg.User = "occurrence_scheduler"
	old, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close(context.Background())
	const worker, token = "legacy-scheduler", "legacy-scheduler-token-0001"
	if err := old.QueryRow(ctx, postgresExecutionClaimSchedulesSQL, worker, token, 5, 1).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var leases struct {
		Items []DiscoveryScheduleLease `json:"items"`
	}
	if err := json.Unmarshal(raw, &leases); err != nil || len(leases.Items) != 1 {
		t.Fatalf("legacy claim=%s: %v", raw, err)
	}
	digest := sha256.Sum256([]byte("legacy version-derived occurrence"))
	args := []any{o, w, e, identity.PrincipalID.String(), schedule, worker, token, integration, "pid_79400001-0000-4000-8000-000000000001", "pid_79400002-0000-4000-8000-000000000002", "pid_79400003-0000-4000-8000-000000000003", "legacy-version-occurrence-0001", digest[:], "parser_v1", "tool_v1"}
	if postInstall {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `LOCK TABLE zasp_discovery_schedules IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var result json.RawMessage
			done <- old.QueryRow(ctx, postgresExecutionScheduledSyncSQL, args...).Scan(&result)
		}()
		joined := false
		defer func() {
			_ = tx.Rollback(context.Background())
			if !joined {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("legacy admission did not join")
				}
			}
		}()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		waiting := false
		for !waiting {
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, int32(old.PgConn().PID())).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if !waiting {
				select {
				case err := <-done:
					joined = true
					t.Fatalf("old call did not wait: %v", err)
				case <-tick.C:
				case <-deadline.C:
					t.Fatal("old call lock wait absent")
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		}
		inside, err := migrations.NewRunner(&occurrenceTransactionDatabase{transaction: tx})
		if err != nil {
			t.Fatal(err)
		}
		if err := inside.UpProductionDiscoveryScheduleReplay(ctx); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			joined = true
			if err != nil {
				t.Fatalf("old first writer not reproduced: %v", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		t.Log("already executing predecessor admission resumed and committed after deliberately violated maintenance fence")
	} else if err := old.QueryRow(ctx, postgresExecutionScheduledSyncSQL, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	// Let the real old lease expire; neither the lease nor receipt is backdated.
	timer := time.NewTimer(time.Until(leases.Items[0].LeaseExpiresAt) + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	before := occurrenceSnapshot(t, ctx, owner, o, w, e, integration)
	assertUnchanged := func() {
		t.Helper()
		for name, after := range occurrenceSnapshot(t, ctx, owner, o, w, e, integration) {
			if before[name] != after {
				t.Fatalf("legacy refusal changed %s", name)
			}
		}
	}
	if !postInstall {
		if err := runner.UpProductionDiscoveryScheduleReplay(ctx); err == nil {
			t.Fatal("expired legacy orphan allowed release60 install")
		}
		if version, err := runner.Version(ctx); err != nil || version != 59 {
			t.Fatalf("legacy preflight version=%d: %v", version, err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: old})
		if err != nil {
			t.Fatal(err)
		}
		if repo, err := NewDiscoveryExecutionRepository(db, DiscoveryExecutionAuthorityScheduler); err != ErrRepositoryConfiguration || repo != nil {
			t.Fatalf("legacy predecessor fallback=%v", err)
		}
		assertUnchanged()
		return
	}
	current, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close(context.Background())
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: current})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewDiscoveryExecutionRepository(db, DiscoveryExecutionAuthorityScheduler)
	if err != nil {
		t.Fatal(err)
	}
	const currentWorker, currentToken = "stable-scheduler", "stable-scheduler-token-0002"
	if items, err := repo.ClaimDiscoverySchedules(ctx, currentWorker, currentToken, 5, 1); err != nil || len(items) != 1 {
		t.Fatalf("stable claim=%+v: %v", items, err)
	}
	before = occurrenceSnapshot(t, ctx, owner, o, w, e, integration)
	request := ScheduledSyncRequest{ScheduleID: schedule, Worker: currentWorker, LeaseToken: currentToken, SyncRequest: SyncRequest{IntegrationID: integration, SyncID: "pid_79500001-0000-4000-8000-000000000001", JobID: "pid_79500002-0000-4000-8000-000000000002", OutboxID: "pid_79500003-0000-4000-8000-000000000003", IdempotencyKey: "stable-occurrence-0001", RequestDigest: digest[:], TriggerKind: "schedule", ParserVersion: "parser_v1", ToolVersion: "tool_v1"}}
	if _, err := repo.RequestScheduledSync(ctx, identity, request); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("legacy identity mapping was accepted: %v", err)
	}
	assertUnchanged()
}

type occurrenceTransactionDatabase struct{ transaction pgx.Tx }

func (database *occurrenceTransactionDatabase) QueryRow(ctx context.Context, statement string, args ...any) migrations.Row {
	return database.transaction.QueryRow(ctx, statement, args...)
}
func (database *occurrenceTransactionDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := database.transaction.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &integrationMigrationTransaction{transaction: tx}, nil
}

func testOccurrenceRepositoryReadiness(t *testing.T, ctx context.Context, owner, scheduler *pgx.Conn, repository *DiscoveryExecutionRepository) {
	t.Helper()
	for _, pair := range [][2]string{{"unknown", migrations.DiscoveryScheduleReplayFingerprint()}, {migrations.ProductionDiscoveryScheduleReplay().Checksum(), "drifted"}} {
		var ready bool
		if err := scheduler.QueryRow(ctx, `SELECT zasp_discovery_schedule_replay_readiness($1,$2)`, pair[0], pair[1]).Scan(&ready); err != nil || ready {
			t.Fatalf("wrong release identity accepted=%t: %v", ready, err)
		}
	}
	cfg := owner.Config().Copy()
	cfg.User = "occurrence_api"
	wrong, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close(context.Background())
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: wrong})
	if err != nil {
		t.Fatal(err)
	}
	if repo, err := NewDiscoveryExecutionRepository(db, DiscoveryExecutionAuthorityScheduler); err != ErrRepositoryConfiguration || repo != nil {
		t.Fatalf("wrong principal constructed scheduler: %v", err)
	}
	const signature = `public.zasp_execution_request_scheduled_sync(text,text,text,text,text,text,text,text,text,text,text,text,bytea,text,text)`
	if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION `+signature+` FROM zasp_discovery_scheduler`); err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != ErrRepositoryUnavailable {
		t.Errorf("revoked scheduled admission remained ready: %v", err)
	}
	if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+signature+` TO zasp_discovery_scheduler`); err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatalf("grant restore did not restore readiness: %v", err)
	}
}

// A complete database response is the narrow double here: the code under test
// is the actual repository decoder. PostgreSQL behavior is covered separately
// below, without mocks. A global tightening of manual replay is also a bug.
func testScheduledOccurrenceResponseIdentity(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	input := ScheduledSyncRequest{
		ScheduleID: "pid_79000003-0000-4000-8000-000000000003", Worker: "decoder-worker", LeaseToken: "decoder-lease-token-0001",
		SyncRequest: SyncRequest{IntegrationID: "pid_79000001-0000-4000-8000-000000000001", SyncID: "pid_79000004-0000-4000-8000-000000000004", JobID: "pid_79000005-0000-4000-8000-000000000005", OutboxID: "pid_79000006-0000-4000-8000-000000000006", IdempotencyKey: "decoder-occurrence-0001", RequestDigest: make([]byte, 32), TriggerKind: "schedule", ParserVersion: "parser_v1", ToolVersion: "tool_v1"},
	}
	for _, field := range []string{"exact", "sync", "job", "outbox"} {
		t.Run(field, func(t *testing.T) {
			response := SyncRequestResult{SyncID: "pid_79000004-0000-4000-8000-000000000004", JobID: "pid_79000005-0000-4000-8000-000000000005", OutboxID: "pid_79000006-0000-4000-8000-000000000006", State: "queued", Replayed: true}
			const other = "pid_79900001-0000-4000-8000-000000000001"
			switch field {
			case "sync":
				response.SyncID = other
			case "job":
				response.JobID = other
			case "outbox":
				response.OutboxID = other
			}
			payload, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresExecutionScheduledSyncSQL: payload}}
			repo := newTestDiscoveryExecutionRepository(t, db, DiscoveryExecutionAuthorityScheduler)
			got, err := repo.RequestScheduledSync(context.Background(), identity, input)
			if field == "exact" {
				if err != nil || got != response {
					t.Errorf("exact scheduled replay=%+v err=%v", got, err)
				}
			} else if !errors.Is(err, ErrRepositoryUnavailable) || got != (SyncRequestResult{}) {
				t.Errorf("scheduled decoder accepted returned/proposed %s mismatch: result=%+v err=%v", field, got, err)
			}
			manual := input.SyncRequest
			manual.TriggerKind = "manual"
			manualDB := &discoveryCallDatabase{schema: DiscoveryExecutionSchemaVersion, responses: map[string]json.RawMessage{postgresExecutionReadySQL: json.RawMessage(`true`), postgresExecutionRequestSyncSQL: payload}}
			manualRepo := newTestDiscoveryRepository(t, manualDB)
			got, err = manualRepo.RequestDiscoverySync(context.Background(), identity, manual)
			if err != nil || got != response {
				t.Errorf("manual normalized replay contract changed: result=%+v err=%v", got, err)
			}
		})
	}
}

// Whole tenant rows deliberately include every schedule/integration-scoped
// record, not just the originally proposed IDs. to_jsonb also captures newly
// added receipt fields (including generation) without an allowlist omission.
func occurrenceSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, integration string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{"zasp_discovery_schedules", "zasp_integrations", "zasp_discovery_syncs", "zasp_discovery_jobs", "zasp_discovery_outbox", "zasp_discovery_job_authorities", "zasp_discovery_schedule_runs", "zasp_discovery_freshness_versions"} {
		var raw string
		if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+pgx.Identifier{table}.Sanitize()+` r WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		result[table] = raw
	}
	var freshness string
	if err := owner.QueryRow(ctx, `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)::text`, o, w, e, integration).Scan(&freshness); err != nil {
		t.Fatal(err)
	}
	result["freshness_response"] = freshness
	return result
}

// Use the real additive predecessor chain, including its readiness checks.
// Callers install60 only after the maintenance-fence tests have inspected59.
func installOccurrenceRelease59(t *testing.T, ctx context.Context, owner *pgx.Conn, runner *migrations.Runner) {
	t.Helper()
	for index, apply := range []func(context.Context) error{
		runner.UpProductionTypedInventoryCutover,
		runner.UpProductionRuntimeDataPlane,
		runner.UpProductionRuntimeGatewayReconciliation,
		runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution,
		runner.UpProductionIdentityAdministration,
		runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse,
		runner.UpProductionSecurityAgentTemporaryPolicy,
		runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation,
		runner.UpProductionRedTeamExecution,
		runner.UpProductionAttackLabExecution,
		runner.UpProductionRecovery,
		runner.UpProductionPolicyDeployment,
		runner.UpProductionHomeAttention,
		runner.UpProductionApprovalNotification,
		runner.UpProductionWorkflowCompatibility,
		runner.UpProductionSecurityAgentPlanner,
		runner.UpProductionSecurityAgentAttackPath,
		runner.UpProductionIntegrationSetup,
		runner.UpProductionIntegrationWebhook,
		runner.UpProductionRuntimeQueueReplay,
		runner.UpProductionRedTeamSafety,
		runner.UpProductionRedTeamInvocation,
		runner.UpProductionRedTeamArtifacts,
		runner.UpProductionRuntimeSessions,
		runner.UpProductionRuntimeSessionReads,
		runner.UpProductionRuntimeSessionSearch,
		runner.UpProductionRuntimeSessionQuery,
		runner.UpProductionRuntimeSessionEvidence,
		runner.UpProductionRuntimeEnrollmentPairing,
		runner.UpProductionReconciliationLanePlan,
		runner.UpProductionRuntimeCandidateAuthority,
		runner.UpProductionRuntimeAcceptance,
		runner.UpProductionRuntimeCorrelationRouting,
		runner.UpProductionRuntimeSandboxBinding,
		runner.UpProductionRuntimePrecision,
		runner.UpProductionAuditExports,
		runner.UpProductionSecurityAgentBudgets,
		runner.UpProductionSecurityAgentRunContext,
		runner.UpProductionSecurityAgentExistingTests,
		runner.UpProductionCompliance,
		runner.UpProductionSecurityAgentAttackLab,
		runner.UpProductionSecurityAgentExports,
		runner.UpProductionSecurityAgentWebhooks,
	} {
		if err := apply(ctx); err != nil {
			t.Fatalf("registered predecessor migration%d: %v", 14+index, err)
		}
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_sa_webhook_readiness($1,$2)`, migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("exact release59 readiness=%t: %v", ready, err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 59 {
		t.Fatalf("registered predecessor version=%d: %v", version, err)
	}
	t.Logf("registered release59 checksum=%s fingerprint=%s ready=true", migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint())
}
