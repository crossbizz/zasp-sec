package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeSessionSearchOutboxBackfillAndFencedCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, apply := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"search_coordinator", "search_archive", "search_index", "search_correlation", "search_projection", "search_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'search_coordinator','search_archive','search_index','search_correlation','search_projection','search_gateway')`); err != nil {
		t.Fatal(err)
	}
	connect := func(name string) *pgx.Conn {
		config := admin.Config().Copy()
		config.User = name
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { connection.Close(context.Background()) })
		return connection
	}
	coordinator, index, api := connect("search_coordinator"), connect("search_index"), connect("invocation_discovery_api")
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var result json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, migrations.ProductionRuntimeSessionSearch().UpSQL()); err != nil {
		probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	err = probe.QueryRow(ctx, `SELECT zasp_production_runtime_session_search_live_fingerprint()`).Scan(&fingerprint)
	probe.Rollback(ctx)
	if err != nil || fingerprint != migrations.ProductionRuntimeSessionSearchSemanticFingerprint() {
		t.Fatalf("candidate42 fingerprint=%s error=%v", fingerprint, err)
	}
	if err := runner.UpProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	apiRepository, err := NewPostgresRepository(apiDatabase)
	if err != nil || apiRepository.Ready(ctx) != nil {
		t.Fatal("schema42 prevented production API startup", err)
	}
	future, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := future.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(43,'future_release',repeat('0',64))`); err != nil {
		future.Rollback(ctx)
		t.Fatal(err)
	}
	var futureSchema string
	futureErr := future.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint(), migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&futureSchema)
	future.Rollback(ctx)
	if !errors.Is(futureErr, pgx.ErrNoRows) {
		t.Fatal("API accepted unknown schema43")
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='pending'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("backfill count=%d err=%v", count, err)
	}
	claim := func(connection *pgx.Conn, worker, token string) (json.RawMessage, error) {
		var body json.RawMessage
		err := connection.QueryRow(ctx, `SELECT zasp_runtime_session_search_claim($1,$2,30)`, worker, token).Scan(&body)
		return body, err
	}
	if _, err := claim(api, "search-worker", "search-lease-token-0001"); err == nil {
		t.Fatal("API claimed indexing work")
	}
	if _, err := index.Exec(ctx, `SELECT * FROM zasp_runtime_session_search_outbox`); err == nil {
		t.Fatal("index worker received direct table access")
	}
	first, err := claim(index, "search-worker", "search-lease-token-0001")
	if err != nil {
		t.Fatal(err)
	}
	var lease struct {
		Organization string   `json:"organization_id"`
		Workspace    string   `json:"workspace_id"`
		Environment  string   `json:"environment_id"`
		Batch        string   `json:"batch_id"`
		Generation   int64    `json:"generation"`
		Attempt      int      `json:"attempt"`
		Digest       string   `json:"receipt_digest"`
		Reference    string   `json:"receipt_reference"`
		Version      string   `json:"receipt_version"`
		DocumentIDs  []string `json:"document_ids"`
	}
	if json.Unmarshal(first, &lease) != nil || lease.Attempt != 1 || len(lease.DocumentIDs) != 3 || len(lease.Digest) != 64 || lease.Reference == "" || lease.Version == "" {
		t.Fatalf("invalid committed claim %s", first)
	}
	if busy, err := claim(index, "search-worker-2", "search-lease-token-0002"); err != nil || len(busy) != 0 {
		t.Fatalf("duplicate claim=%s err=%v", busy, err)
	}
	finish := func(token, digest string, attempt int, ids []string) error {
		return index.QueryRow(ctx, `SELECT zasp_runtime_session_search_finish($1,$2,$3,$4,$5,'search-worker',$6,$7,decode($8,'hex'),'indexed',$9,0)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, token, attempt, digest, ids).Scan(&result)
	}
	for _, fault := range []struct {
		token, digest string
		attempt       int
		ids           []string
	}{
		{"wrong-lease-token-0001", lease.Digest, 1, lease.DocumentIDs},
		{"search-lease-token-0001", lease.Digest, 2, lease.DocumentIDs},
		{"search-lease-token-0001", lease.Digest, 1, lease.DocumentIDs[:2]},
		{"search-lease-token-0001", "0000000000000000000000000000000000000000000000000000000000000000", 1, lease.DocumentIDs},
	} {
		if finish(fault.token, fault.digest, fault.attempt, fault.ids) == nil {
			t.Fatal("forged checkpoint accepted")
		}
	}
	observer := connect(admin.Config().User)
	blockedThroughExpiry := func(operation string, call func() error) {
		t.Helper()
		lock, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET lease_until=clock_timestamp()+interval '1 second' WHERE state='leased'`); err != nil {
			t.Fatal(err)
		}
		pid := index.PgConn().PID()
		done := make(chan error, 1)
		go func() { done <- call() }()
		deadline := time.Now().Add(750 * time.Millisecond)
		blocked := false
		for time.Now().Before(deadline) {
			if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !blocked {
			t.Fatal("index call did not block on the owned row lock")
		}
		time.Sleep(1100 * time.Millisecond)
		if err := lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatalf("%s accepted a lease that expired while waiting for its row lock", operation)
		}
	}
	blockedThroughExpiry("finish", func() error { return finish("search-lease-token-0001", lease.Digest, 1, lease.DocumentIDs) })
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE state='leased'`); err != nil {
		t.Fatal(err)
	}
	if finish("search-lease-token-0001", lease.Digest, 1, lease.DocumentIDs) == nil {
		t.Fatal("expired lease committed")
	}
	second, err := claim(index, "search-worker", "search-lease-token-0002")
	if err != nil || json.Unmarshal(second, &lease) != nil || lease.Attempt != 2 {
		t.Fatalf("reclaim=%s err=%v", second, err)
	}
	if finish("search-lease-token-0001", lease.Digest, 1, lease.DocumentIDs) == nil {
		t.Fatal("stale attempt committed after reclaim")
	}
	blockedThroughExpiry("heartbeat", func() error {
		return index.QueryRow(ctx, `SELECT zasp_runtime_session_search_heartbeat($1,$2,$3,$4,$5,'search-worker','search-lease-token-0002',2,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation).Scan(&result)
	})
	third, err := claim(index, "search-worker", "search-lease-token-0003")
	if err != nil || json.Unmarshal(third, &lease) != nil || lease.Attempt != 3 {
		t.Fatalf("heartbeat reclaim=%s err=%v", third, err)
	}
	if err := finish("search-lease-token-0003", lease.Digest, 3, lease.DocumentIDs); err != nil {
		t.Fatal(err)
	}
	// Exact retry reconciles a lost DB acknowledgement; foreign tokens cannot.
	if err := finish("search-lease-token-0003", lease.Digest, 3, lease.DocumentIDs); err != nil {
		t.Fatal(err)
	}
	if finish("search-lease-token-0001", lease.Digest, 3, lease.DocumentIDs) == nil {
		t.Fatal("foreign retry adopted checkpoint")
	}
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='indexed'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("receipt replay duplicated or reset checkpoint")
	}
	if err := runner.DownProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_projection_receipts`).Scan(&count); err != nil || count != 1 {
		t.Fatal("downgrade removed canonical receipts")
	}
	if err := runner.UpProductionRuntimeSessionSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='pending'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("upgrade did not rebuild derived indexing work")
	}
	// The rebuilt queue must still fence concurrent registered workers, delay
	// retries and retain failed work without exposing table mutation authority.
	peer := connect("search_index")
	type claimResult struct {
		body          json.RawMessage
		err           error
		worker, token string
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for _, contender := range []struct {
		connection    *pgx.Conn
		worker, token string
	}{
		{index, "search-worker-a", "search-concurrent-token-a"},
		{peer, "search-worker-b", "search-concurrent-token-b"},
	} {
		go func() {
			<-start
			body, err := claim(contender.connection, contender.worker, contender.token)
			results <- claimResult{body, err, contender.worker, contender.token}
		}()
	}
	close(start)
	var winner claimResult
	claimed := 0
	for range 2 {
		candidate := <-results
		if candidate.err != nil {
			t.Fatal(candidate.err)
		}
		if len(candidate.body) > 0 {
			claimed++
			winner = candidate
		}
	}
	if claimed != 1 || json.Unmarshal(winner.body, &lease) != nil || lease.Attempt != 1 {
		t.Fatalf("concurrent claim count=%d", claimed)
	}
	if err := runner.DownProductionRuntimeSessionSearch(ctx); err == nil {
		t.Fatal("downgrade discarded an active indexing lease")
	}
	heartbeat := func(token string) error {
		return index.QueryRow(ctx, `SELECT zasp_runtime_session_search_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, winner.worker, token, lease.Attempt).Scan(&result)
	}
	if heartbeat("search-foreign-token-0001") == nil {
		t.Fatal("foreign token renewed lease")
	}
	if err := heartbeat(winner.token); err != nil {
		t.Fatal(err)
	}
	checkpoint := func(outcome string, delay int) error {
		return index.QueryRow(ctx, `SELECT zasp_runtime_session_search_finish($1,$2,$3,$4,$5,$6,$7,$8,decode($9,'hex'),$10,$11,$12)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, winner.worker, winner.token, lease.Attempt, lease.Digest, outcome, []string{}, delay).Scan(&result)
	}
	if err := checkpoint("retryable", 60); err != nil {
		t.Fatal(err)
	}
	if body, err := claim(index, "retry-worker", "search-retry-token-0001"); err != nil || len(body) != 0 {
		t.Fatal("retry delay ignored", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='pending'`); err != nil {
		t.Fatal(err)
	}
	winner.worker, winner.token = "retry-worker", "search-retry-token-0002"
	if body, err := claim(index, winner.worker, winner.token); err != nil || json.Unmarshal(body, &lease) != nil || lease.Attempt != 2 {
		t.Fatal("retry claim failed", err)
	}
	if err := checkpoint("quarantined", 0); err != nil {
		t.Fatal(err)
	}
	if body, err := claim(index, "retry-worker", "search-retry-token-0003"); err != nil || len(body) != 0 {
		t.Fatal("quarantine was reclaimed", err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='quarantined' AND worker_id IS NULL AND lease_digest IS NULL AND lease_until IS NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatal("quarantine retained lease authority", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET state='pending',attempt=100,next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='quarantined'`); err != nil {
		t.Fatal(err)
	}
	if body, err := claim(index, "retry-worker", "search-retry-token-0004"); err != nil || len(body) != 0 {
		t.Fatal("attempt cap ignored", err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='quarantined' AND attempt=100`).Scan(&count); err != nil || count != 1 {
		t.Fatal("exhausted work was not retained in quarantine", err)
	}
}
