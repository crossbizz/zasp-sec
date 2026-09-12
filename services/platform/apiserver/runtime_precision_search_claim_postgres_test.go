package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

func TestRuntimePrecisionSearchOldClaimLeavesUnsupportedRowsUntouched(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	fragment, err := os.ReadFile("../migrations/sql/fragments/runtime_precision_completion.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(fragment)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+preciseCompletionSignature+` TO zasp_runtime_coordinator`); err != nil {
		t.Fatal(err)
	}
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	var output []byte
	if err := coordinator.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...).Scan(&output); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "candidate_index"
	index, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close(context.Background())
	for _, state := range []string{"pending", "expired", "exhausted"} {
		t.Run(state, func(t *testing.T) {
			query := `UPDATE zasp_runtime_sandbox_search_outbox SET state='pending',attempt=0,worker_id=NULL,lease_digest=NULL,lease_until=NULL`
			if state == "expired" {
				query = `UPDATE zasp_runtime_sandbox_search_outbox SET state='leased',attempt=1,worker_id='prior-worker',lease_digest=digest('prior-token','sha256'),lease_until=clock_timestamp()-interval '1 second'`
			}
			if state == "exhausted" {
				query = `UPDATE zasp_runtime_sandbox_search_outbox SET state='pending',attempt=100,worker_id=NULL,lease_digest=NULL,lease_until=NULL`
			}
			if _, err := admin.Exec(ctx, query); err != nil {
				t.Fatal(err)
			}
			var before, after string
			if err := admin.QueryRow(ctx, `SELECT row_to_json(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := index.QueryRow(ctx, `SELECT COALESCE(zasp_runtime_sandbox_search_claim('old-search','old-search-token-01',30),'null'::jsonb)`).Scan(&output); err != nil {
				t.Fatal(err)
			}
			if string(output) != "null" {
				t.Fatal("old reader claimed V3", string(output))
			}
			if err := admin.QueryRow(ctx, `SELECT row_to_json(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&after); err != nil || before != after {
				t.Fatal("old reader mutated V3", err)
			}
		})
	}
}
