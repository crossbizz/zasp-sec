package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// An existing-test action must acquire its own lease-bound admission, not grant
// the Security Agent worker access to the human/API enqueue authority.
func TestSecurityAgentExistingTestPreservesAPIEnqueueBoundaryPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		counts := func() [3]int {
			t.Helper()
			var value [3]int
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_red_team_definitions),(SELECT count(*) FROM zasp_red_team_runs),(SELECT count(*) FROM zasp_red_team_outbox)`).Scan(&value[0], &value[1], &value[2]); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before := counts()
		for _, role := range []struct{ login, code string }{
			{"security_agent_v33_worker_login", "42501"},
			{"security_agent_v33_api_login", "P0002"},
		} {
			config, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			config.User = role.login
			connection, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = connection.Exec(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				"pid_6a000001-0000-4000-8000-000000000001", "pid_6a000002-0000-4000-8000-000000000002", "pid_6a000003-0000-4000-8000-000000000003",
				"pid_8a000001-0000-4000-8000-000000000001", "agent-test-boundary-0001", "pid_8a000002-0000-4000-8000-000000000002", int64(1), "pid_8a000003-0000-4000-8000-000000000003", "pid_8a000004-0000-4000-8000-000000000004")
			closeErr := connection.Close(context.Background())
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != role.code {
				t.Fatalf("login=%s code=%s err=%v", role.login, role.code, err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if after := counts(); after != before {
				t.Fatalf("denied/missing-definition enqueue changed tables: before=%v after=%v", before, after)
			}
		}
	})
}
