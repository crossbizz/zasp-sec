package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func exerciseRedTeamProtocolSelection(t *testing.T, ctx context.Context, owner, worker, adapter *pgx.Conn, org, ws, env, linked, legacy string) {
	t.Helper()
	const query = `SELECT zasp_production_security_agent_existing_tests_worker_protocol($1,$2,$3,$4,$5,$6)`
	args := []any{org, ws, env, linked, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	var raw json.RawMessage
	snapshot := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id)::text FROM zasp_red_team_runs r WHERE run_id IN($1,$2)`, linked, legacy).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	// Establish this negative control explicitly. Registered dispatch has no
	// extra grant, while the private-core fixture may already have one.
	// The protocol must reject drift, then use the restored production ACL.
	if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO security_agent_v33_worker_login`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`)
	var drift *pgconn.PgError
	if err := worker.QueryRow(ctx, query, args...).Scan(&raw); !errors.As(err, &drift) || drift.Code != "55000" {
		t.Fatalf("protocol accepted fixture ACL drift: %v", err)
	}
	if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`); err != nil {
		t.Fatal(err)
	}
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewLinkedRedTeamExecutionRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := domain.ParseProductID(org)
	w, _ := domain.ParseProductID(ws)
	e, _ := domain.ParseProductID(env)
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct{ id, protocol string }{{linked, "linked"}, {legacy, "legacy"}} {
		if result, err := client.RunProtocol(ctx, scope, value.id); err != nil || result != value.protocol {
			t.Fatalf("protocol selection %s: %q %v", value.id, result, err)
		}
	}
	deny := func(conn *pgx.Conn, values []any, code string) {
		t.Helper()
		var pg *pgconn.PgError
		if err := conn.QueryRow(ctx, query, values...).Scan(&raw); !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("protocol refusal %s: %s %v", code, raw, err)
		}
	}
	deny(owner, args, "42501")
	deny(adapter, args, "42501")
	for i := range args {
		values := append([]any(nil), args...)
		values[i] = nil
		code := "22023"
		if i >= 4 {
			code = "55000"
		}
		deny(worker, values, code)
	}
	for i := 0; i < 4; i++ {
		values := append([]any(nil), args...)
		values[i] = "pid_99ffffff-0000-4000-8000-000000000001"
		deny(worker, values, "40001")
	}
	for i := 4; i < 6; i++ {
		values := append([]any(nil), args...)
		values[i] = strings.Repeat("f", 64)
		deny(worker, values, "55000")
	}
	if snapshot() != before {
		t.Fatal("protocol selection mutated run authority")
	}
	if binary := os.Getenv("ZASP_ROUTING_WORKER_BINARY"); binary != "" {
		command := exec.CommandContext(ctx, binary, "-test.run=^TestRedTeamRoutedOwnedPostgres$", "-test.v")
		command.Env = append(os.Environ(), "ZASP_ROUTING_WORKER_DSN="+worker.Config().ConnString(), "ZASP_ROUTING_ORG="+org, "ZASP_ROUTING_WORKSPACE="+ws, "ZASP_ROUTING_ENVIRONMENT="+env, "ZASP_ROUTING_LINKED="+linked, "ZASP_ROUTING_LEGACY="+legacy)
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "--- PASS: TestRedTeamRoutedOwnedPostgres") {
			t.Fatalf("registered worker composition: %s %v", output, err)
		}
		t.Log(string(output))
	}
}
