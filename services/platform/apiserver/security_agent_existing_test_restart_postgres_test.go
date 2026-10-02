package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentExistingTestMultiTenantRestartPostgres(t *testing.T) {
	binary := os.Getenv("ZASP_RECONCILE_CLIENT_BINARY")
	if binary == "" {
		t.Fatal("requires owned registered worker binary")
	}
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, definition, actor string) {
		const otherO = "pid_9a000001-0000-4000-8000-000000000001"
		const otherW = "pid_9a000002-0000-4000-8000-000000000002"
		const otherE = "pid_9a000003-0000-4000-8000-000000000003"
		// The base fixture owns both tenants. Seed a distinct registered test target
		// in the second tenant, keeping target/definition IDs equal to catch scope loss.
		if _, err := owner.Exec(ctx, `
UPDATE zasp_environments SET environment_class='staging' WHERE id=$6;
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 SELECT $4,$5,$6,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_89000011-0000-4000-8000-000000000001');
SELECT zasp_attack_lab_register_credential_binding($4,$5,$6,'pid_89000013-0000-4000-8000-000000000003','pid_89000011-0000-4000-8000-000000000001','ref:red-team/versioned_draft_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 SELECT $4,$5,$6,definition_id,name,target_id,target_kind,categories,safety,created_by FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, pgx.QueryExecModeSimpleProtocol, o, w, e, otherO, otherW, otherE); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		for i, scope := range [][3]string{{o, w, e}, {o, w, e}, {otherO, otherW, otherE}} {
			so, sw, se := scope[0], scope[1], scope[2]
			id := func(suffix int) string { return fmt.Sprintf("pid_99b00%d%02d-0000-4000-8000-000000000001", suffix, i) }
			run := id(1)
			seedExistingTestPreparation(t, ctx, owner, so, sw, se, definition, actor, run, id(2), "run_test", "restart-setup-worker", "restart-prepare-lease")
			if _, err := owner.Exec(ctx, `
UPDATE zasp_security_agent_definitions SET activation='autonomous',body=jsonb_set(body,'{autonomy}','"autonomous"') WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$4 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)
 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest;
INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'run_test',true,$4) ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, so, sw, se, actor); err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			if err := worker.QueryRow(ctx, existingTestPrepareSQL, so, sw, se, run, "restart-setup-worker", "restart-prepare-lease", id(3), time.Now().Add(10*time.Minute), id(4), id(5)).Scan(&raw); err != nil {
				t.Fatal("prepare", err)
			}
			var prepared SecurityAgentPrepareResult
			if err := json.Unmarshal(raw, &prepared); err != nil || prepared.State != "queued" {
				t.Fatalf("prepare state %s: %v", raw, err)
			}
			if err := worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, "restart-setup-worker", "restart-dispatch-lease", 60, 25).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			// Dispatch is intentionally private in the candidate. Only fixture setup
			// grants it temporarily; the real reconciler runs after this grant is gone.
			if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO security_agent_v33_worker_login`); err != nil {
				t.Fatal(err)
			}
			callErr := worker.QueryRow(ctx, `SELECT zasp_security_agent_test_dispatch($1,$2,$3,$4,$5,$6,$7,$8)`, so, sw, se, run, "restart-setup-worker", "restart-dispatch-lease", id(6), id(7)).Scan(&raw)
			if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`); err != nil {
				t.Fatal(err)
			}
			if callErr != nil {
				t.Fatal("dispatch", callErr)
			}
		}
		child := func(mode string, failStop bool) {
			t.Helper()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestExistingTestRuntimeRestartOwnedPostgres$", "-test.v")
			command.Env = append(os.Environ(), "ZASP_RECONCILE_CLIENT_DSN="+owner.Config().ConnString(), "ZASP_RECONCILE_RESTART_MODE="+mode)
			output, err := command.CombinedOutput()
			if failStop {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 23 {
					t.Fatalf("fail-stop %s: %v", output, err)
				}
				return
			}
			if err != nil || !strings.Contains(string(output), "--- PASS: TestExistingTestRuntimeRestartOwnedPostgres") {
				t.Fatalf("restart child %s: %s %v", mode, output, err)
			}
			t.Log(string(output))
		}
		if os.Getenv("ZASP_RECONCILE_CONCURRENT_PROCESSES") == "true" {
			assertExistingTestConcurrentProcesses(t, ctx, owner, binary, o, child)
			return
		}
		child("abandon", true)
		var heldRun, heldGeneration string
		var heldVersion int64
		if err := owner.QueryRow(ctx, `SELECT run_id,reconcile_generation::text,reconcile_version FROM zasp_security_agent_test_links WHERE organization_id=$1 AND reconcile_state='leased' AND reconcile_worker='owned-crashed-reconciler' AND reconcile_expires_at>clock_timestamp()`, o).Scan(&heldRun, &heldGeneration, &heldVersion); err != nil {
			t.Fatal("durable abandoned lease", err)
		}
		if heldVersion != 2 {
			t.Fatal("unexpected initial version", heldVersion)
		}
		child("other-tenants", false)
		var independent bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=3 AND count(*) FILTER(WHERE reconcile_state='leased' AND run_id=$1)=1 AND count(*) FILTER(WHERE reconcile_state='pending' AND reconcile_version=3 AND reconcile_next_at>clock_timestamp())=2 AND count(DISTINCT organization_id)=2 FROM zasp_security_agent_test_links`, heldRun).Scan(&independent); err != nil || !independent {
			t.Fatal("other links starved or live lease stolen", err)
		}
		var before, after string
		snapshot := func() string {
			t.Helper()
			var raw string
			if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(l) ORDER BY organization_id,run_id)::text FROM zasp_security_agent_test_links l WHERE run_id<>$1`, heldRun).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		before = snapshot()
		// Controlled fixture expiry avoids sleeping a minute; this is not a measured
		// lease-duration or live-clock proof. No ownership/generation is altered.
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND run_id=$2`, o, heldRun); err != nil {
			t.Fatal(err)
		}
		child("reclaim", false)
		after = snapshot()
		if before != after {
			t.Fatal("restart changed another link")
		}
		var recovered bool
		if err := owner.QueryRow(ctx, `SELECT reconcile_state='pending' AND reconcile_version=4 AND reconcile_generation::text<>$3 AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL AND reconcile_next_at>clock_timestamp() FROM zasp_security_agent_test_links WHERE organization_id=$1 AND run_id=$2`, o, heldRun, heldGeneration).Scan(&recovered); err != nil || !recovered {
			t.Fatal("expired lease not reclaimed and released", err)
		}
		var noExecution bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=3 AND bool_and(state='queued') FROM zasp_red_team_runs) AND (SELECT count(*)=3 FROM zasp_red_team_outbox) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_invocations) AND (SELECT count(*)=3 FROM zasp_security_agent_test_links)`).Scan(&noExecution); err != nil || !noExecution {
			t.Fatal("reconciliation duplicated or executed target work", err)
		}
	})
}
