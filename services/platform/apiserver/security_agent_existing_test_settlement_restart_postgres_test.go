package apiserver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentExistingTestSettlementProcessRestartPostgres(t *testing.T) {
	if os.Getenv("ZASP_RECONCILE_CLIENT_BINARY") == "" {
		t.Fatal("requires registered worker executable")
	}
	if os.Getenv("ZASP_LINKED_FINISH_NODE") == "" {
		node, err := exec.LookPath("node")
		if err != nil {
			t.Fatal("requires actual Node artifact producer", err)
		}
		t.Setenv("ZASP_LINKED_FINISH_NODE", node)
	}
	if os.Getenv("ZASP_LINKED_FINISH_RUNNER") == "" {
		runner, err := filepath.Abs("../../../workers/redteam-node/runner.mjs")
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("ZASP_LINKED_FINISH_RUNNER", runner)
	}
	t.Setenv("ZASP_RECONCILE_SETTLEMENT_PROCESS", "true")
	t.Setenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS", "true")
	t.Setenv("ZASP_RECONCILE_INCLUDE_BASELINE", "true")
	TestSecurityAgentExistingTestWorkerFinishPostgres(t)
}

func assertExistingTestSettlementProcessRestart(t *testing.T, ctx context.Context, owner *pgx.Conn, command *exec.Cmd, o, w, e, run, step string) {
	t.Helper()
	command.Env = append(command.Env, "ZASP_RECONCILE_SETTLEMENT_FAILSTOP=true")
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 24 {
		t.Fatalf("expected fail-stop after committed settlement: %s %v", output, err)
	}
	snapshot := func() string {
		t.Helper()
		var body string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'link',to_jsonb(l),'run',to_jsonb(r),'step',to_jsonb(s),'effect',to_jsonb(f),
 'test',to_jsonb(t),
 'audits',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id)),
 'invocations',(SELECT jsonb_agg(to_jsonb(j) ORDER BY category) FROM zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)),
 'outbox',(SELECT jsonb_agg(to_jsonb(q) ORDER BY outbox_id) FROM zasp_red_team_outbox q WHERE (q.organization_id,q.workspace_id,q.environment_id)=(l.organization_id,l.workspace_id,l.environment_id) AND q.payload->>'run_id'=l.test_run_id))::text
 FROM zasp_security_agent_test_links l
 JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5) AND l.reconcile_state='settled'`, o, w, e, run, step).Scan(&body); err != nil {
			t.Fatal("durable settled snapshot", err)
		}
		return body
	}
	before := snapshot()
	replacement := exec.CommandContext(ctx, os.Getenv("ZASP_RECONCILE_CLIENT_BINARY"), "-test.run=^TestExistingTestRuntimeRestartOwnedPostgres$", "-test.v")
	replacement.Env = append(os.Environ(), "ZASP_RECONCILE_CLIENT_DSN="+owner.Config().ConnString(), "ZASP_RECONCILE_RESTART_MODE=reclaim")
	output, err = replacement.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestExistingTestRuntimeRestartOwnedPostgres") {
		t.Fatalf("replacement runtime: %s %v", output, err)
	}
	if before != snapshot() {
		t.Fatal("restart rewrote committed settlement or repeated effects")
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=($1,$2,$3,$4,$5,'test_reconciled')`, o, w, e, run, step).Scan(&exact); err != nil || !exact {
		t.Fatal("settlement audit duplicated or missing", err)
	}
	t.Log("fail-stop24 after settlement; replacement retained exact durable snapshot and one settlement audit")
}
