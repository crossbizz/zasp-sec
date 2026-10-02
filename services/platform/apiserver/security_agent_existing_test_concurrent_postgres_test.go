package apiserver

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentExistingTestConcurrentProcessesPostgres(t *testing.T) {
	t.Setenv("ZASP_RECONCILE_CONCURRENT_PROCESSES", "true")
	TestSecurityAgentExistingTestMultiTenantRestartPostgres(t)
}

// Catch duplicate claims, scope loss and release interference while two real
// runtime processes simultaneously own distinct links in the same tenant.
func assertExistingTestConcurrentProcesses(t *testing.T, ctx context.Context, owner *pgx.Conn, binary, org string, child func(string, bool)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	type process struct {
		input  io.WriteCloser
		done   chan struct{}
		output strings.Builder
		err    error
	}
	start := func(identity string) *process {
		t.Helper()
		command := exec.CommandContext(ctx, binary, "-test.run=^TestExistingTestRuntimeRestartOwnedPostgres$", "-test.v")
		command.Env = append(os.Environ(), "ZASP_RECONCILE_CLIENT_DSN="+owner.Config().ConnString(), "ZASP_RECONCILE_RESTART_MODE=concurrent", "ZASP_RECONCILE_CONCURRENT_ID="+identity)
		input, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		command.Stderr = command.Stdout
		p := &process{input: input, done: make(chan struct{})}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		go func() {
			defer close(p.done)
			scanner := bufio.NewScanner(output)
			for scanner.Scan() {
				line := scanner.Text()
				p.output.WriteString(line + "\n")
				if line == "RECONCILE_CLAIM_HELD" {
					close(ready)
				}
			}
			p.err = command.Wait()
			if p.err == nil {
				p.err = scanner.Err()
			}
		}()
		t.Cleanup(func() { input.Close(); cancel(); <-p.done })
		select {
		case <-ready:
		case <-p.done:
			t.Fatalf("child never held claim: %s %v", p.output.String(), p.err)
		case <-ctx.Done():
			t.Fatal("claim barrier deadline", ctx.Err())
		}
		return p
	}
	otherSnapshot := func() string {
		t.Helper()
		var snapshot string
		if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(l) ORDER BY run_id,step_id)::text FROM zasp_security_agent_test_links l WHERE organization_id<>$1`, org).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	beforeOther := otherSnapshot()
	first := start("owned-concurrent-a")
	second := start("owned-concurrent-b")
	var distinct bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND count(DISTINCT run_id)=2 AND count(DISTINCT reconcile_generation)=2 AND count(DISTINCT reconcile_worker)=2 AND bool_and(reconcile_worker IN ('owned-concurrent-a','owned-concurrent-b') AND organization_id=$1 AND reconcile_version=2 AND reconcile_expires_at>clock_timestamp()) FROM zasp_security_agent_test_links WHERE reconcile_state='leased'`, org).Scan(&distinct); err != nil || !distinct {
		t.Fatal("replicas do not own distinct same-tenant leases", err)
	}
	var untouched bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(reconcile_state='pending' AND reconcile_version=1) FROM zasp_security_agent_test_links WHERE organization_id<>$1`, org).Scan(&untouched); err != nil || !untouched {
		t.Fatal("concurrent claims touched another tenant", err)
	}
	for _, p := range []*process{first, second} {
		if _, err := io.WriteString(p.input, "continue\n"); err != nil {
			t.Fatal(err)
		}
		p.input.Close()
	}
	for _, p := range []*process{first, second} {
		select {
		case <-p.done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if p.err != nil || !strings.Contains(p.output.String(), "--- PASS: TestExistingTestRuntimeRestartOwnedPostgres") {
			t.Fatalf("concurrent runtime: %s %v", p.output.String(), p.err)
		}
	}
	if beforeOther != otherSnapshot() {
		t.Fatal("concurrent runtime changed another tenant's link")
	}
	child("other-tenants", false)
	var complete bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=3 AND bool_and(reconcile_state='pending' AND reconcile_version=3 AND reconcile_next_at>clock_timestamp() AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL) FROM zasp_security_agent_test_links) AND (SELECT count(*)=3 AND bool_and(state='queued') FROM zasp_red_team_runs) AND (SELECT count(*)=3 FROM zasp_red_team_outbox) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_invocations)`).Scan(&complete); err != nil || !complete {
		t.Fatal("concurrent runtime duplicated, stranded or executed work", err)
	}
}
