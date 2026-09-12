//go:build darwin || linux

package apiserver

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"
)

// The apiserver fixture owns this disposable database's lifetime. The child
// test exercises package-private worker authority using its real pgx adapter.
// This is a lease protocol test, not evidence of search-provider visibility.
func TestRuntimeSandboxSearchWorkerPostgresRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	scope := fixtureRequestIdentity(t).Scope
	reference := "s3://zasp-evidence/organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/pid_96000008-0000-4000-8000-000000000008"
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET result_reference=$1 WHERE stage='project'`, reference); err != nil {
		t.Fatal(err)
	}
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	fixtureURL, err := url.Parse(admin.Config().ConnString())
	if err != nil || fixtureURL.Scheme != "postgres" {
		t.Fatal("invalid local fixture URL")
	}
	fixtureURL.User = url.User("candidate_index")
	command := exec.Command("go", "test", "-race", "../agentsec-worker", "-run", "^TestSandboxSearchAuthorityPostgres$", "-count=1", "-v")
	command.Env = append(os.Environ(), "ZASP_SANDBOX_SEARCH_TEST_DSN="+fixtureURL.String())
	output, err := runSandboxWorkerCommand(ctx, command)
	if err != nil {
		t.Fatalf("worker authority child test failed: %v\n%s", err, output)
	}
	t.Logf("worker authority child test:\n%s", output)
	var state string
	var attempt int
	if err := admin.QueryRow(ctx, `SELECT state,attempt FROM zasp_runtime_sandbox_search_outbox`).Scan(&state, &attempt); err != nil || state != "indexed" || attempt != 1 {
		t.Fatal("real worker did not checkpoint v2", state, attempt, err)
	}
	if err := admin.QueryRow(ctx, `SELECT state,attempt FROM zasp_runtime_session_search_outbox`).Scan(&state, &attempt); err != nil || state != "pending" || attempt != 0 {
		t.Fatal("real v2 worker changed v1 progress", state, attempt, err)
	}
	api := sandboxSessionAPI(t, ctx, admin)
	if err := api.QueryRow(ctx, sandboxQueryStatusSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), fixtureRequestIdentity(t).PrincipalID.String()).Scan(&body); err != nil {
		t.Fatal(err)
	}
	status, err := decodeRuntimeSearchStatus(body, time.Now())
	if err != nil || status.State != "current" || status.LastIndexed == nil || status.Pending != 0 {
		t.Fatal("worker checkpoint missing from v2 freshness", string(body), err)
	}
}
