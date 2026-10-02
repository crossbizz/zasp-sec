package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

func runWorkerAdapterHTTPChild(t *testing.T, ctx context.Context, owner *pgx.Conn, config runtimeservices.Config, o, w, e, run string, linked map[string]any, diagnostic, recovery bool) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "worker-adapter-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "../redteamadapter")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("adapter child build: %v\n%s", err, output)
	}
	settings, _ := json.Marshal(config)
	var step string
	var originalInput json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT step_id,body FROM zasp_temporal74.test_inputs WHERE run_id=$1 AND test_run_id=$2`, run, linked["test_run_id"]).Scan(&step, &originalInput); err != nil {
		t.Fatal("captured original child input", err)
	}
	request, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "parent_run_id": run, "step_id": step, "original_input": originalInput, "test_run_id": linked["test_run_id"], "effect_key": linked["effect_key"], "category": linked["categories"].([]any)[0], "target_id": linked["target_id"], "target_kind": linked["target_kind"]})
	const name = "TestP7WorkerTest74JournalHTTPNative"
	child := exec.CommandContext(ctx, binary, "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	child.WaitDelay = 5 * time.Second
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ZASP_") {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, "ZASP_P7_ADAPTER_OWNER_DSN="+owner.Config().ConnString(), "ZASP_P7_ADAPTER_FGA_CONFIG="+string(settings), "ZASP_P7_ADAPTER_REQUEST="+string(request))
	if diagnostic {
		child.Env = append(child.Env, "ZASP_P7_ADAPTER_DIAGNOSTIC=1")
	}
	if recovery {
		child.Env = append(child.Env, "ZASP_P7_ADAPTER_COMPLETED_RETRY=1")
	}
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("actual adapter HTTP child failed: %v\n%s", err, output)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal74.invocations WHERE test_run_id=$1 AND state='completed') AND (SELECT count(*)=1 FROM zasp_temporal74.effects WHERE run_id=$2 AND state='started') AND (SELECT count(*)=1 FROM zasp_temporal74.test_inputs WHERE run_id=$2) AND (SELECT count(*)=1 FROM zasp_red_team_runs WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1)`, linked["test_run_id"], run).Scan(&exact); err != nil || !exact {
		t.Fatal("actual HTTP native cardinality", err)
	}
	t.Logf("actual adapter HTTP child joined: %s", output)
}
