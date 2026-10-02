package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Run every non-database constructor used by the native child before paying
// for its PostgreSQL/FGA fixture. No readiness or authority evidence is implied.
func TestRecoveryNativeCompositionHarness(t *testing.T) {
	_, driver, q := fixtureExistingTestEvidence(t)
	var body []byte
	for l, o := range driver.objects {
		if "s3://zasp-evidence/"+l.Key == q.InputArtifact.Reference {
			body = o.Body
		}
	}
	var input redTeamRunnerInput
	if len(body) == 0 || json.Unmarshal(body, &input) != nil {
		t.Fatal("original input fixture")
	}
	ctx := context.Background()
	pool := func() *pgxpool.Pool {
		p, err := pgxpool.New(ctx, "postgres://fixture@127.0.0.1:1/fixture?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	forward, compensation, adapter := pool(), pool(), pool()
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: input.OrganizationID, WorkspaceID: input.WorkspaceID, EnvironmentID: input.EnvironmentID, RunID: snapshotRun}, DefinitionVersion: 1, InputDigest: input.InputDigest}
	product, _, artifacts, forbidden, command, requests := newRecoveryNativeComposition(t, ctx, forward, compensation, adapter, start, body, q.InputArtifact)
	if product.runner == nil || len(artifacts.objects) != 1 || forbidden.calls.Load() != 0 || command.calls != 0 || requests.Load() != 0 || forward.Stat().AcquireCount() != 0 || compensation.Stat().AcquireCount() != 0 || adapter.Stat().AcquireCount() != 0 {
		t.Fatal("fixture composition performed IO or lost dependencies")
	}
	runner := product.runner
	if !validRedTeamTokenFile(runner.config.TargetTokenFile) || !validRedTeamCAFile(runner.config.TargetCAFile) {
		t.Fatal("fixture pinned TLS files")
	}
}

// This checks the host-only TLS/Node fixture before the expensive native run.
// Its literal receipts are not database-authority or settlement evidence.
func TestRecoveryNativeNodeTLSHarness(t *testing.T) {
	_, driver, q := fixtureExistingTestEvidence(t)
	capturedEvidenceFixture(t, driver, &q, false)
	var inputBody []byte
	for l, o := range driver.objects {
		if "s3://zasp-evidence/"+l.Key == q.InputArtifact.Reference {
			inputBody = o.Body
		}
	}
	if len(inputBody) == 0 {
		t.Fatal("input")
	}
	var input redTeamRunnerInput
	_ = json.Unmarshal(inputBody, &input)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/effects/completed-receipt" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			t.Error("wrong fixture transport contract")
			w.WriteHeader(400)
			return
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		for _, receipt := range q.Captured.Receipts {
			if body["category"] == receipt.Category {
				_ = json.NewEncoder(w).Encode(receipt)
				return
			}
		}
		w.WriteHeader(400)
	}))
	defer server.Close()
	dir := t.TempDir()
	in, out, token, ca := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json"), filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem")
	if os.WriteFile(in, inputBody, 0600) != nil || os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0400) != nil || os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400) != nil {
		t.Fatal("owned fixture files")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	module, err := filepath.Abs("../../../workers/redteam-node/runner.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := &recoveryNativeNode{t: t, node: node, module: module, endpoint: server.URL}
	env := []string{"HOME=" + dir, "ZASP_RED_TEAM_TARGET_ENDPOINT=https://agentsec-red-team-adapter.zasp-system.svc.cluster.local/v1/effects/completed-receipt", "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE=" + token, "ZASP_RED_TEAM_TARGET_CA_FILE=" + ca, "ZASP_RED_TEAM_EFFECT_KEY=" + q.Captured.Receipts[0].Effect, "ZASP_RED_TEAM_RECOVERY_PARENT_RUN_ID=" + snapshotRun, "ZASP_RED_TEAM_RECOVERY_STEP_ID=" + snapshotStep, "ZASP_RED_TEAM_RECOVERY_GENERATION=1"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := command.Run(ctx, "/usr/local/bin/node", []string{"/app/redteam-runner.mjs", "recover-completed", in, out}, env, dir); err != nil {
		t.Fatal("actual Node/TLS harness", err)
	}
	result, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCompletedTestArtifact(input, result); err != nil {
		t.Fatal("actual Node/TLS artifact", err)
	}
	if calls != len(input.Categories) || command.calls != 1 {
		t.Fatal("fixture transport cardinality", calls, command.calls)
	}
}
