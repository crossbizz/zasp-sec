//go:build darwin || linux

package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
)

func TestSecurityAgentMultistepPricingWorkerProcessPostgres(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	runOrderedPricingFixture(t, func(ctx context.Context, owner, admin, worker *pgx.Conn, o, w, e, actor string) {
		database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: admin})
		repository, err := multisteppricing.New(database, "admin")
		if err != nil {
			t.Fatal(err)
		}
		q := orderedPricingAdminRequest(o, w, e, actor)
		p := q["policy"].(map[string]any)
		p["request_token_limit"] = 512
		p["request_policy_version"] = "security-agent-planner-v1"
		digest := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
		p["credential_digest"] = "sha256:" + hex.EncodeToString(digest[:])
		raw, _ := json.Marshal(q)
		created, err := repository.Admin(ctx, raw)
		if err != nil {
			t.Fatal("real private admin repository", err)
		}
		binding, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "account_profile": p["account_profile"], "credential_reference": p["credential_reference"], "policy_id": created.PolicyID, "policy_version": created.Version, "policy_digest": created.PolicyDigest, "account_id": created.AccountID, "account_version": created.AccountVersion})
		run := func(mode string) {
			t.Helper()
			command := exec.Command(binary, "-test.run=^TestSecurityAgentMultistepPricingOwnedPostgres$", "-test.v", "-test.timeout=30s")
			command.Dir = "../agentsec-worker"
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, "ZASP_ORDERED_PRICING_TEST_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_PRICING_BINDING="+string(binding), "ZASP_ORDERED_PRICING_MODE="+mode)
			output, err := runSandboxWorkerCommand(ctx, command)
			if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "owned ordered pricing worker joined: provider_calls=0") {
				t.Fatalf("owned pricing worker: %v\n%s", err, output)
			}
			t.Log(string(output))
		}
		before := orderedPricingSnapshot(t, ctx, owner)
		run("exact")
		run("restart")
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("process restart mutated approval history")
		}
		q["operation"] = "disable"
		q["idempotency_key"] = "pricing-process-disable-0002"
		q["expected_version"] = 1
		q["expected_account_version"] = 1
		raw, _ = json.Marshal(q)
		if _, err = repository.Admin(ctx, raw); err != nil {
			t.Fatal("disable via private Go repository", err)
		}
		before = orderedPricingSnapshot(t, ctx, owner)
		run("refuse")
		if orderedPricingSnapshot(t, ctx, owner) != before {
			t.Fatal("revoked restart mutated approval history")
		}
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if _, err = NewSecurityAgentWorkerRepository(db); err == nil {
			t.Fatal("generic worker accepted61")
		}
		if _, err = multisteppricing.New(db, "admin"); err == nil {
			t.Fatal("worker acquired admin private repository")
		}
	})
}
