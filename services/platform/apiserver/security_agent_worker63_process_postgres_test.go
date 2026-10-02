package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentWorker63RepositoryProcessPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-process-trigger"})
		if err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		binary := multistepBudgetWorkerBinary(t, ctx)
		raw, _ := json.Marshal(worker63ClaimRequest("worker63-process-token"))
		first := ""
		for i := 0; i < 2; i++ {
			command := exec.CommandContext(ctx, binary, "-test.run=^TestWorker63RepositoryProcess$", "-test.v")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, "ZASP_WORKER63_TEST_DSN="+owner.Config().ConnString(), "ZASP_WORKER63_TEST_CLAIM="+string(raw))
			output, err := command.CombinedOutput()
			if err != nil || strings.Contains(string(output), "--- SKIP:") {
				t.Fatalf("repository process: %v\n%s", err, output)
			}
			matched := false
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "worker63-repository-result:") {
					matched = true
					var v map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "worker63-repository-result:")), &v) != nil {
						t.Fatal("invalid process output")
					}
					item := v["item"].(map[string]any)
					if item["run_id"] != created.RunID || item["organization_id"] != o || item["workspace_id"] != w || item["environment_id"] != e {
						t.Fatal("foreign result", item)
					}
					if i == 0 {
						first = line
					} else if first != line {
						t.Fatal("restart changed dispatch")
					}
				}
			}
			if !matched {
				t.Fatalf("process did not exercise repository\n%s", output)
			}
		}
	})
}
