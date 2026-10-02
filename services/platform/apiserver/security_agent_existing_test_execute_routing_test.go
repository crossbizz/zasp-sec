package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The execution consumer must cross warm release cutovers just as preparation
// does. Calling the legacy endpoint at55 strands prepared existing-test work.
func TestSecurityAgentExistingTestExecutionRouting(t *testing.T) {
	const versionedSQL = `SELECT public.zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	claim := budgetRepositoryClaim()
	claim.Prepared = true
	const step = "pid_78000005-0000-4000-8000-000000000005"
	const audit = "pid_78000006-0000-4000-8000-000000000006"
	const correlation = "pid_78000007-0000-4000-8000-000000000007"
	const outcome = "pid_78000008-0000-4000-8000-000000000008"
	raw, err := json.Marshal(map[string]any{"run_id": claim.RunID, "state": "running", "version": 3, "step_id": step, "effect_state": "pending", "outcome_id": outcome, "result_digest": "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	db := &existingTestWorkerDatabase{}
	db.responses = map[string]json.RawMessage{versionedSQL: raw, postgresSecurityAgentExecuteRunV24SQL: raw}
	repo := &SecurityAgentWorkerRepository{database: db, executeSQL: postgresSecurityAgentExecuteRunV24SQL}
	for _, available := range []bool{false, true, false, true} {
		db.available = available
		value, err := repo.ExecuteSecurityAgentRun(context.Background(), claim, "worker-1", "worker-lease-00000001", audit, correlation)
		if err != nil || value.RunID != claim.RunID || value.EffectState != "pending" {
			t.Fatalf("dispatch result=%+v error=%v", value, err)
		}
		want := postgresSecurityAgentExecuteRunV24SQL
		if available {
			want = versionedSQL
		}
		if db.statements[len(db.statements)-1] != want {
			t.Fatalf("release=%t execution used %s, want %s", available, db.statements[len(db.statements)-1], want)
		}
		if available {
			args := db.arguments[len(db.arguments)-1]
			if len(args) != 10 || args[8] != migrations.ProductionSecurityAgentExistingTests().Checksum() || args[9] != migrations.SecurityAgentExistingTestsFingerprint() {
				t.Fatal("execution did not carry exact compiled release pins")
			}
		}
	}
	db.availabilityErr = ErrRepositoryUnavailable
	before := len(db.statements)
	if _, err := repo.ExecuteSecurityAgentRun(context.Background(), claim, "worker-1", "worker-lease-00000001", audit, correlation); err == nil || len(db.statements) != before {
		t.Fatal("release drift reached execution or fell back to legacy")
	}
}
