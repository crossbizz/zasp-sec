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
)

// Owner-seeded plan prerequisites do not prove public planner admission. The
// dispatch, worker registration and separate worker processes are real paths;
// their AWS SDK transport is controlled and never contacts a provider.
func TestSecurityAgentExportWorkerProcessPostgres(t *testing.T) {
	if _, err := os.Stat("/compliance-worker.test"); err != nil {
		t.Fatal("owned registered worker binary is required")
	}
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.owner.Exec(f.ctx, `CREATE ROLE compliance_executor LOGIN INHERIT; CREATE ROLE compliance_cleanup LOGIN INHERIT;`); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, f.owner).RegisterComplianceWorkers(f.ctx, "compliance_executor", "compliance_cleanup"); err != nil {
			t.Fatalf("release58 worker registration: %v", err)
		}
		admitted, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
		if err != nil {
			t.Fatalf("registered agent dispatch: %v", err)
		}
		var receipt struct {
			ExportID string `json:"export_id"`
			RunID    string `json:"run_id"`
			StepID   string `json:"step_id"`
		}
		if json.Unmarshal(admitted, &receipt) != nil || !validProductID(receipt.ExportID) || receipt.RunID != exportFixtureRun || receipt.StepID != exportFixtureStep {
			t.Fatalf("invalid admitted identity: %s", admitted)
		}
		dir, err := os.MkdirTemp("/tmp", "agent-export-worker-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		object := filepath.Join(dir, "object.json")
		child := func(phase string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(f.ctx, 16*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/compliance-worker.test", "-test.run=^TestComplianceRuntimeProcess$", "-test.v", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "ZASP_COMPLIANCE_RUNTIME_DSN="+f.owner.Config().ConnString(), "ZASP_COMPLIANCE_RUNTIME_PHASE="+phase, "ZASP_COMPLIANCE_RUNTIME_OBJECT="+object)
			output, err := cmd.CombinedOutput()
			t.Logf("joined agent export %s process: %s", phase, output)
			if err != nil {
				t.Fatalf("worker process %s: %v", phase, err)
			}
			if !strings.Contains(string(output), "--- PASS: TestComplianceRuntimeProcess") || strings.Contains(string(output), "--- SKIP:") {
				t.Fatalf("worker did not exercise runtime: %s", output)
			}
		}
		child("interrupt")
		var before, after []byte
		var state, storage, revision string
		var retained int64
		if err := f.owner.QueryRow(f.ctx, `SELECT package,state,storage_state,retained_bytes,renderer_revision FROM zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, receipt.ExportID).Scan(&before, &state, &storage, &retained, &revision); err != nil || state != "pending" || storage != "unknown" || retained < 1 || revision != "security-agent-evidence-envelope-v1" {
			t.Fatalf("uncertain write lost intent: state=%s storage=%s retained=%d revision=%s error=%v", state, storage, retained, revision, err)
		}
		var envelope struct {
			Version int    `json:"version"`
			ID      string `json:"id"`
			JSON    struct {
				RunID   string `json:"run_id"`
				StepID  string `json:"step_id"`
				Records []struct {
					Kind    string `json:"source_kind"`
					ID      string `json:"source_id"`
					Version int64  `json:"source_version"`
				} `json:"records"`
			} `json:"json"`
			CSV   string `json:"csv"`
			Human string `json:"human"`
		}
		if json.Unmarshal(before, &envelope) != nil || envelope.Version != 1 || envelope.ID != receipt.ExportID || envelope.JSON.RunID != exportFixtureRun || envelope.JSON.StepID != exportFixtureStep || len(envelope.JSON.Records) != 1 || envelope.JSON.Records[0].Kind != "finding" || envelope.JSON.Records[0].ID != exportFixtureFinding || envelope.JSON.Records[0].Version != 1 || envelope.CSV == "" || envelope.Human == "" {
			t.Fatal("registered capture/render lost selected source or formats")
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,export_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, receipt.ExportID); err != nil {
			t.Fatal(err)
		}
		child("resume")
		if err := f.owner.QueryRow(f.ctx, `SELECT package,state,storage_state FROM zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, receipt.ExportID).Scan(&after, &state, &storage); err != nil || state != "completed" || storage != "verified" || !bytes.Equal(before, after) {
			t.Fatalf("restart changed frozen package: state=%s storage=%s error=%v", state, storage, err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.worker})
		if err != nil {
			t.Fatal(err)
		}
		repository := &SecurityAgentWorkerRepository{database: db}
		const settlementLease = "export-process-settlement-lease"
		claims, err := repository.ClaimSecurityAgentExportSettlements(f.ctx, exportFixtureWorker, settlementLease, 60, 2)
		if err != nil || len(claims) != 1 || claims[0].RunID != exportFixtureRun || claims[0].StepID != exportFixtureStep || claims[0].ExportID != receipt.ExportID {
			t.Fatalf("registered Go settlement claim: %+v %v", claims, err)
		}
		const settlementAudit = "pid_8e100006-0000-4000-8000-000000000006"
		const settlementCorrelation = "pid_8e100007-0000-4000-8000-000000000007"
		settled, err := repository.SettleSecurityAgentExport(f.ctx, claims[0], exportFixtureWorker, settlementLease, settlementAudit, settlementCorrelation)
		if err != nil || !settled.Settled || settled.Replayed || settled.State != "needs_human" || settled.Reason != "export_available" {
			t.Fatalf("registered Go settlement: %+v %v", settled, err)
		}
		replayed, err := repository.SettleSecurityAgentExport(f.ctx, claims[0], exportFixtureWorker, settlementLease, settlementAudit, settlementCorrelation)
		if err != nil || !replayed.Replayed {
			t.Fatalf("registered Go replay: %+v %v", replayed, err)
		}
		replayed.Replayed = false
		if replayed != settled {
			t.Fatal("settlement replay changed receipt")
		}
		var parentState, reason string
		if err := f.owner.QueryRow(f.ctx, `SELECT state,last_error_code FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, exportFixtureRun).Scan(&parentState, &reason); err != nil || parentState != "needs_human" || reason != "export_available" {
			t.Fatalf("export mislabeled parent outcome: %s %s %v", parentState, reason, err)
		}
		t.Log("LOCAL component: registered agent dispatch, actual worker process SIGTERM, immutable prepared replay in second process; controlled AWS SDK transport, not live provider or public planner proof")
	})
}
