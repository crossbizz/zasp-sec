package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func exportDispatchFixture(t *testing.T) (SecurityAgentRunClaim, string) {
	t.Helper()
	claim := budgetRepositoryClaim()
	claim.Prepared = true
	raw, err := json.Marshal(map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID,
		"step_id": "pid_78000005-0000-4000-8000-000000000005", "export_id": "pid_78000006-0000-4000-8000-000000000006", "run_version": claim.Version + 1, "state": "pending", "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	return claim, string(raw)
}

func TestSecurityAgentExportDispatchReceipt(t *testing.T) {
	claim, raw := exportDispatchFixture(t)
	const worker, lease = "worker-1", "export-dispatch-lease-0001"
	const audit, correlation = "pid_78000007-0000-4000-8000-000000000007", "pid_78000008-0000-4000-8000-000000000008"
	for _, replayed := range []bool{false, true} {
		body := raw
		if replayed {
			body = strings.Replace(body, `"replayed":false`, `"replayed":true`, 1)
		}
		db := &exportSettlementDatabase{response: json.RawMessage(body)}
		repo := &SecurityAgentWorkerRepository{database: db}
		got, err := repo.ExecuteSecurityAgentExport(context.Background(), claim, worker, lease, audit, correlation)
		if err != nil || got.RunID != claim.RunID || got.State != "pending" || got.RunVersion != claim.Version+1 || got.Replayed != replayed || got.ExportID != "pid_78000006-0000-4000-8000-000000000006" {
			t.Fatalf("dispatch receipt lost: %+v %v", got, err)
		}
		want := []any{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, worker, lease, audit, correlation, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}
		if db.statement != `SELECT public.zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)` || !reflect.DeepEqual(db.args, want) {
			t.Fatal("dispatch lost scoped lease, audit or release binding")
		}
	}
}

func TestSecurityAgentExportDispatchRejectsUnboundReceipt(t *testing.T) {
	claim, raw := exportDispatchFixture(t)
	for _, bad := range []string{
		strings.Replace(raw, claim.OrganizationID, claim.RunID, 1),
		strings.Replace(raw, claim.WorkspaceID, claim.RunID, 1),
		strings.Replace(raw, claim.EnvironmentID, claim.RunID, 1),
		strings.Replace(raw, `"run_id":"`+claim.RunID+`"`, `"run_id":"`+claim.DefinitionID+`"`, 1),
		strings.Replace(raw, `"state":"pending"`, `"state":"remediated"`, 1),
		strings.Replace(raw, `"replayed":false`, `"replayed":null`, 1),
		strings.Replace(raw, `"replayed":false`, `"replayed":false,"replayed":true`, 1),
		strings.Replace(raw, `"run_version":3`, `"run_version":2`, 1),
		strings.Replace(raw, `"run_version":3`, `"run_version":1000001`, 1),
		strings.Replace(raw, `"state":"pending"`, `"state":"pending","key":"private"`, 1),
	} {
		db := &exportSettlementDatabase{response: json.RawMessage(bad)}
		repo := &SecurityAgentWorkerRepository{database: db}
		if _, err := repo.ExecuteSecurityAgentExport(context.Background(), claim, "worker-1", "export-dispatch-lease-0001", claim.RunID, claim.DefinitionID); err == nil {
			t.Fatalf("unsafe dispatch receipt accepted: %s", bad)
		}
	}
}

func TestSecurityAgentExportDispatchInputGuards(t *testing.T) {
	claim, raw := exportDispatchFixture(t)
	for _, field := range []string{"prepared", "scope", "worker", "lease", "audit", "correlation", "cancelled"} {
		t.Run(field, func(t *testing.T) {
			candidate := claim
			worker, lease, audit, correlation := "worker-1", "export-dispatch-lease-0001", claim.RunID, claim.DefinitionID
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch field {
			case "prepared":
				candidate.Prepared = false
			case "scope":
				candidate.EnvironmentID = "foreign"
			case "worker":
				worker = ""
			case "lease":
				lease = "short"
			case "audit":
				audit = "bad"
			case "correlation":
				correlation = "bad"
			case "cancelled":
				cancel()
			}
			db := &exportSettlementDatabase{response: json.RawMessage(raw)}
			repo := &SecurityAgentWorkerRepository{database: db}
			if _, err := repo.ExecuteSecurityAgentExport(ctx, candidate, worker, lease, audit, correlation); err == nil || db.statement != "" {
				t.Fatal("invalid dispatch reached SQL or succeeded")
			}
		})
	}
}

type exportDispatchRoutingDatabase struct {
	existingTestWorkerDatabase
	exportAvailable bool
}

type exportDispatchCommittedDatabase struct {
	exportSettlementDatabase
	cancel context.CancelFunc
}

func (d *exportDispatchCommittedDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	raw, err := d.exportSettlementDatabase.QueryJSON(ctx, statement, args...)
	d.cancel()
	return raw, err
}

func TestSecurityAgentExportDispatchCommittedCancellation(t *testing.T) {
	claim, raw := exportDispatchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := &exportDispatchCommittedDatabase{exportSettlementDatabase: exportSettlementDatabase{response: json.RawMessage(raw)}, cancel: cancel}
	r := &SecurityAgentWorkerRepository{database: db}
	got, err := r.ExecuteSecurityAgentExport(ctx, claim, "worker-1", "export-dispatch-lease-0001", claim.RunID, claim.DefinitionID)
	if ctx.Err() == nil || err != nil || got.State != "pending" {
		t.Fatalf("validated committed receipt lost after lease-clearing cancellation: %+v %v", got, err)
	}
}

func (d *exportDispatchRoutingDatabase) SecurityAgentExportsAvailable(context.Context) (bool, error) {
	return d.exportAvailable, nil
}

func TestSecurityAgentExportDispatchRouting(t *testing.T) {
	claim, receipt := exportDispatchFixture(t)
	const kindSQL = `SELECT public.zasp_sa_export_run_kind($1,$2,$3,$4,$5,$6)`
	const executeSQL = `SELECT public.zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	for _, tc := range []struct {
		name, kind                 string
		available, success, routed bool
	}{
		{"export", `{"export":true}`, true, true, true},
		{"other action", `{"export":false}`, true, false, false},
		{"absent release", `{"export":true}`, false, false, false},
		{"null kind", `{"export":null}`, true, false, false},
		{"unknown field", `{"export":true,"unsafe":true}`, true, false, false},
		{"duplicate kind", `{"export":false,"export":true}`, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &exportDispatchRoutingDatabase{exportAvailable: tc.available}
			db.responses = map[string]json.RawMessage{kindSQL: json.RawMessage(tc.kind), executeSQL: json.RawMessage(receipt)}
			r := &SecurityAgentWorkerRepository{database: db, executeSQL: postgresSecurityAgentExecuteRunV24SQL}
			got, err := r.ExecuteSecurityAgentRun(context.Background(), claim, "worker-1", "export-dispatch-lease-0001", claim.RunID, claim.DefinitionID)
			if (err == nil) != tc.success {
				t.Fatalf("result=%+v error=%v", got, err)
			}
			if tc.success && (got.ExportDispatch == nil || got.RunID != claim.RunID || got.Version != claim.Version+1 || got.State != "verifying" || got.StepID != got.ExportDispatch.StepID || got.OutcomeID != "" || got.ResultDigest != "" || got.EffectState != "") {
				t.Fatal("export was conflated with a security effect")
			}
			routed := false
			for _, statement := range db.statements {
				if statement == executeSQL {
					routed = true
				}
			}
			if routed != tc.routed {
				t.Fatalf("wrong dispatch route: %v", db.statements)
			}
			if tc.available && tc.kind != `{"export":false}` && !tc.success && len(db.statements) != 1 {
				t.Fatal("malformed authority fell back to another executor")
			}
		})
	}
}
