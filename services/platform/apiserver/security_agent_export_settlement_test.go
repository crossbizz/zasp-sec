package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type exportSettlementDatabase struct {
	response  json.RawMessage
	statement string
	args      []any
	err       error
}

func TestSecurityAgentExportSettlementRejectsMalformedReceipts(t *testing.T) {
	var claim SecurityAgentExportSettlementClaim
	if err := json.Unmarshal([]byte(exportSettlementClaimJSON), &claim); err != nil {
		t.Fatal(err)
	}
	valid := fmt.Sprintf(`{"run_id":%q,"step_id":%q,"export_id":%q,"run_version":4,"state":"needs_human","reason":"export_available","settled":true,"replayed":false}`, claim.RunID, claim.StepID, claim.ExportID)
	for _, raw := range []string{
		strings.Replace(valid, `"settled":true`, `"settled":null`, 1),
		strings.Replace(valid, `"replayed":false`, `"replayed":null`, 1),
		strings.Replace(valid, `"run_version":4`, `"run_version":3`, 1),
		strings.Replace(valid, `"state":"needs_human"`, `"state":"remediated"`, 1),
		strings.Replace(valid, `"reason":"export_available"`, `"reason":"export_pending"`, 1),
		strings.Replace(valid, claim.ExportID, claim.StepID, 1),
		strings.Replace(valid, `"settled":true`, `"settled":false,"settled":true`, 1),
	} {
		d := &exportSettlementDatabase{response: json.RawMessage(raw)}
		r := &SecurityAgentWorkerRepository{database: d}
		if _, err := r.SettleSecurityAgentExport(context.Background(), claim, "worker-1", "lease-token-00000001", claim.StepID, claim.ExportID); err == nil {
			t.Fatalf("malformed receipt accepted: %s", raw)
		}
	}
	for _, raw := range []string{"null", "{}", "[" + exportSettlementClaimJSON + "," + exportSettlementClaimJSON + "]", "[" + strings.Replace(exportSettlementClaimJSON, `"run_version":3`, `"run_version":0`, 1) + "]", "[" + strings.Replace(exportSettlementClaimJSON, `"run_version":3`, `"run_version":2,"run_version":3`, 1) + "]"} {
		d := &exportSettlementDatabase{response: json.RawMessage(raw)}
		r := &SecurityAgentWorkerRepository{database: d}
		if _, err := r.ClaimSecurityAgentExportSettlements(context.Background(), "worker-1", "lease-token-00000001", 60, 2); err == nil {
			t.Fatalf("malformed claims accepted: %s", raw)
		}
	}
}

func (*exportSettlementDatabase) Exec(context.Context, string, ...any) error {
	return ErrRepositoryUnavailable
}
func (*exportSettlementDatabase) SchemaVersion(context.Context) (string, error) {
	return "", ErrRepositoryUnavailable
}

func (d *exportSettlementDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	d.statement = statement
	d.args = args
	return d.response, d.err
}

func TestSecurityAgentExportSettlementResultStates(t *testing.T) {
	var c SecurityAgentExportSettlementClaim
	if err := json.Unmarshal([]byte(exportSettlementClaimJSON), &c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		state, reason           string
		version                 int
		settled, replayed, want bool
	}{
		{"verifying", "export_pending", 3, false, false, true},
		{"needs_human", "export_available", 4, true, false, true},
		{"needs_human", "export_failed", 4, true, true, true},
		{"cancelled", "export_cancelled", 3, true, true, true},
		{"needs_human", "export_parent_stopped", 3, true, false, true},
		{"failed", "export_parent_stopped", 4, true, false, true},
		{"remediated", "export_parent_stopped", 3, true, false, true},
		{"running", "export_parent_stopped", 3, true, false, false},
		{"remediated", "export_available", 4, true, false, false},
		{"verifying", "export_pending", 3, false, true, false},
		{"cancelled", "export_cancelled", 2, true, false, false},
		{"needs_human", "export_failed", 3, true, false, false},
	} {
		t.Run(tc.state+"/"+tc.reason+fmt.Sprint(tc.version, tc.replayed), func(t *testing.T) {
			raw := fmt.Sprintf(`{"run_id":%q,"step_id":%q,"export_id":%q,"run_version":%d,"state":%q,"reason":%q,"settled":%t,"replayed":%t}`, c.RunID, c.StepID, c.ExportID, tc.version, tc.state, tc.reason, tc.settled, tc.replayed)
			d := &exportSettlementDatabase{response: json.RawMessage(raw)}
			r := &SecurityAgentWorkerRepository{database: d}
			got, err := r.SettleSecurityAgentExport(context.Background(), c, "worker-1", "lease-token-00000001", c.StepID, c.ExportID)
			if (err == nil) != tc.want || tc.want && (got.State != tc.state || got.Reason != tc.reason || got.Settled != tc.settled || got.Replayed != tc.replayed) {
				t.Fatalf("result=%+v error=%v", got, err)
			}
		})
	}
}

func TestSecurityAgentExportSettlementInputsAndProviderErrors(t *testing.T) {
	var c SecurityAgentExportSettlementClaim
	if err := json.Unmarshal([]byte(exportSettlementClaimJSON), &c); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"worker", "token", "duration", "limit", "cancelled", "scope", "audit"} {
		t.Run(mode, func(t *testing.T) {
			d := &exportSettlementDatabase{response: json.RawMessage(`[]`)}
			r := &SecurityAgentWorkerRepository{database: d}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			worker, token := "worker-1", "lease-token-00000001"
			seconds, limit := 60, 2
			claim := c
			audit := c.StepID
			switch mode {
			case "worker":
				worker = ""
			case "token":
				token = "short"
			case "duration":
				seconds = 301
			case "limit":
				limit = 26
			case "cancelled":
				cancel()
			case "scope":
				claim.EnvironmentID = "wrong"
			case "audit":
				audit = "wrong"
			}
			var err error
			if mode == "scope" || mode == "audit" {
				_, err = r.SettleSecurityAgentExport(ctx, claim, worker, token, audit, c.ExportID)
			} else {
				_, err = r.ClaimSecurityAgentExportSettlements(ctx, worker, token, seconds, limit)
			}
			if err == nil || d.statement != "" {
				t.Fatalf("invalid input reached database: %s %v", d.statement, err)
			}
		})
	}
	d := &exportSettlementDatabase{err: ErrRepositoryConflict}
	r := &SecurityAgentWorkerRepository{database: d}
	if _, err := r.SettleSecurityAgentExport(context.Background(), c, "worker-1", "lease-token-00000001", c.StepID, c.ExportID); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("lease conflict lost: %v", err)
	}
	d.err = errors.New("database offline")
	if _, err := r.ClaimSecurityAgentExportSettlements(context.Background(), "worker-1", "lease-token-00000001", 60, 2); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("outage classification lost: %v", err)
	}
	d.err = nil
	d.response = json.RawMessage(`[]`)
	if got, err := r.ClaimSecurityAgentExportSettlements(context.Background(), "worker-1", "lease-token-00000001", 60, 2); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty queue rejected: %+v %v", got, err)
	}
}

const exportSettlementClaimJSON = `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_78000005-0000-4000-8000-000000000005","export_id":"pid_78000008-0000-4000-8000-000000000008","run_version":3,"lease_expires_at":"2026-09-19T01:02:03Z"}`

func TestSecurityAgentExportSettlementClient(t *testing.T) {
	d := &exportSettlementDatabase{response: json.RawMessage("[" + exportSettlementClaimJSON + "]")}
	r := &SecurityAgentWorkerRepository{database: d}
	claims, err := r.ClaimSecurityAgentExportSettlements(context.Background(), "worker-1", "lease-token-00000001", 60, 2)
	if err != nil || len(claims) != 1 {
		t.Fatalf("valid claim refused: %+v %v", claims, err)
	}
	if d.statement != `SELECT public.zasp_sa_export_settlement_claim($1,$2,$3,$4,$5,$6)` || len(d.args) != 6 || d.args[0] != "worker-1" || d.args[1] != "lease-token-00000001" || d.args[2] != 60 || d.args[3] != 2 || d.args[4] != migrations.ProductionSecurityAgentExports().Checksum() || d.args[5] != migrations.SecurityAgentExportsFingerprint() {
		t.Fatalf("wrong claim boundary: %s %+v", d.statement, d.args)
	}
	c := claims[0]
	d.response = json.RawMessage(fmt.Sprintf(`{"run_id":%q,"step_id":%q,"export_id":%q,"run_version":4,"state":"needs_human","reason":"export_available","settled":true,"replayed":true}`, c.RunID, c.StepID, c.ExportID))
	got, err := r.SettleSecurityAgentExport(context.Background(), c, "worker-1", "lease-token-00000001", c.StepID, c.ExportID)
	if err != nil || !got.Settled || !got.Replayed || got.Reason != "export_available" || got.RunVersion != 4 {
		t.Fatalf("valid replay refused: %+v %v", got, err)
	}
	want := []any{c.OrganizationID, c.WorkspaceID, c.EnvironmentID, c.RunID, "worker-1", "lease-token-00000001", c.StepID, c.ExportID, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}
	if d.statement != `SELECT public.zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)` || len(d.args) != len(want) {
		t.Fatalf("wrong settle boundary: %s %+v", d.statement, d.args)
	}
	for i, v := range want {
		if d.args[i] != v {
			t.Fatalf("argument %d: %v != %v", i, d.args[i], v)
		}
	}
}

func TestSecurityAgentExportSettlementPostgresUTCTimestamp(t *testing.T) {
	d := &exportSettlementDatabase{response: json.RawMessage("[" + strings.Replace(exportSettlementClaimJSON, "01:02:03Z", "01:02:03+00:00", 1) + "]")}
	r := &SecurityAgentWorkerRepository{database: d}
	if claims, err := r.ClaimSecurityAgentExportSettlements(context.Background(), "worker-1", "lease-token-00000001", 60, 2); err != nil || len(claims) != 1 {
		t.Fatalf("PostgreSQL UTC timestamp rejected: %+v %v", claims, err)
	}
}
