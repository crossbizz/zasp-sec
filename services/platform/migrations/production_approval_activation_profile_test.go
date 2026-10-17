package migrations

import (
	"context"
	"strings"
	"testing"
)

func TestApprovalActivationProfileBoundaries(t *testing.T) {
	source, pin, err := approvalActivationSource()
	if err != nil || len(pin) != 64 || strings.Contains(source, "-- activation checksum") {
		t.Fatal("source not wholly bound", err)
	}
	for _, required := range []string{"FORCE ROW LEVEL SECURITY", "zasp_approval_activation_v1.activate_controlled_organization", "zasp_approval_activation_v1.admit_with_origin", "zasp_authorization79.touch(o)", "eligible>20", "xmin::text::bigint=txid_current()%4294967296", "connector_origins", "approval_origins"} {
		if !strings.Contains(source, required) {
			t.Errorf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"REFERENCES zasp_", "CREATE OR REPLACE", "enqueue_delegation(", "GRANT EXECUTE ON ALL", "TO PUBLIC", "TO zasp_approval_maintenance_worker"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("unsafe %s", forbidden)
		}
	}
	a := strings.Index(source, "PERFORM pg_advisory_xact_lock(hashtextextended('zasp-auth79/'||o,0));")
	b := strings.Index(source, "zasp_connector_maintenance.activate_controlled_organization(o,")
	if a < 0 || b < a {
		t.Fatal("organization lock must precede activation")
	}
}
func TestApprovalActivationInstallerRejectsInvalidRunner(t *testing.T) {
	var r *Runner
	if r.UpProductionApprovalActivationProfile(context.Background()) != ErrInvalidRunner {
		t.Fatal("nil runner")
	}
	if _, err := ApprovalActivationProfileChecksum(); err != nil {
		t.Fatal(err)
	}
}

// The real Runner controls transaction ordering; fake metadata only selects
// existing/missing/refused catalogs. These checks are not PostgreSQL proof.
func TestApprovalActivationInstallerTransactions(t *testing.T) {
	for _, present := range []bool{false, true} {
		name := "fresh"
		if present {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
			tx := &fakeTransaction{rows: maintenanceRoleAdmissionRows(rows)}
			db := &fakeDatabase{transaction: tx}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.UpProductionApprovalActivationProfile(context.Background()); err != nil {
				t.Fatal(err)
			}
			events := strings.Join(db.events, "\n")
			if !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
				t.Fatal("installation did not commit cleanly")
			}
			ddl := strings.Contains(events, "CREATE TABLE zasp_approval_activation_v1.registration")
			if ddl == present {
				t.Fatal("existing catalog replay or fresh definitions missing")
			}
			if strings.Contains(events, "exec:UPDATE zasp_approval_maintenance.registration SET active=true") {
				t.Fatal("installer activated workers")
			}
		})
	}
	for _, failAt := range []int{1, 3, 4, 5} {
		t.Run("catalog-refusal-"+string(rune('0'+failAt)), func(t *testing.T) {
			rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
			rows[failAt-1] = fakeRow{values: []any{false}}
			tx := &fakeTransaction{rows: maintenanceRoleAdmissionRows(rows)}
			db := &fakeDatabase{transaction: tx}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.UpProductionApprovalActivationProfile(context.Background()); err != ErrInvalidState {
				t.Fatalf("refusal=%v", err)
			}
			events := strings.Join(db.events, "\n")
			if strings.Contains(events, "commit") || !strings.Contains(events, "rollback") {
				t.Fatal("refused profile not rolled back")
			}
			if strings.Contains(events, "CREATE TABLE") || strings.Contains(events, "INSERT INTO zasp_approval_activation_v1.registration") {
				t.Fatal("existing refused catalog mutated")
			}
		})
	}
}
