package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestApprovalSettlementAuditProfileBoundaries(t *testing.T) {
	source, pin, err := approvalSettlementAuditSource()
	if err != nil {
		t.Fatal(err)
	}
	activationPin, err := ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(strings.ReplaceAll(approvalSettlementAuditSQL, "-- activation checksum", activationPin)))
	if pin != hex.EncodeToString(h[:]) || strings.Contains(source, "-- settlement checksum") || strings.Contains(source, "-- activation checksum") {
		t.Fatal("whole supplementary dependency source not bound")
	}
	for _, want := range []string{"FORCE ROW LEVEL SECURITY", "zasp_approval_settlement_v1.catalog_ready(pin text)", "zasp_approval_activation_v1.catalog_ready('", "zasp_approval_maintenance.settle(q,envelope_value,successful)", "ON CONFLICT DO NOTHING", "approval_notification_delivered", "approval_notification_retryable", "approval_notification_exhausted", "approval_delivery_audit", "receipt_digest"} {
		if !strings.Contains(source, want) {
			t.Errorf("missing safety boundary %q", want)
		}
	}
	for _, bad := range []string{"CREATE OR REPLACE", "REFERENCES zasp_", "UPDATE zasp_approval_maintenance.registration", "INSERT INTO zasp_approval_maintenance", "zasp_authorization79.touch(", "'secret_reference'", "'destination_url'", "'lease_token'", "'payload'", "'receipt'", "TO PUBLIC", "TO zasp_temporal_executor"} {
		if strings.Contains(source, bad) {
			t.Errorf("unexpected capability/evidence %q", bad)
		}
	}
	var prior = -1
	for _, marker := range []string{"PERFORM pg_advisory_xact_lock(", "PERFORM 1 FROM zasp_authorization79.organizations", "r:=zasp_approval_maintenance.reserved(q)", "result_value:=zasp_approval_maintenance.settle(q,envelope_value,successful)", "INSERT INTO public.zasp_security_agent_audit", "IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit"} {
		at := strings.Index(source, marker)
		if at <= prior {
			t.Fatalf("lock/settlement/audit ordering missing %q", marker)
		}
		prior = at
	}
}
func TestApprovalSettlementAuditInstallerTransactions(t *testing.T) {
	var absent *Runner
	if absent.UpProductionApprovalSettlementAuditProfile(context.Background()) != ErrInvalidRunner {
		t.Fatal("nil runner accepted")
	}
	for _, present := range []bool{false, true} {
		name := "fresh"
		if present {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			tx := &fakeTransaction{rows: maintenanceRoleAdmissionRows([]Row{fakeRow{values: []any{true}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}})}
			db := &fakeDatabase{transaction: tx}
			runner, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			if err := runner.UpProductionApprovalSettlementAuditProfile(context.Background()); err != nil {
				t.Fatal(err)
			}
			events := strings.Join(db.events, "\n")
			if !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
				t.Fatal("valid installation not committed")
			}
			if strings.Contains(events, "CREATE TABLE zasp_approval_settlement_v1.registration") == present {
				t.Fatal("existing source replayed or fresh source absent")
			}
		})
	}
	for _, at := range []int{1, 3, 4, 5} {
		t.Run("refused-catalog-"+string(rune('0'+at)), func(t *testing.T) {
			rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
			rows[at-1] = fakeRow{values: []any{false}}
			tx := &fakeTransaction{rows: maintenanceRoleAdmissionRows(rows)}
			db := &fakeDatabase{transaction: tx}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.UpProductionApprovalSettlementAuditProfile(context.Background()); err != ErrInvalidState {
				t.Fatal("different catalog accepted", err)
			}
			events := strings.Join(db.events, "\n")
			if strings.Contains(events, "commit") || !strings.Contains(events, "rollback") || strings.Contains(events, "CREATE TABLE") {
				t.Fatal("refused existing catalog changed")
			}
		})
	}
}
