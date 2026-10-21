package migrations

import (
	"context"
	"strings"
	"testing"
)

func TestRetentionJournalCompiledClosureAndInstaller(t *testing.T) {
	source, pin := retentionJournalProfileSource()
	if len(pin) != 64 || !IsRetentionJournalProfileChecksum(pin) || IsRetentionJournalProfileChecksum(strings.Repeat("0", 64)) || !strings.Contains(source, RetentionAuditProfileChecksum()) {
		t.Fatal("journal does not bind exact retention parent")
	}
	for _, name := range []string{"begin_execution", "admit_execution", "reserve_request", "claim_send", "append_terminal", "close_inventory", "seal_partition", "execution_status", "enroll_scope", "raw_ready", "enrollment_guard", "settlement_guard"} {
		if !strings.Contains(source, "zasp_retention_journal_v1."+name+"(") {
			t.Fatalf("missing connected journal operation %s", name)
		}
	}
	for _, hook := range []string{"zasp_retention_journal_v1_enrollment", "zasp_retention_journal_v1_settlement"} {
		if !strings.Contains(source, "CREATE TRIGGER "+hook) {
			t.Fatal("mandatory database hook missing")
		}
	}
	if strings.Contains(source, "set_config(") || strings.Contains(source, "GRANT INSERT ON") || strings.Contains(source, "GRANT UPDATE ON") {
		t.Fatal("journal exposes bypass authority")
	}
	for _, present := range []bool{false, true} {
		tx := &fakeTransaction{rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}}}
		db := &fakeDatabase{transaction: tx}
		r, _ := NewRunner(db)
		if err := r.UpProductionRetentionJournalProfile(context.Background()); err != nil {
			t.Fatal(err)
		}
		events := strings.Join(db.events, "\n")
		if !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
			t.Fatal("journal install not confirmed")
		}
		if present && strings.Contains(events, "CREATE SCHEMA zasp_retention_journal_v1") {
			t.Fatal("existing independent recipe rewritten")
		}
	}
	tx := &fakeTransaction{rows: []Row{fakeRow{values: []any{false}}}}
	db := &fakeDatabase{transaction: tx}
	r, _ := NewRunner(db)
	if r.UpProductionRetentionJournalProfile(context.Background()) != ErrInvalidState || !strings.Contains(strings.Join(db.events, "\n"), "rollback") {
		t.Fatal("invalid parent did not refuse atomically")
	}
}

func TestRetentionJournalRawSealHasNoReadinessRecursion(t *testing.T) {
	source, _ := retentionJournalProfileSource()
	start := strings.Index(source, "CREATE FUNCTION zasp_retention_journal_v1.raw_ready(")
	if start < 0 {
		t.Fatal("raw seal missing")
	}
	end := strings.Index(source[start:], "$raw_ready$;")
	if start < 0 || end < 0 {
		t.Fatal("raw seal missing")
	}
	raw := source[start : start+end]
	for _, s := range []string{"zasp_retention_v1.fingerprint(", "zasp_retention_v1.effective_catalog_ready(", "zasp_retention_v1.independent_seal(", "zasp_retention_v1.caller_ready(", "zasp_retention_v1.writer_history(", "zasp_retention_v1.writers_drained("} {
		if strings.Contains(raw, s) {
			t.Fatal("raw catalog seal is recursive")
		}
	}
	if !strings.Contains(source, "pg_current_xact_id()") || !strings.Contains(source, "pg_backend_pid()") || !strings.Contains(source, "capability_hash") {
		t.Fatal("private transaction or execution authority absent")
	}
}
