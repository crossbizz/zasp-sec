package migrations

import (
	"context"
	"strings"
	"testing"
)

// These are source-seal and Runner transaction checks. They do not constitute
// PostgreSQL permission, concurrency or deployed provider acceptance.
func TestOptionalEgressProfileSealsAndAdmissionBoundaries(t *testing.T) {
	source, pin := optionalEgressProfileSource()
	if len(pin) != 64 || pin != OptionalEgressProfileChecksum() || strings.Contains(source, "-- optional ") || strings.Contains(source, "-- authorization79 checksum") || strings.Contains(source, "-- authorization80 checksum") {
		t.Fatal("unbound supplementary source")
	}
	auditSource, auditPin := optionalEgressAuditProfileSource()
	_, normalWorker := authorizationWorkerProfileSource()
	_, auditWorker := authorizationWorkerAuditProfileSource()
	if auditPin == pin || !IsOptionalEgressProfileChecksum(pin) || !IsOptionalEgressProfileChecksum(auditPin) || IsOptionalEgressProfileChecksum(strings.Repeat("0", 64)) || strings.Contains(auditSource, "-- optional ") || !strings.Contains(source, "checksum='"+normalWorker+"'") || !strings.Contains(auditSource, "checksum='"+auditWorker+"'") {
		t.Fatal("compiled parent selection crossed")
	}
	// Parent selection is exactly one literal source replacement. The existing
	// standalone recipe remains byte-identical; neither SQL accepts both parents.
	if strings.ReplaceAll(strings.ReplaceAll(source, normalWorker, auditWorker), pin, auditPin) != auditSource {
		t.Fatal("audit recipe changed more than its exact compiled parent and checksum")
	}
	for _, required := range []string{
		"FORCE ROW LEVEL SECURITY", "zasp_authorization80.identity_fence(p)", "zasp_authorization79.revalidate(o,", "zasp_authorization80.require_read(o,w,e,operations,permission_value,true,q->>'actor_id')",
		"zasp_optional_egress_v1.principal('captured-settlement')", "r.binding IS DISTINCT FROM b", "r.nonce_digest IS DISTINCT FROM encode(digest(q->>'nonce','sha256'),'hex')", "'expired_no_send'", "'deadline'", "state='reserved' RETURNING * INTO STRICT r", "'newly_started',false", "'newly_started',true", "zasp_authorization80_worker.require_planning78('start',q)",
		"expected_cost:=ceil(", "maximum_outstanding_nano_credits", "maximum_concurrency", "'secret_ref_ai/'",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing admission/seal boundary %q", required)
		}
	}
	for _, forbidden := range []string{"CREATE OR REPLACE", "ALTER FUNCTION zasp_authorization", "GRANT EXECUTE ON ALL", "TO PUBLIC", "request_body text", "raw_result text", "response_body", "prompt text", "RESET ROLE", "SET row_security"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("unsafe supplementary source %q", forbidden)
		}
	}
	// Dispatch must retain the organization -> policy -> request lock order. A
	// duplicate STARTED response must be returned before any new nonce is minted.
	a := strings.Index(source, "CREATE FUNCTION zasp_optional_egress_v1.dispatch(q")
	b := strings.Index(source[a:], "CREATE FUNCTION zasp_optional_egress_v1.settle(q") + a
	dispatch := source[a:b]
	positions := []int{strings.Index(dispatch, "require_human("), strings.Index(dispatch, "FROM zasp_optional_egress_v1.policies"), strings.Index(dispatch, "FROM zasp_optional_egress_v1.requests"), strings.Index(dispatch, "IF r.state<>'reserved'"), strings.Index(dispatch, "gen_random_bytes(32)")}
	for i, p := range positions {
		if p < 0 || i > 0 && p <= positions[i-1] {
			t.Fatal("dispatch authority/claim ordering changed")
		}
	}
	// Captured settlement records an already admitted effect, even after permission
	// revocation. It cannot recheck forward FGA or read a provider response body.
	c := strings.Index(source, "CREATE FUNCTION zasp_optional_egress_v1.settle(q")
	d := strings.Index(source[c:], "CREATE FUNCTION zasp_optional_egress_v1.read(q") + c
	settlement := source[c:d]
	if strings.Contains(settlement, "require_human") || strings.Contains(settlement, "current_profile(") || strings.Contains(settlement, "finding_summary(") {
		t.Fatal("settlement depends on current forward authority")
	}
}

func TestOptionalEgressInstallerTransactions(t *testing.T) {
	var missing *Runner
	if missing.UpProductionOptionalEgressProfile(context.Background()) != ErrInvalidRunner || missing.UpProductionOptionalEgressAuditProfile(context.Background()) != ErrInvalidRunner {
		t.Fatal("nil runner accepted")
	}
	for _, present := range []bool{false, true} {
		rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
		tx := &fakeTransaction{rows: rows}
		db := &fakeDatabase{transaction: tx}
		r, err := NewRunner(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.UpProductionOptionalEgressProfile(context.Background()); err != nil {
			t.Fatal(err)
		}
		events := strings.Join(db.events, "\n")
		if !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
			t.Fatal("profile transaction did not commit")
		}
		if strings.Contains(events, "CREATE TABLE zasp_optional_egress_v1.registration") == present {
			t.Fatal("fresh/existing catalog installation crossed")
		}
		if strings.Contains(events, "exec:UPDATE") || strings.Contains(events, "exec:INSERT INTO zasp_optional_egress_v1.approved_profiles") {
			t.Fatal("installation enables or approves optional egress")
		}
	}
	for _, failure := range []int{0, 2, 3, 4} {
		rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
		rows[failure] = fakeRow{values: []any{false}}
		tx := &fakeTransaction{rows: rows}
		db := &fakeDatabase{transaction: tx}
		r, err := NewRunner(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.UpProductionOptionalEgressProfile(context.Background()); err != ErrInvalidState {
			t.Fatalf("catalog failure %d: %v", failure, err)
		}
		events := strings.Join(db.events, "\n")
		if strings.Contains(events, "commit") || !strings.Contains(events, "rollback") || strings.Contains(events, "CREATE TABLE") {
			t.Fatal("refused existing profile mutated or committed")
		}
	}
	for _, present := range []bool{false, true} {
		rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
		tx := &fakeTransaction{rows: rows}
		db := &fakeDatabase{transaction: tx}
		r, err := NewRunner(db)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.UpProductionOptionalEgressAuditProfile(context.Background()); err != nil {
			t.Fatal(err)
		}
		events := strings.Join(db.events, "\n")
		if !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
			t.Fatal("audit recipe did not commit")
		}
		if !present {
			_, workerPin := authorizationWorkerAuditProfileSource()
			if !strings.Contains(events, "checksum='"+workerPin+"'") {
				t.Fatal("audit installer emitted wrong compiled worker parent")
			}
		}
	}

}
