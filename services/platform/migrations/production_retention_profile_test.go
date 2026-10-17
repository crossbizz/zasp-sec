package migrations

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// These tests cover compiled recipe identity and installer transaction behavior.
// PostgreSQL DDL, permissions and mixed replay parity need the native fixture.
func TestRetentionCompiledRecipeAndInstaller(t *testing.T) {
	t.Run("one_audit_recipe_concurrent_identity", func(t *testing.T) {
		var joined sync.WaitGroup
		pins := make(chan string, 16)
		for i := 0; i < 16; i++ {
			joined.Add(1)
			go func() { defer joined.Done(); pins <- RetentionAuditProfileChecksum() }()
		}
		joined.Wait()
		close(pins)
		pin := ProductionRetentionProfile().Checksum()
		for got := range pins {
			if got != pin || !IsRetentionProfileChecksum(got) {
				t.Fatal("compiled recipe identity changed")
			}
		}
		if len(pin) != 64 || IsRetentionProfileChecksum(strings.Repeat("0", 64)) || ProductionRetentionProfile().Name() != RetentionProfileName {
			t.Fatal("invalid recipe selection")
		}
	})
	t.Run("nil_and_cancelled", func(t *testing.T) {
		var r *Runner
		if r.UpProductionRetentionAuditProfile(context.Background()) != ErrInvalidRunner {
			t.Fatal("nil runner accepted")
		}
		tx := &fakeTransaction{}
		db := &fakeDatabase{transaction: tx}
		r, err := NewRunner(db)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if r.UpProductionRetentionAuditProfile(ctx) != ErrInvalidRunner || len(db.events) != 0 {
			t.Fatal("cancelled installer accessed database")
		}
	})
	for _, present := range []bool{false, true} {
		name := "new_prepared"
		if present {
			name = "existing_exact"
		}
		t.Run(name, func(t *testing.T) {
			tx := &fakeTransaction{rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}}}
			db := &fakeDatabase{transaction: tx}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.UpProductionRetentionAuditProfile(context.Background()); err != nil {
				t.Fatal(err)
			}
			events := strings.Join(db.events, "\n")
			if !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
				t.Fatal("prepared transaction did not commit")
			}
			ownerBridge := strings.Index(events, "CREATE FUNCTION zasp_retention_v1.policy_lock")
			setRole := strings.LastIndex(events, "exec:SET LOCAL ROLE zasp_discovery_authority")
			originalRole := strings.Index(events, "exec:SET LOCAL ROLE NONE")
			authorityDDL := strings.Index(events, "CREATE TABLE zasp_retention_v1.preimages")
			if !present && (originalRole < 0 || ownerBridge <= originalRole || setRole <= ownerBridge || authorityDDL <= setRole) {
				t.Fatal("source owner boundary crossed")
			}
			if present && (ownerBridge >= 0 || authorityDDL >= 0) {
				t.Fatal("existing catalog rewritten")
			}
			// PREPARED installs no source trigger and records no external cutover proof.
			if strings.Contains(events, "exec:SELECT zasp_retention_v1.activate") || strings.Contains(events, "exec:INSERT INTO zasp_retention_v1.cutover_receipts") {
				t.Fatal("installer activated unproven cutover")
			}
		})
	}
	for _, failure := range []int{0, 2} {
		t.Run("refuse_drift_"+string(rune('0'+failure)), func(t *testing.T) {
			rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
			rows[failure] = fakeRow{values: []any{false}}
			tx := &fakeTransaction{rows: rows}
			db := &fakeDatabase{transaction: tx}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			if r.UpProductionRetentionAuditProfile(context.Background()) != ErrInvalidState {
				t.Fatal("invalid existing authority accepted")
			}
			events := strings.Join(db.events, "\n")
			if strings.Contains(events, "commit") || !strings.Contains(events, "rollback") || strings.Contains(events, "CREATE TABLE") {
				t.Fatal("drift refusal mutated catalog")
			}
		})
	}
}
