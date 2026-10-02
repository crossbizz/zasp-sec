package migrations

import (
	"context"
	"errors"
	"testing"
)

// The real installer must reject missing ancestry or changed existing profile
// before issuing DDL; reblessing either state would make these cases fail.
func TestAuthorizationInventoryInstallerRefusesUnreadyAncestryAndExistingDrift(t *testing.T) {
	for _, mode := range []string{"ancestry", "existing_drift"} {
		t.Run(mode, func(t *testing.T) {
			db := &fakeDatabase{}
			tx := &fakeTransaction{events: &db.events}
			db.transaction = tx
			tx.rows = []Row{fakeRow{values: []any{false}}}
			if mode == "existing_drift" {
				tx.rows = []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{false}}}
			}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			installer, ok := any(r).(interface{ UpProductionAuthorizationInventoryProfile(context.Context) error })
			if !ok {
				t.Fatal("registered inventory installer is missing")
			}
			err = installer.UpProductionAuthorizationInventoryProfile(context.Background())
			if !errors.Is(err, ErrInvalidState) {
				t.Fatalf("invalid ancestry/profile accepted: %v", err)
			}
			if tx.execs != 1 || len(db.events) == 0 || db.events[len(db.events)-1] != "rollback" {
				t.Fatalf("refused profile mutated: %v", db.events)
			}
		})
	}
}

// An existing accepted registration is checked without DDL; a changed
// predecessor after fresh DDL aborts before any registration is published.
func TestAuthorizationInventoryInstallerPreservesRegisteredAncestry(t *testing.T) {
	for _, mode := range []string{"existing", "changed_ancestry", "fresh"} {
		t.Run(mode, func(t *testing.T) {
			db := &fakeDatabase{}
			tx := &fakeTransaction{events: &db.events}
			db.transaction = tx
			if mode == "existing" {
				tx.rows = []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{true}}, fakeRow{values: []any{true}}}
			} else {
				after := "same"
				if mode == "changed_ancestry" {
					after = "changed"
				}
				tx.rows = []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{false}}, fakeRow{values: []any{"same"}}, fakeRow{values: []any{after}}, fakeRow{values: []any{true}}}
			}
			r, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			err = r.UpProductionAuthorizationInventoryProfile(context.Background())
			if mode == "changed_ancestry" {
				if !errors.Is(err, ErrInvalidState) || tx.execs != 2 || db.events[len(db.events)-1] != "rollback" {
					t.Fatalf("changed ancestry published: %v %v", err, db.events)
				}
			} else {
				want := 3
				if mode == "existing" {
					want = 1
				}
				if err != nil || tx.execs != want || db.events[len(db.events)-1] != "commit" {
					t.Fatalf("installation/replay failed: %v %v", err, db.events)
				}
			}
		})
	}
}
