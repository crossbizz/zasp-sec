package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// These controls catch our preparation issuing DDL before owner/preexistence
// checks, returning with residue, or failing to roll back after cancellation.
// The external SQL boundary is recorded; this is not PostgreSQL/OID evidence.
func TestOrderedReferenceVariantBoundary(t *testing.T) {
	pristine := orderedReferenceState{Session: "zasp_e2e", Current: "zasp_e2e", Inventory: "original catalog identities"}
	t.Run("fixed bounded preparation and cleanup", func(t *testing.T) {
		var statements []string
		reads := 0
		err := prepareOrderedReferenceVariant(context.Background(), orderedReferenceIO{
			snapshot: func(context.Context) (orderedReferenceState, error) { reads++; return pristine, nil },
			exec:     func(_ context.Context, q string) error { statements = append(statements, q); return nil },
		})
		if err != nil || reads != 2 || len(statements) != 68 {
			t.Fatalf("preparation: error=%v reads=%d statements=%d", err, reads, len(statements))
		}
		if statements[0] != "BEGIN" || statements[1] != "CREATE SCHEMA p7_reference_oid_shift" || statements[66] != "DROP SCHEMA p7_reference_oid_shift CASCADE" || statements[67] != "COMMIT" {
			t.Fatal("transaction/owned cleanup boundary")
		}
		if statements[2] != "CREATE TABLE p7_reference_oid_shift.t00 (value text)" || statements[3] != "CREATE FUNCTION p7_reference_oid_shift.f00() RETURNS integer LANGUAGE sql AS 'SELECT 1'" || statements[64] != "CREATE TABLE p7_reference_oid_shift.t31 (value text)" || statements[65] != "CREATE FUNCTION p7_reference_oid_shift.f31() RETURNS integer LANGUAGE sql AS 'SELECT 1'" {
			t.Fatal("fixed object bounds")
		}
		seen := map[string]bool{}
		for _, q := range statements[2:66] {
			if seen[q] || strings.Contains(q, "TEMP") || strings.Contains(q, "ROLE") {
				t.Fatal("duplicate or out-of-scope DDL")
			}
			seen[q] = true
		}
	})
	for _, kind := range []string{"session", "current", "scratch", "migrated", "inventory", "snapshot-error", "cancelled"} {
		t.Run("refuse-before-DDL/"+kind, func(t *testing.T) {
			state := pristine
			var failure error
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "session":
				state.Session = "zasp_test"
			case "current":
				state.Current = "other"
			case "scratch":
				state.Scratch = true
			case "migrated":
				state.Migrated = true
			case "inventory":
				state.Inventory = ""
			case "snapshot-error":
				failure = errors.New("external")
			case "cancelled":
				cancel()
			}
			writes := 0
			err := prepareOrderedReferenceVariant(ctx, orderedReferenceIO{snapshot: func(context.Context) (orderedReferenceState, error) { return state, failure }, exec: func(context.Context, string) error { writes++; return nil }})
			if err == nil || writes != 0 {
				t.Fatalf("refusal error=%v writes=%d", err, writes)
			}
		})
	}
	for _, kind := range []string{"session", "current", "scratch", "migrated", "inventory", "snapshot-error"} {
		t.Run("refuse-postcommit-residue/"+kind, func(t *testing.T) {
			reads := 0
			err := prepareOrderedReferenceVariant(context.Background(), orderedReferenceIO{snapshot: func(context.Context) (orderedReferenceState, error) {
				reads++
				s := pristine
				if reads == 2 {
					switch kind {
					case "session":
						s.Session = "zasp_test"
					case "current":
						s.Current = "other"
					case "scratch":
						s.Scratch = true
					case "migrated":
						s.Migrated = true
					case "inventory":
						s.Inventory = "changed"
					case "snapshot-error":
						return s, errors.New("external")
					}
				}
				return s, nil
			}, exec: func(context.Context, string) error { return nil }})
			if err == nil {
				t.Fatal("accepted preparation residue")
			}
		})
	}
	t.Run("cancelled write rolls back independently and bounded", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rollbacks := 0
		err := prepareOrderedReferenceVariant(ctx, orderedReferenceIO{snapshot: func(context.Context) (orderedReferenceState, error) { return pristine, nil }, exec: func(call context.Context, q string) error {
			if q == "CREATE SCHEMA p7_reference_oid_shift" {
				cancel()
				return context.Canceled
			}
			if q == "ROLLBACK" {
				rollbacks++
				deadline, ok := call.Deadline()
				if call.Err() != nil || !ok || time.Until(deadline) > 3*time.Second {
					t.Error("unbounded/cancelled cleanup")
				}
			}
			return nil
		}})
		if err == nil || rollbacks != 1 {
			t.Fatalf("failure cleanup error=%v rollbacks=%d", err, rollbacks)
		}
	})
	for _, failed := range []string{"CREATE SCHEMA p7_reference_oid_shift", "CREATE TABLE p7_reference_oid_shift.t00 (value text)", "DROP SCHEMA p7_reference_oid_shift CASCADE", "COMMIT"} {
		t.Run("statement failure rolls back/"+failed, func(t *testing.T) {
			rollbacks := 0
			reads := 0
			rejected := false
			err := prepareOrderedReferenceVariant(context.Background(), orderedReferenceIO{
				snapshot: func(context.Context) (orderedReferenceState, error) { reads++; return pristine, nil },
				exec: func(ctx context.Context, q string) error {
					if q == "ROLLBACK" {
						rollbacks++
						if ctx.Err() != nil {
							t.Error("cleanup cancelled")
						}
						return nil
					}
					if rejected {
						t.Error("continued after failed statement")
					}
					if q == failed {
						rejected = true
						return errors.New("external")
					}
					return nil
				},
			})
			if err == nil || rollbacks != 1 || reads != 1 {
				t.Fatalf("failure not contained: error=%v rollbacks=%d reads=%d", err, rollbacks, reads)
			}
		})
	}
}
