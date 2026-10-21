package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type preflightCatalogFixture struct {
	mode      string
	queries   int
	forbidden bool
	rows      []Metadata
}

func (f *preflightCatalogFixture) QueryRow(ctx context.Context, q string, args ...any) Row {
	f.queries++
	if !strings.HasPrefix(strings.TrimSpace(q), "SELECT ") {
		f.forbidden = true
	}
	if f.mode == "denied" {
		return fakeRow{err: errors.New("NEVER_REFLECT_DATABASE_TEXT")}
	}
	switch q {
	case tableExistsSQL:
		return fakeRow{values: []any{f.mode != "absent" && f.mode != "partial"}}
	case countRowsSQL:
		n := int64(len(f.rows))
		if f.mode == "extra" {
			n++
		}
		return fakeRow{values: []any{n}}
	case readVersionSQL:
		version := args[0].(int64)
		for _, m := range f.rows {
			if m.Version() == version {
				sum := m.Checksum()
				if f.mode == "drift" && version == 1 {
					sum = "changed"
				}
				return fakeRow{values: []any{version, m.Name(), sum}}
			}
		}
		return fakeRow{err: errors.New("missing row")}
	}
	if strings.Contains(q, "pg_namespace") {
		return fakeRow{values: []any{f.mode == "partial"}}
	}
	return fakeRow{values: []any{f.mode != "profile-drift"}}
}
func TestReadOnlyPreflightCurrentProfile(t *testing.T) {
	for _, mode := range []string{"normal", "audit", "absent", "partial", "drift", "extra", "denied", "profile-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := &preflightCatalogFixture{mode: mode, rows: append(multistepPredecessors(), ProductionSecurityAgentMultistep())}
			recipe := "worker-v1"
			if mode == "audit" {
				recipe = "audit-identity-worker-v1"
			}
			state, e := ObservePreflightProfile(context.Background(), f, recipe)
			if f.queries == 0 || f.forbidden {
				t.Fatal("observer skipped catalog or attempted mutation")
			}
			if mode == "normal" || mode == "audit" {
				if e != nil || !state.Installed || state.CanonicalVersion != 61 || state.Code != "current" {
					t.Fatal("complete compiled canonical and private profile not observed")
				}
			} else if mode == "absent" {
				if e != nil || state.Installed || state.Code != "not_installed" {
					t.Fatal("empty-before-install confused with installed profile or error")
				}
			} else if e == nil {
				t.Fatal("partial, drifted or inaccessible authority accepted")
			}
		})
	}
}
