package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type singleRecoveryAvailabilityRow func(...any) error

func (r singleRecoveryAvailabilityRow) Scan(values ...any) error { return r(values...) }

type singleRecoveryAvailabilityStep struct {
	value bool
	err   error
}

type singleRecoveryAvailabilityCall struct {
	query string
	args  []any
	ctx   context.Context
}

type singleRecoveryAvailabilityBudgetDriver struct {
	t             *testing.T
	steps         []singleRecoveryAvailabilityStep
	calls         []singleRecoveryAvailabilityCall
	requireBudget bool
}

func (d *singleRecoveryAvailabilityBudgetDriver) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	d.calls = append(d.calls, singleRecoveryAvailabilityCall{query: query, args: append([]any(nil), args...), ctx: ctx})
	if deadline, ok := ctx.Deadline(); d.requireBudget && (!ok || time.Until(deadline) < 9*time.Second) {
		return singleRecoveryAvailabilityRow(func(...any) error { return errors.New("database budget spent before query") })
	}
	step := singleRecoveryAvailabilityStep{value: true}
	if len(d.steps) >= len(d.calls) {
		step = d.steps[len(d.calls)-1]
	}
	return singleRecoveryAvailabilityRow(func(values ...any) error {
		if step.err != nil {
			return step.err
		}
		if len(values) != 1 {
			d.t.Fatal("scan arity")
		}
		value, ok := values[0].(*bool)
		if !ok {
			d.t.Fatal("scan type")
		}
		*value = step.value
		return nil
	})
}

func (*singleRecoveryAvailabilityBudgetDriver) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected exec")
}

func (*singleRecoveryAvailabilityBudgetDriver) Close() error { return nil }

func TestSingleRecoveryAvailabilityPreservesDatabaseBudget(t *testing.T) {
	driver := &singleRecoveryAvailabilityBudgetDriver{t: t, requireBudget: true}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	available, err := database.SingleTestRecoveryAvailable(context.Background())
	if err != nil || !available || len(driver.calls) != 3 {
		t.Fatalf("metadata derivation spent database budget: available=%t err=%v calls=%d", available, err, len(driver.calls))
	}
}

func TestSingleRecoveryAvailabilityFailClosedAndRechecksDatabase(t *testing.T) {
	metadata := migrations.ProductionTemporalSingleRecoveryMetadata()
	cases := []struct {
		name      string
		steps     []singleRecoveryAvailabilityStep
		available bool
		wantError bool
		calls     int
	}{
		{"missing", []singleRecoveryAvailabilityStep{{value: false}}, false, false, 1},
		{"malformed", []singleRecoveryAvailabilityStep{{err: errors.New("malformed row")}}, false, true, 1},
		{"source false", []singleRecoveryAvailabilityStep{{value: true}, {value: false}}, false, true, 2},
		{"source error", []singleRecoveryAvailabilityStep{{value: true}, {err: errors.New("private source error")}}, false, true, 2},
		{"ready false", []singleRecoveryAvailabilityStep{{value: true}, {value: true}, {value: false}}, false, true, 3},
		{"ready error", []singleRecoveryAvailabilityStep{{value: true}, {value: true}, {err: errors.New("private ready error")}}, false, true, 3},
		{"valid", []singleRecoveryAvailabilityStep{{value: true}, {value: true}, {value: true}}, true, false, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			driver := &singleRecoveryAvailabilityBudgetDriver{t: t, steps: tc.steps}
			database, _ := NewPostgresJSONDatabase(driver)
			available, err := database.SingleTestRecoveryAvailable(context.Background())
			if available != tc.available || (err != nil) != tc.wantError || len(driver.calls) != tc.calls {
				t.Fatalf("available=%t err=%v calls=%d", available, err, len(driver.calls))
			}
			if tc.calls >= 2 && (!reflect.DeepEqual(driver.calls[1].args, []any{metadata.ReadyBodyDigest}) || driver.calls[1].query != migrations.TemporalSingleRecoveryReadySourceSQL) {
				t.Fatal("source metadata query changed")
			}
			if tc.calls == 3 && (!reflect.DeepEqual(driver.calls[2].args, []any{metadata.Checksum}) || driver.calls[2].query != `SELECT zasp_temporal_single_recovery.ready($1)`) {
				t.Fatal("readiness metadata query changed")
			}
		})
	}

	driver := &singleRecoveryAvailabilityBudgetDriver{t: t, steps: []singleRecoveryAvailabilityStep{{value: true}, {value: true}, {value: true}, {value: true}, {value: false}}}
	database, _ := NewPostgresJSONDatabase(driver)
	first, firstErr := database.SingleTestRecoveryAvailable(context.Background())
	second, secondErr := database.SingleTestRecoveryAvailable(context.Background())
	if !first || firstErr != nil || second || secondErr == nil || len(driver.calls) != 5 {
		t.Fatalf("database drift was cached: first=%t/%v second=%t/%v calls=%d", first, firstErr, second, secondErr, len(driver.calls))
	}
}

func TestSingleRecoveryAvailabilityHonorsParentContext(t *testing.T) {
	_ = migrations.ProductionTemporalSingleRecoveryMetadata()
	for _, mode := range []string{"canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "expired" {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			cancel()
			driver := &singleRecoveryAvailabilityBudgetDriver{t: t}
			database, _ := NewPostgresJSONDatabase(driver)
			if available, err := database.SingleTestRecoveryAvailable(ctx); available || err == nil || len(driver.calls) != 0 {
				t.Fatalf("invalid parent reached database: available=%t err=%v calls=%d", available, err, len(driver.calls))
			}
		})
	}

	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	driver := &singleRecoveryAvailabilityBudgetDriver{t: t}
	database, _ := NewPostgresJSONDatabase(driver)
	if available, err := database.SingleTestRecoveryAvailable(parent); err != nil || !available {
		t.Fatal("valid parent refused", err)
	}
	parentDeadline, _ := parent.Deadline()
	for _, call := range driver.calls {
		deadline, ok := call.ctx.Deadline()
		if !ok || deadline.After(parentDeadline) {
			t.Fatal("caller deadline broadened")
		}
	}
}
