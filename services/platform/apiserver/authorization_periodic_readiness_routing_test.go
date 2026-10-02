package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const periodicReadinessCharacterizationSQL = `SELECT to_jsonb(zasp_temporal65.ready($1,$2))`

type periodicReadinessCountingDriver struct {
	queryCalls, execCalls, beginCalls int
	arguments                         []any
}

func (d *periodicReadinessCountingDriver) QueryRow(_ context.Context, q string, args ...any) PostgresRow {
	d.queryCalls++
	return periodicReadinessCountingRow{valid: q == periodicReadinessCharacterizationSQL && reflect.DeepEqual(args, d.arguments)}
}

func (d *periodicReadinessCountingDriver) Exec(context.Context, string, ...any) error {
	d.execCalls++
	return errors.New("unexpected readiness execution")
}

func (d *periodicReadinessCountingDriver) Begin(context.Context) (pgx.Tx, error) {
	d.beginCalls++
	return nil, errors.New("unexpected readiness transaction")
}

func (*periodicReadinessCountingDriver) Close() error { return nil }

type periodicReadinessCountingRow struct{ valid bool }

func (r periodicReadinessCountingRow) Scan(dest ...any) error {
	if !r.valid || len(dest) != 1 {
		return errors.New("unexpected readiness query or destination")
	}
	value, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("unexpected readiness destination type")
	}
	*value = []byte("true")
	return nil
}

// This diagnostic characterizes the current adapter defect, not desired healthy
// startup. Allowing the exact callback query through a future typed repair will
// require replacing this denial characterization with the repaired contract.
func TestP7PeriodicReadinessQueryRoutingCharacterization(t *testing.T) {
	args := []any{migrations.ProductionTemporalOutbox().Checksum(), migrations.TemporalOutboxFingerprint()}
	for _, enforcing := range []bool{false, true} {
		name := "non-enforcing-control"
		if enforcing {
			name = "current-authorization-denies-before-io"
		}
		t.Run(name, func(t *testing.T) {
			driver := &periodicReadinessCountingDriver{arguments: args}
			database, err := NewPostgresJSONDatabase(driver)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := database.Close(); err != nil {
					t.Error(err)
				}
			})
			if enforcing {
				if err := database.RequireCurrentAuthorization(); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := database.QueryJSON(context.Background(), periodicReadinessCharacterizationSQL, args...)
			if enforcing {
				if !errors.Is(err, ErrAuthorizationDenied) || len(raw) != 0 || driver.queryCalls != 0 {
					t.Fatalf("expected denial before query: denied=%t payload_bytes=%d queries=%d", errors.Is(err, ErrAuthorizationDenied), len(raw), driver.queryCalls)
				}
			} else if err != nil || string(raw) != "true" || driver.queryCalls != 1 {
				t.Fatalf("control: error=%v payload=%q queries=%d", err, raw, driver.queryCalls)
			}
			if driver.execCalls != 0 || driver.beginCalls != 0 {
				t.Fatalf("unexpected io: exec=%d begin=%d", driver.execCalls, driver.beginCalls)
			}
			t.Logf("enforcing=%t denied=%t queries=%d exec=%d begin=%d", enforcing, errors.Is(err, ErrAuthorizationDenied), driver.queryCalls, driver.execCalls, driver.beginCalls)
		})
	}
}
