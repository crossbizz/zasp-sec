package gatewaycontrol

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestTemporalAutomaticGatewayReadiness(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses []any
		wantOK    bool
		wantCalls int
	}{
		{"installed valid", []any{true, true}, true, 2},
		{"installed invalid no legacy fallback", []any{true, false, true}, false, 2},
		{"installed missing function no legacy fallback", []any{true, &pgconn.PgError{Code: "42883"}, true}, false, 2},
		{"installation query error", []any{errors.New("unavailable"), true}, false, 1},
		{"absent retains recovery", []any{false, true}, true, 2},
		{"absent retains older fallback", []any{false, &pgconn.PgError{Code: "42883"}, true}, true, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &postgresDatabaseStub{responses: test.responses}
			repo, _ := NewPostgresRepository(db, time.Second)
			err := repo.Ready(context.Background())
			if (err == nil) != test.wantOK || len(db.calls) != test.wantCalls {
				t.Fatalf("ready=%v calls=%#v", err, db.calls)
			}
			if db.calls[0].statement != `SELECT to_regnamespace('zasp_temporal77') IS NOT NULL` {
				t.Fatal("missing exact optional installation probe", db.calls)
			}
			if test.responses[0] == true {
				if db.calls[1].statement != `SELECT zasp_temporal77.gateway_ready($1,$2)` || !reflect.DeepEqual(db.calls[1].arguments, []any{migrations.ProductionTemporalAutomaticSources().Checksum(), migrations.TemporalAutomaticSourcesFingerprint()}) {
					t.Fatal("inexact installed contract", db.calls)
				}
			}
		})
	}
}
