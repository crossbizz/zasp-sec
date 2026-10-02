package apiserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type guardedReadinessDriver struct {
	t                       *testing.T
	calls                   int
	args                    []any
	independent, production bool
	fail                    bool
	cancel                  context.CancelFunc
}

func (d *guardedReadinessDriver) QueryRow(_ context.Context, q string, a ...any) PostgresRow {
	d.calls++
	if q != postgresAuthorizationRuntimeReadySQL || !reflect.DeepEqual(a, d.args) {
		d.t.Error("unexpected readiness statement/pins/identity")
	}
	return guardedReadinessRow{d}
}
func (*guardedReadinessDriver) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}
func (*guardedReadinessDriver) Close() error { return nil }
func (*guardedReadinessDriver) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected transaction")
}

type guardedReadinessRow struct{ d *guardedReadinessDriver }

func (r guardedReadinessRow) Scan(v ...any) error {
	if r.d.cancel != nil {
		r.d.cancel()
	}
	if r.d.fail {
		return errors.New("unavailable or null result")
	}
	if len(v) != 2 {
		return errors.New("wrong result shape")
	}
	*v[0].(*bool), *v[1].(*bool) = r.d.independent, r.d.production
	return nil
}

func TestP7GuardedRuntimeReadinessAdapter(t *testing.T) {
	checksum, audit := migrations.ProductionAuthorizationEnforcement().Checksum(), migrations.AuthorizationAuditProfileChecksum()
	for _, name := range []string{"discovery", "agent", "independent false", "endpoint false", "scan error", "late cancel", "early cancel", "nil context", "wrong role", "short key", "uppercase key", "non-enforcing", "closed"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			role, key := "zasp_discovery_api", strings.Repeat("a", 64)
			if name == "agent" {
				role = "zasp_security_agent_api"
			}
			d := &guardedReadinessDriver{t: t, independent: name != "independent false", production: name != "endpoint false", fail: name == "scan error"}
			db, _ := NewPostgresJSONDatabase(d)
			defer db.Close()
			if name != "non-enforcing" {
				if err := db.RequireCurrentAuthorization(); err != nil {
					t.Fatal(err)
				}
			}
			if name == "closed" {
				_ = db.Close()
			}
			if name == "early cancel" {
				cancel()
			}
			if name == "late cancel" {
				d.cancel = cancel
			}
			if name == "nil context" {
				ctx = nil
			}
			if name == "wrong role" {
				role = "zasp_security_agent_worker"
			}
			if name == "short key" {
				key = "a"
			}
			if name == "uppercase key" {
				key = strings.Repeat("A", 64)
			}
			d.args = []any{checksum, audit, key, role}
			err := db.CurrentAuthorizationRuntimeReady(ctx, role, key)
			if (err == nil) != (name == "discovery" || name == "agent") {
				t.Fatalf("error=%v", err)
			}
			want := 1
			switch name {
			case "early cancel", "nil context", "wrong role", "short key", "uppercase key", "non-enforcing", "closed":
				want = 0
			}
			if d.calls != want {
				t.Fatalf("queries=%d want=%d", d.calls, want)
			}
		})
	}
	t.Run("no general proof bypass", func(t *testing.T) {
		d := &guardedReadinessDriver{t: t}
		db, _ := NewPostgresJSONDatabase(d)
		defer db.Close()
		_ = db.RequireCurrentAuthorization()
		if _, err := db.QueryJSON(context.Background(), `SELECT true`); !errors.Is(err, ErrAuthorizationDenied) || d.calls != 0 {
			t.Fatal("generic query bypass")
		}
	})
}
