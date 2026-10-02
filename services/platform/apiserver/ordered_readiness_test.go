package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The double controls only external SQL. The real adapter must choose the fixed
// route, bind compiled pins, check both results, and refuse generic SQL access.
type orderedReadinessDriver struct {
	t         *testing.T
	ready     bool
	body      string
	err       error
	afterScan func()
	queries   int
}

func (d *orderedReadinessDriver) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	d.queries++
	if query != `SELECT zasp_authorization80.ready($1), zasp_ordered_public62.api($2,$3,'{"operation":"deployment_ready"}'::jsonb)` || len(args) != 3 {
		d.t.Fatal("readiness escaped its fixed typed statement")
	}
	if args[0] != migrations.ProductionAuthorizationEnforcement().Checksum() || args[1] != migrations.ProductionSecurityAgentPublic().Checksum() || args[2] != migrations.SecurityAgentPublicFingerprint() {
		d.t.Fatal("readiness replaced compiled pins")
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second || ctx.Err() != nil {
		d.t.Fatal("readiness deadline absent, expired or exceeds five seconds")
	}
	return orderedReadinessRow{d}
}
func (d *orderedReadinessDriver) Begin(context.Context) (pgx.Tx, error) {
	d.t.Fatal("readiness must not start an application transaction")
	return nil, errors.New("unexpected transaction")
}
func (d *orderedReadinessDriver) Exec(context.Context, string, ...any) error {
	d.t.Fatal("readiness must not write")
	return errors.New("unexpected write")
}
func (*orderedReadinessDriver) Close() error { return nil }

type orderedReadinessRow struct{ d *orderedReadinessDriver }

func (r orderedReadinessRow) Scan(dest ...any) error {
	if r.d.err != nil {
		return r.d.err
	}
	if len(dest) != 2 {
		return errors.New("wrong result arity")
	}
	ready, ok := dest[0].(*bool)
	if !ok {
		return errors.New("wrong readiness result type")
	}
	body, ok := dest[1].(*[]byte)
	if !ok {
		return errors.New("wrong deployment result type")
	}
	*ready, *body = r.d.ready, []byte(r.d.body)
	if r.d.afterScan != nil {
		r.d.afterScan()
	}
	return nil
}

func orderedReadinessDatabase(t *testing.T, d *orderedReadinessDriver) *PostgresJSONDatabase {
	t.Helper()
	db, err := NewPostgresJSONDatabase(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db
}

func TestP7OrderedReadinessTyped(t *testing.T) {
	const valid = `{"contract_version":62,"ready":true}`
	cases := []struct {
		name, body string
		ready      bool
		err        error
		want       bool
	}{
		{"exact installed release", valid, true, nil, true},
		{"128 bytes accepted", valid + strings.Repeat(" ", 128-len(valid)), true, nil, true},
		{"129 bytes refused", valid + strings.Repeat(" ", 129-len(valid)), true, nil, false},
		{"independent80 false", valid, false, nil, false},
		{"sql failure", valid, true, errors.New("private SQL failure"), false},
		{"null80 scan failure", valid, true, errors.New("cannot scan NULL into bool"), false},
		{"null62", "null", true, nil, false},
		{"missing62", "", true, nil, false},
		{"malformed62", "{", true, nil, false},
		{"false62", `{"contract_version":62,"ready":false}`, true, nil, false},
		{"wrong contract", `{"contract_version":61,"ready":true}`, true, nil, false},
		{"missing contract", `{"ready":true}`, true, nil, false},
		{"null ready", `{"contract_version":62,"ready":null}`, true, nil, false},
		{"extra field", `{"contract_version":62,"ready":true,"actor_id":"x"}`, true, nil, false},
		{"duplicate field", `{"contract_version":62,"ready":true,"ready":true}`, true, nil, false},
		{"trailing value", valid + `{}`, true, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &orderedReadinessDriver{t: t, ready: c.ready, body: c.body, err: c.err}
			db := orderedReadinessDatabase(t, d)
			err := db.VerifySecurityAgentOrderedHTTPRelease(context.Background())
			if (err == nil) != c.want || (!c.want && err != ErrRepositoryUnavailable) {
				t.Fatalf("ready=%t want=%t err=%v", err == nil, c.want, err)
			}
			if d.queries != 1 {
				t.Fatalf("query count=%d, want exactly one fixed query", d.queries)
			}
			if _, err := db.QueryJSON(context.Background(), securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(`{"operation":"deployment_ready"}`)); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatal("generic SQL became a readiness bypass", err)
			}
			if d.queries != 1 {
				t.Fatal("generic SQL reached driver")
			}
		})
	}
}

func TestP7OrderedReadinessLifecycle(t *testing.T) {
	for _, name := range []string{"nil database", "nil driver", "typed nil driver", "closed", "nil context", "canceled", "cancel during scan"} {
		t.Run(name, func(t *testing.T) {
			d := &orderedReadinessDriver{t: t, ready: true, body: `{"contract_version":62,"ready":true}`}
			db := orderedReadinessDatabase(t, d)
			original := db
			defer func() { original.driver = d }()
			ctx := context.Background()
			wantQueries := 0
			switch name {
			case "nil database":
				db = nil
			case "nil driver":
				db.driver = nil
			case "typed nil driver":
				db.driver = (*orderedReadinessDriver)(nil)
			case "closed":
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			case "nil context":
				ctx = nil
			case "canceled":
				ctx = canceledOrderedContext()
			case "cancel during scan":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				d.afterScan = cancel
				wantQueries = 1
			}
			if err := db.VerifySecurityAgentOrderedHTTPRelease(ctx); err != ErrRepositoryUnavailable {
				t.Fatal("invalid lifecycle admitted", err)
			}
			if d.queries != wantQueries {
				t.Fatalf("query count=%d want=%d", d.queries, wantQueries)
			}
		})
	}
}

func TestP7OrderedReadinessHandlerBuilder(t *testing.T) {
	for _, c := range []struct {
		name                 string
		enabled, ready, want bool
		queries              int
	}{
		{"enabled installed", true, true, true, 1},
		{"enabled refused", true, false, false, 1},
		{"disabled compatibility", false, false, true, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &orderedReadinessDriver{t: t, ready: c.ready, body: `{"contract_version":62,"ready":true}`}
			db := orderedReadinessDatabase(t, d)
			config := SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey}
			h, err := newSecurityAgentProductionHTTPHandler(context.Background(), &PostgresRepository{database: db}, http.NotFoundHandler(), config, c.enabled)
			if (err == nil) != c.want || (h != nil) != c.want || (!c.want && err != ErrRepositoryUnavailable) {
				t.Fatalf("handler=%T err=%v want=%t", h, err, c.want)
			}
			if d.queries != c.queries {
				t.Fatalf("queries=%d want=%d", d.queries, c.queries)
			}
		})
	}
}
