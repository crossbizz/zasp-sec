package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type singleRecoveryManualAdmissionObservation struct {
	stage, route, class, sqlstate string
	ordinal                       int
	observed, value               bool
}

type singleRecoveryManualAdmissionDiagnostic struct {
	mu   sync.Mutex
	last singleRecoveryManualAdmissionObservation
	next int
}

func wrapSingleRecoveryManualAdmissionDatabase(database *PostgresJSONDatabase) (*PostgresJSONDatabase, *singleRecoveryManualAdmissionDiagnostic) {
	diagnostic := &singleRecoveryManualAdmissionDiagnostic{}
	database.mu.RLock()
	driver, currentAuthorization, closed := database.driver, database.currentAuthorization, database.closed
	database.mu.RUnlock()
	if closed || nilInterface(driver) {
		return database, diagnostic
	}
	wrappedDriver := wrapSingleRecoveryManualAdmissionDriver(driver, diagnostic)
	wrapped, err := NewPostgresJSONDatabase(wrappedDriver)
	if err != nil {
		return database, diagnostic
	}
	wrapped.currentAuthorization = currentAuthorization
	return wrapped, diagnostic
}

func (d *singleRecoveryManualAdmissionDiagnostic) summary(repositoryErr error, receiptMatch bool) string {
	d.mu.Lock()
	observation := d.last
	d.mu.Unlock()
	if observation.stage == "" {
		observation.stage, observation.route, observation.class = "unknown", "unknown", "none"
	}
	repository, receipt := singleRecoveryManualAdmissionRepositoryClass(repositoryErr), "unknown"
	if repositoryErr == nil {
		receipt = "mismatch"
		if receiptMatch {
			receipt = "match"
		}
	}
	ordinal := fmt.Sprint(observation.ordinal)
	if observation.ordinal > 5 {
		ordinal = "many"
	}
	return fmt.Sprintf("stage=%s ordinal=%s observed=%t value=%t route=%s class=%s sqlstate=%s repository=%s receipt=%s", observation.stage, ordinal, observation.observed, observation.value, observation.route, observation.class, observation.sqlstate, repository, receipt)
}

const (
	singleRecoveryManualTemporalNamespaceSQL = `SELECT to_regnamespace('zasp_temporal66') IS NOT NULL`
	singleRecoveryManualTemporalReadySQL     = `SELECT zasp_temporal66.ready($1,$2)`
	singleRecoveryManualLegacyNamespaceSQL   = `SELECT to_regprocedure('public.zasp_sa_export_readiness(text,text)') IS NOT NULL`
	singleRecoveryManualLegacyReadySQL       = `SELECT public.zasp_sa_export_readiness($1,$2)`
)

type singleRecoveryManualAdmissionDriver struct {
	driver     PostgresDriver
	diagnostic *singleRecoveryManualAdmissionDiagnostic
}

type singleRecoveryManualAdmissionTransactionDriver struct {
	*singleRecoveryManualAdmissionDriver
	transactions AuthorizationTransactionDriver
}

func wrapSingleRecoveryManualAdmissionDriver(driver PostgresDriver, diagnostic *singleRecoveryManualAdmissionDiagnostic) PostgresDriver {
	wrapped := &singleRecoveryManualAdmissionDriver{driver: driver, diagnostic: diagnostic}
	if transactions, ok := driver.(AuthorizationTransactionDriver); ok {
		return &singleRecoveryManualAdmissionTransactionDriver{singleRecoveryManualAdmissionDriver: wrapped, transactions: transactions}
	}
	return wrapped
}

func (d *singleRecoveryManualAdmissionTransactionDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	return d.transactions.Begin(ctx)
}

func (d *singleRecoveryManualAdmissionDriver) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	stage, route, known := singleRecoveryManualAdmissionQuery(query)
	row := d.driver.QueryRow(ctx, query, args...)
	if !known {
		return row
	}
	d.diagnostic.mu.Lock()
	d.diagnostic.next++
	ordinal := d.diagnostic.next
	d.diagnostic.mu.Unlock()
	return singleRecoveryAvailabilityRow(func(destinations ...any) error {
		err := row.Scan(destinations...)
		observation := singleRecoveryManualAdmissionObservation{stage: stage, route: route, class: singleRecoveryManualAdmissionQueryClass(ctx, err), sqlstate: singleRecoveryManualAdmissionSQLState(err), ordinal: ordinal}
		if err == nil {
			observation.observed = true
			if len(destinations) == 1 {
				if value, ok := destinations[0].(*bool); ok {
					observation.value = *value
				}
			}
		}
		d.diagnostic.mu.Lock()
		d.diagnostic.last = observation
		d.diagnostic.mu.Unlock()
		return err
	})
}

func (d *singleRecoveryManualAdmissionDriver) Exec(ctx context.Context, query string, args ...any) error {
	return d.driver.Exec(ctx, query, args...)
}

func (d *singleRecoveryManualAdmissionDriver) Close() error { return d.driver.Close() }

func singleRecoveryManualAdmissionQuery(query string) (stage, route string, known bool) {
	switch query {
	case singleRecoveryManualTemporalNamespaceSQL:
		return "temporal-namespace", "temporal", true
	case singleRecoveryManualTemporalReadySQL:
		return "temporal-ready", "temporal", true
	case singleRecoveryManualLegacyNamespaceSQL:
		return "legacy-namespace", "legacy", true
	case singleRecoveryManualLegacyReadySQL:
		return "legacy-ready", "legacy", true
	case postgresTemporalManualRunSQL:
		return "manual-run", "temporal", true
	case postgresSecurityAgentManualRunSQL:
		return "manual-run", "legacy", true
	default:
		return "", "", false
	}
}

func singleRecoveryManualAdmissionQueryClass(ctx context.Context, err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled {
		return "canceled"
	}
	return "query"
}

func singleRecoveryManualAdmissionSQLState(err error) string {
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) {
		return ""
	}
	switch postgres.Code {
	case "22023", "22P02", "23505", "23514", "40001", "42501", "53100", "53200", "55000", "57014":
		return postgres.Code
	default:
		return "other"
	}
}

func singleRecoveryManualAdmissionRepositoryClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrRepositoryUnavailable):
		return "unavailable"
	case errors.Is(err, ErrRepositoryAuthorization):
		return "authorization"
	case errors.Is(err, ErrRepositoryConflict):
		return "conflict"
	case errors.Is(err, ErrRepositoryOperation):
		return "operation"
	default:
		return "other"
	}
}

type singleRecoveryManualAdmissionStep struct {
	query   string
	value   any
	err     error
	args    []any
	context context.Context
}

type singleRecoveryManualAdmissionDriverFixture struct {
	steps []singleRecoveryManualAdmissionStep
	calls []singleRecoveryManualAdmissionStep
}

func (d *singleRecoveryManualAdmissionDriverFixture) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	call := singleRecoveryManualAdmissionStep{query: query, args: append([]any(nil), args...), context: ctx}
	d.calls = append(d.calls, call)
	step := singleRecoveryManualAdmissionStep{query: query, value: true}
	if len(d.steps) >= len(d.calls) {
		step = d.steps[len(d.calls)-1]
	}
	return singleRecoveryAvailabilityRow(func(values ...any) error {
		if step.err != nil {
			return step.err
		}
		if len(values) != 1 {
			return errors.New("scan arity")
		}
		switch destination := values[0].(type) {
		case *bool:
			value, ok := step.value.(bool)
			if !ok {
				return errors.New("scan bool")
			}
			*destination = value
		case *[]byte:
			value, ok := step.value.([]byte)
			if !ok {
				return errors.New("scan bytes")
			}
			*destination = append((*destination)[:0], value...)
		default:
			return errors.New("scan type")
		}
		return nil
	})
}

func (*singleRecoveryManualAdmissionDriverFixture) Exec(context.Context, string, ...any) error {
	return nil
}
func (*singleRecoveryManualAdmissionDriverFixture) Close() error { return nil }

type singleRecoveryManualAdmissionTransactionFixture struct {
	*singleRecoveryManualAdmissionDriverFixture
	tx       pgx.Tx
	beginCtx context.Context
	beginErr error
}

func (d *singleRecoveryManualAdmissionTransactionFixture) Begin(ctx context.Context) (pgx.Tx, error) {
	d.beginCtx = ctx
	return d.tx, d.beginErr
}

func TestSingleRecoveryManualAdmissionDiagnosticRoutesAndClassifies(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{ name string }{"manual"}, "preserved")
	t.Run("legacy fallback and manual result", func(t *testing.T) {
		driver := &singleRecoveryManualAdmissionDriverFixture{steps: []singleRecoveryManualAdmissionStep{
			{value: false},
			{value: true},
			{value: true},
			{value: []byte(`{"id":"fixed"}`)},
		}}
		database, _ := NewPostgresJSONDatabase(driver)
		wrapped, diagnostic := wrapSingleRecoveryManualAdmissionDatabase(database)
		if _, ok := any(wrapped.driver).(AuthorizationTransactionDriver); ok {
			t.Fatal("nontransactional driver gained Begin")
		}
		if available, err := wrapped.TemporalAdmissionAvailable(ctx); err != nil || available {
			t.Fatal("temporal namespace absence changed", available, err)
		}
		if available, err := wrapped.SecurityAgentExportsAvailable(ctx); err != nil || !available {
			t.Fatal("legacy readiness changed", available, err)
		}
		if _, err := wrapped.QueryJSON(ctx, postgresSecurityAgentManualRunSQL, "fixed-argument"); err != nil {
			t.Fatal("manual query changed", err)
		}
		want := "stage=manual-run ordinal=4 observed=true value=false route=legacy class=none sqlstate= repository=none receipt=match"
		if got := diagnostic.summary(nil, true); got != want {
			t.Fatalf("summary=%q want=%q", got, want)
		}
		if len(driver.calls) != 4 || driver.calls[3].query != postgresSecurityAgentManualRunSQL || driver.calls[3].context != ctx || len(driver.calls[3].args) != 1 || driver.calls[3].args[0] != "fixed-argument" {
			t.Fatal("manual query context or arguments changed")
		}
	})

	t.Run("present but unready temporal route", func(t *testing.T) {
		driver := &singleRecoveryManualAdmissionDriverFixture{steps: []singleRecoveryManualAdmissionStep{{value: true}, {value: false}}}
		database, _ := NewPostgresJSONDatabase(driver)
		wrapped, diagnostic := wrapSingleRecoveryManualAdmissionDatabase(database)
		if ready, err := wrapped.TemporalAdmissionAvailable(ctx); err == nil || ready {
			t.Fatal("unready temporal release did not fail closed")
		}
		want := "stage=temporal-ready ordinal=2 observed=true value=false route=temporal class=none sqlstate= repository=unavailable receipt=unknown"
		if got := diagnostic.summary(ErrRepositoryUnavailable, false); got != want {
			t.Fatalf("summary=%q want=%q", got, want)
		}
	})

	t.Run("query failure and canceled context", func(t *testing.T) {
		secret := "postgres" + "://private:secret@host/body"
		for _, test := range []struct {
			name, want string
			err        error
		}{
			{"allowlisted SQLSTATE", "class=query sqlstate=57014", &pgconn.PgError{Code: "57014", Message: secret}},
			{"unlisted SQLSTATE", "class=query sqlstate=other", &pgconn.PgError{Code: "ZZ999", Message: secret}},
			{"canceled", "class=canceled sqlstate=", context.Canceled},
			{"deadline", "class=deadline sqlstate=", context.DeadlineExceeded},
		} {
			t.Run(test.name, func(t *testing.T) {
				driver := &singleRecoveryManualAdmissionDriverFixture{steps: []singleRecoveryManualAdmissionStep{{err: test.err}}}
				database, _ := NewPostgresJSONDatabase(driver)
				wrapped, diagnostic := wrapSingleRecoveryManualAdmissionDatabase(database)
				_, _ = wrapped.TemporalAdmissionAvailable(ctx)
				got := diagnostic.summary(ErrRepositoryUnavailable, false)
				if !strings.Contains(got, "stage=temporal-namespace ordinal=1 observed=false value=false route=temporal "+test.want) || strings.Contains(got, secret) || strings.Contains(got, "ZZ999") {
					t.Fatalf("unsafe query summary: %s", got)
				}
			})
		}
	})

	t.Run("repository and receipt outcome", func(t *testing.T) {
		diagnostic := &singleRecoveryManualAdmissionDiagnostic{last: singleRecoveryManualAdmissionObservation{stage: "manual-run", route: "temporal", class: "none", ordinal: 3, observed: true}}
		for _, test := range []struct {
			err   error
			match bool
			want  string
		}{
			{nil, false, "repository=none receipt=mismatch"},
			{ErrRepositoryUnavailable, false, "repository=unavailable receipt=unknown"},
			{ErrRepositoryAuthorization, false, "repository=authorization receipt=unknown"},
			{errors.New("private repository body"), false, "repository=other receipt=unknown"},
		} {
			if got := diagnostic.summary(test.err, test.match); !strings.Contains(got, test.want) || strings.Contains(got, "private") {
				t.Fatalf("repository outcome escaped: %s", got)
			}
		}
	})
}

func TestSingleRecoveryManualAdmissionDiagnosticPreservesOptionalTransaction(t *testing.T) {
	plain := &singleRecoveryManualAdmissionDriverFixture{}
	plainDatabase, _ := NewPostgresJSONDatabase(plain)
	wrappedPlain, _ := wrapSingleRecoveryManualAdmissionDatabase(plainDatabase)
	if _, ok := any(wrappedPlain.driver).(AuthorizationTransactionDriver); ok {
		t.Fatal("plain driver gained transaction support")
	}

	wantTx := &authorizationTxFixture{}
	transactional := &singleRecoveryManualAdmissionTransactionFixture{singleRecoveryManualAdmissionDriverFixture: &singleRecoveryManualAdmissionDriverFixture{}, tx: wantTx, beginErr: errors.New("fixed begin")}
	transactionalDatabase, _ := NewPostgresJSONDatabase(transactional)
	wrappedTransactional, _ := wrapSingleRecoveryManualAdmissionDatabase(transactionalDatabase)
	transactions, ok := any(wrappedTransactional.driver).(AuthorizationTransactionDriver)
	if !ok {
		t.Fatal("transactional driver lost Begin")
	}
	ctx := context.WithValue(context.Background(), struct{ name string }{"tx"}, "preserved")
	gotTx, gotErr := transactions.Begin(ctx)
	if gotTx != wantTx || !errors.Is(gotErr, transactional.beginErr) || transactional.beginCtx != ctx {
		t.Fatal("transaction context, result, or error changed")
	}

	unknown := "SELECT private_unknown($1)"
	row := wrappedTransactional.driver.QueryRow(ctx, unknown, "fixed")
	if err := row.Scan(new(bool)); err != nil {
		t.Fatal(err)
	}
	if len(transactional.calls) != 1 || transactional.calls[0].query != unknown || transactional.calls[0].context != ctx || fmt.Sprint(transactional.calls[0].args) != "[fixed]" {
		t.Fatal("unknown query delegation changed")
	}
}
