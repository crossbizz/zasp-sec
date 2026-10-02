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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

const singleRecoveryCapabilityNamespaceSQL = `SELECT to_regnamespace('zasp_temporal_single_recovery') IS NOT NULL`
const singleRecoveryCapabilityReadySQL = `SELECT zasp_temporal_single_recovery.ready($1)`

type singleRecoveryCapabilityObservation struct {
	stage              string
	observed, value    bool
	deadline, canceled bool
	sqlstate           string
}

type singleRecoveryCapabilityDiagnosticDriver struct {
	driver PostgresDriver
	mu     sync.Mutex
	last   singleRecoveryCapabilityObservation
}

type singleRecoveryCapabilityDiagnosticTransactionDriver struct {
	*singleRecoveryCapabilityDiagnosticDriver
	transactions AuthorizationTransactionDriver
}

func wrapSingleRecoveryCapabilityDiagnosticDriver(driver PostgresDriver) (PostgresDriver, *singleRecoveryCapabilityDiagnosticDriver) {
	diagnostic := &singleRecoveryCapabilityDiagnosticDriver{driver: driver}
	if transactions, ok := driver.(AuthorizationTransactionDriver); ok {
		return &singleRecoveryCapabilityDiagnosticTransactionDriver{singleRecoveryCapabilityDiagnosticDriver: diagnostic, transactions: transactions}, diagnostic
	}
	return diagnostic, diagnostic
}

func (d *singleRecoveryCapabilityDiagnosticTransactionDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	return d.transactions.Begin(ctx)
}

func (d *singleRecoveryCapabilityDiagnosticDriver) QueryRow(ctx context.Context, query string, args ...any) PostgresRow {
	row := d.driver.QueryRow(ctx, query, args...)
	stage := ""
	switch query {
	case singleRecoveryCapabilityNamespaceSQL:
		stage = "namespace"
	case migrations.TemporalSingleRecoveryReadySourceSQL:
		stage = "source"
	case singleRecoveryCapabilityReadySQL:
		stage = "ready"
	}
	if stage == "" {
		return row
	}
	return singleRecoveryAvailabilityRow(func(values ...any) error {
		err := row.Scan(values...)
		observation := singleRecoveryCapabilityObservation{stage: stage, deadline: errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded), canceled: errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled)}
		if err == nil && len(values) == 1 {
			if value, ok := values[0].(*bool); ok {
				observation.observed, observation.value = true, *value
			}
		}
		var pg *pgconn.PgError
		if errors.As(err, &pg) && validSingleRecoveryDiagnosticSQLState(pg.Code) {
			observation.sqlstate = pg.Code
		}
		d.mu.Lock()
		d.last = observation
		d.mu.Unlock()
		return err
	})
}

func (d *singleRecoveryCapabilityDiagnosticDriver) Exec(ctx context.Context, query string, args ...any) error {
	return d.driver.Exec(ctx, query, args...)
}

func (d *singleRecoveryCapabilityDiagnosticDriver) Close() error { return d.driver.Close() }

func validSingleRecoveryDiagnosticSQLState(value string) bool {
	if len(value) != 5 {
		return false
	}
	for _, c := range []byte(value) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func (d *singleRecoveryCapabilityDiagnosticDriver) summary() string {
	d.mu.Lock()
	observation := d.last
	d.mu.Unlock()
	return fmt.Sprintf("stage=%s observed=%t value=%t deadline=%t canceled=%t sqlstate=%s", observation.stage, observation.observed, observation.value, observation.deadline, observation.canceled, observation.sqlstate)
}

type singleRecoveryCapabilityTransactionSource struct {
	*singleRecoveryAvailabilityBudgetDriver
	tx       pgx.Tx
	beginCtx context.Context
	beginErr error
}

func (d *singleRecoveryCapabilityTransactionSource) Begin(ctx context.Context) (pgx.Tx, error) {
	d.beginCtx = ctx
	return d.tx, d.beginErr
}

const singleRecoveryNativeDiscoveryReadinessSQL = `SELECT zasp_authorization80.ready($1), public.zasp_discovery_principal_ready('zasp_discovery_api')`

type singleRecoveryNativeRoleDriver struct {
	role string
}

func (d *singleRecoveryNativeRoleDriver) QueryRow(_ context.Context, query string, _ ...any) PostgresRow {
	return singleRecoveryAvailabilityRow(func(values ...any) error {
		allowed := false
		switch query {
		case postgresAuthorizationReadySQL:
			allowed = true
		case singleRecoveryNativeDiscoveryReadinessSQL:
			allowed = d.role == "discovery"
		case singleRecoveryCapabilityNamespaceSQL, migrations.TemporalSingleRecoveryReadySourceSQL, singleRecoveryCapabilityReadySQL:
			allowed = d.role == "security-agent"
		}
		if !allowed {
			return &pgconn.PgError{Code: "42501", Message: "role boundary"}
		}
		for _, value := range values {
			result, ok := value.(*bool)
			if !ok {
				return errors.New("unexpected scan type")
			}
			*result = true
		}
		return nil
	})
}

func (*singleRecoveryNativeRoleDriver) Exec(context.Context, string, ...any) error { return nil }
func (*singleRecoveryNativeRoleDriver) Close() error                               { return nil }
func (*singleRecoveryNativeRoleDriver) Begin(context.Context) (pgx.Tx, error) {
	return &authorizationTxFixture{}, nil
}

func singleRecoveryNativeRoleDatabase(t *testing.T, role string) *PostgresJSONDatabase {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&singleRecoveryNativeRoleDriver{role: role})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestSingleRecoveryNativeAuthorityRolesStaySeparated(t *testing.T) {
	base, err := pgxpool.ParseConfig("postgres://setup@127.0.0.1/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	identityConfig := singleRecoveryNativeIdentityPoolConfig(base, "registered_discovery_api")
	if identityConfig == base || identityConfig.ConnConfig.User != "registered_discovery_api" || base.ConnConfig.User != "setup" {
		t.Fatal("identity pool configuration did not retain the registered discovery principal")
	}
	identityProjection, ownerProjection := &pgxpool.Pool{}, &pgxpool.Pool{}
	if got := singleRecoveryNativeProjectionPool(identityProjection, ownerProjection); got != identityProjection {
		t.Fatal("projection revision reader used setup owner instead of registered discovery API")
	}

	identityDatabase := singleRecoveryNativeRoleDatabase(t, "discovery")
	recoveryDatabase := singleRecoveryNativeRoleDatabase(t, "security-agent")
	if !identityDatabase.CurrentAuthorizationRequired() || !recoveryDatabase.CurrentAuthorizationRequired() {
		t.Fatal("native authority lost current authorization enforcement")
	}

	repository, resolver, err := singleRecoveryNativeIdentitySurfaces(identityDatabase, recoveryDatabase)
	if err != nil {
		t.Fatal("identity and recovery authorities were conflated", err)
	}
	if repository.database != identityDatabase || resolver.database != identityDatabase || resolver.securityAgentDatabase != recoveryDatabase {
		t.Fatal("identity repository or resolver used the recovery authority")
	}
	if available, err := recoveryDatabase.SingleTestRecoveryAvailable(context.Background()); err != nil || !available {
		t.Fatal("security-agent authority lost recovery readiness", err)
	}
	observer := recoveryObserverFunc(func(context.Context, orchestration.StartRequest) (orchestration.SingleTestOriginalObservation, error) {
		return orchestration.SingleTestOriginalObservation{}, nil
	})
	authority, err := NewSingleTestRecoveryRepository(recoveryDatabase, observer)
	if err != nil || authority.database != recoveryDatabase {
		t.Fatal("single-recovery repository left the security-agent authority", err)
	}
}

func TestSingleRecoveryCapabilityDiagnosticPreservesTransactionBoundary(t *testing.T) {
	tx := &authorizationTxFixture{}
	source := &singleRecoveryCapabilityTransactionSource{
		singleRecoveryAvailabilityBudgetDriver: &singleRecoveryAvailabilityBudgetDriver{t: t},
		tx:                                     tx,
	}
	wrapper, _ := wrapSingleRecoveryCapabilityDiagnosticDriver(source)
	database, err := NewPostgresJSONDatabase(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RequireCurrentAuthorization(); err != nil {
		t.Fatal("transactional diagnostic wrapper refused current authorization", err)
	}
	transactionDriver, ok := wrapper.(AuthorizationTransactionDriver)
	if !ok {
		t.Fatal("transaction capability was hidden")
	}
	ctx := context.WithValue(context.Background(), struct{ name string }{"diagnostic"}, "preserved")
	gotTx, gotErr := transactionDriver.Begin(ctx)
	if gotErr != nil || gotTx != tx || source.beginCtx != ctx {
		t.Fatalf("transaction delegation changed result or context: tx=%t err=%v context=%t", gotTx == tx, gotErr, source.beginCtx == ctx)
	}
	sentinel := errors.New("begin sentinel")
	source.beginErr = sentinel
	gotTx, gotErr = transactionDriver.Begin(ctx)
	if gotTx != tx || gotErr != sentinel || source.beginCtx != ctx {
		t.Fatalf("transaction error delegation changed result or context: tx=%t err=%v context=%t", gotTx == tx, gotErr, source.beginCtx == ctx)
	}

	nontransactional, _ := wrapSingleRecoveryCapabilityDiagnosticDriver(&singleRecoveryAvailabilityBudgetDriver{t: t})
	if _, ok := nontransactional.(AuthorizationTransactionDriver); ok {
		t.Fatal("nontransactional driver gained authorization transaction capability")
	}
	if _, ok := nontransactional.(integrationRejectionTransactionDriver); ok {
		t.Fatal("diagnostic wrapper synthesized an unrelated transaction capability")
	}
	nontransactionalDatabase, err := NewPostgresJSONDatabase(nontransactional)
	if err != nil {
		t.Fatal(err)
	}
	if err := nontransactionalDatabase.RequireCurrentAuthorization(); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("nontransactional diagnostic wrapper did not fail closed: %v", err)
	}
}

func TestSingleRecoveryCapabilityDiagnosticIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name, query, want string
		err               error
		value             bool
	}{
		{"false", singleRecoveryCapabilityNamespaceSQL, "stage=namespace observed=true value=false deadline=false canceled=false sqlstate=", nil, false},
		{"state", migrations.TemporalSingleRecoveryReadySourceSQL, "stage=source observed=false value=false deadline=false canceled=false sqlstate=42501", &pgconn.PgError{Code: "42501", Message: "private-secret"}, false},
		{"invalid state", singleRecoveryCapabilityReadySQL, "stage=ready observed=false value=false deadline=false canceled=false sqlstate=", &pgconn.PgError{Code: "bad/1", Message: "private-secret"}, false},
		{"deadline", singleRecoveryCapabilityReadySQL, "stage=ready observed=false value=false deadline=true canceled=false sqlstate=57014", errors.Join(context.DeadlineExceeded, &pgconn.PgError{Code: "57014", Message: "private-secret"}), false},
		{"canceled", singleRecoveryCapabilityReadySQL, "stage=ready observed=false value=false deadline=false canceled=true sqlstate=", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &singleRecoveryAvailabilityBudgetDriver{t: t, steps: []singleRecoveryAvailabilityStep{{value: tc.value, err: tc.err}}}
			diagnostic := &singleRecoveryCapabilityDiagnosticDriver{driver: base}
			var value bool
			_ = diagnostic.QueryRow(context.Background(), tc.query).Scan(&value)
			got := diagnostic.summary()
			if got != tc.want || strings.Contains(got, "private-secret") || strings.Contains(got, tc.query) {
				t.Fatalf("unsafe diagnostic: %q", got)
			}
		})
	}
}
