package sandboxcutover

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type PostgresDatabase struct {
	config              *pgx.ConnConfig
	principal, identity string
}

// NewPostgresDatabase binds a dedicated migration-owner connection to the
// deployment's configured database identity. It neither registers principals nor
// grants access. TLS/endpoint provenance belongs to the trusted configuration
// loader; there is no DSN discovery or production CLI in this package.
func NewPostgresDatabase(config *pgx.ConnConfig, expectedPrincipal, identity string) (*PostgresDatabase, error) {
	if config == nil || !text(config.Host) || config.Port == 0 || !text(config.Database) || config.User != expectedPrincipal || !text(expectedPrincipal) || !text(identity) {
		return nil, errRejected
	}
	return &PostgresDatabase{config.Copy(), expectedPrincipal, identity}, nil
}

func (database *PostgresDatabase) Capture(ctx context.Context, binding ReleaseBinding) (Capture, error) {
	if !database.valid(ctx, binding) {
		return Capture{}, errRejected
	}
	ctx, cancel := context.WithTimeout(ctx, evidenceLifetime)
	defer cancel()
	conn, err := database.connect(ctx)
	if err != nil {
		return Capture{}, errRejected
	}
	defer closeCutoverConnection(conn)
	if err := database.ready(ctx, conn); err != nil {
		return Capture{}, errRejected
	}
	return captureReceipts(ctx, conn)
}

func (database *PostgresDatabase) WithFence(ctx context.Context, binding ReleaseBinding, fn func(Fence) error) (result FenceResult, operationErr error) {
	if !database.valid(ctx, binding) || fn == nil {
		return result, errRejected
	}
	ctx, cancel := context.WithTimeout(ctx, fenceLifetime)
	defer cancel()
	conn, err := database.connect(ctx)
	if err != nil {
		return result, errRejected
	}
	var tx pgx.Tx
	var pid uint32
	var backendStart time.Time
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		var rollbackErr error
		if tx != nil {
			rollbackErr = tx.Rollback(cleanup)
		}
		closeErr := conn.Close(cleanup)
		result.CleanupConfirmed = rollbackErr == nil && closeErr == nil
		if !result.CleanupConfirmed && pid != 0 && !backendStart.IsZero() {
			result.CleanupConfirmed = database.backendGone(cleanup, pid, backendStart)
		}
		if !result.CleanupConfirmed {
			operationErr = errors.Join(operationErr, errRejected)
		}
	}()
	if err := database.owner(ctx, conn); err != nil {
		return result, errRejected
	}
	pid = conn.PgConn().PID()
	if err := conn.QueryRow(ctx, `SELECT backend_start FROM pg_catalog.pg_stat_activity WHERE pid=pg_backend_pid()`).Scan(&backendStart); err != nil {
		return result, errRejected
	}
	tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, errRejected
	}
	// Startup parameters also bound connection setup, but the transaction must
	// not get a fresh full window after slow authentication/owner checks. Re-arm
	// its server timeout using the remaining absolute fence deadline. PostgreSQL
	// does not shorten an already active transaction timer on a nonzero SET.
	// Disable/re-enable before acquiring any of the fence locks; a failed setup
	// therefore cannot leave an unbounded application lock set.
	if _, err := tx.Exec(ctx, `SET LOCAL transaction_timeout=0`); err != nil {
		return result, errRejected
	}
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return result, errRejected
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('transaction_timeout',$1,true),set_config('statement_timeout',$2,true)`, strconv.FormatInt(max(1, remaining.Milliseconds()), 10), strconv.FormatInt(max(1, min(remaining, 5*time.Second).Milliseconds()), 10)); err != nil {
		return result, errRejected
	}
	for _, statement := range []string{
		`LOCK TABLE public.zasp_schema_versions,public.zasp_schema_metadata IN SHARE MODE NOWAIT`,
		`LOCK TABLE public.zasp_runtime_session_projection_receipts,public.zasp_runtime_sandbox_search_outbox IN SHARE ROW EXCLUSIVE MODE NOWAIT`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return result, errRejected
		}
	}
	fence := &postgresFence{database: database, tx: tx, ctx: ctx}
	if err := fence.Ready(ctx); err != nil {
		return result, errRejected
	}
	operationErr = fn(fence)
	if operationErr == nil && ctx.Err() != nil {
		operationErr = ctx.Err()
	}
	return result, operationErr
}

func (database *PostgresDatabase) valid(ctx context.Context, binding ReleaseBinding) bool {
	return database != nil && database.config != nil && ctx != nil && ctx.Err() == nil && binding.DatabaseIdentity == database.identity
}

func (database *PostgresDatabase) connect(ctx context.Context) (*pgx.Conn, error) {
	config := database.config.Copy()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errRejected
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, errRejected
	}
	config.ConnectTimeout = min(remaining, 5*time.Second)
	if config.RuntimeParams == nil {
		config.RuntimeParams = map[string]string{}
	}
	config.RuntimeParams["transaction_timeout"] = strconv.FormatInt(max(1, remaining.Milliseconds()), 10)
	config.RuntimeParams["statement_timeout"] = strconv.FormatInt(max(1, min(remaining, 5*time.Second).Milliseconds()), 10)
	return pgx.ConnectConfig(ctx, config)
}

type rowQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (database *PostgresDatabase) owner(ctx context.Context, q rowQuery) error {
	var allowed bool
	err := q.QueryRow(ctx, `SELECT session_user=$1 AND current_user=$1 AND current_database()=$2 AND pg_has_role(session_user,'zasp_discovery_authority','USAGE') AND current_setting('session_replication_role')='origin' AND current_setting('row_security')='on'`, database.principal, database.config.Database).Scan(&allowed)
	if err != nil || !allowed {
		return errRejected
	}
	return nil
}

func (database *PostgresDatabase) ready(ctx context.Context, q rowQuery) error {
	if err := database.owner(ctx, q); err != nil {
		return errRejected
	}
	runner, err := migrations.NewRunner(migrationReader{q})
	if err != nil {
		return errRejected
	}
	version, err := runner.Version(ctx)
	if err != nil || version != 50 {
		return errRejected
	}
	var ready bool
	err = q.QueryRow(ctx, `SELECT public.zasp_production_runtime_sandbox_binding_readiness($1,$2)`, migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready)
	if err != nil || !ready || ctx.Err() != nil {
		return errRejected
	}
	return nil
}

// Version performs exact compiled registry checks. This adapter intentionally
// cannot begin a migration transaction or expose a migration mutation path.
type migrationReader struct{ q rowQuery }

func (r migrationReader) QueryRow(ctx context.Context, s string, args ...any) migrations.Row {
	return r.q.QueryRow(ctx, s, args...)
}
func (r migrationReader) Begin(context.Context) (migrations.Transaction, error) {
	return nil, errRejected
}

type postgresFence struct {
	database *PostgresDatabase
	tx       pgx.Tx
	ctx      context.Context
}

func (f *postgresFence) operation(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil || f.ctx.Err() != nil {
		return nil, nil, errRejected
	}
	deadline, _ := f.ctx.Deadline()
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	bounded, cancel := context.WithDeadline(f.ctx, deadline)
	stop := context.AfterFunc(ctx, cancel)
	return bounded, func() { stop(); cancel() }, nil
}
func (f *postgresFence) Ready(ctx context.Context) error {
	ctx, done, err := f.operation(ctx)
	if err != nil {
		return err
	}
	defer done()
	return f.database.ready(ctx, f.tx)
}
func (f *postgresFence) Capture(ctx context.Context) (Capture, error) {
	ctx, done, err := f.operation(ctx)
	if err != nil {
		return Capture{}, err
	}
	defer done()
	if err := f.database.ready(ctx, f.tx); err != nil {
		return Capture{}, err
	}
	return captureReceipts(ctx, f.tx)
}
func (f *postgresFence) AliveAt(ctx context.Context) (time.Time, error) {
	ctx, done, err := f.operation(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer done()
	var now time.Time
	if err := f.tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || ctx.Err() != nil {
		return time.Time{}, errRejected
	}
	return now.UTC(), nil
}

func closeCutoverConnection(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}

func (database *PostgresDatabase) backendGone(ctx context.Context, pid uint32, start time.Time) bool {
	probe, err := database.connect(ctx)
	if err != nil {
		return false
	}
	defer closeCutoverConnection(probe)
	for ctx.Err() == nil {
		var absent bool
		if probe.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND backend_start=$2)`, pid, start).Scan(&absent) != nil {
			return false
		}
		if absent {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}
