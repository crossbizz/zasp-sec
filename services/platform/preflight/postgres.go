package preflight

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type neonCredentials struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
}

func preflightPostgresConfig(c *NeonConfig, secret []byte) (*pgxpool.Config, error) {
	if c == nil || !validNeon(c) || len(secret) < 1 || len(secret) > 16384 || !uniqueJSON(secret) {
		return nil, ErrRejected
	}
	// The official parser reads service/pass/TLS files before exposing Config.
	// Reject ambient authority first; never mutate process-global environment.
	for _, entry := range os.Environ() {
		k, v, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(k, "PG") && v != "" {
			return nil, ErrRejected
		}
	}
	var credentials neonCredentials
	d := json.NewDecoder(bytes.NewReader(secret))
	d.DisallowUnknownFields()
	if d.Decode(&credentials) != nil || credentials.Host != c.ExpectedHost || credentials.Port != 5432 || credentials.Database != c.ExpectedDatabase || credentials.User != c.ExpectedPrincipal || !validCredentialValue(credentials.Password, 1, 4096) {
		return nil, ErrRejected
	}
	// Fixed never-connected parser seed preserves official private parsed flags.
	// No real credential enters ConnString or any error. Every actual connection
	// field below is replaced together before this config can reach a pool.
	config, e := pgxpool.ParseConfig("host=preflight.invalid port=5432 dbname=preflight user=preflight password=unused sslmode=disable passfile=/dev/null sslcert='' sslkey='' sslrootcert='' connect_timeout=5")
	if e != nil {
		return nil, ErrRejected
	}
	conn := config.ConnConfig
	conn.Host = credentials.Host
	conn.Port = 5432
	conn.Database = credentials.Database
	conn.User = credentials.User
	conn.Password = credentials.Password
	conn.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: credentials.Host}
	conn.Fallbacks = nil
	conn.ConnectTimeout = 5 * time.Second
	conn.DialFunc = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	conn.LookupFunc = (&net.Resolver{PreferGo: true}).LookupHost
	conn.RuntimeParams = map[string]string{"application_name": "agentsecctl-preflight", "jit": "off"}
	conn.KerberosSrvName = ""
	conn.KerberosSpn = ""
	conn.SSLNegotiation = "postgres"
	conn.ValidateConnect = nil
	conn.AfterConnect = nil
	conn.AfterNetConnect = nil
	conn.OnNotice = nil
	conn.OnNotification = nil
	conn.OnPgError = nil
	conn.OAuthTokenProvider = nil
	conn.MinProtocolVersion = "3.0"
	conn.MaxProtocolVersion = "3.0"
	conn.ChannelBinding = "prefer"
	conn.RequireAuth = "scram-sha-256"
	conn.Tracer = nil
	conn.StatementCacheCapacity = 0
	conn.DescriptionCacheCapacity = 0
	conn.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.BeforeConnect = nil
	config.AfterConnect = nil
	config.BeforeAcquire = nil
	config.PrepareConn = nil
	config.AfterRelease = nil
	config.BeforeClose = nil
	config.ShouldPing = nil
	config.MinConns = 0
	config.MinIdleConns = 0
	config.MaxConns = 1
	config.MaxConnLifetime = time.Minute
	config.MaxConnLifetimeJitter = 0
	config.MaxConnIdleTime = time.Minute
	config.HealthCheckPeriod = time.Minute
	config.PingTimeout = 5 * time.Second
	return config, nil
}

const preflightDatabaseIdentitySQL = `SELECT pg_catalog.current_database(),session_user::text,current_user::text,pg_catalog.current_setting('server_version_num')::bigint`

type postgresProbeTx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Rollback(context.Context) error
}
type postgresProbePool interface {
	Ping(context.Context) error
	BeginTx(context.Context, pgx.TxOptions) (postgresProbeTx, error)
	Close()
}
type postgresProbeFactory func(context.Context, *pgxpool.Config) (postgresProbePool, error)
type actualPostgresProbePool struct{ pool *pgxpool.Pool }

func (p *actualPostgresProbePool) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }
func (p *actualPostgresProbePool) BeginTx(ctx context.Context, opts pgx.TxOptions) (postgresProbeTx, error) {
	return p.pool.BeginTx(ctx, opts)
}
func (p *actualPostgresProbePool) Close() { p.pool.Close() }
func newPostgresProbePool(ctx context.Context, c *pgxpool.Config) (postgresProbePool, error) {
	p, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		return nil, e
	}
	return &actualPostgresProbePool{p}, nil
}
func (r *Runner) observeNeon(ctx context.Context, report *Report, c *NeonConfig) {
	r.observeNeonWithFactory(ctx, report, c, newPostgresProbePool)
}
func (r *Runner) observeNeonWithFactory(ctx context.Context, report *Report, c *NeonConfig, factory postgresProbeFactory) {
	if c == nil || ctx == nil || !validNeon(c) {
		return
	}
	target := neonTarget(r.config, c)
	body, e := privateFile(c.CredentialFile, 16384)
	if e != nil {
		r.record(report, "neon_pool_reachable", false, "credentials_unavailable", "none", target, false)
		return
	}
	defer clear(body)
	config, e := preflightPostgresConfig(c, body)
	if e != nil {
		r.record(report, "neon_pool_reachable", false, "explicit_connection_configuration_rejected", "none", target, false)
		return
	}
	defer func() { config.ConnConfig.Password = "" }()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, e := factory(bounded, config)
	if e != nil || pool == nil {
		r.neonFailure(report, "neon_pool_reachable", "postgres:Connect", target, postgresOutcome(e))
		return
	}
	defer pool.Close()
	operation, stop := context.WithTimeout(bounded, 10*time.Second)
	e = pool.Ping(operation)
	if operation.Err() != nil {
		e = operation.Err()
	}
	stop()
	if e != nil {
		r.neonFailure(report, "neon_pool_reachable", "postgres:Connect", target, postgresOutcome(e))
		return
	}
	operation, stop = context.WithTimeout(bounded, 10*time.Second)
	tx, e := pool.BeginTx(operation, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if operation.Err() != nil {
		e = operation.Err()
	}
	stop()
	if e != nil || tx == nil {
		r.neonFailure(report, "neon_pool_reachable", "postgres:Connect", target, postgresOutcome(e))
		return
	}
	rolledBack := false
	defer func() {
		if !rolledBack {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(bounded), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		}
	}()
	var database, sessionUser, currentUser string
	var serverVersion int64
	operation, stop = context.WithTimeout(bounded, 10*time.Second)
	e = tx.QueryRow(operation, preflightDatabaseIdentitySQL).Scan(&database, &sessionUser, &currentUser, &serverVersion)
	if operation.Err() != nil {
		e = operation.Err()
	}
	stop()
	if e != nil {
		r.neonFailure(report, "neon_pool_reachable", "postgres:Connect", target, postgresOutcome(e))
		return
	}
	if database != c.ExpectedDatabase || sessionUser != c.ExpectedPrincipal || currentUser != c.ExpectedPrincipal || serverVersion < 100000 || serverVersion > 999999 {
		r.neonFailure(report, "neon_pool_reachable", "postgres:Connect", target, "binding_mismatch")
		return
	}
	r.record(report, "neon_pool_reachable", true, "database_connection_unavailable", "operator", target, true)
	queryer := &preflightMigrationQueryer{tx: tx}
	state, e := migrations.ObservePreflightProfile(bounded, queryer, c.ProfileRecipe)
	if e != nil {
		outcome := queryer.failure
		if bounded.Err() != nil || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			outcome = "unreachable"
		} else if outcome == "" {
			outcome = "binding_mismatch"
		}
		r.neonFailure(report, "neon_migration_compatible", "postgres:InspectProfile", target, outcome)
		return
	}
	operation, stop = context.WithTimeout(bounded, 10*time.Second)
	e = tx.Rollback(operation)
	if operation.Err() != nil {
		e = operation.Err()
	}
	stop()
	rolledBack = true
	if e != nil {
		r.neonFailure(report, "neon_migration_compatible", "postgres:InspectProfile", target, postgresOutcome(e))
		return
	}
	if state.Installed && state.CanonicalVersion == 61 && state.Code == "current" {
		r.record(report, "neon_migration_compatible", true, "profile_unavailable", "operator", target, true)
		dependencyCode(report, "neon_migration_compatible", "observed_current_compiled_profile")
	} else if state.Code == "not_installed" && report.Mode == "before-install" {
		dependencyCode(report, "neon_migration_compatible", "not_installed")
	} else {
		r.neonFailure(report, "neon_migration_compatible", "postgres:InspectProfile", target, "binding_mismatch")
	}
}
func (r *Runner) neonFailure(report *Report, name, operation string, target any, outcome string) {
	r.record(report, name, false, "database_observation_unavailable", "operator", target, true)
	r.dependencyFailure(report, name, operation, target, outcome)
}
func neonTarget(config Config, c *NeonConfig) any {
	return struct {
		Scope     Scope  `json:"intended_scope"`
		Host      string `json:"host"`
		Database  string `json:"database"`
		Principal string `json:"principal"`
		Profile   string `json:"profile_recipe"`
	}{config.Scope, c.ExpectedHost, c.ExpectedDatabase, c.ExpectedPrincipal, c.ProfileRecipe}
}
func postgresOutcome(e error) string {
	if e == nil {
		return "binding_mismatch"
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) {
		switch pg.Code {
		case "42501", "28000", "28P01":
			return "denied"
		case "3D000", "42P01", "42883", "3F000":
			return "binding_mismatch"
		case "22P02", "08P01":
			return "malformed"
		}
	}
	return "unreachable"
}

type preflightMigrationQueryer struct {
	tx      postgresProbeTx
	failure string
}

func (q *preflightMigrationQueryer) QueryRow(ctx context.Context, statement string, args ...any) migrations.Row {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	return preflightMigrationRow{row: q.tx.QueryRow(bounded, statement, args...), queryer: q, ctx: bounded, cancel: cancel}
}

type preflightMigrationRow struct {
	ctx     context.Context
	cancel  context.CancelFunc
	row     pgx.Row
	queryer *preflightMigrationQueryer
}

func (row preflightMigrationRow) Scan(dest ...any) error {
	defer row.cancel()
	e := row.row.Scan(dest...)
	if row.ctx.Err() != nil && e == nil {
		e = row.ctx.Err()
	}
	if e != nil && row.queryer.failure == "" {
		row.queryer.failure = postgresOutcome(e)
	}
	return e
}
