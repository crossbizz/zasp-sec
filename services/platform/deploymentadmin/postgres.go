package deploymentadmin

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
)

type store interface {
	attempt(context.Context, string) (bool, error)
	start(context.Context, []byte, time.Time) error
	expiration(context.Context, []byte) (time.Time, error)
	revoke(context.Context, []byte) error
	settings(context.Context) (Settings, error)
	update(context.Context, int64, Pointers) (Settings, error)
}

type postgres struct {
	pool *pgxpool.Pool
	id   string
}

const schema = `
CREATE SCHEMA IF NOT EXISTS deployment_console;
CREATE TABLE IF NOT EXISTS deployment_console.installation(
	singleton boolean PRIMARY KEY CHECK(singleton),
	deployment_id text NOT NULL UNIQUE,
	public_origin text NOT NULL,
	version bigint NOT NULL DEFAULT 1 CHECK(version>0),
	pointers jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS deployment_console.sessions(
	deployment_id text NOT NULL REFERENCES deployment_console.installation(deployment_id),
	digest bytea PRIMARY KEY,
	expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS deployment_console.login_attempts(
	deployment_id text NOT NULL REFERENCES deployment_console.installation(deployment_id),
	bucket text NOT NULL,
	start_at timestamptz NOT NULL,
	attempts integer NOT NULL,
	PRIMARY KEY(deployment_id,bucket)
);`

func openPostgres(ctx context.Context, c *Config) (*postgres, error) {
	poolConfig, err := runtimepostgres.ParsePoolConfig(c.dsn)
	if err != nil {
		return nil, errConfig
	}
	poolConfig.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errConfig
	}
	s := &postgres{pool: pool, id: c.id}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// Concurrent API replicas may initialize the same freshly provisioned DB.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(4061451149007)"); err != nil {
			return err
		}
		var dedicated bool
		err := tx.QueryRow(ctx, `SELECT current_database() NOT IN ('postgres','template0','template1') AND
			d.datdba=r.oid AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls OR r.rolreplication) AND
			NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid) AND
			NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public','information_schema','deployment_console') AND left(nspname,3)<>'pg_') AND
			NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace)
			FROM pg_database d,pg_roles r WHERE d.datname=current_database() AND r.rolname=current_user`).Scan(&dedicated)
		if err != nil || !dedicated {
			return errConfig
		}
		if _, err = tx.Exec(ctx, schema); err != nil {
			return err
		}
		seed, err := json.Marshal(c.initial)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO deployment_console.installation(singleton,deployment_id,public_origin,pointers)
			VALUES(true,$1,$2,$3) ON CONFLICT(singleton) DO NOTHING`, c.id, c.origin, seed)
		if err != nil {
			return err
		}
		var bound bool
		if err = tx.QueryRow(ctx, `SELECT deployment_id=$1 AND public_origin=$2 FROM deployment_console.installation WHERE singleton`, c.id, c.origin).Scan(&bound); err != nil || !bound {
			return errConfig
		}
		return nil
	})
	if err != nil {
		pool.Close()
		return nil, errConfig
	}
	return s, nil
}
func (s *postgres) Close() error { s.pool.Close(); return nil }

func (s *postgres) attempt(ctx context.Context, peer string) (bool, error) {
	var allowed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialize the admission decision across API replicas. Once a source
		// reaches its limit it cannot consume the remaining deployment budget.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(4061451149008)"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM deployment_console.login_attempts WHERE deployment_id=$1 AND start_at < now()-interval '2 minutes'`, s.id); err != nil {
			return err
		}
		source := "ip:" + peer
		err := tx.QueryRow(ctx, `SELECT NOT EXISTS (
			SELECT 1 FROM deployment_console.login_attempts WHERE deployment_id=$1 AND start_at>=date_trunc('minute',now())
			AND ((bucket='all' AND attempts>=60) OR (bucket=$2 AND attempts>=6)))`, s.id, source).Scan(&allowed)
		if err != nil || !allowed {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO deployment_console.login_attempts AS a(deployment_id,bucket,start_at,attempts)
			VALUES ($1,'all',date_trunc('minute',now()),1), ($1,$2,date_trunc('minute',now()),1)
			ON CONFLICT(deployment_id,bucket) DO UPDATE SET start_at=excluded.start_at,
				attempts=CASE WHEN a.start_at < excluded.start_at THEN 1 ELSE a.attempts+1 END`, s.id, source)
		return err
	})
	return allowed, err
}

func (s *postgres) start(ctx context.Context, digest []byte, expires time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM deployment_console.sessions WHERE deployment_id=$1 AND expires_at<=now()`, s.id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO deployment_console.sessions(deployment_id,digest,expires_at) VALUES($1,$2,$3)`, s.id, digest, expires)
		return err
	})
}
func (s *postgres) expiration(ctx context.Context, digest []byte) (time.Time, error) {
	var expiry time.Time
	err := s.pool.QueryRow(ctx, `SELECT expires_at FROM deployment_console.sessions WHERE deployment_id=$1 AND digest=$2 AND expires_at>now()`, s.id, digest).Scan(&expiry)
	return expiry, err
}
func (s *postgres) revoke(ctx context.Context, digest []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM deployment_console.sessions WHERE deployment_id=$1 AND digest=$2`, s.id, digest)
	return err
}
func (s *postgres) read(row pgx.Row) (Settings, error) {
	v := Settings{DeploymentID: s.id}
	err := row.Scan(&v.Version, &v.Pointers)
	return v, err
}
func (s *postgres) settings(ctx context.Context) (Settings, error) {
	return s.read(s.pool.QueryRow(ctx, `SELECT version,pointers FROM deployment_console.installation WHERE deployment_id=$1`, s.id))
}

var errConflict = errors.New("settings version changed")

func (s *postgres) update(ctx context.Context, version int64, p Pointers) (Settings, error) {
	v, err := s.read(s.pool.QueryRow(ctx, `UPDATE deployment_console.installation SET version=version+1,pointers=$3 WHERE deployment_id=$1 AND version=$2 RETURNING version,pointers`, s.id, version, p))
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, errConflict
	}
	return v, err
}
