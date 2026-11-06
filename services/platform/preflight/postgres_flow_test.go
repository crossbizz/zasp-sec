package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresProbeFixture struct {
	mode                        string
	queries, rollbacks          int
	closed, readonly, forbidden bool
}

func (f *postgresProbeFixture) Ping(context.Context) error {
	if f.mode == "denied" {
		return &pgconn.PgError{Code: "28P01", Message: "NEVER_REFLECT_DATABASE_TEXT"}
	}
	return nil
}
func (f *postgresProbeFixture) BeginTx(_ context.Context, options pgx.TxOptions) (postgresProbeTx, error) {
	f.readonly = options.AccessMode == pgx.ReadOnly && options.IsoLevel == pgx.ReadCommitted
	return f, nil
}
func (f *postgresProbeFixture) Close() { f.closed = true }
func (f *postgresProbeFixture) Rollback(context.Context) error {
	f.rollbacks++
	if f.mode == "rollback-error" {
		return errors.New("NEVER_REFLECT_DATABASE_TEXT")
	}
	return nil
}
func (f *postgresProbeFixture) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	f.queries++
	if !strings.HasPrefix(strings.TrimSpace(q), "SELECT ") {
		f.forbidden = true
	}
	if q == preflightDatabaseIdentitySQL {
		principal := "zasp_api_runtime"
		if f.mode == "wrong-principal" {
			principal = "owner"
		}
		return postgresProbeFixtureRow{values: []any{"zasp", principal, principal, int64(180004)}}
	}
	if f.mode == "profile-denied" {
		return postgresProbeFixtureRow{err: &pgconn.PgError{Code: "42501", Message: "NEVER_REFLECT_DATABASE_TEXT"}}
	}
	return postgresProbeFixtureRow{values: []any{f.mode == "partial" && strings.Contains(q, "pg_catalog.pg_namespace")}}
}

type postgresProbeFixtureRow struct {
	values []any
	err    error
}

func (r postgresProbeFixtureRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("controlled arity mismatch")
	}
	for i, v := range r.values {
		switch d := dest[i].(type) {
		case *string:
			x, ok := v.(string)
			if !ok {
				return errors.New("controlled type mismatch")
			}
			*d = x
		case *int64:
			x, ok := v.(int64)
			if !ok {
				return errors.New("controlled type mismatch")
			}
			*d = x
		case *bool:
			x, ok := v.(bool)
			if !ok {
				return errors.New("controlled type mismatch")
			}
			*d = x
		default:
			return errors.New("controlled destination mismatch")
		}
	}
	return nil
}
func neonProbeConfig(t *testing.T) *NeonConfig {
	t.Helper()
	file := filepath.Join(t.TempDir(), "database.json")
	body := []byte(`{"host":"ep-selected-pooler.us-west-2.aws.neon.tech","port":5432,"database":"zasp","user":"zasp_api_runtime","password":"fixture-database-secret"}`)
	if os.WriteFile(file, body, 0600) != nil {
		t.Fatal("controlled private database source unavailable")
	}
	return &NeonConfig{CredentialFile: file, ExpectedHost: "ep-selected-pooler.us-west-2.aws.neon.tech", ExpectedDatabase: "zasp", ExpectedPrincipal: "zasp_api_runtime", ProfileRecipe: "worker-v1"}
}
func TestReadOnlyPoolObservationAndAbsentInstallBoundary(t *testing.T) {
	for _, mode := range []string{"before-install", "installed", "wrong-principal", "denied", "profile-denied", "partial", "rollback-error", "ambient-block"} {
		t.Run(mode, func(t *testing.T) {
			config := neonProbeConfig(t)
			f := &postgresProbeFixture{mode: mode}
			r := &Runner{config: sdkContractConfig(t)}
			runMode := "before-install"
			if mode == "installed" {
				runMode = "installed"
			}
			report := initialReport(r.config, runMode)
			calls := 0
			if mode == "ambient-block" {
				t.Setenv("PGSERVICE", "foreign")
			}
			factory := func(ctx context.Context, got *pgxpool.Config) (postgresProbePool, error) {
				calls++
				if got.ConnConfig.Host != config.ExpectedHost || got.ConnConfig.TLSConfig == nil || got.ConnConfig.TLSConfig.InsecureSkipVerify || len(got.ConnConfig.Fallbacks) != 0 {
					t.Fatal("production pool factory received redirected or insecure config")
				}
				return f, nil
			}
			r.observeNeonWithFactory(context.Background(), &report, config, factory)
			pool, profile := report.Checks[5].Observations[1], report.Checks[5].Observations[0]
			if mode == "ambient-block" {
				if calls != 0 || f.queries != 0 || pool.Status == "pass" {
					t.Fatal("ambient authority reached actual dial/pool boundary")
				}
				return
			}
			if calls != 1 || !f.closed || f.forbidden || mode != "denied" && (!f.readonly || f.rollbacks < 1) {
				t.Fatal("pool lifecycle, read-only transaction or SELECT-only boundary lost")
			}
			switch mode {
			case "before-install":
				if pool.Status != "pass" || profile.Status != "unobserved" || profile.Code != "not_installed" {
					t.Fatal("pool truth and absent schema conflated")
				}
			case "wrong-principal", "denied":
				if pool.Status == "pass" || len(pool.Failures) != 1 {
					t.Fatal("wrong or denied identity accepted")
				}
			default:
				if profile.Status == "pass" || len(profile.Failures) != 1 {
					t.Fatal("missing, partial, denied or uncertain profile accepted")
				}
			}
			raw, _ := json.Marshal(report)
			if strings.Contains(string(raw), "NEVER_REFLECT_DATABASE_TEXT") || strings.Contains(string(raw), "fixture-database-secret") {
				t.Fatal("database credential or dependency text leaked")
			}
			if report.Ready || report.ProductionEndToEndVerified {
				t.Fatal("metadata became complete deployment acceptance")
			}
		})
	}
}
