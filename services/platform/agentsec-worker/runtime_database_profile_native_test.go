package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestP7CurrentRuntimeSQLStartupNative(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_RUNTIME_PROFILE_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned current runtime fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ownerCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("owned config")
	}
	ownerCfg.MaxConns = 1
	ownerCfg.MinConns = 0
	owner, err := pgxpool.NewWithConfig(ctx, ownerCfg)
	if err != nil {
		t.Fatal("owned connection")
	}
	defer owner.Close()
	for _, mode := range []workerMode{workerModeRuntimeCoordinator, workerModeRuntimeArchive, workerModeRuntimeIndex, workerModeRuntimeCorrelation, workerModeRuntimeProjection, workerModeRuntimeComplete} {
		t.Run(string(mode), func(t *testing.T) {
			c := workerRuntimeConfig{Mode: mode, RuntimeDatabaseProfile: migrations.AuthorizationRuntimeProfileName, DatabaseAuthority: runtimeDatabaseAuthority(mode)}
			cfg := ownerCfg.Copy()
			if err := owner.QueryRow(ctx, `SELECT principal_name::text FROM zasp_runtime_principal_bindings WHERE authority_role=$1`, c.DatabaseAuthority).Scan(&cfg.ConnConfig.User); err != nil {
				t.Fatal("registered fixture principal", err)
			}
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			if err := workerStartupProfileReady(ctx, pool, c); err != nil {
				t.Fatal("registered SQL-only startup refused", err)
			}
			if workerProductionProfileReady(ctx, pool) == nil {
				t.Fatal("partial full-worker gate unexpectedly open")
			}
			if workerStartupProfileReady(ctx, owner, c) == nil {
				t.Fatal("unregistered startup login accepted")
			}
			wrong := c
			wrong.DatabaseAuthority = "zasp_security_agent_worker"
			if workerStartupProfileReady(ctx, pool, wrong) == nil {
				t.Fatal("wrong startup role accepted")
			}
			wrong = c
			wrong.Mode = workerModeSecurityAgent
			if workerStartupProfileReady(ctx, pool, wrong) == nil {
				t.Fatal("foreign worker bypassed full gate")
			}
			wrong = c
			wrong.RuntimeDatabaseProfile = "unknown"
			if workerStartupProfileReady(ctx, pool, wrong) == nil {
				t.Fatal("unknown startup profile accepted")
			}
			wrong = c
			wrong.RuntimeDatabaseProfile = ""
			if workerStartupProfileReady(ctx, pool, wrong) == nil {
				t.Fatal("historical startup accepted installed partial profile")
			}
		})
	}
}
