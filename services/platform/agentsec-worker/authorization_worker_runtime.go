package main

import (
	"context"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Keep installed partial profiles out of every actual runtime, including
// callers whose native role cannot inspect private profile readiness.
func workerProductionProfileReady(ctx context.Context, pool *pgxpool.Pool) error {
	return workerLegacyProductionProfileReady(ctx, pool)
}

type workerProfileQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Only the seven current runtime-pipeline modes have a separate native gate.
// This does not enable any unfinished forward-effect worker composition.
func workerStartupProfileReady(ctx context.Context, pool workerProfileQuery, config workerRuntimeConfig) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(pool) || !validWorkerRuntimeDatabaseProfile(config) {
		return errRuntimeUnavailable
	}
	if workerUsesCurrentRuntimeProfile(config) {
		authority := runtimeDatabaseAuthority(config.Mode)
		if config.DatabaseAuthority != authority {
			return errRuntimeUnavailable
		}
		var ready bool
		if err := pool.QueryRow(ctx, `SELECT zasp_authorization80_runtime.ready($1,$2)`, migrations.AuthorizationRuntimeProfileChecksum(), authority).Scan(&ready); err != nil || !ready {
			return errRuntimeUnavailable
		}
		return nil
	}
	return workerLegacyProductionProfileReady(ctx, pool)
}

func workerLegacyProductionProfileReady(ctx context.Context, pool workerProfileQuery) error {
	if ctx == nil || nilWorkerDependency(pool) {
		return errRuntimeUnavailable
	}
	var installed, ready bool
	if err := pool.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_worker') IS NOT NULL`).Scan(&installed); err != nil {
		return errRuntimeUnavailable
	}
	if !installed {
		return nil
	}
	if err := pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.runtime_ready()`).Scan(&ready); err != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}

func temporalWorkerProductionProfileReady(ctx context.Context, dsn string) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errRuntimeUnavailable
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(bounded, cfg)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer pool.Close()
	return workerProductionProfileReady(bounded, pool)
}

// The runtime owns both pools and the authenticated SDK checker. An installed
// private profile never falls back to the retained unproved adapter.
func bindTemporalWorkerAuthorization(ctx context.Context, cfg workerRuntimeConfig, checker authorization.Checker, p *temporalSecurityAgentProduct, pools []*pgxpool.Pool) error {
	if ctx == nil || p == nil || len(pools) != 2 || pools[0] == nil || pools[1] == nil {
		return errRuntimeUnavailable
	}
	var installed [2]bool
	for i, pool := range pools {
		if err := pool.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_worker') IS NOT NULL`).Scan(&installed[i]); err != nil {
			return errRuntimeUnavailable
		}
	}
	if installed[0] != installed[1] {
		return errRuntimeUnavailable
	}
	if !installed[0] {
		if cfg.WorkerAuthorizationKeyFile != "" || cfg.CompensationAuthorizationKeyFile != "" {
			return errRuntimeUnavailable
		}
		return nil
	}
	if checker == nil || cfg.WorkerAuthorizationKeyFile == "" || cfg.CompensationAuthorizationKeyFile == "" || cfg.WorkerAuthorizationKeyFile == cfg.CompensationAuthorizationKeyFile {
		return errRuntimeUnavailable
	}
	forwardFile, err := os.Lstat(cfg.WorkerAuthorizationKeyFile)
	if err != nil {
		return errRuntimeUnavailable
	}
	compensationFile, err := os.Lstat(cfg.CompensationAuthorizationKeyFile)
	if err != nil || os.SameFile(forwardFile, compensationFile) {
		return errRuntimeUnavailable
	}
	keys := make([]*authorization.WorkerKey, 2)
	for i, input := range []struct {
		purpose authorization.WorkerPurpose
		path    string
	}{{authorization.WorkerForward, cfg.WorkerAuthorizationKeyFile}, {authorization.CapturedCompensation, cfg.CompensationAuthorizationKeyFile}} {
		key, err := authorization.LoadWorkerKeyFile(input.purpose, input.path)
		if err != nil {
			return errRuntimeUnavailable
		}
		keys[i] = key
	}
	forward, err := authorization.NewWorkerExecutor(pools[0], checker, cfg.RuntimeServices.StoreID, cfg.RuntimeServices.ModelID, keys[0])
	if err != nil {
		return errRuntimeUnavailable
	}
	compensation, err := authorization.NewWorkerExecutor(pools[1], nil, "", "", keys[1])
	if err != nil {
		return errRuntimeUnavailable
	}
	if forward.Ready(ctx) != nil || compensation.Ready(ctx) != nil {
		return errRuntimeUnavailable
	}
	p.workerForward, p.workerCompensation = forward, compensation
	return nil
}
