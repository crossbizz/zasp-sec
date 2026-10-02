package main

import (
	"context"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// Installed worker profiles cannot reach old unsigned adapters. The native
// all-family readiness gate remains false during staged implementation.
func adapterProductionProfile(ctx context.Context, db redteamadapter.JSONDatabase, configured bool) (bool, error) {
	if ctx == nil || ctx.Err() != nil || db == nil {
		return false, errRuntimeUnavailable
	}
	d := boundedAdapterDatabase{db}
	raw, err := d.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_authorization80_worker') IS NOT NULL)`)
	if err != nil || string(raw) != "true" && string(raw) != "false" {
		return false, errRuntimeUnavailable
	}
	installed := string(raw) == "true"
	if installed != configured {
		return false, errRuntimeUnavailable
	}
	if !installed {
		return false, nil
	}
	raw, err = d.QueryJSON(ctx, `SELECT to_jsonb(zasp_authorization80_worker.runtime_ready())`)
	if err != nil || string(raw) != "true" {
		return false, errRuntimeUnavailable
	}
	return true, nil
}

func bindWorkerAdapterAuthority(ctx context.Context, c runtimeConfig, checker authorization.Checker, forwardPool, compPool *pgxpool.Pool) (*authorization.WorkerExecutor, *authorization.WorkerExecutor, error) {
	if ctx == nil || checker == nil || forwardPool == nil || compPool == nil || !c.Authorization.Enabled || !validWorkerAdapterConfiguration(c) {
		return nil, nil, errRuntimeUnavailable
	}
	a, err := os.Lstat(c.WorkerKeyFile)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	b, err := os.Lstat(c.CompensationKeyFile)
	if err != nil || os.SameFile(a, b) {
		return nil, nil, errRuntimeUnavailable
	}
	forwardKey, err := authorization.LoadWorkerKeyFile(authorization.WorkerForward, c.WorkerKeyFile)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	compKey, err := authorization.LoadWorkerKeyFile(authorization.CapturedCompensation, c.CompensationKeyFile)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	forward, err := authorization.NewWorkerAdapter(forwardPool, checker, c.Authorization.StoreID, c.Authorization.ModelID, forwardKey)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	comp, err := authorization.NewWorkerExecutor(compPool, nil, "", "", compKey)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	if forward.Ready(ctx) != nil || comp.Ready(ctx) != nil {
		return nil, nil, errRuntimeUnavailable
	}
	return forward, comp, nil
}

func composeWorkerAdapterProtocols(ctx context.Context, db redteamadapter.JSONDatabase, c redteamadapter.Config, invoker *redteamadapter.HTTPSInvoker, forward, comp *authorization.WorkerExecutor) (http.Handler, func(context.Context) error, error) {
	readyProfile := func(ctx context.Context) error {
		worker, err := adapterProductionProfile(ctx, db, true)
		if err != nil || !worker {
			return errRuntimeUnavailable
		}
		return nil
	}
	if readyProfile(ctx) != nil {
		return nil, nil, errRuntimeUnavailable
	}
	journal, err := redteamadapter.NewWorkerSingleTestPostgresJournal(boundedAdapterDatabase{db}, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), forward, comp)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	ordered, err := redteamadapter.NewWorkerOrderedTestPostgresJournal(boundedAdapterDatabase{db}, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint(), forward, comp)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	router, err := redteamadapter.NewWorkerTestEffectRouter(boundedAdapterDatabase{db}, journal, ordered)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	handler, err := redteamadapter.NewWorkerEffectJournaledHandler(c, router, invoker, router, journal)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	ready := func(ctx context.Context) error {
		if readyProfile(ctx) != nil || router.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if ready(ctx) != nil {
		return nil, nil, errRuntimeUnavailable
	}
	return handler, ready, nil
}
