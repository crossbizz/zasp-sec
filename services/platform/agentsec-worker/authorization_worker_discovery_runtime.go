package main

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func bindDiscoveryWorkerAuthorization(ctx context.Context, cfg workerRuntimeConfig, checker authorization.Checker, p *temporalDiscoveryProduct) (func(), error) {
	closeNothing := func() {}
	if ctx == nil || p == nil {
		return closeNothing, errRuntimeUnavailable
	}
	forward, err := pgxpool.New(ctx, cfg.PostgresDSN)
	if err != nil {
		return closeNothing, errRuntimeUnavailable
	}
	var installed bool
	if err = forward.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_worker') IS NOT NULL`).Scan(&installed); err != nil {
		forward.Close()
		return closeNothing, errRuntimeUnavailable
	}
	if !installed {
		forward.Close()
		if cfg.WorkerAuthorizationKeyFile != "" || cfg.CompensationAuthorizationKeyFile != "" {
			return closeNothing, errRuntimeUnavailable
		}
		return closeNothing, nil
	}
	if checker == nil || cfg.TemporalCompensationDSN == "" || cfg.TemporalCompensationDSN == cfg.PostgresDSN || cfg.WorkerAuthorizationKeyFile == "" || cfg.CompensationAuthorizationKeyFile == "" || cfg.WorkerAuthorizationKeyFile == cfg.CompensationAuthorizationKeyFile {
		forward.Close()
		return closeNothing, errRuntimeUnavailable
	}
	first, err := os.Lstat(cfg.WorkerAuthorizationKeyFile)
	second, secondErr := os.Lstat(cfg.CompensationAuthorizationKeyFile)
	if err != nil || secondErr != nil || os.SameFile(first, second) {
		forward.Close()
		return closeNothing, errRuntimeUnavailable
	}
	forwardKey, err := authorization.LoadWorkerKeyFile(authorization.WorkerForward, cfg.WorkerAuthorizationKeyFile)
	if err != nil {
		forward.Close()
		return closeNothing, errRuntimeUnavailable
	}
	compensationKey, err := authorization.LoadWorkerKeyFile(authorization.CapturedCompensation, cfg.CompensationAuthorizationKeyFile)
	if err != nil {
		forward.Close()
		return closeNothing, errRuntimeUnavailable
	}
	compensation, err := pgxpool.New(ctx, cfg.TemporalCompensationDSN)
	if err != nil {
		forward.Close()
		return closeNothing, errRuntimeUnavailable
	}
	closePools := func() { compensation.Close(); forward.Close() }
	f, err := authorization.NewWorkerDiscovery(forward, checker, cfg.RuntimeServices.StoreID, cfg.RuntimeServices.ModelID, forwardKey)
	if err != nil {
		closePools()
		return closeNothing, errRuntimeUnavailable
	}
	c, err := authorization.NewWorkerDiscovery(compensation, nil, "", "", compensationKey)
	if err != nil {
		closePools()
		return closeNothing, errRuntimeUnavailable
	}
	d := &workerDiscoveryDatabase{forward: f, compensation: c}
	if d.ready(ctx) != nil {
		closePools()
		return closeNothing, errRuntimeUnavailable
	}
	p.authorization = d
	return closePools, nil
}
