package main

import (
	"context"
	"io"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
)

// Configuration selects one registered profile; absence never enables a
// partial native worker. Actual catalog/active/session checks belong to Ready.
func validConnectorMaintenanceRuntimeConfig(c RuntimeConfig) bool {
	pin := c.RuntimeServices.ConnectorMaintenanceProfileChecksum
	if pin == "" {
		return c.ConnectorMaintenancePostgresDSN == "" && c.ConnectorMaintenanceKeyFile == ""
	}
	if !c.RuntimeServices.Enabled || c.RuntimeServices.Validate() != nil || !filepath.IsAbs(c.ConnectorMaintenanceKeyFile) || filepath.Clean(c.ConnectorMaintenanceKeyFile) != c.ConnectorMaintenanceKeyFile || c.ConnectorMaintenanceKeyFile == c.ApprovalMaintenanceKeyFile {
		return false
	}
	original, ok := parseRuntimePostgresDSN(c.SecurityAgentPostgresDSN)
	if !ok {
		return false
	}
	maintenance, ok := parseRuntimePostgresDSN(c.ConnectorMaintenancePostgresDSN)
	if !ok || maintenance.User.Username() == original.User.Username() || maintenance.Scheme != original.Scheme || maintenance.Host != original.Host || maintenance.Path != original.Path || maintenance.RawQuery != original.RawQuery {
		return false
	}
	core, ok := parseRuntimePostgresDSN(c.PostgresDSN)
	if !ok || maintenance.User.Username() == core.User.Username() {
		return false
	}
	if c.ApprovalMaintenancePostgresDSN != "" {
		approval, valid := parseRuntimePostgresDSN(c.ApprovalMaintenancePostgresDSN)
		if !valid || approval.User.Username() == maintenance.User.Username() {
			return false
		}
	}
	return true
}

type connectorMaintenanceRuntimeCloser struct {
	authority *connectormaintenance.Authority
	pool      *pgxpool.Pool
}

func (c *connectorMaintenanceRuntimeCloser) Close() error {
	if c != nil {
		if c.authority != nil {
			c.authority.Close()
		}
		if c.pool != nil {
			c.pool.Close()
		}
	}
	return nil
}

type connectorRuntimeFactory func() (*apiserver.ConnectorReconciler, func(context.Context) error, io.Closer, error)

func selectConnectorLifecycle(c RuntimeConfig, native, legacy connectorRuntimeFactory) (*apiserver.ConnectorReconciler, func(context.Context) error, io.Closer, error) {
	if !validConnectorMaintenanceRuntimeConfig(c) {
		return nil, nil, nil, errRuntimeUnavailable
	}
	chosen := legacy
	if c.RuntimeServices.ConnectorMaintenanceProfileChecksum != "" {
		chosen = native
	}
	if chosen == nil {
		return nil, nil, nil, errRuntimeUnavailable
	}
	r, ready, closer, err := chosen()
	if err != nil || r == nil || ready == nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, nil, errRuntimeUnavailable
	}
	return r, ready, closer, nil
}

func newRuntimeConnectorMaintenance(ctx context.Context, c RuntimeConfig, a apiserver.RequestAuthorizer, config apiserver.ConnectorReconcilerConfig) (*apiserver.ConnectorReconciler, func(context.Context) error, io.Closer, error) {
	if ctx == nil || ctx.Err() != nil || !validConnectorMaintenanceRuntimeConfig(c) || c.ConnectorMaintenancePostgresDSN == "" {
		return nil, nil, nil, errRuntimeUnavailable
	}
	authorizer, ok := a.(*apiserver.OpenFGAAuthorizer)
	if !ok || authorizer == nil || authorizer.Checker == nil || authorizer.StoreID != c.RuntimeServices.StoreID || authorizer.ModelID != c.RuntimeServices.ModelID {
		return nil, nil, nil, errRuntimeUnavailable
	}
	// Reuse the existing bounded private same-FD 0400/32-byte key reader.
	seed, err := loadApprovalMaintenanceKey(c.ConnectorMaintenanceKeyFile)
	if err != nil {
		return nil, nil, nil, errRuntimeUnavailable
	}
	defer clear(seed)
	probe, cancel := context.WithTimeout(ctx, c.ProviderTimeout)
	defer cancel()
	poolConfig, err := runtimepostgres.ParsePoolConfig(c.ConnectorMaintenancePostgresDSN)
	if err != nil {
		return nil, nil, nil, errRuntimeUnavailable
	}
	poolConfig.MaxConns = 2
	poolConfig.MinConns = 0
	pool, err := pgxpool.NewWithConfig(probe, poolConfig)
	if err != nil {
		return nil, nil, nil, errRuntimeUnavailable
	}
	closer := &connectorMaintenanceRuntimeCloser{pool: pool}
	executor, err := connectormaintenance.NewExecutor(probe, pool, c.RuntimeServices.ConnectorMaintenanceProfileChecksum, seed)
	if err != nil {
		_ = closer.Close()
		return nil, nil, nil, errRuntimeUnavailable
	}
	authority, err := connectormaintenance.NewAuthority(executor, authorizer.Checker, authorizer.StoreID, authorizer.ModelID, c.RuntimeServices.ConnectorMaintenanceProfileChecksum, seed)
	if err != nil {
		_ = closer.Close()
		return nil, nil, nil, errRuntimeUnavailable
	}
	closer.authority = authority
	native, err := apiserver.NewNativeConnectorRepository(probe, executor, authority)
	if err != nil {
		_ = closer.Close()
		return nil, nil, nil, errRuntimeUnavailable
	}
	reconciler, err := apiserver.NewAuthorizedConnectorReconciler(probe, native, config)
	if err != nil {
		_ = closer.Close()
		return nil, nil, nil, errRuntimeUnavailable
	}
	// Run does the original recovery/claim loop. Every readiness probe repeats
	// the complete native catalog/active/session verifier before worker readiness.
	ready := func(ctx context.Context) error {
		if executor.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	return reconciler, ready, closer, nil
}
