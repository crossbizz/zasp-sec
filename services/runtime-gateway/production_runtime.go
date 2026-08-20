package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const gatewayEvidenceRecordInterval = 100 * time.Millisecond

type productionGatewayDatabase struct {
	pool *pgxpool.Pool
}

func (database *productionGatewayDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) gatewayDatabaseRow {
	if database == nil || database.pool == nil {
		return gatewayErrorRow{}
	}
	return database.pool.QueryRow(ctx, statement, arguments...)
}

type gatewayErrorRow struct{}

func (gatewayErrorRow) Scan(...any) error { return errGatewayRepository }

type boundGatewayControl struct {
	next     gatewayControlPlane
	expected gatewayAuthority
}

func (control boundGatewayControl) Ready(ctx context.Context) error {
	if control.next == nil {
		return errGatewayRepository
	}
	return control.next.Ready(ctx)
}

func (control boundGatewayControl) Authority(ctx context.Context, credentialID string) (gatewayAuthority, error) {
	if control.next == nil || credentialID != control.expected.CredentialID {
		return gatewayAuthority{}, errGatewayRepository
	}
	authority, err := control.next.Authority(ctx, credentialID)
	if err != nil || !sameGatewayAuthority(authority, control.expected) {
		return gatewayAuthority{}, errGatewayRepository
	}
	return authority, nil
}

func (control boundGatewayControl) Policy(ctx context.Context, credentialID string, afterSequence uint64) (*policy.GatewayPolicyEnvelope, error) {
	if control.next == nil || credentialID != control.expected.CredentialID {
		return nil, errGatewayRepository
	}
	return control.next.Policy(ctx, credentialID, afterSequence)
}

func (control boundGatewayControl) Record(ctx context.Context, event gatewayDecisionEvent) error {
	if control.next == nil || event.CredentialID != control.expected.CredentialID || event.DeviceID != control.expected.DeviceID {
		return errGatewayRepository
	}
	return control.next.Record(ctx, event)
}

type productionGatewayDependencies struct {
	Handler http.Handler
	Ready   func(context.Context) error
	Run     func(context.Context) error
	Drain   func(context.Context) error
	Close   func() error
}

func buildProductionGatewayDependencies(ctx context.Context, config productionGatewayConfig) (productionGatewayDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validProductionGatewayConfig(config) {
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	poolConfig.MaxConns = 4
	poolConfig.MinConns = 0
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	failPool := func() (productionGatewayDependencies, error) {
		pool.Close()
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	keys, err := loadGatewayPolicyKeys(config.PolicyKeysFile)
	if err != nil {
		return failPool()
	}
	expected := gatewayAuthority{OrganizationID: config.OrganizationID, WorkspaceID: config.WorkspaceID, EnvironmentID: config.EnvironmentID, DeviceID: config.DeviceID, CredentialID: config.CredentialID}
	cache, err := policy.NewGatewayPolicyDiskCache(config.PolicyCacheFile, keys, expected.Binding(), func() time.Time { return time.Now().UTC().Truncate(time.Second) })
	if err != nil {
		return failPool()
	}
	failCache := func() (productionGatewayDependencies, error) {
		_ = cache.Close()
		pool.Close()
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	database := &productionGatewayDatabase{pool: pool}
	repository, err := newGatewayPostgresControl(database, config.OperationTimeout)
	if err != nil {
		return failCache()
	}
	control := boundGatewayControl{next: repository, expected: expected}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{
		Control: control, Cache: cache, CredentialID: config.CredentialID, BootstrapFailureMode: config.BootstrapFailureMode,
		MaximumPendingEvents: config.MaximumPendingEvents, Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	})
	if err != nil {
		return failCache()
	}
	// A cold control plane must not prevent deterministic local failure-mode
	// enforcement. A successful refresh is required only to emit durable events.
	_ = runtime.SyncOnce(ctx)
	handler, err := newGatewayHandler(runtime, config.MaximumRequestBytes)
	if err != nil {
		return failCache()
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			if err := cache.Close(); err != nil {
				closeErr = errRuntimeUnavailable
			}
			pool.Close()
		})
		return closeErr
	}
	return productionGatewayDependencies{
		Handler: handler,
		Ready:   runtime.Ready,
		Run: func(runCtx context.Context) error {
			return runtime.Run(runCtx, config.SyncInterval, gatewayEvidenceRecordInterval)
		},
		Drain: runtime.Drain,
		Close: closeDependencies,
	}, nil
}

var _ gatewayDatabase = (*productionGatewayDatabase)(nil)
var _ gatewayControlPlane = boundGatewayControl{}
