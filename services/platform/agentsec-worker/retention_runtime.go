package main

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimepostgres"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

// Ready verifies the independently compiled retention profile and its original
// registered executor purpose; it must never accept a predecessor profile.
type retentionRuntimeStore interface {
	orchestration.RetentionStore
	Ready(context.Context) error
}

type retentionSDKWorker interface {
	RegisterWorkflow(any)
	RegisterActivityWithOptions(any, activity.RegisterOptions)
	Start() error
	Stop()
}

type retentionRuntime struct {
	activities          *orchestration.RetentionActivities
	worker              retentionSDKWorker
	ready               func(context.Context) error
	closeClients        func() error
	timeout             time.Duration
	closing             atomic.Bool
	stopOnce, closeOnce sync.Once
	stopped             chan struct{}
	closeErr            error
}

// The production constructor owns SDK registration and the application's fixed
// schedule. Scope, policy and private leases are resolved inside the SQL store.
func newTemporalRetentionRuntime(ctx context.Context, c client.Client, queue string, store retentionRuntimeStore, ready func(context.Context) error, closeClients func() error, timeout, rpcTimeout time.Duration) (*retentionRuntime, error) {
	if nilWorkerDependency(c) || rpcTimeout <= 0 || rpcTimeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	if _, err := orchestration.RetentionScheduleOptions(queue); err != nil {
		return nil, errRuntimeUnavailable
	}
	w := worker.New(c, queue, worker.Options{WorkerStopTimeout: timeout, MaxConcurrentActivityExecutionSize: 1, MaxConcurrentWorkflowTaskExecutionSize: 2})
	schedule := func(scheduleCtx context.Context) error {
		return orchestration.EnsureRetentionSchedule(scheduleCtx, c.ScheduleClient(), queue, rpcTimeout)
	}
	checkSchedule := func(checkCtx context.Context) error {
		return orchestration.CheckRetentionSchedule(checkCtx, c.ScheduleClient(), queue, rpcTimeout)
	}
	return startRetentionRuntime(ctx, store, w, schedule, ready, checkSchedule, closeClients, timeout)
}

// Ownership transfers only after successful startup. Failure leaves all clients
// with the caller, which can close them without any running activity borrowers.
func startRetentionRuntime(ctx context.Context, store retentionRuntimeStore, w retentionSDKWorker, schedule, servicesReady, scheduleReady func(context.Context) error, closeClients func() error, timeout time.Duration) (*retentionRuntime, error) {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(store) || nilWorkerDependency(w) || schedule == nil || servicesReady == nil || scheduleReady == nil || closeClients == nil || timeout < time.Second || timeout > time.Minute {
		return nil, errRuntimeUnavailable
	}
	baseReady := func(checkCtx context.Context) error {
		if checkCtx == nil || checkCtx.Err() != nil || store.Ready(checkCtx) != nil || servicesReady(checkCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if baseReady(ctx) != nil || schedule(ctx) != nil || scheduleReady(ctx) != nil {
		return nil, errRuntimeUnavailable
	}
	ready := func(checkCtx context.Context) error {
		if baseReady(checkCtx) != nil || scheduleReady(checkCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	activities := &orchestration.RetentionActivities{Store: retentionReadyStore{store: store, ready: ready}}
	w.RegisterWorkflow(orchestration.RetentionScheduledWorkflow)
	w.RegisterActivityWithOptions(activities.Sweep, activity.RegisterOptions{Name: orchestration.RetentionActivityName})
	if w.Start() != nil {
		return nil, errRuntimeUnavailable
	}
	return &retentionRuntime{activities: activities, worker: w, ready: ready, closeClients: closeClients, timeout: timeout, stopped: make(chan struct{})}, nil
}
func (r *retentionRuntime) Ready(ctx context.Context) error {
	if r == nil || r.closing.Load() {
		return errRuntimeUnavailable
	}
	return r.ready(ctx)
}

// The ordinary process polling loop never expires references itself.
func (r *retentionRuntime) RunOnce(ctx context.Context) error { return r.Ready(ctx) }
func (r *retentionRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closing.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	r.stopOnce.Do(func() { go func() { r.worker.Stop(); close(r.stopped) }() })
	if r.activities.Close(ctx) != nil {
		return errRuntimeUnavailable
	}
	select {
	case <-r.stopped:
	case <-ctx.Done():
		return errRuntimeUnavailable
	}
	r.closeOnce.Do(func() { r.closeErr = r.closeClients() })
	return r.closeErr
}

// Every admitted activity rechecks current dependency readiness. The SQL store
// additionally validates policy and registered purpose inside its transaction.
type retentionReadyStore struct {
	store retentionRuntimeStore
	ready func(context.Context) error
}

func (s retentionReadyStore) Sweep(ctx context.Context, key string) (orchestration.RetentionCounters, error) {
	if s.ready(ctx) != nil {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	return s.store.Sweep(ctx, key)
}

// The sweep is a private SQL transaction, not a workflow payload. An uncertain
// COMMIT returns no counters; Temporal retries the same cycle key and SQL receipt.
type retentionTransactionPool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type retentionPostgresStore struct {
	pool     retentionTransactionPool
	checksum string
	timeout  time.Duration
}

var retentionCycleKeyPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s *retentionPostgresStore) Ready(ctx context.Context) error {
	if s == nil || nilWorkerDependency(s.pool) || ctx == nil || ctx.Err() != nil || !retentionCycleKeyPattern.MatchString(s.checksum) || s.timeout <= 0 || s.timeout > 30*time.Second {
		return errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	var ready bool
	if s.pool.QueryRow(bounded, `SELECT zasp_retention_v1.caller_ready('sweep',$1)`, s.checksum).Scan(&ready) != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}
func (s *retentionPostgresStore) Sweep(ctx context.Context, key string) (orchestration.RetentionCounters, error) {
	if s == nil || nilWorkerDependency(s.pool) || ctx == nil || ctx.Err() != nil || !retentionCycleKeyPattern.MatchString(key) {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var ready bool
	if tx.QueryRow(bounded, `SELECT zasp_retention_v1.caller_ready('sweep',$1)`, s.checksum).Scan(&ready) != nil || !ready {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	q, _ := json.Marshal(struct {
		CycleKey string `json:"cycle_key"`
	}{CycleKey: key})
	var raw []byte
	if tx.QueryRow(bounded, `SELECT zasp_retention_v1.sweep($1::jsonb)`, q).Scan(&raw) != nil {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	// Pointer fields distinguish a complete zero-count receipt from absent fields.
	var wire struct {
		Scopes  *int `json:"scopes"`
		Scanned *int `json:"scanned"`
		Expired *int `json:"expired"`
	}
	if decodeStrictWorkerJSON(raw, &wire) != nil || wire.Scopes == nil || wire.Scanned == nil || wire.Expired == nil {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	result := orchestration.RetentionCounters{Scopes: *wire.Scopes, Scanned: *wire.Scanned, Expired: *wire.Expired}
	if !result.Valid() || tx.Commit(bounded) != nil {
		return orchestration.RetentionCounters{}, errRuntimeUnavailable
	}
	return result, nil
}

func buildProductionRetentionRuntime(ctx context.Context, c workerRuntimeConfig) (workerRuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validWorkerRuntimeConfig(c) || c.Mode != workerModeRetentionReferenceExpiry || c.RetentionProfileChecksum != migrations.RetentionAuditProfileChecksum() {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, c.RuntimeServices.Timeout)
	defer cancel()
	cfg, err := runtimepostgres.ParsePoolConfig(c.PostgresDSN)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	cfg.MaxConns, cfg.MinConns = 3, 1
	pool, err := pgxpool.NewWithConfig(bounded, cfg)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	store := &retentionPostgresStore{pool: pool, checksum: c.RetentionProfileChecksum, timeout: c.RuntimeServices.Timeout}
	if pool.Ping(bounded) != nil || store.Ready(bounded) != nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	services, err := runtimeservices.Connect(ctx, c.RuntimeServices)
	if err != nil || services == nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	closeClients := func() error { err := services.Close(); pool.Close(); return err }
	runtime, err := newTemporalRetentionRuntime(ctx, services.Temporal, c.RetentionTaskQueue, store, services.Ready, closeClients, c.ShutdownTimeout, c.RuntimeServices.Timeout)
	if err != nil {
		_ = closeClients()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: runtime, Ready: runtime.Ready, Close: runtime.Close}, nil
}
