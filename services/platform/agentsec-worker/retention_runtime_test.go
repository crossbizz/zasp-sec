package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/activity"
)

type retentionRuntimeStoreFixture struct {
	readiness error
	sweeps    atomic.Int32
}

func (s *retentionRuntimeStoreFixture) Ready(context.Context) error { return s.readiness }
func (s *retentionRuntimeStoreFixture) Sweep(context.Context, string) (orchestration.RetentionCounters, error) {
	s.sweeps.Add(1)
	return orchestration.RetentionCounters{}, nil
}

type retentionRuntimeWorkerFixture struct {
	workflows, activities, starts, stops atomic.Int32
	startErr                             error
	release                              chan struct{}
}

func (w *retentionRuntimeWorkerFixture) RegisterWorkflow(any) { w.workflows.Add(1) }
func (w *retentionRuntimeWorkerFixture) RegisterActivityWithOptions(any, activity.RegisterOptions) {
	w.activities.Add(1)
}
func (w *retentionRuntimeWorkerFixture) Start() error { w.starts.Add(1); return w.startErr }
func (w *retentionRuntimeWorkerFixture) Stop() {
	w.stops.Add(1)
	if w.release != nil {
		<-w.release
	}
}

func TestRetentionRuntimeConnectedRegistrationAndReadiness(t *testing.T) {
	store := &retentionRuntimeStoreFixture{}
	w := &retentionRuntimeWorkerFixture{}
	var scheduled, closed atomic.Int32
	var scheduleErr error
	r, err := startRetentionRuntime(context.Background(), store, w, func(context.Context) error { scheduled.Add(1); return nil }, func(context.Context) error { return nil }, func(context.Context) error { return scheduleErr }, func() error { closed.Add(1); return nil }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if w.workflows.Load() != 1 || w.activities.Load() != 1 || w.starts.Load() != 1 || scheduled.Load() != 1 {
		t.Fatal("scheduled production workflow/activity not connected")
	}
	if err := r.RunOnce(context.Background()); err != nil || store.sweeps.Load() != 0 {
		t.Fatal("poll loop must check readiness; only Temporal activity may sweep")
	}
	store.readiness = errors.New("profile drift")
	if r.Ready(context.Background()) == nil {
		t.Fatal("periodic profile drift accepted")
	}
	store.readiness = nil
	scheduleErr = errors.New("schedule paused or drifted")
	if r.Ready(context.Background()) == nil {
		t.Fatal("persisted schedule drift accepted")
	}
	if out, err := r.activities.Store.Sweep(context.Background(), strings.Repeat("b", 64)); err == nil || out != (orchestration.RetentionCounters{}) || store.sweeps.Load() != 0 {
		t.Fatal("activity admitted after schedule drift")
	}
	if scheduled.Load() != 1 {
		t.Fatal("readiness recreated operator schedule")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.Ready(context.Background()) == nil || w.stops.Load() != 1 || closed.Load() != 1 {
		t.Fatal("close failed to stop admission and clients")
	}
}

func TestRetentionRuntimeFailuresNeverAdmitWork(t *testing.T) {
	for _, phase := range []string{"profile", "services", "schedule", "start"} {
		t.Run(phase, func(t *testing.T) {
			denied := errors.New("unavailable")
			store := &retentionRuntimeStoreFixture{}
			w := &retentionRuntimeWorkerFixture{}
			services := func(context.Context) error { return nil }
			schedule := func(context.Context) error { return nil }
			switch phase {
			case "profile":
				store.readiness = denied
			case "services":
				services = func(context.Context) error { return denied }
			case "schedule":
				schedule = func(context.Context) error { return denied }
			case "start":
				w.startErr = denied
			}
			r, err := startRetentionRuntime(context.Background(), store, w, schedule, services, func(context.Context) error { return nil }, func() error { return nil }, time.Second)
			if err == nil || r != nil {
				t.Fatal("unavailable dependency accepted")
			}
			if phase != "start" && w.starts.Load() != 0 {
				t.Fatal("worker started before exact dependency admission")
			}
		})
	}
}

func TestRetentionRuntimeShutdownTimeoutRetainsClientsForRetry(t *testing.T) {
	store := &retentionRuntimeStoreFixture{}
	w := &retentionRuntimeWorkerFixture{release: make(chan struct{})}
	var closed atomic.Int32
	r, err := startRetentionRuntime(context.Background(), store, w, func(context.Context) error { return nil }, func(context.Context) error { return nil }, func(context.Context) error { return nil }, func() error { closed.Add(1); return nil }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r.Close() == nil || closed.Load() != 0 || r.Ready(context.Background()) == nil {
		t.Fatal("unjoined worker lost clients")
	}
	close(w.release)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if w.stops.Load() != 1 || closed.Load() != 1 {
		t.Fatal("shutdown retry was not idempotent")
	}
}

type retentionTransactionFixture struct {
	pgx.Tx
	commitErr          error
	wire               []byte
	commits, rollbacks atomic.Int32
	key                string
}

func (t *retentionTransactionFixture) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "caller_ready") {
		return retentionRowFixture{ready: true}
	}
	var request struct {
		CycleKey string `json:"cycle_key"`
	}
	_ = json.Unmarshal(args[0].([]byte), &request)
	t.key = request.CycleKey
	return retentionRowFixture{wire: t.wire}
}
func (t *retentionTransactionFixture) Commit(context.Context) error {
	t.commits.Add(1)
	return t.commitErr
}
func (t *retentionTransactionFixture) Rollback(context.Context) error { t.rollbacks.Add(1); return nil }

type retentionRowFixture struct {
	ready bool
	wire  []byte
}

func (r retentionRowFixture) Scan(dest ...any) error {
	switch target := dest[0].(type) {
	case *bool:
		*target = r.ready
	case *[]byte:
		*target = r.wire
	default:
		return errors.New("unexpectedrow")
	}
	return nil
}

type retentionPoolFixture struct{ tx *retentionTransactionFixture }

func (p retentionPoolFixture) QueryRow(context.Context, string, ...any) pgx.Row {
	return retentionRowFixture{ready: true}
}
func (p retentionPoolFixture) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if options.IsoLevel != pgx.ReadCommitted {
		return nil, errors.New("unsafe transaction isolation")
	}
	return p.tx, nil
}
func TestRetentionRuntimeSQLPublishesOnlyConfirmedReceipts(t *testing.T) {
	for _, phase := range []string{"confirmed", "unknown_commit", "invalid_receipt"} {
		t.Run(phase, func(t *testing.T) {
			tx := &retentionTransactionFixture{wire: []byte(`{"scopes":1,"scanned":5,"expired":2}`)}
			if phase == "unknown_commit" {
				tx.commitErr = errors.New("transportlost")
			}
			if phase == "invalid_receipt" {
				tx.wire = []byte(`{"scopes":1,"scanned":5}`)
			}
			store := &retentionPostgresStore{pool: retentionPoolFixture{tx: tx}, checksum: strings.Repeat("a", 64), timeout: time.Second}
			key := strings.Repeat("b", 64)
			result, err := store.Sweep(context.Background(), key)
			if phase == "confirmed" {
				if err != nil || result.Expired != 2 {
					t.Fatal("confirmed receipt lost", err)
				}
			} else if err == nil || result != (orchestration.RetentionCounters{}) {
				t.Fatal("unconfirmed or malformed result published")
			}
			if tx.key != key || tx.rollbacks.Load() != 1 {
				t.Fatal("privatecyclekey or transaction cleanup lost")
			}
			if phase == "invalid_receipt" && tx.commits.Load() != 0 {
				t.Fatal("invalid receipt committed")
			}
		})
	}
}

func TestRetentionRuntimeRequiresDedicatedCompiledComposition(t *testing.T) {
	cfg := workerRuntimeConfig{
		Mode: workerModeRetentionReferenceExpiry, DatabaseAuthority: "zasp_temporal_executor", PostgresDSN: "postgres://retention@postgres.internal/zasp?sslmode=verify-full", WorkerID: "retention-01", PollInterval: time.Second, LeaseDuration: time.Minute, ShutdownTimeout: time.Second, BatchSize: 1,
		RetentionTaskQueue: "retention-expiry", RetentionProfileChecksum: migrations.RetentionAuditProfileChecksum(),
		RuntimeServices: runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "owned", TaskQueue: "security-agent", DiscoveryTaskQueue: "discovery", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/fixture/token", Timeout: time.Second},
	}
	if !validWorkerRuntimeConfig(cfg) {
		t.Fatal("dedicated compiled composition rejected")
	}
	for name, mutate := range map[string]func(*workerRuntimeConfig){
		"wrongmode":              func(c *workerRuntimeConfig) { c.Mode = workerModeScheduler },
		"uncompiledpin":          func(c *workerRuntimeConfig) { c.RetentionProfileChecksum = strings.Repeat("f", 64) },
		"sharedqueue":            func(c *workerRuntimeConfig) { c.RetentionTaskQueue = c.RuntimeServices.TaskQueue },
		"runtimeprofilefallback": func(c *workerRuntimeConfig) { c.RuntimeDatabaseProfile = migrations.AuthorizationRuntimeProfileName },
		"legacyrole":             func(c *workerRuntimeConfig) { c.DatabaseAuthority = "zasp_discovery_scheduler" },
		"noTemporal":             func(c *workerRuntimeConfig) { c.RuntimeServices = runtimeservices.Config{} },
		"extraprovider":          func(c *workerRuntimeConfig) { c.RedTeamRoleARN = "arn:aws:iam::123456789012:role/extra" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cfg
			mutate(&bad)
			if validWorkerRuntimeConfig(bad) {
				t.Fatal("unproved composition accepted")
			}
		})
	}
}
