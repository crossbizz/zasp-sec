package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This child uses the real registered database client and runtime scheduler.
// Cloud readiness/storage are controlled boundaries, not live AWS evidence.
func TestExistingTestRuntimeRestartOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_RECONCILE_CLIENT_DSN")
	if dsn == "" {
		t.Skip("requires owned restart fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "security_agent_v33_worker_login"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var login string
	if err := pool.QueryRow(ctx, "SELECT session_user::text").Scan(&login); err != nil || login != config.ConnConfig.User {
		t.Fatal("wrong registered login", err)
	}
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	mode := os.Getenv("ZASP_RECONCILE_RESTART_MODE")
	if mode == "abandon" {
		client, err := newExistingTestClient(db, "owned-crashed-reconciler", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		scope, found, err := client.NextScope(ctx, domain.Scope{})
		if err != nil || !found {
			t.Fatal("scope not discovered", err)
		}
		claims, err := client.Claim(ctx, scope, 60, 1)
		if err != nil || len(claims) != 1 {
			t.Fatal("claim not acquired", err)
		}
		// Simulate fail-stop after the durable claim commit, before any release.
		os.Exit(23)
	}
	if mode != "other-tenants" && mode != "reclaim" && mode != "concurrent" {
		t.Fatal("unknown restart mode")
	}
	store, driver, _ := fixtureExistingTestEvidence(t)
	runtimeConfig := loadExistingTestRuntimeFixture(t)
	var runtimeQuery existingTestQuery = db
	if mode == "concurrent" {
		runtimeConfig.WorkerID = os.Getenv("ZASP_RECONCILE_CONCURRENT_ID")
		runtimeQuery = concurrentHeldClaimQuery{db}
	}
	runtime, err := composeExistingTestRuntime(runtimeConfig, runtimeQuery, existingTestRuntimeDependencies{
		Artifacts: store, Ready: func(context.Context) error { return nil }, Close: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	polls := 1
	if mode == "other-tenants" {
		polls = 2
	}
	for i := 0; i < polls; i++ {
		if err := runtime.Processor.RunOnce(ctx); err != nil {
			t.Fatal("registered runtime poll", err)
		}
	}
	if len(driver.reads) != 0 {
		t.Fatal("queued reconciliation read artifacts")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.Processor.RunOnce(ctx) == nil {
		t.Fatal("closed runtime reused database")
	}
}
