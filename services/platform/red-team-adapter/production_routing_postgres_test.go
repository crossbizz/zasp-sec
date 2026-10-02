package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// Invoked only by the owned offline release55 fixture, never starts host PG.
func TestProductionAdapterOwnedRouting(t *testing.T) {
	dsn := os.Getenv("ZASP_ADAPTER_ROUTING_DSN")
	if dsn == "" {
		t.Skip("requires owned adapter fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// The parent's ConnString contains its original owner identity.
	principalName := "existing_test_red_adapter"
	ownerName := "zasp_e2e"
	if os.Getenv("ZASP_TEMPORAL_ROUTING") == "1" {
		principalName = "ordered_test_red_adapter"
		ownerName = "zasp_test"
	}
	config.ConnConfig.User = principalName
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var principal string
	if err := pool.QueryRow(ctx, "SELECT session_user::text").Scan(&principal); err != nil || principal != principalName {
		t.Fatalf("registered principal=%q error=%v", principal, err)
	}
	invoker, err := redteamadapter.NewProductionHTTPSInvoker([]string{"93.184.216.0/24"}, time.Second, noRoutingCredential{t})
	if err != nil {
		t.Fatal(err)
	}
	handler, ready, err := composeAdapterProtocols(ctx, postgresJSONDatabase{connection: pool, lifetime: ctx, timeout: time.Second}, redteamadapter.Config{WorkerToken: []byte(strings.Repeat("a", 64)), MaximumRequestBytes: 4096}, invoker)
	if err != nil || handler == nil || ready == nil {
		t.Fatalf("registered composition: %v", err)
	}
	if err := ready(ctx); err != nil {
		t.Fatalf("registered readiness: %v", err)
	}
	t.Log("actual owned adapter composition", principalName, "temporal68", os.Getenv("ZASP_TEMPORAL_ROUTING") == "1")
	// Same release and DB, unregistered owner identity must not become ready.
	ownerConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ownerConfig.MaxConns = 1
	owner, err := pgxpool.NewWithConfig(ctx, ownerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var ownerIdentity string
	if err := owner.QueryRow(ctx, "SELECT session_user::text").Scan(&ownerIdentity); err != nil || ownerIdentity != ownerName || ctx.Err() != nil {
		t.Fatalf("owner refusal control identity=%q error=%v context=%v", ownerIdentity, err, ctx.Err())
	}
	if _, _, err := composeAdapterProtocols(ctx, postgresJSONDatabase{connection: owner, lifetime: ctx, timeout: time.Second}, redteamadapter.Config{WorkerToken: []byte(strings.Repeat("a", 64)), MaximumRequestBytes: 4096}, invoker); err == nil {
		t.Fatal("owner admitted as adapter")
	}
	if err := owner.QueryRow(ctx, "SELECT session_user::text").Scan(&ownerIdentity); err != nil || ownerIdentity != ownerName || ctx.Err() != nil {
		t.Fatalf("owner refusal lost database/context: %v %v", err, ctx.Err())
	}
}
