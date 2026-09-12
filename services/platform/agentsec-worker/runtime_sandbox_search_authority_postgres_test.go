package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The parent PostgreSQL fixture owns setup and cleanup, installs the compiled
// release50, and commits one pending v2 receipt containing three document IDs.
// This test proves only the real Go lease authority, without provider writes.
func TestSandboxSearchAuthorityPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_SANDBOX_SEARCH_TEST_DSN")
	if dsn == "" {
		t.Skip("requires owned sandbox search PostgreSQL fixture")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid sandbox search PostgreSQL fixture configuration")
	}
	localHost := func(host string) bool {
		address := net.ParseIP(host)
		return host == "localhost" || address != nil && address.IsLoopback() || filepath.IsAbs(host)
	}
	if config.User != "candidate_index" || !localHost(config.Host) {
		t.Fatal("sandbox search fixture must use candidate_index on a local host or Unix socket")
	}
	for _, fallback := range config.Fallbacks {
		if !localHost(fallback.Host) {
			t.Fatal("sandbox search fixture has a non-local fallback host")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database := &sandboxSearchPostgresCalls{recoveryJSONDatabase: combinedE2ERecoveryDatabase(t, ctx, dsn)}
	authority, err := newConfiguredPostgresRuntimeSessionSearchAuthority(database, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Ready(ctx); err != nil {
		t.Fatal("compiled release50 index authority is not ready", err)
	}
	const worker, token = "sandbox-search-postgres-worker", "sandbox-search-postgres-lease-0001"
	lease, err := authority.Claim(ctx, worker, token, 30)
	if err != nil || lease == nil {
		t.Fatalf("claim committed v2 receipt: lease=%v err=%v", lease != nil, err)
	}
	if len(lease.DocumentIDs) != 3 {
		t.Fatalf("fixture receipt has %d document IDs, want 3", len(lease.DocumentIDs))
	}
	legacy, err := newPostgresRuntimeSessionSearchAuthority(database)
	if err != nil {
		t.Fatal(err)
	}
	before := database.calls.Load()
	if _, err := legacy.Heartbeat(ctx, *lease, worker, token, 30); err == nil {
		t.Fatal("v1 authority accepted a v2 lease heartbeat")
	}
	if err := legacy.Finish(ctx, *lease, worker, token, "indexed", lease.DocumentIDs, 0); err == nil {
		t.Fatal("v1 authority accepted a v2 lease completion")
	}
	if database.calls.Load() != before {
		t.Fatal("cross-target lease reached PostgreSQL")
	}
	until, err := authority.Heartbeat(ctx, *lease, worker, token, 30)
	if err != nil || !until.After(time.Now()) {
		t.Fatal("renew claimed v2 lease", err)
	}
	for attempt := range 2 {
		if err := authority.Finish(ctx, *lease, worker, token, "indexed", lease.DocumentIDs, 0); err != nil {
			t.Fatalf("indexed completion/retry %d: %v", attempt, err)
		}
	}
	t.Log("real PostgreSQL Go v2 authority: compiled50 readiness, claimed receipt, renewed lease, indexed completion, exact acknowledgement retry, cross-target rejection before database; provider indexing not exercised")
}

type sandboxSearchPostgresCalls struct {
	recoveryJSONDatabase
	calls atomic.Int64
}

func (database *sandboxSearchPostgresCalls) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	database.calls.Add(1)
	return database.recoveryJSONDatabase.QueryJSON(ctx, statement, args...)
}
