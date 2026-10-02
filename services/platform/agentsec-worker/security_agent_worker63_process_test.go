package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The parent owns a disposable database populated by the public API. This
// subprocess calls the package-private repository as the worker login.
func TestWorker63RepositoryProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_WORKER63_TEST_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned worker63 database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || config.User != "zasp_e2e" || config.Database != "postgres" || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	for _, f := range config.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	config.User = "security_agent_v33_worker_login"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	repo := &orderedDispatchRepository{database: &orderedPricingWorkerPG{conn: conn}}
	if err = repo.ready(ctx); err != nil {
		t.Fatal("registered readiness", err)
	}
	var q orderedDispatchClaim
	if err = json.Unmarshal([]byte(os.Getenv("ZASP_WORKER63_TEST_CLAIM")), &q); err != nil {
		t.Fatal(err)
	}
	first, err := repo.claim(ctx, q)
	if err != nil || first.Outcome != "claimed" || first.Item == nil {
		t.Fatal("strict claim", first, err)
	}
	again, err := repo.claim(ctx, q)
	if err != nil || again.Item == nil || *again.Item != *first.Item {
		t.Fatal("same-process replay", again, err)
	}
	raw, _ := json.Marshal(first)
	fmt.Println("worker63-repository-result:" + string(raw))
}
