package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"net"
	"os"
	"testing"
	"time"
)

func TestTemporalOwnedCleanup(t *testing.T) {
	dsn := os.Getenv("ZASP_TEMPORAL_CLEANUP_DSN")
	if dsn == "" {
		t.Skip("requires owned69 cleanup fixture")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, f := range cfg.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg.User = "temporal_compensation_test_login"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	db := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, t: t}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"p3c-current-key": public})
	if err != nil {
		t.Fatal(err)
	}
	p := &temporalSecurityAgentProduct{compensation: db, signing: func() (string, ed25519.PrivateKey, policy.GatewayPolicyKeys, error) {
		return "p3c-current-key", key, keys, nil
	}, workerID: "p3c-cleanup-worker"}
	var request orchestration.StartRequest
	if json.Unmarshal([]byte(os.Getenv("ZASP_TEMPORAL_CLEANUP_START")), &request) != nil {
		t.Fatal("scoped start")
	}
	wrong := request
	wrong.Ref.EnvironmentID = request.Ref.OrganizationID
	if err := p.Cleanup(ctx, orchestration.CleanupRequest{Start: wrong, Reason: "workflow_cancelled"}); err == nil {
		t.Fatal("wrong scope compensation accepted")
	}
	for i := 0; i < 2; i++ {
		if err := p.Cleanup(ctx, orchestration.CleanupRequest{Start: request, Reason: "workflow_cancelled"}); err != nil {
			t.Fatal("real mandatory cleanup consumer", i, err)
		}
	}
	state, err := p.inspect(ctx, request, db)
	if err != nil || !state.Terminal || state.CleanupRequired {
		t.Fatal("cleanup proof", state.RunState, err)
	}
	t.Log("actual cleanup consumer replayed safely with current key only; wrong scope refused")
}
