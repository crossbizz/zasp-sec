package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Full production API/session/pgx mounting. Only private readiness transport is
// redirected to the owned worker process; no query or product handler is fake.
func TestAttackLabBrowserAPIProcess(t *testing.T) {
	if os.Getenv("ZASP_ATTACK_LAB_BROWSER_API") != "true" {
		t.Skip("owned browser fixture only")
	}
	config, err := loadRuntimeConfigFromEnvironment(os.LookupEnv)
	if err != nil || config.Environment != "test" || config.AttackLabWorkflow != "enabled" || config.AuditExports != nil || config.ComplianceExports != nil || auditBrowserProcessInputs(config, os.Getenv("ZASP_ATTACK_LAB_BROWSER_PG_PORT")) != nil {
		t.Fatal("owned API configuration refused", err)
	}
	port := os.Getenv("ZASP_ATTACK_LAB_BROWSER_WORKER_PORT")
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || strconv.Itoa(number) != port {
		t.Fatal("owned worker port refused")
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_ATTACK_LAB_BROWSER_DEADLINE"))
	if err != nil || time.Until(deadline) < time.Second || time.Until(deadline) > 30*time.Minute {
		t.Fatal("bounded API deadline required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		allowed := false
		for _, endpoint := range attackLabWorkflowServices {
			if endpoint == "http://"+address+"/readyz" {
				allowed = true
			}
		}
		if !allowed {
			return nil, errors.New("unexpected readiness destination")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", "127.0.0.1:"+port)
	}}
	defer transport.CloseIdleConnections()
	dependencies, err := buildRuntimeDependenciesWithReadinessTransport(ctx, config, newAuditExportStorageClients, newComplianceStorageResources, transport)
	if err != nil {
		t.Fatal("actual mounted API build", err)
	}
	if err := serveRuntime(ctx, os.Stdout, "attack-lab-browser", config, dependencies, net.Listen); err != nil {
		t.Fatal("actual mounted API lifecycle", err)
	}
	t.Log("owned Attack Lab API joined")
}
