//go:build darwin || linux

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func auditBrowserProcessInputs(config RuntimeConfig, port string) error {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || strconv.Itoa(number) != port {
		return errRuntimeUnavailable
	}
	for _, pair := range [][2]string{{config.PostgresDSN, "zasp_e2e_api"}, {config.SecurityAgentPostgresDSN, "zasp_e2e_security_agent_api"}} {
		parsed, err := pgx.ParseConfig(pair[0])
		if err != nil || parsed.Host != "127.0.0.1" || parsed.Port != uint16(number) || parsed.Database != "postgres" || parsed.User != pair[1] || parsed.Password != "" || len(parsed.Fallbacks) != 0 || parsed.TLSConfig != nil {
			return errRuntimeUnavailable
		}
	}
	return nil
}

func TestAuditBrowserAPIProcess(t *testing.T) {
	if os.Getenv("ZASP_AUDIT_BROWSER_API") != "true" {
		t.Skip("selected owned browser API not requested")
	}
	config, err := loadRuntimeConfigFromEnvironment(os.LookupEnv)
	if err != nil {
		t.Fatal("browser production configuration refused", err)
	}
	if err = auditBrowserProcessInputs(config, os.Getenv("ZASP_AUDIT_BROWSER_PG_PORT")); err != nil {
		t.Fatal("browser database ownership refused")
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_AUDIT_BROWSER_DEADLINE"))
	if err != nil || time.Until(deadline) < 30*time.Second || time.Until(deadline) > 35*time.Minute {
		t.Fatal("browser API deadline refused")
	}
	signaled, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(signaled, deadline)
	defer cancel()
	factory := func(c RuntimeConfig) ([]apiserver.AuditExportStorageConfiguration, *http.Transport, error) {
		resources, err := auditBrowserStorageResources(c, os.Getenv("ZASP_AUDIT_BROWSER_PROVIDER_ADDRESS"), os.Getenv("ZASP_AUDIT_BROWSER_PROVIDER_CA"), os.Getenv("ZASP_AUDIT_BROWSER_PROVIDER_TOKEN"))
		return resources.entries, resources.transport, err
	}
	dependencies, err := buildRuntimeDependenciesWithAuditExportStorage(ctx, config, factory)
	if err != nil {
		t.Fatal("full browser runtime build refused", err)
	}
	if err = serveRuntime(ctx, os.Stdout, "audit-browser", config, dependencies, net.Listen); err != nil {
		t.Fatal("full browser runtime lifecycle failed", err)
	}
	t.Log("owned full browser API cleanup complete")
}

func TestAuditBrowserAPIProcessRejectsForeignDatabase(t *testing.T) {
	config := auditBrowserAPIConfig(t)
	config.PostgresDSN = "postgres://zasp_e2e_api@127.0.0.1:15432/postgres?sslmode=disable"
	config.SecurityAgentPostgresDSN = "postgres://zasp_e2e_security_agent_api@127.0.0.1:15432/postgres?sslmode=disable"
	if err := auditBrowserProcessInputs(config, "15432"); err != nil {
		t.Fatal("owned browser databases refused")
	}
	for _, dsn := range []string{"postgres://zasp_e2e@127.0.0.1:15432/postgres?sslmode=disable", "postgres://zasp_e2e_api@192.0.2.1:15432/postgres?sslmode=disable", "postgres://zasp_e2e_api@127.0.0.1:15433/postgres?sslmode=disable", "postgres://zasp_e2e_api@127.0.0.1:15432/other?sslmode=disable", "postgres://zasp_e2e_api@127.0.0.1:15432/postgres?sslmode=disable&host=127.0.0.1,192.0.2.1"} {
		candidate := config
		candidate.PostgresDSN = dsn
		if auditBrowserProcessInputs(candidate, "15432") == nil {
			t.Fatal("foreign database admitted", dsn)
		}
	}
}
