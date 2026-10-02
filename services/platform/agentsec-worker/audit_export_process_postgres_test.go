//go:build darwin || linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This entry point accepts only the parent-owned local provider and the exact
// registered login for its mode. It receives no objects or successful SQL rows.
func TestAuditExportProcessWorkerPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned process fixture")
	}
	mode := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_MODE")
	fault := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_FAULT")
	outcome := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_OUTCOME")
	if (fault != "" && fault != "finish-outbox-response") || (outcome != "" && outcome != "error") || (fault != "" || outcome != "") && mode != "audit-export-outbox" || fault != "" && outcome != "error" {
		t.Fatal("invalid process fault contract")
	}
	address := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_ADDRESS")
	if err := auditExportProcessInputs(dsn, mode, address); err != nil {
		t.Fatal(err)
	}
	ca := auditExportProcessPrivateFile(t, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_CA"), 16384)
	tokenPath := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_TOKEN")
	_ = auditExportProcessPrivateFile(t, tokenPath, 4096)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid owned TLS CA")
	}
	plan, err := auditExportProcessPlan(mode, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_SELECTION"), os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_POLICY"), os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_DEADLINE"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	values := plan.values
	values["ZASP_POSTGRES_DSN"] = dsn
	values["ZASP_BATCH_SIZE"] = "1"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil {
		t.Fatal("strict process configuration", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), plan.deadline)
	defer cancel()
	clients, err := newAuditExportProductionClients(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clients.transport.CloseIdleConnections()
	// Keep the production configuration's exact projected-token path. Only the
	// owned test credential provider reads this private fixture token instead.
	clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = tokenPath
	clients.transport.TLSClientConfig.RootCAs = roots
	clients.transport.TLSClientConfig.ServerName = "example.com"
	clients.transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		if err := auditExportProcessDestination(plan, mode, network, destination); err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	database := &auditExportProcessDatabase{base: combinedE2ERecoveryDatabase(t, ctx, dsn), loseFinish: fault == "finish-outbox-response"}
	runtime, err := composeAuditExportWorkerRuntime(ctx, config, database, clients)
	if err != nil {
		t.Fatal("registered production process composition", err)
	}
	runErr := runtime.Processor.RunOnce(ctx)
	closeErr := runtime.Close()
	if closeErr != nil || (outcome == "error") != (runErr != nil) {
		t.Fatal("production process operation", runErr, closeErr)
	}
	database.mu.Lock()
	losses := database.losses
	database.mu.Unlock()
	if (fault == "finish-outbox-response" && losses != 1) || (fault == "" && losses != 0) {
		t.Fatal("intended committed SQL response loss not reached")
	}
	t.Logf("process result: expected_error=%t committed_finish_response_losses=%d", outcome == "error", losses)
	t.Logf("registered parent-provider process completed: mode=%s pid=%d", mode, os.Getpid())
}

// Only a successful real SQL call can trigger this response-loss fixture. It
// never invents an authority response or suppresses the underlying database work.
type auditExportProcessDatabase struct {
	base       recoveryJSONDatabase
	mu         sync.Mutex
	loseFinish bool
	losses     int
}

func (d *auditExportProcessDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	body, err := d.base.QueryJSON(ctx, query, args...)
	if err != nil {
		return body, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if query == auditExportOutboxFinishSQL && d.loseFinish {
		d.loseFinish = false
		d.losses++
		return nil, errors.New("owned loss after committed outbox Finish")
	}
	return body, nil
}

func auditExportProcessInputs(dsn, mode, address string) error {
	login := ""
	switch mode {
	case "audit-export":
		login = "audit_export_worker_fixture"
	case "audit-export-outbox":
		login = "audit_export_outbox_fixture"
	default:
		return errors.New("invalid process mode")
	}
	config, err := pgx.ParseConfig(dsn)
	local := func(host string) bool {
		ip := net.ParseIP(host)
		return host == "localhost" || ip != nil && ip.IsLoopback() || filepath.IsAbs(host)
	}
	if err != nil || config.User != login || !local(config.Host) {
		return errors.New("invalid owned process database")
	}
	for _, fallback := range config.Fallbacks {
		if !local(fallback.Host) {
			return errors.New("nonlocal process fallback")
		}
	}
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return errors.New("nonloopback process provider")
	}
	return nil
}

func auditExportProcessPrivateFile(t *testing.T, path string, maximum int64) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > maximum {
		t.Fatal("invalid private process fixture file")
	}
	body, err := os.ReadFile(path)
	if err != nil || int64(len(body)) > maximum {
		t.Fatal("private process fixture read", err)
	}
	return body
}

func TestAuditExportProcessInputsAreModeBound(t *testing.T) {
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		login := "audit_export_worker_fixture"
		if mode == "audit-export-outbox" {
			login = "audit_export_outbox_fixture"
		}
		dsn := "postgres://" + login + "@127.0.0.1:15432/zasp?sslmode=disable"
		if auditExportProcessInputs(dsn, mode, "127.0.0.1:14443") != nil {
			t.Fatal("owned mode rejected")
		}
		other := "audit-export"
		if mode == other {
			other = "audit-export-outbox"
		}
		for _, test := range []struct{ dsn, mode, address string }{
			{dsn, other, "127.0.0.1:14443"}, {dsn, "runtime", "127.0.0.1:14443"},
			{strings.Replace(dsn, "127.0.0.1", "203.0.113.1", 1), mode, "127.0.0.1:14443"},
			{dsn, mode, "203.0.113.1:14443"}, {dsn, mode, "localhost:14443"},
			{dsn, mode, "127.0.0.1:http"}, {dsn, mode, "127.0.0.1:0"}, {dsn, mode, "127.0.0.1:65536"}, {dsn, mode, "127.0.0.1:014443"},
			{strings.Replace(dsn, login, "zasp_audit_export_worker", 1), mode, "127.0.0.1:14443"},
			{dsn + "&host=127.0.0.1,203.0.113.1", mode, "127.0.0.1:14443"},
		} {
			if auditExportProcessInputs(test.dsn, test.mode, test.address) == nil {
				t.Fatal("unsafe process input accepted", test.mode, test.address)
			}
		}
	}
}
