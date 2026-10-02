//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// A broadened phase must not start a production worker with fixture authority.
func TestAuditExportRecoveryProcessClosedPhases(t *testing.T) {
	for _, phase := range []string{"capture", "receipt", "stale", "claim", "manifest", "finish", "recovery", "terminal"} {
		if !auditExportRecoveryPhase(phase) {
			t.Errorf("closed phase refused: %s", phase)
		}
	}
	for _, phase := range []string{"", "anything", "outbox", "../capture"} {
		if auditExportRecoveryPhase(phase) {
			t.Errorf("foreign phase admitted: %s", phase)
		}
	}
}

// Losing the wrong side of SQL would falsely label an uncommitted operation.
func TestAuditExportRecoveryProcessCutOrdering(t *testing.T) {
	for _, tc := range []struct {
		phase, query string
		before       bool
	}{
		{"capture", auditExportWorkerCaptureSQL, false},
		{"receipt", auditExportWorkerRecordChunkSQL, false},
		{"stale", auditExportWorkerRecordChunkSQL, true},
		{"claim", auditExportWorkerClaimSQL, false},
		{"manifest", auditExportWorkerFinishSQL, true},
		{"finish", auditExportWorkerFinishSQL, false},
	} {
		if !auditExportRecoveryCut(tc.phase, tc.query, tc.before) || auditExportRecoveryCut(tc.phase, tc.query, !tc.before) || auditExportRecoveryCut(tc.phase, auditExportWorkerRetrySQL, tc.before) {
			t.Errorf("wrong SQL loss boundary: %s", tc.phase)
		}
	}
}

func auditExportRecoveryPhase(phase string) bool {
	switch phase {
	case "capture", "receipt", "stale", "claim", "manifest", "finish", "recovery", "terminal":
		return true
	}
	return false
}
func auditExportRecoveryCut(phase, query string, before bool) bool {
	switch phase {
	case "capture":
		return query == auditExportWorkerCaptureSQL && !before
	case "receipt":
		return query == auditExportWorkerRecordChunkSQL && !before
	case "stale":
		return query == auditExportWorkerRecordChunkSQL && before
	case "claim":
		return query == auditExportWorkerClaimSQL && !before
	case "manifest":
		return query == auditExportWorkerFinishSQL && before
	case "finish":
		return query == auditExportWorkerFinishSQL && !before
	}
	return false
}

type auditExportRecoveryObservation struct {
	PID                                               int
	Phase, Operation                                  string
	Before, Hold, ContextLive                         bool
	Body                                              json.RawMessage
	SQLState, Worker, TokenDigest, CaptureID, Version string
	Generation                                        int64
	Attempt                                           int
}

type auditExportRecoveryDatabase struct {
	base            recoveryJSONDatabase
	phase, endpoint string
	client          *http.Client
	mu              sync.Mutex
	cut             bool
}

func (d *auditExportRecoveryDatabase) observe(ctx context.Context, query string, before bool, body json.RawMessage, callErr error, args []any) error {
	operation := ""
	switch query {
	case auditExportWorkerClaimSQL:
		operation = "claim"
	case auditExportWorkerCaptureSQL:
		operation = "capture"
	case auditExportWorkerRecordChunkSQL:
		operation = "record"
	case auditExportWorkerFinishSQL:
		operation = "finish"
	case auditExportWorkerRetrySQL:
		operation = "retry"
	case auditExportWorkerTerminalSQL:
		operation = "terminal"
	default:
		return nil
	}
	event := auditExportRecoveryObservation{PID: os.Getpid(), Phase: d.phase, Operation: operation, Before: before, Body: body, ContextLive: ctx.Err() == nil}
	if callErr != nil {
		var pg *pgconn.PgError
		if errors.As(callErr, &pg) {
			event.SQLState = pg.Code
		} else {
			event.SQLState = "non-pg-error"
		}
	}
	if operation != "claim" && operation != "terminal" {
		event.CaptureID, _ = args[4].(string)
		event.Generation, _ = args[5].(int64)
		event.Attempt, _ = args[6].(int)
		event.Worker, _ = args[7].(string)
		token, _ := args[8].(string)
		digest := sha256.Sum256([]byte(token))
		event.TokenDigest = hex.EncodeToString(digest[:])
		if operation == "record" {
			event.Version, _ = args[14].(string)
		}
		if operation == "finish" {
			event.Version, _ = args[13].(string)
		}
	}
	d.mu.Lock()
	event.Hold = !d.cut && callErr == nil && auditExportRecoveryCut(d.phase, query, before)
	if event.Hold {
		d.cut = true
	}
	d.mu.Unlock()
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusNoContent {
		return errors.New("parent observation refused")
	}
	return err
}

// Successful responses are held only after the real database call returned.
// Before-Record/Finish cuts occur after writeArtifact's real SDK pinned reads.
func (d *auditExportRecoveryDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if err := d.observe(ctx, query, true, nil, nil, args); err != nil {
		return nil, err
	}
	body, err := d.base.QueryJSON(ctx, query, args...)
	if observed := d.observe(ctx, query, false, body, err, args); observed != nil {
		return nil, observed
	}
	return body, err
}

func TestAuditExportRecoveryProcessWorkerPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_DSN")
	if dsn == "" {
		t.Skip("parent-owned recovery fixture")
	}
	phase := os.Getenv("ZASP_AUDIT_EXPORT_RECOVERY_PHASE")
	address := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_ADDRESS")
	endpoint, err := url.Parse(os.Getenv("ZASP_AUDIT_EXPORT_RECOVERY_CONTROL"))
	if !auditExportRecoveryPhase(phase) || auditExportProcessInputs(dsn, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_MODE"), address) != nil || endpoint == nil || err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/observe" || os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_MODE") != "audit-export" || os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_FAULT") != "" || os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_OUTCOME") != "" {
		t.Fatal("closed recovery inputs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := auditExportProcessPrivateFile(t, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_CA"), 16384)
	token := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_TOKEN")
	_ = auditExportProcessPrivateFile(t, token, 4096)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("recovery CA")
	}
	values := auditExportProductionEnvironment("audit-export")
	values["ZASP_POSTGRES_DSN"], values["ZASP_BATCH_SIZE"] = dsn, "1"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil {
		t.Fatal(err)
	}
	clients, err := newAuditExportProductionClients(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clients.transport.CloseIdleConnections()
	clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = token
	clients.transport.TLSClientConfig.RootCAs, clients.transport.TLSClientConfig.ServerName = roots, "example.com"
	clients.transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(destination)
		if err != nil || port != "443" || (host != "sts.us-east-1.amazonaws.com" && host != "sqs.us-east-1.amazonaws.com" && host != auditExportWorkerPolicyFixture().Bucket+".s3.us-east-1.amazonaws.com") {
			return nil, errors.New("foreign recovery destination")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	database := &auditExportRecoveryDatabase{base: combinedE2ERecoveryDatabase(t, ctx, dsn), phase: phase, endpoint: endpoint.String(), client: &http.Client{Transport: transport, Timeout: 25 * time.Second}}
	runtime, err := composeAuditExportWorkerRuntime(ctx, config, database, clients)
	if err != nil {
		t.Fatal(err)
	}
	runErr := runtime.Processor.RunOnce(ctx)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || (runErr != nil) != (phase == "stale") {
		t.Fatal("recovery RunOnce", runErr, ctx.Err())
	}
	t.Log(fmt.Sprintf("registered recovery joined: phase=%s pid=%d run_error=%t", phase, os.Getpid(), runErr != nil))
}
