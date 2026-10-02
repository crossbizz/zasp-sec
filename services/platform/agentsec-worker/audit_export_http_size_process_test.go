//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	goruntime "runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestAuditHTTPSizeWorkerRetention(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Own") != "unchanged" || r.ContentLength != 7 {
			t.Error("tee changed request")
		}
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer server.Close()
	retained := new(auditHTTPSizeWorkerRetained)
	client := &http.Client{Transport: &auditHTTPSizeWorkerTee{base: http.DefaultTransport, retained: retained}}
	defer client.CloseIdleConnections()
	for _, method := range []string{"PUT", "POST"} {
		r, _ := http.NewRequest(method, server.URL, bytes.NewBufferString("payload"))
		r.Header.Set("X-Own", "unchanged")
		body := &auditHTTPSizeCloseProbe{ReadCloser: r.Body, closed: make(chan struct{})}
		r.Body = body
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		select {
		case <-body.closed:
		case <-time.After(time.Second):
			t.Fatal("tee lost body Close")
		}
		if string(received) != "payload" || retained.Bytes() != 7 {
			t.Fatal("actual transport bytes/Close/PUT retention changed", retained.Bytes())
		}
	}
}

type auditHTTPSizeCloseProbe struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
}

func (b *auditHTTPSizeCloseProbe) Close() error {
	b.once.Do(func() { close(b.closed) })
	return b.ReadCloser.Close()
}

type auditHTTPSizeWorkerRetained struct {
	mu     sync.Mutex
	chunks [][]byte
	count  int64
}

func (r *auditHTTPSizeWorkerRetained) Bytes() int64 { r.mu.Lock(); defer r.mu.Unlock(); return r.count }
func (r *auditHTTPSizeWorkerRetained) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunks = append(r.chunks, append([]byte(nil), p...))
	r.count += int64(len(p))
	return len(p), nil
}

type auditHTTPSizeWorkerTee struct {
	base     http.RoundTripper
	retained *auditHTTPSizeWorkerRetained
}

func (t *auditHTTPSizeWorkerTee) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && r.Body != nil {
		copy := r.Clone(r.Context())
		copy.Body = &auditHTTPSizeTeeBody{Reader: io.TeeReader(r.Body, t.retained), closer: r.Body}
		return t.base.RoundTrip(copy)
	}
	return t.base.RoundTrip(r)
}

type auditHTTPSizeTeeBody struct {
	io.Reader
	closer io.Closer
}

func (b *auditHTTPSizeTeeBody) Close() error { return b.closer.Close() }

type auditHTTPSizeCaptureClock struct{ t *testing.T }
type auditHTTPSizeCaptureClockKey struct{}

func (c auditHTTPSizeCaptureClock) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if data.SQL == auditExportWorkerCaptureSQL {
		return context.WithValue(ctx, auditHTTPSizeCaptureClockKey{}, time.Now())
	}
	return ctx
}
func (c auditHTTPSizeCaptureClock) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if started, ok := ctx.Value(auditHTTPSizeCaptureClockKey{}).(time.Time); ok {
		c.t.Logf("actual capture query elapsed=%s policy_capture=120s success=%v", time.Since(started), data.Err == nil)
	}
}

func TestAuditHTTPSizeWorkerProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_HTTP_SIZE_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned worker fixture")
	}
	mode, address := os.Getenv("ZASP_AUDIT_HTTP_SIZE_MODE"), os.Getenv("ZASP_AUDIT_HTTP_SIZE_ADDRESS")
	control := os.Getenv("ZASP_AUDIT_HTTP_SIZE_CONTROL")
	if control != "" && control != "diagnostics" && (control != "worker-retain" || mode != "audit-export") || os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_FAULT") != "" || os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_OUTCOME") != "" {
		t.Fatal("invalid worker control")
	}
	if err := auditExportProcessInputs(dsn, mode, address); err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_AUDIT_HTTP_SIZE_DEADLINE"))
	maximum := 8 * time.Minute
	if mode == "audit-export-outbox" {
		maximum = 90 * time.Second
	}
	if err != nil || time.Until(deadline) <= 20*time.Second || time.Until(deadline) > maximum {
		t.Fatal("invalid worker deadline")
	}
	ca := auditExportProcessPrivateFile(t, os.Getenv("ZASP_AUDIT_HTTP_SIZE_CA"), 16384)
	tokenPath := os.Getenv("ZASP_AUDIT_HTTP_SIZE_TOKEN")
	_ = auditExportProcessPrivateFile(t, tokenPath, 4096)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid owned worker CA")
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline.Add(-20*time.Second))
	defer cancel()
	values := auditExportProductionEnvironment(mode)
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
	retained := new(auditHTTPSizeWorkerRetained)
	if control == "worker-retain" {
		queue, ok := clients.queue.(*sqs.Client)
		if !ok {
			t.Fatal("actual SDK queue client missing")
		}
		client, ok := queue.Options().HTTPClient.(*http.Client)
		if !ok || client.Transport != clients.transport {
			t.Fatal("shared SDK transport missing")
		}
		client.Transport = &auditHTTPSizeWorkerTee{base: clients.transport, retained: retained}
	}
	clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = tokenPath
	clients.transport.Proxy = nil
	clients.transport.TLSClientConfig.RootCAs = roots
	clients.transport.TLSClientConfig.ServerName = "example.com"
	clients.transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(destination)
		if network != "tcp" || err != nil || port != "443" || (host != "sts.us-east-1.amazonaws.com" && host != "sqs.us-east-1.amazonaws.com" && (mode != "audit-export" || host != auditExportWorkerPolicyFixture().Bucket+".s3.us-east-1.amazonaws.com")) {
			return nil, errors.New("unexpected owned worker provider destination")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns, poolConfig.MinConns = 3, 1
	poolConfig.ConnConfig.Tracer = auditHTTPSizeCaptureClock{t: t}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	// The pool is needed by concurrent lease renewal. Explicitly join its close
	// before the terminal record, including partial runtime construction.
	closePool := func() error {
		done := make(chan struct{})
		go func() { pool.Close(); close(done) }()
		select {
		case <-done:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("worker pool close join uncertain")
		}
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err, closePool())
	}
	runtime, err := composeAuditExportWorkerRuntime(ctx, config, database, clients)
	if err != nil {
		cancel()
		clients.transport.CloseIdleConnections()
		t.Fatal("actual worker composition", err, closePool())
	}
	runErr := runtime.Processor.RunOnce(ctx)
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close() }()
	var runtimeErr error
	select {
	case runtimeErr = <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("worker runtime join uncertain")
	}
	clients.transport.CloseIdleConnections()
	poolErr := closePool()
	if err := errors.Join(runErr, runtimeErr, poolErr); err != nil {
		t.Fatal("worker operation/cleanup refused", err)
	}
	status := os.NewFile(3, "status")
	defer status.Close()
	var selfRSS int64
	if control == "diagnostics" {
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil || usage.Maxrss <= 0 {
			t.Fatal("self rusage unavailable", err)
		}
		selfRSS = usage.Maxrss
		if goruntime.GOOS == "linux" {
			if selfRSS > int64(^uint64(0)>>1)/1024 {
				t.Fatal("self rusage overflow")
			}
			selfRSS *= 1024
		}
	}
	if err := json.NewEncoder(status).Encode(struct {
		PID           int    `json:"pid"`
		URL           string `json:"url"`
		Mode          string `json:"mode"`
		RetainedBytes int64  `json:"retained_bytes,omitempty"`
		SelfRSSBytes  int64  `json:"self_rss_bytes,omitempty"`
	}{os.Getpid(), "cleanup-complete", mode, retained.Bytes(), selfRSS}); err != nil {
		t.Fatal(err)
	}
	goruntime.KeepAlive(retained)
	t.Logf("actual Processor.RunOnce and explicit runtime/transport/pool cleanup: mode=%s pid=%d", mode, os.Getpid())
}
