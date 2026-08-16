package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var healthTestClient = &http.Client{Timeout: 250 * time.Millisecond}

func TestNewHealthServerRetainsExactBoundsAndStartsNotReady(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "1.2.3-test+1"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	if server.httpServer.Handler != server.handler {
		t.Fatal("HTTP server did not retain the shared handler")
	}
	if server.httpServer.ReadHeaderTimeout != 2*time.Second ||
		server.httpServer.ReadTimeout != 2*time.Second ||
		server.httpServer.WriteTimeout != 2*time.Second ||
		server.httpServer.IdleTimeout != 30*time.Second ||
		server.httpServer.MaxHeaderBytes != 4*1024 ||
		server.shutdownTimeout != 5*time.Second {
		t.Fatalf("unexpected server bounds: %+v timeout=%v", server.httpServer, server.shutdownTimeout)
	}
	assertHandlerResponse(t, server, "/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertHandlerResponse(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")

	for _, path := range []string{"/healthz", "/readyz", "/version", "/metrics"} {
		response := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("default mux %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestNewHealthServerRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	for _, config := range []healthServerConfig{
		{},
		{service: "Event-Ingest", version: "dev"},
		{service: "event-ingest", version: " bad"},
	} {
		if server, err := newHealthServer(config); server != nil || !errors.Is(err, errInvalidHealthConfig) {
			t.Fatalf("newHealthServer(%+v) = (%v, %v), want (nil, errInvalidHealthConfig)", config, server, err)
		}
	}
}

func TestHealthServerServesExactRoutesAndWithdrawsReadiness(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "2.0.0-test"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()

	baseURL := "http://" + listener.Addr().String()
	waitForHealthStatus(t, baseURL+"/readyz", http.StatusOK)
	assertHTTPResponse(t, baseURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertHTTPResponse(t, baseURL+"/readyz", http.StatusOK, "{\"status\":\"ready\"}\n")
	assertHTTPResponse(t, baseURL+"/version", http.StatusOK, "{\"service\":\"event-ingest\",\"version\":\"2.0.0-test\"}\n")
	assertHTTPContains(t, baseURL+"/metrics", "agentsec_ready{service=\"event-ingest\"} 1\n")

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not terminate after cancellation")
	}
	assertHandlerResponse(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")
	if err := server.Serve(context.Background(), listener); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("second Serve() error = %v, want errInvalidHealthRuntime", err)
	}
}

func TestHealthServerRejectsMalformedRuntimeBeforeUse(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "dev"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	listener := &healthStubListener{}
	var typedNilContext *healthStubContext
	var typedNilListener *healthStubListener
	for _, invocation := range []func() error{
		func() error { return server.Serve(nil, listener) },
		func() error { return server.Serve(typedNilContext, listener) },
		func() error { return server.Serve(context.Background(), nil) },
		func() error { return server.Serve(context.Background(), typedNilListener) },
		func() error { var nilServer *healthServer; return nilServer.Serve(context.Background(), listener) },
	} {
		if err := invocation(); !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("Serve() error = %v, want errInvalidHealthRuntime", err)
		}
	}

	for _, mutate := range []func(*healthServer){
		func(value *healthServer) { value.handler = nil },
		func(value *healthServer) { value.httpServer = nil },
		func(value *healthServer) { value.serve = nil },
		func(value *healthServer) { value.shutdown = nil },
		func(value *healthServer) { value.shutdownTimeout = time.Second },
	} {
		value, newErr := newHealthServer(healthServerConfig{service: "event-ingest", version: "dev"})
		if newErr != nil {
			t.Fatalf("newHealthServer() error = %v", newErr)
		}
		mutate(value)
		if err := value.Serve(context.Background(), &healthStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("corrupt Serve() error = %v, want errInvalidHealthRuntime", err)
		}
	}
}

func TestHealthServerUsesIndependentShutdownAndCleanupFailureWins(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "dev"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server.serve = func(net.Listener) error {
		close(started)
		<-release
		return http.ErrServerClosed
	}
	server.shutdown = func(ctx context.Context) error {
		if ctx.Err() != nil {
			t.Error("shutdown inherited main cancellation")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 4*time.Second || time.Until(deadline) > 5*time.Second {
			t.Errorf("shutdown deadline = (%v, %v)", deadline, ok)
		}
		assertHandlerResponse(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")
		close(release)
		return errors.New("sensitive shutdown failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, &healthStubListener{}) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not start")
	}
	if err := server.Serve(context.Background(), &healthStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("concurrent Serve() error = %v, want errInvalidHealthRuntime", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("Serve() error = %v, want errInvalidHealthRuntime", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not terminate after shutdown failure")
	}
}

func TestHealthServerShutdownPanicUnblocksAndJoinsServe(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "dev"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	server.shutdown = func(context.Context) error { panic("sensitive shutdown panic") }
	go func() { result <- server.Serve(ctx, listener) }()
	waitForHealthStatus(t, "http://"+listener.Addr().String()+"/readyz", http.StatusOK)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("Serve() error = %v, want errInvalidHealthRuntime", err)
		}
	case <-time.After(500 * time.Millisecond):
		_ = listener.Close()
		select {
		case <-result:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("Serve() remained blocked after recovered shutdown panic")
	}
	if err := listener.Close(); err == nil {
		t.Fatal("listener remained open after shutdown panic")
	}
}

func TestHealthServerCanceledStartupClosesListenerAndNeverAdvertisesReady(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		closeErr  error
		wantError error
	}{
		{name: "closed", wantError: nil},
		{name: "close failure", closeErr: errors.New("sensitive close failure"), wantError: errInvalidHealthRuntime},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "dev"})
			if err != nil {
				t.Fatalf("newHealthServer() error = %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			listener := &healthStubListener{closeErr: test.closeErr}
			err = server.Serve(ctx, listener)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Serve() error = %v, want %v", err, test.wantError)
			}
			if listener.closes != 1 {
				t.Fatalf("listener closes = %d, want 1", listener.closes)
			}
			assertHandlerResponse(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")
		})
	}
}

func TestHealthServerReturnsFixedErrorForUnexpectedServeResult(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "event-ingest", version: "dev"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	server.serve = func(net.Listener) error { return errors.New("sensitive serve failure") }
	if err := server.Serve(context.Background(), &healthStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("Serve() error = %v, want errInvalidHealthRuntime", err)
	}
	assertHandlerResponse(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")
}

func TestHealthRuntimeCallbackPanicsAreContained(t *testing.T) {
	t.Parallel()

	if err := callHealthServe(func(net.Listener) error { panic("sensitive serve panic") }, &healthStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("callHealthServe() error = %v, want errInvalidHealthRuntime", err)
	}
	if err := callHealthShutdown(func(context.Context) error { panic("sensitive shutdown panic") }, context.Background()); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("callHealthShutdown() error = %v, want errInvalidHealthRuntime", err)
	}
	if err := callHealthClose(&healthPanicCloseListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("callHealthClose() error = %v, want errInvalidHealthRuntime", err)
	}
}

func TestServeProcessExposesEventIngestHealthAndExactOutput(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan healthListenResult, 1)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		opened <- healthListenResult{listener: listener, network: network, address: address, err: err}
		return listener, err
	}
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() { result <- serveProcess(ctx, &output, "1.2.3-test", listen) }()
	var listener net.Listener
	select {
	case value := <-opened:
		if value.err != nil || value.network != "tcp" || value.address != healthListenAddress {
			t.Fatalf("listen = (%q, %q, %v), want (tcp, %s, nil)", value.network, value.address, value.err, healthListenAddress)
		}
		listener = value.listener
	case <-time.After(2 * time.Second):
		t.Fatal("serveProcess() did not attempt listen")
	}
	baseURL := "http://" + listener.Addr().String()
	waitForHealthStatus(t, baseURL+"/readyz", http.StatusOK)
	assertHTTPResponse(t, baseURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertHTTPResponse(t, baseURL+"/readyz", http.StatusOK, "{\"status\":\"ready\"}\n")
	assertHTTPResponse(t, baseURL+"/version", http.StatusOK, "{\"service\":\"event-ingest\",\"version\":\"1.2.3-test\"}\n")
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serveProcess() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveProcess() did not terminate")
	}
	if got, want := output.String(), "event-ingest build 1.2.3-test\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestServeProcessFailsBeforeOrClosesRetainedListener(t *testing.T) {
	t.Parallel()

	t.Run("invalid before listen", func(t *testing.T) {
		calls := 0
		listen := func(string, string) (net.Listener, error) { calls++; return &healthStubListener{}, nil }
		if err := serveProcess(context.Background(), &bytes.Buffer{}, " bad", listen); !errors.Is(err, errInvalidBuildVersion) {
			t.Fatalf("serveProcess() error = %v, want errInvalidBuildVersion", err)
		}
		if calls != 0 {
			t.Fatalf("listen calls = %d, want 0", calls)
		}
	})

	t.Run("canceled before listen", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		listen := func(string, string) (net.Listener, error) { calls++; return &healthStubListener{}, nil }
		if err := serveProcess(ctx, &bytes.Buffer{}, "dev", listen); err != nil || calls != 0 {
			t.Fatalf("serveProcess() = %v, listen calls = %d", err, calls)
		}
	})

	for _, test := range []struct {
		name       string
		listener   *healthStubListener
		listenErr  error
		output     io.Writer
		want       error
		wantCloses int
	}{
		{name: "listen rejection", listener: &healthStubListener{}, listenErr: errListenFixture, output: &bytes.Buffer{}, want: errListenFixture, wantCloses: 1},
		{name: "listen cleanup wins", listener: &healthStubListener{closeErr: errors.New("close failed")}, listenErr: errors.New("listen failed"), output: &bytes.Buffer{}, want: errRuntimeUnavailable, wantCloses: 1},
		{name: "writer rejection", listener: &healthStubListener{}, output: errorWriter{err: errWriteFixture}, want: errWriteFixture, wantCloses: 1},
		{name: "writer panic", listener: &healthStubListener{}, output: healthPanicWriter{}, want: errRuntimeUnavailable, wantCloses: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			listen := func(string, string) (net.Listener, error) { return test.listener, test.listenErr }
			err := serveProcess(context.Background(), test.output, "dev", listen)
			if !errors.Is(err, test.want) {
				t.Fatalf("serveProcess() error = %v, want %v", err, test.want)
			}
			if test.listener.closes != test.wantCloses {
				t.Fatalf("listener closes = %d, want %d", test.listener.closes, test.wantCloses)
			}
		})
	}
}

func TestServeProcessRejectsInvalidRuntimeAndMalformedListenSuccess(t *testing.T) {
	t.Parallel()

	var typedNilContext *healthStubContext
	var typedNilWriter *bytes.Buffer
	for _, invocation := range []func() error{
		func() error {
			return serveProcess(nil, &bytes.Buffer{}, "dev", func(string, string) (net.Listener, error) { return &healthStubListener{}, nil })
		},
		func() error {
			return serveProcess(typedNilContext, &bytes.Buffer{}, "dev", func(string, string) (net.Listener, error) { return &healthStubListener{}, nil })
		},
		func() error {
			return serveProcess(context.Background(), typedNilWriter, "dev", func(string, string) (net.Listener, error) { return &healthStubListener{}, nil })
		},
		func() error { return serveProcess(context.Background(), &bytes.Buffer{}, "dev", nil) },
		func() error {
			return serveProcess(context.Background(), &bytes.Buffer{}, "dev", func(string, string) (net.Listener, error) { return nil, nil })
		},
	} {
		if err := invocation(); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("serveProcess() error = %v, want errRuntimeUnavailable", err)
		}
	}

	listener := &healthStubListener{closeErr: errors.New("sensitive close failure")}
	listen := func(string, string) (net.Listener, error) { return listener, nil }
	if err := serveProcess(context.Background(), errorWriter{err: errWriteFixture}, "dev", listen); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("serveProcess() cleanup error = %v, want errRuntimeUnavailable", err)
	}
}

var (
	errListenFixture = errors.New("listen failed")
	errWriteFixture  = errors.New("write failed")
)

func assertHandlerResponse(t *testing.T, server *healthServer, path string, status int, body string) {
	t.Helper()
	response := httptest.NewRecorder()
	server.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != status || response.Body.String() != body {
		t.Fatalf("GET %s = (%d, %q), want (%d, %q)", path, response.Code, response.Body.String(), status, body)
	}
}

func waitForHealthStatus(t *testing.T, target string, status int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := healthTestClient.Get(target) // #nosec G107 -- owned numeric-loopback test listener.
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == status {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not return status %d", target, status)
}

func assertHTTPResponse(t *testing.T, target string, status int, body string) {
	t.Helper()
	response, err := healthTestClient.Get(target) // #nosec G107 -- owned numeric-loopback test listener.
	if err != nil {
		t.Fatalf("GET %s error = %v", target, err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != status || string(value) != body {
		t.Fatalf("GET %s = (%d, %q, %v), want (%d, %q, nil)", target, response.StatusCode, value, err, status, body)
	}
}

func assertHTTPContains(t *testing.T, target, fragment string) {
	t.Helper()
	response, err := healthTestClient.Get(target) // #nosec G107 -- owned numeric-loopback test listener.
	if err != nil {
		t.Fatalf("GET %s error = %v", target, err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(value), fragment) {
		t.Fatalf("GET %s = (%d, %q, %v), want 200 containing %q", target, response.StatusCode, value, err, fragment)
	}
}

type healthStubListener struct {
	closes   int
	closeErr error
}

type healthStubContext struct{}
type healthPanicWriter struct{}
type healthPanicCloseListener struct{ healthStubListener }
type healthListenResult struct {
	listener net.Listener
	network  string
	address  string
	err      error
}
type healthAddress string

func (*healthStubListener) Accept() (net.Conn, error)  { return nil, errors.New("closed") }
func (listener *healthStubListener) Close() error      { listener.closes++; return listener.closeErr }
func (*healthStubListener) Addr() net.Addr             { return healthAddress("127.0.0.1:0") }
func (*healthStubContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*healthStubContext) Done() <-chan struct{}       { return nil }
func (*healthStubContext) Err() error                  { return nil }
func (*healthStubContext) Value(any) any               { return nil }
func (healthPanicWriter) Write([]byte) (int, error)    { panic("sensitive writer panic") }
func (*healthPanicCloseListener) Close() error         { panic("sensitive close panic") }
func (healthAddress) Network() string                  { return "tcp" }
func (address healthAddress) String() string           { return string(address) }
