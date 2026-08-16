package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayHealthServerLifecycle(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "1.2.3-test"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	assertGatewayHandler(t, server, "/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertGatewayHandler(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	baseURL := "http://" + listener.Addr().String()
	waitForGatewayStatus(t, baseURL+"/readyz", http.StatusOK)
	assertGatewayHTTP(t, baseURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertGatewayHTTP(t, baseURL+"/readyz", http.StatusOK, "{\"status\":\"ready\"}\n")
	assertGatewayHTTP(t, baseURL+"/version", http.StatusOK, "{\"service\":\"runtime-gateway\",\"version\":\"1.2.3-test\"}\n")
	assertGatewayContains(t, baseURL+"/metrics", "agentsec_ready{service=\"runtime-gateway\"} 1\n")

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not terminate")
	}
	assertGatewayHandler(t, server, "/readyz", http.StatusServiceUnavailable, "{\"status\":\"not_ready\"}\n")
	if err := listener.Close(); err == nil {
		t.Fatal("listener remained open")
	}
}

func TestGatewayHealthServerBoundsAndInvalidState(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
	if err != nil {
		t.Fatalf("newHealthServer() error = %v", err)
	}
	if server.httpServer.Handler == http.DefaultServeMux ||
		server.httpServer.ReadHeaderTimeout != 2*time.Second ||
		server.httpServer.ReadTimeout != 2*time.Second ||
		server.httpServer.WriteTimeout != 2*time.Second ||
		server.httpServer.IdleTimeout != 30*time.Second ||
		server.httpServer.MaxHeaderBytes != 4*1024 ||
		server.shutdownTimeout != 5*time.Second {
		t.Fatal("health server bounds do not match the fixed contract")
	}
	for _, config := range []healthServerConfig{
		{},
		{service: "Runtime-Gateway", version: "dev"},
		{service: "runtime-gateway", version: " bad"},
	} {
		if _, err := newHealthServer(config); err == nil {
			t.Fatalf("newHealthServer(%+v) accepted invalid config", config)
		}
	}
	var nilServer *healthServer
	if err := nilServer.Serve(context.Background(), &gatewayStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("nil Serve() error = %v", err)
	}
	if err := server.Serve(nil, &gatewayStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("nil context error = %v", err)
	}
	if err := server.Serve(context.Background(), nil); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("nil listener error = %v", err)
	}
}

func TestGatewayHealthServerShutdownPanicUnblocksAndContainsPanics(t *testing.T) {
	t.Parallel()

	server, err := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
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
	waitForGatewayStatus(t, "http://"+listener.Addr().String()+"/readyz", http.StatusOK)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("Serve() error = %v, want fixed runtime error", err)
		}
	case <-time.After(500 * time.Millisecond):
		_ = listener.Close()
		t.Fatal("Serve() remained blocked after shutdown panic")
	}
	if err := callHealthServe(func(net.Listener) error { panic("sensitive serve panic") }, &gatewayStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("callHealthServe() error = %v", err)
	}
	if err := callHealthClose(&gatewayPanicCloseListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("callHealthClose() error = %v", err)
	}
}

func TestGatewayHealthServerMalformedAndCleanupMatrix(t *testing.T) {
	t.Parallel()

	listener := &gatewayStubListener{}
	var typedNilContext *gatewayStubContext
	var typedNilListener *gatewayStubListener
	for _, invocation := range []func() error{
		func() error {
			server, _ := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
			return server.Serve(typedNilContext, listener)
		},
		func() error {
			server, _ := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
			return server.Serve(context.Background(), typedNilListener)
		},
	} {
		if err := invocation(); !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("typed-nil Serve() error = %v", err)
		}
	}
	for _, mutate := range []func(*healthServer){
		func(value *healthServer) { value.handler = nil },
		func(value *healthServer) { value.httpServer = nil },
		func(value *healthServer) { value.serve = nil },
		func(value *healthServer) { value.shutdown = nil },
		func(value *healthServer) { value.shutdownTimeout = time.Second },
	} {
		server, _ := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
		mutate(server)
		if err := server.Serve(context.Background(), &gatewayStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("corrupt Serve() error = %v", err)
		}
	}

	for _, closeErr := range []error{nil, errors.New("sensitive close failure")} {
		server, _ := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		candidate := &gatewayStubListener{closeErr: closeErr}
		err := server.Serve(ctx, candidate)
		if closeErr == nil && err != nil || closeErr != nil && !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("canceled Serve() error = %v, close error = %v", err, closeErr)
		}
		if candidate.closes != 1 {
			t.Fatalf("candidate closes = %d, want 1", candidate.closes)
		}
	}

	server, _ := newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
	server.serve = func(net.Listener) error { return errors.New("sensitive serve failure") }
	if err := server.Serve(context.Background(), &gatewayStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("unexpected serve result = %v", err)
	}

	server, _ = newHealthServer(healthServerConfig{service: "runtime-gateway", version: "dev"})
	started := make(chan struct{})
	release := make(chan struct{})
	server.serve = func(net.Listener) error {
		close(started)
		<-release
		return http.ErrServerClosed
	}
	server.shutdown = func(ctx context.Context) error {
		if ctx.Err() != nil {
			t.Error("shutdown inherited canceled main context")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 4*time.Second || time.Until(deadline) > 5*time.Second {
			t.Errorf("shutdown deadline = %v, %v", deadline, ok)
		}
		close(release)
		return errors.New("sensitive shutdown failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, &gatewayStubListener{}) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not start")
	}
	if err := server.Serve(context.Background(), &gatewayStubListener{}); !errors.Is(err, errInvalidHealthRuntime) {
		t.Fatalf("concurrent Serve() error = %v", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, errInvalidHealthRuntime) {
			t.Fatalf("shutdown failure result = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not join shutdown")
	}
}

func TestGatewayServeProcessRealListenerAndPreflight(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	var output gatewayLockedBuffer
	opened := make(chan net.Listener, 1)
	result := make(chan error, 1)
	go func() {
		result <- serveProcess(ctx, &output, "1.2.3-test", func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != healthListenAddress {
				t.Errorf("listen = %q %q", network, address)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			opened <- listener
			return listener, err
		})
	}()
	waitForGatewayOutput(t, &output, "runtime-gateway build 1.2.3-test\n")
	listener := <-opened
	baseURL := "http://" + listener.Addr().String()
	waitForGatewayStatus(t, baseURL+"/readyz", http.StatusOK)
	assertGatewayHTTP(t, baseURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertGatewayHTTP(t, baseURL+"/readyz", http.StatusOK, "{\"status\":\"ready\"}\n")
	assertGatewayHTTP(t, baseURL+"/version", http.StatusOK, "{\"service\":\"runtime-gateway\",\"version\":\"1.2.3-test\"}\n")
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serveProcess() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveProcess() did not terminate")
	}

	canceled, stop := context.WithCancel(context.Background())
	stop()
	var listened atomic.Bool
	if err := serveProcess(canceled, &bytes.Buffer{}, "dev", func(string, string) (net.Listener, error) {
		listened.Store(true)
		return &gatewayStubListener{}, nil
	}); err != nil || listened.Load() {
		t.Fatalf("canceled preflight error/listened = %v/%v", err, listened.Load())
	}
}

func TestGatewayServeProcessFailureMatrix(t *testing.T) {
	t.Parallel()

	var listenCalls atomic.Int32
	listen := func(string, string) (net.Listener, error) {
		listenCalls.Add(1)
		return &gatewayStubListener{}, nil
	}
	if err := serveProcess(context.Background(), &bytes.Buffer{}, " bad", listen); !errors.Is(err, errInvalidBuildVersion) || listenCalls.Load() != 0 {
		t.Fatalf("invalid version = %v, calls = %d", err, listenCalls.Load())
	}
	var typedNilContext *gatewayStubContext
	var typedNilWriter *bytes.Buffer
	for _, invocation := range []func() error{
		func() error { return serveProcess(nil, &bytes.Buffer{}, "dev", listen) },
		func() error { return serveProcess(typedNilContext, &bytes.Buffer{}, "dev", listen) },
		func() error { return serveProcess(context.Background(), typedNilWriter, "dev", listen) },
		func() error { return serveProcess(context.Background(), &bytes.Buffer{}, "dev", nil) },
		func() error {
			return serveProcess(context.Background(), &bytes.Buffer{}, "dev", func(string, string) (net.Listener, error) { return nil, nil })
		},
	} {
		if err := invocation(); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("invalid runtime error = %v", err)
		}
	}

	for _, test := range []struct {
		name       string
		listener   *gatewayStubListener
		listenErr  error
		output     io.Writer
		want       error
		wantCloses int
	}{
		{name: "listen rejection", listener: &gatewayStubListener{}, listenErr: errGatewayListen, output: &bytes.Buffer{}, want: errGatewayListen, wantCloses: 1},
		{name: "listen cleanup wins", listener: &gatewayStubListener{closeErr: errors.New("close failed")}, listenErr: errGatewayListen, output: &bytes.Buffer{}, want: errRuntimeUnavailable, wantCloses: 1},
		{name: "writer rejection", listener: &gatewayStubListener{}, output: errorWriter{err: errGatewayWrite}, want: errGatewayWrite, wantCloses: 1},
		{name: "writer cleanup wins", listener: &gatewayStubListener{closeErr: errors.New("close failed")}, output: errorWriter{err: errGatewayWrite}, want: errRuntimeUnavailable, wantCloses: 1},
		{name: "writer panic", listener: &gatewayStubListener{}, output: gatewayPanicWriter{}, want: errRuntimeUnavailable, wantCloses: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := serveProcess(context.Background(), test.output, "dev", func(string, string) (net.Listener, error) {
				return test.listener, test.listenErr
			})
			if !errors.Is(err, test.want) || test.listener.closes != test.wantCloses {
				t.Fatalf("serveProcess() = %v, closes = %d, want %v/%d", err, test.listener.closes, test.want, test.wantCloses)
			}
		})
	}
	if err := serveProcess(context.Background(), gatewayPanicWriter{}, "dev", func(string, string) (net.Listener, error) {
		return &gatewayPanicCloseListener{}, nil
	}); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("nested panic result = %v", err)
	}
}

func assertGatewayHandler(t *testing.T, server *healthServer, path string, status int, body string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != status || recorder.Body.String() != body {
		t.Fatalf("%s = %d %q, want %d %q", path, recorder.Code, recorder.Body.String(), status, body)
	}
}

func assertGatewayHTTP(t *testing.T, url string, status int, body string) {
	t.Helper()
	response, err := (&http.Client{Timeout: time.Second}).Get(url)
	if err != nil {
		t.Fatalf("GET %s error = %v", url, err)
	}
	defer response.Body.Close()
	recorder := httptest.NewRecorder()
	_, _ = recorder.Body.ReadFrom(response.Body)
	if response.StatusCode != status || recorder.Body.String() != body {
		t.Fatalf("GET %s = %d %q", url, response.StatusCode, recorder.Body.String())
	}
}

func assertGatewayContains(t *testing.T, url, fragment string) {
	t.Helper()
	response, err := (&http.Client{Timeout: time.Second}).Get(url)
	if err != nil {
		t.Fatalf("GET %s error = %v", url, err)
	}
	defer response.Body.Close()
	recorder := httptest.NewRecorder()
	_, _ = recorder.Body.ReadFrom(response.Body)
	if response.StatusCode != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(fragment)) {
		t.Fatalf("GET %s = %d %q", url, response.StatusCode, recorder.Body.String())
	}
}

func waitForGatewayStatus(t *testing.T, url string, status int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := (&http.Client{Timeout: 100 * time.Millisecond}).Get(url)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == status {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not reach %d", url, status)
}

func waitForGatewayOutput(t *testing.T, output *gatewayLockedBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if output.String() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("output = %q, want %q", output.String(), want)
}

type gatewayPanicCloseListener struct{ gatewayStubListener }
type gatewayStubContext struct{}
type gatewayPanicWriter struct{}
type gatewayAddress string
type gatewayLockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

var (
	errGatewayListen = errors.New("listen failed")
	errGatewayWrite  = errors.New("write failed")
)

type gatewayStubListener struct {
	closes   int
	closeErr error
}

func (*gatewayStubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (listener *gatewayStubListener) Close() error {
	listener.closes++
	return listener.closeErr
}
func (*gatewayStubListener) Addr() net.Addr             { return gatewayAddress("127.0.0.1:0") }
func (*gatewayPanicCloseListener) Close() error         { panic("sensitive close panic") }
func (*gatewayStubContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*gatewayStubContext) Done() <-chan struct{}       { return nil }
func (*gatewayStubContext) Err() error                  { return nil }
func (*gatewayStubContext) Value(any) any               { return nil }
func (gatewayPanicWriter) Write([]byte) (int, error)    { panic("sensitive writer panic") }
func (gatewayAddress) Network() string                  { return "tcp" }
func (address gatewayAddress) String() string           { return string(address) }
func (buffer *gatewayLockedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}
func (buffer *gatewayLockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}
