package healthserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testHTTPClient = &http.Client{Timeout: 250 * time.Millisecond}

func TestNewRetainsExactBoundedHTTPServer(t *testing.T) {
	t.Parallel()

	server, err := New(Config{Service: "agentsec-api", Version: "1.2.3-test+1"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if server.httpServer.Handler != server.handler {
		t.Fatal("http handler does not retain the shared health handler")
	}
	if got, want := server.httpServer.ReadHeaderTimeout, 2*time.Second; got != want {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", got, want)
	}
	if got, want := server.httpServer.ReadTimeout, 2*time.Second; got != want {
		t.Fatalf("ReadTimeout = %v, want %v", got, want)
	}
	if got, want := server.httpServer.WriteTimeout, 2*time.Second; got != want {
		t.Fatalf("WriteTimeout = %v, want %v", got, want)
	}
	if got, want := server.httpServer.IdleTimeout, 30*time.Second; got != want {
		t.Fatalf("IdleTimeout = %v, want %v", got, want)
	}
	if got, want := server.httpServer.MaxHeaderBytes, 4*1024; got != want {
		t.Fatalf("MaxHeaderBytes = %d, want %d", got, want)
	}
	if got, want := server.shutdownTimeout, 5*time.Second; got != want {
		t.Fatalf("shutdownTimeout = %v, want %v", got, want)
	}
}

func TestReadinessProbesBackOffWithoutOverlapAndRecover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active, maximum, calls atomic.Int32
	ready := atomic.Bool{}
	states := make(chan bool, 8)
	check := func(context.Context) bool {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			prior := maximum.Load()
			if current <= prior || maximum.CompareAndSwap(prior, current) {
				break
			}
		}
		count := calls.Add(1)
		if count >= 3 {
			ready.Store(true)
		}
		time.Sleep(3 * time.Millisecond)
		return ready.Load()
	}
	done := make(chan struct{})
	go func() {
		runReadyProbes(ctx, 5*time.Millisecond, 20*time.Millisecond, check, func(value bool) {
			states <- value
			if value {
				cancel()
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe loop did not recover")
	}
	if maximum.Load() != 1 || calls.Load() != 3 {
		t.Fatalf("probes max/calls = %d/%d", maximum.Load(), calls.Load())
	}
	if !ready.Load() {
		t.Fatal("readiness did not recover")
	}
}

func TestReadyPropagatesCancellationToBlockedProbe(t *testing.T) {
	probeStarted := make(chan struct{})
	probeDone := make(chan struct{})
	server, err := New(Config{Service: "agentsec-api", Version: "dev", ReadyCheck: func(ctx context.Context) bool {
		close(probeStarted)
		<-ctx.Done()
		close(probeDone)
		return false
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- server.ready(ctx) }()
	<-probeStarted
	cancel()
	select {
	case ready := <-result:
		if ready {
			t.Fatal("canceled provider probe reported ready")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("provider probe did not observe runtime cancellation")
	}
	select {
	case <-probeDone:
	default:
		t.Fatal("provider probe did not finish before readiness returned")
	}
}

func TestNewRejectsInvalidSharedConfiguration(t *testing.T) {
	t.Parallel()

	for _, configuration := range []Config{
		{},
		{Service: "AgentSec-API", Version: "dev"},
		{Service: "agentsec-api", Version: " bad"},
	} {
		if server, err := New(configuration); server != nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(%+v) = (%v, %v), want (nil, ErrInvalidConfig)", configuration, server, err)
		}
	}
}

func TestNewDoesNotRegisterSharedRoutesOnDefaultMux(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{Service: "agentsec-api", Version: "dev"}); err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, path := range []string{"/healthz", "/readyz", "/version", "/metrics"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("default mux %s status = %d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
}

func TestServeExposesExactRoutesOverRealListener(t *testing.T) {
	t.Parallel()

	server, err := New(Config{Service: "agentsec-worker", Version: "2.0.0-test"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()

	baseURL := "http://" + listener.Addr().String()
	waitForStatus(t, baseURL+"/readyz", http.StatusOK)
	assertResponse(t, baseURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertResponse(t, baseURL+"/readyz", http.StatusOK, "{\"status\":\"ready\"}\n")
	assertResponse(t, baseURL+"/version", http.StatusOK, "{\"service\":\"agentsec-worker\",\"version\":\"2.0.0-test\"}\n")
	assertResponseContains(t, baseURL+"/metrics", "agentsec_ready{service=\"agentsec-worker\"} 1\n")

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not terminate after cancellation")
	}
	if err := server.Serve(context.Background(), listener); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("second Serve() error = %v, want ErrInvalidRuntime", err)
	}
}

func TestServeRejectsInvalidRuntimeBeforeUse(t *testing.T) {
	t.Parallel()

	server, err := New(Config{Service: "agentsec-api", Version: "dev"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	listener := &stubListener{}
	if err := server.Serve(nil, listener); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("Serve(nil context) error = %v, want ErrInvalidRuntime", err)
	}
	if err := server.Serve(context.Background(), nil); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("Serve(nil listener) error = %v, want ErrInvalidRuntime", err)
	}
	var typedNilContext *stubContext
	if err := server.Serve(typedNilContext, listener); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("Serve(typed-nil context) error = %v, want ErrInvalidRuntime", err)
	}
	var typedNilListener *stubListener
	if err := server.Serve(context.Background(), typedNilListener); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("Serve(typed-nil listener) error = %v, want ErrInvalidRuntime", err)
	}
	var nilServer *Server
	if err := nilServer.Serve(context.Background(), listener); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("nil Server.Serve() error = %v, want ErrInvalidRuntime", err)
	}
}

func TestServeRejectsCorruptedRetainedState(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*Server)
	}{
		{name: "handler", mutate: func(server *Server) { server.handler = nil }},
		{name: "http server", mutate: func(server *Server) { server.httpServer = nil }},
		{name: "serve function", mutate: func(server *Server) { server.serve = nil }},
		{name: "shutdown function", mutate: func(server *Server) { server.shutdown = nil }},
		{name: "shutdown timeout", mutate: func(server *Server) { server.shutdownTimeout = time.Second }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server, err := New(Config{Service: "agentsec-api", Version: "dev"})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			test.mutate(server)
			if err := server.Serve(context.Background(), &stubListener{}); !errors.Is(err, ErrInvalidRuntime) {
				t.Fatalf("Serve() error = %v, want ErrInvalidRuntime", err)
			}
		})
	}
}

func TestServeCanceledBeforeStartupNeverAdvertisesReady(t *testing.T) {
	t.Parallel()

	server, err := New(Config{Service: "agentsec-api", Version: "dev"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listener := &stubListener{}
	if err := server.Serve(ctx, listener); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.handler.ServeHTTP(response, request)
	if got, want := response.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("ready status = %d, want %d", got, want)
	}
	if listener.accepts != 0 {
		t.Fatalf("listener accepts = %d, want 0", listener.accepts)
	}

	closeFailure, err := New(Config{Service: "agentsec-api", Version: "dev"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := closeFailure.Serve(ctx, &stubListener{closeErr: errors.New("close failed")}); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("Serve() close error = %v, want ErrInvalidRuntime", err)
	}
}

func TestServeFencesConcurrentUseAndDropsReadyBeforeShutdown(t *testing.T) {
	t.Parallel()

	server, err := New(Config{Service: "agentsec-api", Version: "dev"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server.serve = func(net.Listener) error {
		close(started)
		<-release
		return http.ErrServerClosed
	}
	server.shutdown = func(shutdownContext context.Context) error {
		if shutdownContext.Err() != nil {
			t.Error("shutdown context inherited cancellation")
		}
		deadline, ok := shutdownContext.Deadline()
		if !ok {
			t.Error("shutdown context has no deadline")
		} else if remaining := time.Until(deadline); remaining <= 4*time.Second || remaining > shutdownTimeout {
			t.Errorf("shutdown deadline remaining = %v, want (4s, %v]", remaining, shutdownTimeout)
		}
		request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		response := httptest.NewRecorder()
		server.handler.ServeHTTP(response, request)
		if got, want := response.Code, http.StatusServiceUnavailable; got != want {
			t.Errorf("ready status during shutdown = %d, want %d", got, want)
		}
		close(release)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, &stubListener{}) }()
	<-started
	if err := server.Serve(context.Background(), &stubListener{}); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("concurrent Serve() error = %v, want ErrInvalidRuntime", err)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeReturnsFixedErrorsForServeAndShutdownFailures(t *testing.T) {
	t.Parallel()

	t.Run("serve", func(t *testing.T) {
		server, err := New(Config{Service: "agentsec-api", Version: "dev"})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		server.serve = func(net.Listener) error { return errors.New("sensitive serve failure") }
		if err := server.Serve(context.Background(), &stubListener{}); !errors.Is(err, ErrInvalidRuntime) {
			t.Fatalf("Serve() error = %v, want ErrInvalidRuntime", err)
		}
	})

	t.Run("shutdown", func(t *testing.T) {
		server, err := New(Config{Service: "agentsec-api", Version: "dev"})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		release := make(chan struct{})
		server.serve = func(net.Listener) error {
			<-release
			return http.ErrServerClosed
		}
		server.shutdown = func(context.Context) error {
			close(release)
			return errors.New("sensitive shutdown failure")
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- server.Serve(ctx, &stubListener{}) }()
		waitForHandlerReady(t, server)
		cancel()
		if err := <-result; !errors.Is(err, ErrInvalidRuntime) {
			t.Fatalf("Serve() error = %v, want ErrInvalidRuntime", err)
		}
	})
}

func TestServeReturnsFixedErrorWhenShutdownDeadlineExpires(t *testing.T) {
	t.Parallel()

	server, err := New(Config{Service: "agentsec-api", Version: "dev"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	release := make(chan struct{})
	server.serve = func(net.Listener) error {
		<-release
		return http.ErrServerClosed
	}
	server.shutdown = func(shutdownContext context.Context) error {
		<-shutdownContext.Done()
		close(release)
		return shutdownContext.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, &stubListener{}) }()
	waitForHandlerReady(t, server)
	started := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrInvalidRuntime) {
			t.Fatalf("Serve() error = %v, want ErrInvalidRuntime", err)
		}
	case <-time.After(shutdownTimeout + 2*time.Second):
		t.Fatalf("Serve() did not terminate within %v", shutdownTimeout+2*time.Second)
	}
	if elapsed := time.Since(started); elapsed < shutdownTimeout || elapsed > shutdownTimeout+time.Second {
		t.Fatalf("shutdown elapsed = %v, want [%v, %v]", elapsed, shutdownTimeout, shutdownTimeout+time.Second)
	}
}

func waitForHandlerReady(t *testing.T, server *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		response := httptest.NewRecorder()
		server.handler.ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("handler never became ready")
}

func waitForStatus(t *testing.T, target string, status int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := testHTTPClient.Get(target) // #nosec G107 -- test target is an owned numeric-loopback listener.
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

func assertResponse(t *testing.T, target string, status int, body string) {
	t.Helper()
	response, err := testHTTPClient.Get(target) // #nosec G107 -- test target is an owned numeric-loopback listener.
	if err != nil {
		t.Fatalf("GET %s error = %v", target, err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	if response.StatusCode != status || string(value) != body {
		t.Fatalf("GET %s = (%d, %q), want (%d, %q)", target, response.StatusCode, value, status, body)
	}
}

func assertResponseContains(t *testing.T, target, fragment string) {
	t.Helper()
	response, err := testHTTPClient.Get(target) // #nosec G107 -- test target is an owned numeric-loopback listener.
	if err != nil {
		t.Fatalf("GET %s error = %v", target, err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(value), fragment) {
		t.Fatalf("GET %s = (%d, %q), want status 200 containing %q", target, response.StatusCode, value, fragment)
	}
}

type stubListener struct {
	accepts  int
	closeErr error
}

type stubContext struct{}

func (*stubContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*stubContext) Done() <-chan struct{}       { return nil }
func (*stubContext) Err() error                  { return nil }
func (*stubContext) Value(any) any               { return nil }

func (listener *stubListener) Accept() (net.Conn, error) {
	listener.accepts++
	return nil, errors.New("listener closed")
}

func (listener *stubListener) Close() error { return listener.closeErr }
func (*stubListener) Addr() net.Addr        { return stubAddress("127.0.0.1:0") }

type stubAddress string

func (stubAddress) Network() string        { return "tcp" }
func (address stubAddress) String() string { return string(address) }
