package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type auditHTTPFixtureContextKey struct{}
type auditHTTPFixtureClose struct {
	name  string
	close func(context.Context) error
}
type auditHTTPFixtureOwner struct {
	root                           string
	resources, processes, handlers []auditHTTPFixtureClose
	retained                       error
	closed                         bool
	result                         error
	onRetain                       func()
	startPostgres                  func(*testing.T, context.Context, string) string
}

func auditHTTPFixtureOwnerFrom(ctx context.Context) *auditHTTPFixtureOwner {
	if ctx == nil {
		return nil
	}
	owner, _ := ctx.Value(auditHTTPFixtureContextKey{}).(*auditHTTPFixtureOwner)
	return owner
}
func auditHTTPFixtureOwnConnection(ctx context.Context, name string, conn *pgx.Conn) bool {
	owner := auditHTTPFixtureOwnerFrom(ctx)
	if owner == nil {
		return false
	}
	owner.resources = append(owner.resources, auditHTTPFixtureClose{name, func(ctx context.Context) error {
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return conn.Close(closeCtx)
	}})
	return true
}
func (o *auditHTTPFixtureOwner) Close(ctx context.Context) error {
	if o.closed {
		return o.result
	}
	o.closed = true
	var err error
	// Even an unjoined child cannot keep admitting handlers on borrowed SQL.
	// Attempt both phases, but never close resources without every join proof.
	for _, phase := range [][]auditHTTPFixtureClose{o.processes, o.handlers} {
		for i := len(phase) - 1; i >= 0; i-- {
			if e := phase[i].close(ctx); e != nil {
				err = errors.Join(err, fmt.Errorf("%s: %w", phase[i].name, e))
			}
		}
	}
	err = errors.Join(err, o.retained)
	if err != nil {
		o.result = err
		if o.onRetain != nil {
			o.onRetain()
		}
		return err
	}
	for i := len(o.resources) - 1; i >= 0; i-- {
		if err := o.resources[i].close(ctx); err != nil {
			o.result = fmt.Errorf("%s: %w", o.resources[i].name, err)
			if o.onRetain != nil {
				o.onRetain()
			}
			return o.result
		}
	}
	return nil
}

// Registration precedes root acquisition and all constructor calls. The sole
// callback owns early t.Fatal paths too. No child uses this context for PG lifetime.
func newAuditHTTPFixtureOwner(t *testing.T, ctx context.Context, parent string, onRetain func()) (context.Context, *auditHTTPFixtureOwner) {
	t.Helper()
	owner := &auditHTTPFixtureOwner{onRetain: onRetain}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := owner.Close(cleanup); err != nil {
			t.Errorf("fixture resources retained: root=%s error=%v", owner.root, err)
		} else {
			t.Logf("fixture owner closed all resources: root=%s", owner.root)
		}
	})
	root, err := os.MkdirTemp(parent, "zasp-http-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	owner.root = root
	owner.resources = append(owner.resources, auditHTTPFixtureClose{"fixture root", func(context.Context) error { return os.RemoveAll(root) }})
	return context.WithValue(ctx, auditHTTPFixtureContextKey{}, owner), owner
}

type auditHTTPHandlerLifetime struct {
	mu     sync.Mutex
	active int
	closed bool
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

func newAuditHTTPHandlerLifetime(ctx context.Context) *auditHTTPHandlerLifetime {
	ctx, cancel := context.WithCancel(ctx)
	return &auditHTTPHandlerLifetime{done: make(chan struct{}), ctx: ctx, cancel: cancel}
}
func (l *auditHTTPHandlerLifetime) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			http.Error(w, "closed", 503)
			return
		}
		l.active++
		l.mu.Unlock()
		defer func() {
			l.mu.Lock()
			l.active--
			if l.closed && l.active == 0 {
				close(l.done)
			}
			l.mu.Unlock()
		}()
		requestCtx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(l.ctx, cancel)
		defer stop()
		defer cancel()
		next.ServeHTTP(w, r.WithContext(requestCtx))
	})
}
func (l *auditHTTPHandlerLifetime) Close(ctx context.Context) error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		l.cancel()
		if l.active == 0 {
			close(l.done)
		}
	}
	l.mu.Unlock()
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func auditHTTPSizeCloseAfterHandlers(ctx context.Context, l *auditHTTPHandlerLifetime, cleanup func() error) error {
	if err := l.Close(ctx); err != nil {
		return err
	}
	return cleanup()
}

func auditHTTPSizeShutdownServer(ctx context.Context, server *http.Server) error {
	err := server.Shutdown(ctx)
	// Admission is closed before borrower cancellation. Shutdown still drains
	// connections before returning its listener-close error; a drain timeout
	// returns ctx.Err instead and must never be normalized.
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type auditHTTPShutdownListener struct {
	net.Listener
	closeErr error
}

func (l *auditHTTPShutdownListener) Close() error {
	_ = l.Listener.Close()
	return l.closeErr
}

// Catches treating an already-closed admission socket as an unjoined borrower,
// while still refusing timeouts and unrelated listener failures.
func TestAuditHTTPSizeShutdownClosedAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		closeErr error
		hold     bool
		want     error
	}{
		{"already closed", fmt.Errorf("listener: %w", net.ErrClosed), false, nil},
		{"held handler", net.ErrClosed, true, context.DeadlineExceeded},
		{"other error", context.Canceled, false, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			wait := func(ch <-chan struct{}, name string) {
				t.Helper()
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
					t.Fatalf("timed out waiting for %s", name)
				}
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				if tc.hold {
					<-release
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			server.Listener = &auditHTTPShutdownListener{Listener: server.Listener, closeErr: tc.closeErr}
			server.Start()
			defer server.Close()
			defer unblock()
			server.Client().Timeout = time.Second
			go func() {
				defer close(done)
				response, err := server.Client().Get(server.URL)
				if err == nil {
					response.Body.Close()
				}
			}()
			defer func() {
				unblock()
				wait(done, "request cleanup")
			}()
			wait(entered, "handler admission")
			if !tc.hold {
				wait(done, "request completion")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			err := auditHTTPSizeShutdownServer(ctx, server.Config)
			cancel()
			unblock()
			wait(done, "request completion")
			if !errors.Is(err, tc.want) {
				t.Fatalf("shutdown = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuditHTTPFixtureLifetimeRetainsUnknownBorrowers(t *testing.T) {
	for _, kind := range []string{"held-handler", "background-runner-error", "failure-before-child"} {
		t.Run(kind, func(t *testing.T) {
			root, err := os.MkdirTemp("", "zasp-http-owner-control-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			var closed atomic.Int64
			owner := &auditHTTPFixtureOwner{root: root}
			owner.resources = []auditHTTPFixtureClose{{"root", func(context.Context) error { return os.RemoveAll(root) }}, {"borrowed SQL", func(context.Context) error { closed.Add(1); return nil }}}
			if kind != "failure-before-child" {
				guard := auditHTTPFixtureClose{kind, func(context.Context) error { return errors.New("borrower still running") }}
				if kind == "held-handler" {
					owner.handlers = append(owner.handlers, guard)
				} else {
					owner.processes = append(owner.processes, guard)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = owner.Close(ctx)
			if kind == "failure-before-child" {
				if err != nil || closed.Load() != 1 {
					t.Fatal("pre-child startup resources leaked", err)
				}
				if _, err := os.Stat(root); !os.IsNotExist(err) {
					t.Fatal("startup root not removed")
				}
				return
			}
			if err == nil || closed.Load() != 0 {
				t.Error("unjoined borrower allowed resource cleanup")
			}
			if _, err := os.Stat(root); err != nil {
				t.Error("unjoined borrower lost root")
			}
		})
	}
}

func TestAuditHTTPSizeShutdownWaitsForHandler(t *testing.T) {
	life := newAuditHTTPHandlerLifetime(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(life.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })))
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, _ := server.Client().Get(server.URL)
		if response != nil {
			response.Body.Close()
		}
	}()
	<-entered
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	shutdownErr := server.Config.Shutdown(shutdown)
	cancel()
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatal("held handler did not force HTTP shutdown timeout", shutdownErr)
	}
	_ = server.Config.Close()
	var closed atomic.Int64
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := auditHTTPSizeCloseAfterHandlers(ctx, life, func() error { closed.Add(1); return nil })
	stop()
	if err == nil || closed.Load() != 0 {
		t.Error("HTTP socket/Serve close mistaken for handler join; SQL closed")
	}
	close(release)
	<-requestDone
	server.Close()
	ctx, stop = context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := auditHTTPSizeCloseAfterHandlers(ctx, life, func() error { closed.Add(1); return nil }); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatal("joined handler failed to release borrowed SQL exactly once")
	}
}
