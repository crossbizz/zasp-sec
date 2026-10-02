package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/health"
)

func TestAttackLabWorkflowConfigurationIsClosed(t *testing.T) {
	for _, value := range []string{"true", "https://arbitrary.invalid", "1", " enabled ", "false"} {
		env := fixtureRuntimeEnvironment()
		env["ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW"] = value
		if _, err := loadRuntimeConfig(func(key string) string { return env[key] }); err == nil {
			t.Fatalf("ambiguous runtime gate %q accepted", value)
		}
	}
	for _, value := range []string{"", "enabled"} {
		env := fixtureRuntimeEnvironment()
		env["ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW"] = value
		if _, err := loadRuntimeConfig(func(key string) string { return env[key] }); err != nil {
			t.Fatalf("closed runtime gate %q rejected: %v", value, err)
		}
	}
}

type readinessWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *readinessWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestAttackLabWorkflowReadinessSharesHealthyFlightWithoutCaching(t *testing.T) {
	handler, err := health.New(health.Config{Service: "agentsec-worker", Version: "local"})
	if err != nil {
		t.Fatal(err)
	}
	handler.SetReady(true)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	probe := newAttackLabWorkflowReadiness(transport)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owner := make(chan bool, 1)
	go func() { owner <- probe(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("health handler not entered")
	}
	results := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		waiting := &readinessWaitingContext{Context: ctx, waiting: make(chan struct{})}
		go func() { results <- probe(waiting) }()
		select {
		case <-waiting.waiting:
		case <-ctx.Done():
			t.Fatal("concurrent caller did not share flight")
		}
	}
	waiterCtx, cancelWaiter := context.WithCancel(ctx)
	waiting := &readinessWaitingContext{Context: waiterCtx, waiting: make(chan struct{})}
	cancelled := make(chan bool, 1)
	go func() { cancelled <- probe(waiting) }()
	select {
	case <-waiting.waiting:
	case <-ctx.Done():
		t.Fatal("cancelled caller did not share flight")
	}
	cancelWaiter()
	if <-cancelled {
		t.Fatal("cancelled waiter accepted readiness")
	}
	close(release)
	if !<-owner {
		t.Fatal("real health handler rejected")
	}
	for i := 0; i < 16; i++ {
		if !<-results {
			t.Fatal("healthy concurrent caller observed false readiness")
		}
	}
	if calls.Load() != 5 {
		t.Fatalf("shared flight made %d probes", calls.Load())
	}
	if !probe(ctx) || calls.Load() != 10 {
		t.Fatal("completed positive readiness was cached")
	}
	handler.SetReady(false)
	if probe(ctx) {
		t.Fatal("unready real health handler enabled catalog")
	}
}

func TestAttackLabWorkflowReadinessRequiresEveryPrivateService(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	broken := ""
	body := "{\"status\":\"ready\"}\n"
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/readyz" || r.URL.RawQuery != "" {
			t.Errorf("unexpected readiness request %s %s", r.Method, r.URL)
		}
		seen[r.Host]++
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Host == broken {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
			return
		}
		_, _ = io.WriteString(w, "{\"status\":\"ready\"}\n")
	}))
	defer server.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	probe := newAttackLabWorkflowReadiness(transport)
	if !probe(context.Background()) {
		t.Fatal("five healthy private services not ready")
	}
	want := []string{"agentsec-security-agent:8081", "agentsec-attack-lab-outbox:8081", "agentsec-attack-lab-controller:8081", "agentsec-attack-lab-proxy:8081", "security-agent-attack-lab-reconciler:8081"}
	if len(seen) != len(want) {
		t.Fatalf("wrong readiness destinations: %v", seen)
	}
	for _, host := range want {
		if seen[host] != 1 {
			t.Fatalf("missing exact private endpoint %s: %v", host, seen)
		}
	}
	for _, host := range want {
		for _, invalid := range []struct {
			status int
			body   string
		}{{503, "{\"status\":\"ready\"}\n"}, {200, "{\"status\":\"not_ready\"}\n"}, {200, "{\"status\":\"ready\",\"extra\":true}\n"}, {200, strings.Repeat("x", 65)}, {302, "{\"status\":\"ready\"}\n"}} {
			mu.Lock()
			broken, status, body = host, invalid.status, invalid.body
			mu.Unlock()
			if probe(context.Background()) {
				t.Fatalf("unhealthy %s status=%d body=%q enabled catalog", host, status, body)
			}
		}
	}
	mu.Lock()
	broken = ""
	mu.Unlock()
	if !probe(context.Background()) {
		t.Fatal("recovered services remained unavailable")
	}
}

func TestAttackLabWorkflowReadinessBoundsRequests(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	probe := newAttackLabWorkflowReadiness(transport)
	done := make(chan bool, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() { done <- probe(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter controlled service")
	}
	if probe(context.Background()) {
		t.Fatal("saturated probe enabled catalog")
	}
	select {
	case ready := <-done:
		if ready {
			t.Fatal("timed out service enabled catalog")
		}
	case <-time.After(time.Second):
		t.Fatal("probe ignored deadline")
	}
}
