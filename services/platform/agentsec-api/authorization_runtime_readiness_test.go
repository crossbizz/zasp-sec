package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Startup must derive readiness from the runtime parent, after connection and
// metadata preparation, rather than reuse the spent connection deadline.
func TestStartupAuthorizationUsesIndependentParentBudget(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "production_runtime.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || (name.Name != "checkAuthorizationRuntimeReady" && name.Name != "checkAuthorizationRuntimeReadyWithinTimeout") {
			return true
		}
		found = true
		parent, ok := call.Args[0].(*ast.Ident)
		if name.Name != "checkAuthorizationRuntimeReadyWithinTimeout" || !ok || parent.Name != "ctx" || len(call.Args) != 5 {
			t.Error("startup readiness reuses the connection budget instead of the runtime parent")
		}
		return true
	})
	if !found {
		t.Fatal("startup readiness gate missing")
	}
}

type runtimeAuthorizationProbeDriver struct {
	t         *testing.T
	role, key string
	calls     int
	fail      bool
	observe   func(context.Context)
}

func (d *runtimeAuthorizationProbeDriver) QueryRow(ctx context.Context, q string, args ...any) apiserver.PostgresRow {
	d.calls++
	if d.observe != nil {
		d.observe(ctx)
	}
	if q != `SELECT zasp_authorization80.ready($1), zasp_authorization80_audit.production_ready($1,$2,$3,$4)` || len(args) != 4 || args[2] != d.key || args[3] != d.role {
		d.t.Errorf("wrong fixed runtime readiness query or binding")
	}
	if _, ok := ctx.Deadline(); !ok {
		d.t.Error("readiness lacks deadline")
	}
	return runtimeAuthorizationProbeRow{ready: !d.fail}
}
func (*runtimeAuthorizationProbeDriver) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}
func (*runtimeAuthorizationProbeDriver) Close() error { return nil }
func (*runtimeAuthorizationProbeDriver) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected transaction")
}

type runtimeAuthorizationProbeRow struct{ ready bool }

func (r runtimeAuthorizationProbeRow) Scan(dest ...any) error {
	if len(dest) != 2 {
		return errors.New("wrong readiness result shape")
	}
	*dest[0].(*bool), *dest[1].(*bool) = r.ready, r.ready
	return nil
}

func TestP7GuardedRuntimeReadinessCallback(t *testing.T) {
	for _, name := range []string{"healthy", "services refused", "discovery refused", "agent refused", "previous refused"} {
		t.Run(name, func(t *testing.T) {
			key := strings.Repeat("a", 64)
			coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, fail: name == "discovery refused"}
			agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key, fail: name == "agent refused"}
			core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
			agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
			defer core.Close()
			defer agent.Close()
			if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
				t.Fatal("enforcing fixture")
			}
			serviceCalls, previousCalls := 0, 0
			failure := errors.New("controlled readiness failure")
			callback := authorizationRuntimeReadiness(func(context.Context) error {
				serviceCalls++
				if name == "services refused" {
					return failure
				}
				return nil
			}, func(context.Context) error {
				previousCalls++
				if name == "previous refused" {
					return failure
				}
				return nil
			}, core, agent, key, time.Second)
			err := callback(context.Background())
			if (err == nil) != (name == "healthy") {
				t.Errorf("callback error=%v", err)
			}
			wantCore, wantAgent, wantPrevious := 1, 1, 1
			minCore, minAgent, minPrevious := 1, 1, 1
			if name == "services refused" {
				wantCore, wantAgent, wantPrevious = 0, 0, 0
				minCore, minAgent, minPrevious = 0, 0, 0
			}
			if name == "discovery refused" {
				minAgent, minPrevious = 0, 0
			}
			if name == "agent refused" {
				minCore = 0
				minPrevious = 0
			}
			if name == "previous refused" {
				minCore, minAgent = 0, 0
			}
			if serviceCalls != 1 || coreDriver.calls < minCore || coreDriver.calls > wantCore || agentDriver.calls < minAgent || agentDriver.calls > wantAgent || previousCalls < minPrevious || previousCalls > wantPrevious {
				t.Errorf("calls services=%d core=%d agent=%d previous=%d", serviceCalls, coreDriver.calls, agentDriver.calls, previousCalls)
			}
		})
	}
}

// This is the exact gate called before production composition. It does not
// construct the provider, service connections, or complete runtime.
func TestP7GuardedRuntimeReadinessStartupGate(t *testing.T) {
	for _, name := range []string{"healthy", "discovery refused", "agent refused", "expired context", "invalid key"} {
		t.Run(name, func(t *testing.T) {
			key := strings.Repeat("a", 64)
			coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, fail: name == "discovery refused"}
			agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key, fail: name == "agent refused"}
			core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
			agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
			defer core.Close()
			defer agent.Close()
			if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
				t.Fatal("enforcing fixture")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if name == "expired context" {
				cancel()
			}
			if name == "invalid key" {
				key = "invalid"
			}
			err := checkAuthorizationRuntimeReady(ctx, core, agent, key)
			if name == "healthy" && err != nil || name != "healthy" && !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("startup gate error=%v", err)
			}
			wantCore, wantAgent := 1, 1
			minCore, minAgent := 1, 1
			if name == "discovery refused" {
				minAgent = 0
			}
			if name == "agent refused" {
				minCore = 0
			}
			if name == "expired context" || name == "invalid key" {
				wantCore, wantAgent = 0, 0
				minCore, minAgent = 0, 0
			}
			if coreDriver.calls < minCore || coreDriver.calls > wantCore || agentDriver.calls < minAgent || agentDriver.calls > wantAgent {
				t.Fatalf("startup gate calls core=%d agent=%d", coreDriver.calls, agentDriver.calls)
			}
		})
	}
}

func TestStartupAuthorizationFreshBudgetRemainsFailClosed(t *testing.T) {
	for _, name := range []string{"spent connection budget", "earlier parent deadline", "canceled parent", "expired parent", "zero budget", "core refusal", "agent refusal", "cancel during core"} {
		t.Run(name, func(t *testing.T) {
			key := strings.Repeat("a", 64)
			coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, fail: name == "core refusal"}
			agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key, fail: name == "agent refusal"}
			core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
			agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
			defer core.Close()
			defer agent.Close()
			if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
				t.Fatal("enforcing fixture")
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := time.Second
			if name == "earlier parent deadline" {
				var c context.CancelFunc
				parent, c = context.WithTimeout(parent, 500*time.Millisecond)
				defer c()
			}
			if name == "expired parent" {
				var c context.CancelFunc
				parent, c = context.WithDeadline(parent, time.Now().Add(-time.Second))
				defer c()
			}
			if name == "canceled parent" {
				cancel()
			}
			if name == "zero budget" {
				timeout = 0
			}
			if name == "spent connection budget" {
				spent, c := context.WithDeadline(parent, time.Now().Add(-time.Second))
				defer c()
				if checkAuthorizationRuntimeReady(spent, core, agent, key) == nil {
					t.Fatal("old spent budget unexpectedly admitted readiness")
				}
			}
			observed := make(chan context.Context, 2)
			coreDriver.observe = func(ctx context.Context) {
				observed <- ctx
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > timeout {
					t.Error("provider timeout widened")
				}
				if d, ok := parent.Deadline(); ok && !deadline.Equal(d) {
					t.Error("parent deadline widened")
				}
				if name == "cancel during core" {
					cancel()
				}
			}
			agentDriver.observe = func(ctx context.Context) { observed <- ctx }
			err := checkAuthorizationRuntimeReadyWithinTimeout(parent, core, agent, key, timeout)
			healthy := name == "spent connection budget" || name == "earlier parent deadline"
			if healthy && err != nil || !healthy && !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("readiness error=%v", err)
			}
			wantCore, wantAgent := 1, 1
			minCore, minAgent := 1, 1
			switch name {
			case "canceled parent", "expired parent", "zero budget":
				wantCore, wantAgent = 0, 0
				minCore, minAgent = 0, 0
			case "core refusal", "cancel during core":
				minAgent = 0
			case "agent refusal":
				minCore = 0
			}
			if coreDriver.calls < minCore || coreDriver.calls > wantCore || agentDriver.calls < minAgent || agentDriver.calls > wantAgent {
				t.Fatalf("probe calls core=%d agent=%d", coreDriver.calls, agentDriver.calls)
			}
			close(observed)
			var first context.Context
			for probeContext := range observed {
				if first != nil && first != probeContext {
					t.Error("probes have separate budgets")
				}
				first = probeContext
				if probeContext.Err() == nil {
					t.Error("completed probe context was not canceled")
				}
			}
		})
	}
}

func TestAuthorizationIndependentProbesShareOneConcurrentBudget(t *testing.T) {
	key := strings.Repeat("a", 64)
	started := make(chan context.Context, 2)
	release := make(chan struct{})
	observe := func(ctx context.Context) {
		started <- ctx
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, observe: observe}
	agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key, observe: observe}
	core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
	agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
	defer core.Close()
	defer agent.Close()
	if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
		t.Fatal("enforcing fixture")
	}
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- checkAuthorizationRuntimeReadyWithinTimeout(parent, core, agent, key, time.Second) }()
	contexts := []context.Context{}
	for len(contexts) < 2 {
		select {
		case ctx := <-started:
			contexts = append(contexts, ctx)
		case <-parent.Done():
			goto joined
		}
	}
joined:
	close(release)
	err := <-result
	if len(contexts) != 2 {
		t.Fatalf("independent probes did not both start within the original shared budget: started=%d error=%v", len(contexts), err)
	}
	if contexts[0] != contexts[1] {
		t.Fatal("probes did not share one context")
	}
	if err != nil {
		t.Fatalf("both healthy probes refused: %v", err)
	}
	if contexts[0].Err() == nil {
		t.Fatal("probe context not closed after joined completion")
	}
}

func TestAuthorizationProbeRefusalCancelsAndJoinsSibling(t *testing.T) {
	key := strings.Repeat("a", 64)
	started := make(chan context.Context, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, fail: true}
	agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key}
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	coreDriver.observe = func(ctx context.Context) {
		select {
		case <-entered:
		case <-ctx.Done():
		}
	}
	agentDriver.observe = func(ctx context.Context) { started <- ctx; close(entered); <-release }
	core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
	agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
	defer core.Close()
	defer agent.Close()
	if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
		t.Fatal("enforcing fixture")
	}
	result := make(chan error, 1)
	go func() { result <- checkAuthorizationRuntimeReady(parent, core, agent, key) }()
	// The core cannot refuse until the sibling has entered its query. The sibling
	// deliberately delays finishing after cancellation to check the explicit join.
	var probe context.Context
	for probe == nil {
		select {
		case probe = <-started:
		case <-parent.Done():
			close(release)
			<-result
			t.Fatal("sibling did not enter probe")
		}
	}
	select {
	case <-probe.Done():
	case <-parent.Done():
	}
	select {
	case <-result:
		close(release)
		t.Fatal("gate returned before canceled sibling joined")
	default:
	}
	close(release)
	if err := <-result; !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("refused probe admitted: %v", err)
	}
	if probe.Err() != context.Canceled {
		t.Errorf("sibling context error=%v", probe.Err())
	}
	if coreDriver.calls != 1 || agentDriver.calls != 1 {
		t.Fatalf("probe calls core=%d agent=%d", coreDriver.calls, agentDriver.calls)
	}
}
