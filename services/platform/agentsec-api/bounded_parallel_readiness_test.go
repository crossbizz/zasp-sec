package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessChecksStartWithinOneSharedBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan context.Context, 2)
	release := make(chan struct{})
	done := make(chan error, 1)
	check := func(ctx context.Context) error {
		entered <- ctx
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	go func() { done <- boundedParallelReadiness(ctx, check, check) }()
	contexts := []context.Context{}
	for len(contexts) < 2 {
		select {
		case c := <-entered:
			contexts = append(contexts, c)
		case <-ctx.Done():
			goto joined
		}
	}
joined:
	close(release)
	err := <-done
	if len(contexts) != 2 || err != nil {
		t.Fatalf("checks did not enter together: entered=%d error=%v", len(contexts), err)
	}
	if contexts[0] != contexts[1] {
		t.Fatal("checks used different budgets")
	}
	if contexts[0].Err() == nil {
		t.Fatal("joined check context not canceled")
	}
}

func TestReadinessRefusalCancelsAndJoinsLateCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	refused := func(ctx context.Context) error {
		select {
		case <-entered:
		case <-ctx.Done():
		}
		return errors.New("private refusal")
	}
	late := func(ctx context.Context) error { close(entered); <-ctx.Done(); close(canceled); <-release; return nil }
	go func() { done <- boundedParallelReadiness(ctx, refused, late) }()
	select {
	case <-canceled:
	case <-ctx.Done():
		close(release)
		<-done
		t.Fatal("sibling was not canceled")
	}
	select {
	case <-done:
		close(release)
		t.Fatal("gate returned before sibling cleanup joined")
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("public refusal changed: %v", err)
	}
}

func TestReadinessInputRefusalRunsNoChecks(t *testing.T) {
	var calls atomic.Int32
	check := func(context.Context) error { calls.Add(1); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx} {
		if boundedParallelReadiness(c, check) == nil {
			t.Fatal("invalid parent admitted")
		}
	}
	if boundedParallelReadiness(context.Background(), check, nil) == nil {
		t.Fatal("nil check admitted")
	}
	if calls.Load() != 0 {
		t.Fatal("input refusal ran a check")
	}
}

func TestReadinessFinalFlagRunsOnlyAfterAllSuccessfulJoins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan error, 1)
	var joined, flags atomic.Int32
	check := func(ctx context.Context) error {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		joined.Add(1)
		return nil
	}
	final := func() bool { flags.Add(1); return joined.Load() == 2 }
	go func() { done <- currentComponentReadiness(ctx, final, check, check) }()
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			close(release)
			<-done
			t.Fatal("checks failed to start")
		}
	}
	if flags.Load() != 0 {
		t.Fatal("final flag inspected before metadata joined")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if flags.Load() != 1 {
		t.Fatal("final flag missing")
	}
	if currentComponentReadiness(context.Background(), func() bool { return false }, func(context.Context) error { return nil }) == nil {
		t.Fatal("false final flag admitted")
	}
	flags.Store(0)
	if currentComponentReadiness(context.Background(), func() bool { flags.Add(1); return true }, func(context.Context) error { return errors.New("refused") }) == nil || flags.Load() != 0 {
		t.Fatal("flag ran after refusal")
	}
}

func TestReadinessLateParentCancellationCannotAdmitSuccessfulChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if boundedParallelReadiness(ctx, func(context.Context) error { cancel(); return nil }) == nil {
		t.Fatal("canceled parent admitted")
	}
}

func TestCurrentReadinessPipelineStartsAllIndependentMetadata(t *testing.T) {
	key := strings.Repeat("a", 64)
	entered := make(chan context.Context, 3)
	release := make(chan struct{})
	result := make(chan error, 1)
	observe := func(ctx context.Context) {
		entered <- ctx
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
		t.Fatal("fixture")
	}
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	callback := authorizationRuntimeReadiness(func(context.Context) error { return nil }, func(ctx context.Context) error { observe(ctx); return nil }, core, agent, key, time.Second)
	go func() { result <- callback(parent) }()
	contexts := []context.Context{}
	for len(contexts) < 3 {
		select {
		case c := <-entered:
			contexts = append(contexts, c)
		case <-parent.Done():
			goto joined
		}
	}
joined:
	close(release)
	err := <-result
	if len(contexts) != 3 || err != nil {
		t.Fatalf("metadata pipeline remained serial: entered=%d error=%v", len(contexts), err)
	}
	deadline, _ := contexts[0].Deadline()
	for _, c := range contexts {
		d, ok := c.Deadline()
		if !ok || !d.Equal(deadline) || c.Err() == nil {
			t.Fatal("deadline widened or completed context uncanceled")
		}
	}
}

func TestLegacyReadinessNeverStartsPreviousAfterAuthorizationRefusal(t *testing.T) {
	for _, enforcing := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		t.Run(fmt.Sprint(enforcing), func(t *testing.T) {
			key := strings.Repeat("a", 64)
			coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key}
			agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key}
			core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
			agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
			defer core.Close()
			defer agent.Close()
			if enforcing[0] {
				if core.RequireCurrentAuthorization() != nil {
					t.Fatal("core")
				}
			}
			if enforcing[1] {
				if agent.RequireCurrentAuthorization() != nil {
					t.Fatal("agent")
				}
			}
			var previous atomic.Int32
			cb := authorizationRuntimeReadiness(func(context.Context) error { return nil }, func(context.Context) error { previous.Add(1); return nil }, core, agent, key, time.Second)
			if cb(context.Background()) == nil || previous.Load() != 0 {
				t.Fatal("legacy refusal invoked later readiness")
			}
		})
	}
}

func TestServiceRefusalIdentityAndNoMetadataArePreserved(t *testing.T) {
	sentinel := errors.New("controlled service refusal")
	var calls atomic.Int32
	cb := authorizationRuntimeReadiness(func(context.Context) error { return sentinel }, func(context.Context) error { calls.Add(1); return nil }, nil, nil, "", time.Second)
	if cb(context.Background()) != sentinel || calls.Load() != 0 {
		t.Fatal("service error identity or early gate changed")
	}
}
