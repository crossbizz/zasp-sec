package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func schedulerScope(t *testing.T, prefix string) domain.Scope {
	t.Helper()
	o, e1 := domain.ParseProductID("pid_" + prefix + "01-0000-4000-8000-000000000001")
	w, e2 := domain.ParseProductID("pid_" + prefix + "02-0000-4000-8000-000000000002")
	e, e3 := domain.ParseProductID("pid_" + prefix + "03-0000-4000-8000-000000000003")
	s, err := domain.NewScope(o, w, e)
	if e1 != nil || e2 != nil || e3 != nil || err != nil {
		t.Fatal("invalid fixture scope")
	}
	return s
}

func schedulerScopeJSON(s domain.Scope) json.RawMessage {
	body, _ := json.Marshal([]map[string]string{{"organization_id": s.OrganizationID().String(), "workspace_id": s.WorkspaceID().String(), "environment_id": s.EnvironmentID().String()}})
	return body
}

// Removing strict decoding or the monotonic keyset check must break this test.
func TestExistingTestNextScopeBoundary(t *testing.T) {
	a, b := schedulerScope(t, "991100"), schedulerScope(t, "992200")
	valid := string(schedulerScopeJSON(b))
	for _, tc := range []struct {
		name, raw string
		want      bool
		fail      bool
	}{
		{"next", valid, true, false}, {"empty", "[]", false, false},
		{"null", "null", false, true}, {"object", "{}", false, true},
		{"same", string(schedulerScopeJSON(a)), false, true},
		{"duplicate rows", strings.TrimSuffix(valid, "]") + "," + strings.TrimPrefix(valid, "["), false, true},
		{"alias", strings.Replace(valid, "organization_id", "Organization_ID", 1), false, true},
		{"unknown", strings.Replace(valid, "[{", "[{\"extra\":true,", 1), false, true},
		{"duplicate key", strings.Replace(valid, "[{", "[{\"organization_id\":\""+b.OrganizationID().String()+"\",", 1), false, true},
		{"missing", strings.Replace(valid, "\"organization_id\":\""+b.OrganizationID().String()+"\",", "", 1), false, true},
		{"same ids", strings.ReplaceAll(valid, b.WorkspaceID().String(), b.OrganizationID().String()), false, true},
		{"invalid", strings.ReplaceAll(valid, b.EnvironmentID().String(), "private-invalid-id"), false, true},
		{"database error", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			db := &reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
				calls++
				if q != "SELECT zasp_production_security_agent_existing_tests_reconcile_scopes($1,$2,$3,$4,$5,$6)" || len(args) != 6 || args[0] != a.OrganizationID().String() || args[1] != a.WorkspaceID().String() || args[2] != a.EnvironmentID().String() || args[3] != "scope-worker" || args[4] != migrations.ProductionSecurityAgentExistingTests().Checksum() || args[5] != migrations.SecurityAgentExistingTestsFingerprint() {
					t.Fatal("scope/pin binding lost")
				}
				if tc.name == "database error" {
					return nil, errors.New("private database detail")
				}
				return json.RawMessage(tc.raw), nil
			}}
			client, _ := newExistingTestClient(db, "scope-worker", time.Now)
			got, found, err := client.NextScope(context.Background(), a)
			if calls != 1 || (err != nil) != tc.fail || found != tc.want || tc.want && got != b || !tc.want && !got.IsZero() {
				t.Fatalf("got scope=%v found=%t err=%v calls=%d", got, found, err, calls)
			}
			if err != nil && err != errRuntimeUnavailable {
				t.Fatal("private error escaped")
			}
		})
	}
}

func TestExistingTestNextScopeStartAndCancellation(t *testing.T) {
	b := schedulerScope(t, "992200")
	calls := 0
	db := &reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		calls++
		if args[0] != "" || args[1] != "" || args[2] != "" {
			t.Fatal("initial cursor not empty")
		}
		return schedulerScopeJSON(b), nil
	}}
	c, _ := newExistingTestClient(db, "scope-worker", time.Now)
	got, found, err := c.NextScope(context.Background(), domain.Scope{})
	if err != nil || !found || got != b || calls != 1 {
		t.Fatalf("initial discovery failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, _, err := c.NextScope(ctx, domain.Scope{}); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if calls != 1 {
		t.Fatal("cancelled discovery reached database")
	}
}

// A failed tenant must not monopolize subsequent polls; discovery failure must
// not lose the last successfully selected position. Only SQL I/O is controlled.
func TestExistingTestSchedulerRotatesAfterFailureAndWraps(t *testing.T) {
	a, b := schedulerScope(t, "991100"), schedulerScope(t, "992200")
	store, _, _ := fixtureExistingTestEvidence(t)
	var cursors, claims []string
	failDiscovery := false
	db := &reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded scheduler SQL")
		}
		switch {
		case strings.Contains(q, "reconcile_scopes("):
			cursor := args[0].(string)
			cursors = append(cursors, cursor)
			if failDiscovery {
				failDiscovery = false
				return nil, errors.New("transient scope lookup")
			}
			switch cursor {
			case "":
				return schedulerScopeJSON(a), nil
			case a.OrganizationID().String():
				return schedulerScopeJSON(b), nil
			default:
				return json.RawMessage("[]"), nil
			}
		case strings.Contains(q, "reconcile_claim("):
			org := args[0].(string)
			claims = append(claims, org)
			if org == a.OrganizationID().String() {
				return nil, errors.New("tenant A unavailable")
			}
			return json.RawMessage("[]"), nil
		default:
			t.Fatalf("unexpected SQL %s", q)
			return nil, nil
		}
	}}
	c, _ := newExistingTestClient(db, "scope-worker", time.Now)
	p, err := newExistingTestScheduler(c, store)
	if err != nil {
		t.Fatal(err)
	}
	if p.RunOnce(context.Background()) == nil {
		t.Fatal("tenant failure hidden")
	}
	failDiscovery = true
	if p.RunOnce(context.Background()) == nil {
		t.Fatal("discovery failure hidden")
	}
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatal("tenant B starved", err)
	}
	if p.RunOnce(context.Background()) == nil {
		t.Fatal("wrapped tenant failure hidden")
	}
	wantCursors := []string{"", a.OrganizationID().String(), a.OrganizationID().String(), b.OrganizationID().String(), ""}
	wantClaims := []string{a.OrganizationID().String(), b.OrganizationID().String(), a.OrganizationID().String()}
	if strings.Join(cursors, ",") != strings.Join(wantCursors, ",") || strings.Join(claims, ",") != strings.Join(wantClaims, ",") {
		t.Fatalf("rotation cursors=%v claims=%v", cursors, claims)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.RunOnce(context.Background()) == nil {
		t.Fatal("closed scheduler ran")
	}
	if len(cursors) != 5 {
		t.Fatal("closed scheduler reached database")
	}
}

func TestExistingTestSchedulerEmptyAndInvalidDependencies(t *testing.T) {
	store, _, _ := fixtureExistingTestEvidence(t)
	calls := 0
	c, _ := newExistingTestClient(&reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
		calls++
		return json.RawMessage("[]"), nil
	}}, "scope-worker", time.Now)
	for _, makeInvalid := range []func() error{
		func() error { _, err := newExistingTestScheduler(nil, store); return err },
		func() error { _, err := newExistingTestScheduler(c, nil); return err },
		func() error {
			var absent *artifactstore.Store
			_, err := newExistingTestScheduler(c, absent)
			return err
		},
		func() error {
			broken := *c
			broken.db = nil
			_, err := newExistingTestScheduler(&broken, store)
			return err
		},
		func() error {
			broken := *c
			broken.now = nil
			_, err := newExistingTestScheduler(&broken, store)
			return err
		},
	} {
		if makeInvalid() == nil {
			t.Fatal("invalid dependencies accepted")
		}
	}
	p, err := newExistingTestScheduler(c, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.RunOnce(context.Background()); err != nil || calls != 1 {
		t.Fatalf("empty population busy loop: %v %d", err, calls)
	}
	if p.RunOnce(nil) == nil {
		t.Fatal("nil context accepted")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal("close not idempotent", err)
	}
}

func TestExistingTestSchedulerCancelsAndJoinsBeforeClose(t *testing.T) {
	store, _, _ := fixtureExistingTestEvidence(t)
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	c, _ := newExistingTestClient(&reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil, ctx.Err()
	}}, "scope-worker", time.Now)
	p, err := newExistingTestScheduler(c, store)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.RunOnce(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("scheduler never queried")
	}
	waitCtx, waitCancel := context.WithCancel(context.Background())
	waitCancel()
	if p.RunOnce(waitCtx) == nil {
		t.Fatal("cancelled waiter accepted")
	}
	// The first query still owns the gate. This second caller must wait for its
	// own deadline without canceling the owner or entering another SQL call.
	waiting, stopWaiting := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopWaiting()
	if p.RunOnce(waiting) == nil || waiting.Err() != context.DeadlineExceeded {
		t.Fatal("occupied gate did not honor waiting caller cancellation")
	}
	select {
	case <-cancelled:
		t.Fatal("waiting caller canceled the active owner")
	default:
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer closeCancel()
	if p.Close(closeCtx) == nil {
		t.Fatal("close reported completion with SQL still running")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("close failed to cancel SQL")
	}
	if p.RunOnce(context.Background()) == nil {
		t.Fatal("new borrow allowed after close")
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation hidden")
		}
	case <-time.After(time.Second):
		t.Fatal("borrow did not join")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal("joined close refused", err)
	}
}

// A replacement process must rediscover pending work without relying on the
// previous process's in-memory cursor. Real database reclaim is a separate gate.
func TestExistingTestSchedulerFreshInstanceRediscovers(t *testing.T) {
	scope := schedulerScope(t, "991100")
	store, _, _ := fixtureExistingTestEvidence(t)
	discovered, reconciled := 0, 0
	c, err := newExistingTestClient(&reconcileQueryFixture{call: func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		switch {
		case strings.Contains(q, "reconcile_scopes("):
			if args[0] != "" || args[1] != "" || args[2] != "" {
				t.Fatal("fresh process inherited a stale discovery cursor")
			}
			discovered++
			return schedulerScopeJSON(scope), nil
		case strings.Contains(q, "reconcile_claim("):
			if args[0] != scope.OrganizationID().String() || args[1] != scope.WorkspaceID().String() || args[2] != scope.EnvironmentID().String() {
				t.Fatal("rediscovered tenant binding lost")
			}
			reconciled++
			return json.RawMessage("[]"), nil
		default:
			t.Fatalf("unexpected SQL %s", q)
			return nil, nil
		}
	}}, "scope-worker", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		p, err := newExistingTestScheduler(c, store)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := p.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if discovered != 2 || reconciled != 2 {
		t.Fatalf("restart discovery=%d reconciliation=%d", discovered, reconciled)
	}
}
