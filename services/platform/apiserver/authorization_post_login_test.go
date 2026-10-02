package apiserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"slices"
	"testing"
)

func TestP7PostLoginCapabilityContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	rev := authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	first, second := "pid_84000001-0000-4000-8000-000000000001", "pid_84000002-0000-4000-8000-000000000002"
	targets := []AuthorizationTarget{{Scope: i.Scope, Kind: "finding", ID: first}, {Scope: i.Scope, Kind: "finding", ID: second}}
	conjunction := false
	calls := map[authorization.CheckRequest]int{}
	a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, StoreID: rev.StoreID, ModelID: rev.ModelID, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: targets}}, Checker: authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
		calls[q]++
		allow := q.ResourceID == first && (q.Permission == "view" || q.Permission == "view_audit" || conjunction && q.Permission == "view_compliance") || q.ResourceID == second && q.Permission == "view_compliance"
		return authorization.Decision{Allowed: allow, ModelID: rev.ModelID}, nil
	})}
	newChecks := func() *postLoginCapabilityChecks {
		return &postLoginCapabilityChecks{authorizer: a, identity: i, revision: rev, decisions: map[authorization.CheckRequest]bool{}, targets: map[string][]AuthorizationTarget{}, candidates: map[string]bool{}, permissions: map[string]bool{}}
	}
	env := AuthorizationTarget{Scope: i.Scope, Kind: "environment", ID: i.Scope.EnvironmentID().String()}
	c := newChecks()
	if allowed, err := c.check(context.Background(), targets[1], "view_compliance"); err != nil || !allowed {
		t.Fatal("fixture must have a separately allowed compliance permission")
	}
	caps, err := c.capabilities(context.Background(), env)
	if err != nil || slices.Contains(caps, "compliance.read") || !c.permissions["view_compliance"] {
		t.Fatalf("cross-resource permission union: %v %v %v", caps, c.permissions, err)
	}
	for _, n := range calls {
		if n != 1 {
			t.Error("duplicate current check")
		}
	}
	conjunction = true
	c = newChecks()
	caps, err = c.capabilities(context.Background(), env)
	if err != nil || !slices.Contains(caps, "compliance.read") {
		t.Fatalf("same-target conjunction unavailable: %v %v", caps, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.capabilities(ctx, env); !errors.Is(err, authorization.ErrUnavailable) {
		t.Errorf("deadline yielded partial capabilities: %v", err)
	}
	a.Resolver = authorizationTargetFixture{AuthorizationTargets{Complete: false, Targets: targets}}
	if _, err = newChecks().resolve(context.Background(), "listFindings"); !errors.Is(err, authorization.ErrUnavailable) {
		t.Errorf("incomplete enumeration: %v", err)
	}
	many := make([]AuthorizationTarget, 10000)
	for n := range many {
		many[n] = AuthorizationTarget{Scope: i.Scope, Kind: "finding", ID: fmt.Sprintf("pid_84000001-0000-4000-8000-%012d", n)}
	}
	a.Resolver = authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: many}}
	c = newChecks()
	if _, err = c.resolve(context.Background(), "listFindings"); err != nil {
		t.Fatal(err)
	}
	a.Resolver = authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: i.Scope, Kind: "agent", ID: first}}}}
	if _, err = c.resolve(context.Background(), "listAgents"); !errors.Is(err, authorization.ErrUnavailable) {
		t.Errorf("aggregate candidate bound: %v", err)
	}
}
