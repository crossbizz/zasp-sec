package apiserver

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// A large collection is checked by a bounded number of concurrent readers.
// The grant is the one sequential checking produces: every target checked,
// the allowed set in target order, and no grant at all when any check fails.
func TestAuthorizerChecksLargeCollectionsConcurrently(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	o := identity.Scope.OrganizationID().String()
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "concurrent-checks", Digest: [32]byte{3}}
	targets := func(count int) []AuthorizationTarget {
		values := make([]AuthorizationTarget, count)
		for n := range values {
			values[n] = AuthorizationTarget{Scope: identity.Scope, Kind: "finding", ID: fmt.Sprintf("pid_50%06x-0000-4000-8000-%012d", n, n), Version: 1}
		}
		return values
	}
	run := func(count int, denied map[int]bool, failing int) (RequestAuthorization, error, int32, int32) {
		candidates := targets(count)
		index := map[string]int{}
		for n, target := range candidates {
			index[target.ID] = n
		}
		var inFlight, peak, calls atomic.Int32
		resolver := authorizationTargetFunc(func(_ context.Context, _ RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
			if route.OperationID != "listFindings" {
				return AuthorizationTargets{}, authorization.ErrInvalid
			}
			return AuthorizationTargets{Complete: true, Collection: true, Targets: candidates}, nil
		})
		checker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
			current := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				seen := peak.Load()
				if current <= seen || peak.CompareAndSwap(seen, current) {
					break
				}
			}
			calls.Add(1)
			time.Sleep(2 * time.Millisecond)
			n := index[q.ResourceID]
			if n == failing {
				return authorization.Decision{}, authorization.ErrUnavailable
			}
			return authorization.Decision{Allowed: !denied[n], ModelID: rev.ModelID}, nil
		})
		authorizer := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
		grant, err := authorizer.Authorize(context.Background(), identity, credential, RoutedOperation{OperationID: "listFindings"})
		return grant, err, peak.Load(), calls.Load()
	}

	t.Run("large collection", func(t *testing.T) {
		denied := map[int]bool{3: true, 17: true, 39: true}
		grant, err, peak, calls := run(40, denied, -1)
		if err != nil {
			t.Fatal(err)
		}
		if peak < 2 || peak > authorizationCheckConcurrency {
			t.Fatalf("concurrent readers peaked at %d, want 2..%d", peak, authorizationCheckConcurrency)
		}
		if calls != 40 || len(grant.Targets) != 40 || len(grant.Decisions) != 40 || len(grant.Allowed) != 37 {
			t.Fatalf("calls=%d targets=%d decisions=%d allowed=%d", calls, len(grant.Targets), len(grant.Decisions), len(grant.Allowed))
		}
		want := targets(40)
		position := 0
		for n, target := range want {
			if grant.Decisions[n].Request.ResourceID != target.ID {
				t.Fatalf("decision %d is for %s, want %s", n, grant.Decisions[n].Request.ResourceID, target.ID)
			}
			if denied[n] {
				continue
			}
			if grant.Allowed[position] != target {
				t.Fatalf("allowed[%d]=%+v, want %+v", position, grant.Allowed[position], target)
			}
			position++
		}
	})
	t.Run("a failing check refuses the collection", func(t *testing.T) {
		grant, err, _, _ := run(40, nil, 23)
		if !errors.Is(err, authorization.ErrUnavailable) || len(grant.Allowed) != 0 || len(grant.attestation) != 0 {
			t.Fatalf("grant=%+v error=%v", grant, err)
		}
	})
	t.Run("small collection is checked in order by the request", func(t *testing.T) {
		grant, err, peak, calls := run(authorizationCheckConcurrency, map[int]bool{1: true}, -1)
		if err != nil || peak != 1 || calls != authorizationCheckConcurrency || len(grant.Allowed) != authorizationCheckConcurrency-1 {
			t.Fatalf("peak=%d calls=%d allowed=%d error=%v", peak, calls, len(grant.Allowed), err)
		}
	})
}
