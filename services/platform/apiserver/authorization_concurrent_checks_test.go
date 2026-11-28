package apiserver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
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

type collectionTestRevisionRead func(context.Context, string) (authorization.Revision, error)

func (read collectionTestRevisionRead) Revision(ctx context.Context, organization string) (authorization.Revision, error) {
	return read(ctx, organization)
}

func TestAuthorizationCollectionRevisionFence(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	original := authorization.Revision{OrganizationID: identity.Scope.OrganizationID().String(), Desired: 5, Applied: 5, Generation: 2, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	const otherModel = "01K00000000000000000000003"
	const count = 104
	targets := make([]AuthorizationTarget, count)
	for n := range targets {
		targets[n] = AuthorizationTarget{Scope: identity.Scope, Kind: "policy", ID: fmt.Sprintf("pid_50000000-0000-4000-8000-%012d", count-n), Version: 1}
	}
	permissions := []string{"view", "view_audit", "view_compliance"}
	credential := CredentialBinding{Kind: identity.CredentialKind, ID: "collection-fence", Digest: [32]byte{3}}
	key := authorizationFixtureAttestor(t)
	authorize := func(ctx context.Context, read collectionTestRevisionRead, check authorizationDecisionFunc) (RequestAuthorization, error) {
		targetResolver := authorizationTargetFunc(func(context.Context, RequestIdentity, RoutedOperation) (AuthorizationTargets, error) {
			return AuthorizationTargets{Collection: true, Complete: true, Targets: targets}, nil
		})
		a := OpenFGAAuthorizer{Reader: read, Checker: check, Resolver: targetResolver, StoreID: original.StoreID, ModelID: original.ModelID, AttestationKey: key}
		return a.Authorize(ctx, identity, credential, RoutedOperation{OperationID: "listComplianceEvidence"})
	}
	refused := func(t *testing.T, grant RequestAuthorization, err, want error) {
		t.Helper()
		if !errors.Is(err, want) || !reflect.DeepEqual(grant, RequestAuthorization{}) {
			t.Fatalf("expected an empty grant and %v, got %v with %d decisions and %d attestation bytes", want, err, len(grant.Decisions), len(grant.attestation))
		}
	}

	t.Run("two reads enclose every distinct object and permission", func(t *testing.T) {
		const checks = count * 3
		var reads atomic.Int32
		var mu sync.Mutex
		seen := map[authorization.CheckRequest]int{}
		denied := map[string]string{targets[0].ID: "view", targets[51].ID: "view_audit", targets[count-1].ID: "view_compliance"}
		firstComplete := make(chan struct{})
		var release sync.Once
		read := func(_ context.Context, org string) (authorization.Revision, error) {
			mu.Lock()
			defer mu.Unlock()
			n := reads.Add(1)
			if org != original.OrganizationID || (n == 1 && len(seen) != 0) || (n == 2 && len(seen) != checks) || n > 2 {
				t.Errorf("revision read %d for %q with %d checked bindings", n, org, len(seen))
			}
			return original, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		grant, err := authorize(ctx, read, func(ctx context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
			// The second candidate deliberately completes first. The grant must still follow resolver order.
			if q.ResourceID == targets[0].ID && q.Permission == "view" {
				select {
				case <-firstComplete:
				case <-ctx.Done():
					return authorization.Decision{}, ctx.Err()
				}
			}
			mu.Lock()
			seen[q]++
			mu.Unlock()
			if q.ResourceID == targets[1].ID && q.Permission == "view_compliance" {
				release.Do(func() { close(firstComplete) })
			}
			return authorization.Decision{Allowed: denied[q.ResourceID] != q.Permission, ModelID: original.ModelID}, nil
		})
		if err != nil || reads.Load() != 2 || len(seen) != checks || len(grant.Decisions) != checks || !reflect.DeepEqual(grant.Targets, targets) || grant.Revision != original || len(grant.attestation) == 0 {
			t.Fatalf("reads=%d checks=%d decisions=%d targets=%d error=%v", reads.Load(), len(seen), len(grant.Decisions), len(grant.Targets), err)
		}
		var allowed []AuthorizationTarget
		for n, target := range targets {
			if _, excluded := denied[target.ID]; !excluded {
				allowed = append(allowed, target)
			}
			for p, permission := range permissions {
				want := authorization.CheckRequest{PrincipalKind: "user", PrincipalID: identity.PrincipalID.String(), OrganizationID: original.OrganizationID, WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ResourceType: target.Kind, ResourceID: target.ID, Permission: permission}
				checked := grant.Decisions[n*len(permissions)+p]
				if seen[want] != 1 || checked.Request != want || checked.Revision != original || checked.Decision.ModelID != original.ModelID || checked.Decision.Allowed != (denied[target.ID] != permission) {
					t.Fatalf("unexpected decision for ordered target %d permission %s: %+v, calls=%d", n, permission, checked, seen[want])
				}
			}
		}
		if !reflect.DeepEqual(grant.Allowed, allowed) {
			t.Fatalf("allowed targets do not match the ordered permission intersection, got %d want %d", len(grant.Allowed), len(allowed))
		}
	})

	for _, tc := range []struct {
		name   string
		change func(*authorization.Revision)
	}{
		{"pending beginning", func(r *authorization.Revision) { r.Desired++ }},
		{"foreign organization at beginning", func(r *authorization.Revision) { r.OrganizationID = "pid_99000001-0000-4000-8000-000000000001" }},
		{"unconfigured store at beginning", func(r *authorization.Revision) { r.StoreID = "01K00000000000000000000004" }},
		{"unconfigured model at beginning", func(r *authorization.Revision) { r.ModelID = otherModel }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revision := original
			tc.change(&revision)
			var reads, checks atomic.Int32
			grant, err := authorize(context.Background(), func(context.Context, string) (authorization.Revision, error) { reads.Add(1); return revision, nil }, func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
				checks.Add(1)
				return authorization.Decision{Allowed: true, ModelID: original.ModelID}, nil
			})
			refused(t, grant, err, authorization.ErrPending)
			if reads.Load() != 1 || checks.Load() != 0 {
				t.Fatalf("reads=%d checks=%d", reads.Load(), checks.Load())
			}
		})
	}
	for _, tc := range []struct {
		name    string
		restore bool
	}{
		{"applied permission change invalidates stale allows", false},
		{"restored values with higher generation invalidate stale allows", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var revision atomic.Pointer[authorization.Revision]
			revision.Store(&original)
			var reads, checks atomic.Int32
			var once sync.Once
			grant, err := authorize(context.Background(), func(context.Context, string) (authorization.Revision, error) {
				reads.Add(1)
				return *revision.Load(), nil
			}, func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
				checks.Add(1)
				once.Do(func() {
					pending := original
					pending.Desired++
					revision.Store(&pending)
					applied := pending
					applied.Applied = applied.Desired
					revision.Store(&applied)
					if tc.restore {
						restored := original
						restored.Generation++
						revision.Store(&restored)
					}
				})
				return authorization.Decision{Allowed: true, ModelID: original.ModelID}, nil
			})
			refused(t, grant, err, authorization.ErrConflict)
			if reads.Load() != 2 || checks.Load() != count*3 {
				t.Fatalf("reads=%d checks=%d", reads.Load(), checks.Load())
			}
		})
	}
	t.Run("foreign checker model", func(t *testing.T) {
		var mismatches atomic.Int32
		grant, err := authorize(context.Background(), func(context.Context, string) (authorization.Revision, error) { return original, nil }, func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
			model := original.ModelID
			if q.ResourceID == targets[80].ID && q.Permission == "view_audit" {
				model = otherModel
				mismatches.Add(1)
			}
			return authorization.Decision{Allowed: true, ModelID: model}, nil
		})
		refused(t, grant, err, authorization.ErrConflict)
		if mismatches.Load() != 1 {
			t.Fatalf("unexpected %d mismatched decisions", mismatches.Load())
		}
	})
	t.Run("cancellation during checks", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var checks atomic.Int32
		grant, err := authorize(ctx, func(context.Context, string) (authorization.Revision, error) { return original, nil }, func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
			checks.Add(1)
			cancel()
			return authorization.Decision{Allowed: true, ModelID: original.ModelID}, nil
		})
		refused(t, grant, err, authorization.ErrUnavailable)
		if checks.Load() == 0 || checks.Load() >= count*3 {
			t.Fatalf("unexpected %d checks after cancellation", checks.Load())
		}
	})
	t.Run("cancellation during final revision read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var reads, checks atomic.Int32
		grant, err := authorize(ctx, func(context.Context, string) (authorization.Revision, error) {
			if reads.Add(1) == 2 {
				cancel()
			}
			return original, nil
		}, func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
			checks.Add(1)
			return authorization.Decision{Allowed: true, ModelID: original.ModelID}, nil
		})
		refused(t, grant, err, authorization.ErrUnavailable)
		if reads.Load() != 2 || checks.Load() != count*3 {
			t.Fatalf("reads=%d checks=%d", reads.Load(), checks.Load())
		}
	})
}
