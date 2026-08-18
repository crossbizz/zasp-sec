package tenantquota

import (
	"errors"
	"sync"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	organizationA = "pid_00000000-0000-4000-8000-000000000001"
	organizationB = "pid_00000000-0000-4000-8000-000000000002"
	workspaceA    = "pid_00000000-0000-4000-8000-000000000101"
	workspaceB    = "pid_00000000-0000-4000-8000-000000000102"
	environmentA  = "pid_00000000-0000-4000-8000-000000000201"
	environmentB  = "pid_00000000-0000-4000-8000-000000000202"
)

func testScope(t *testing.T, organization, workspace, environment string) domain.Scope {
	t.Helper()
	parse := func(text string) domain.ProductID {
		id, err := domain.ParseProductID(text)
		if err != nil {
			t.Fatalf("ParseProductID = %v", err)
		}
		return id
	}
	scope, err := domain.NewScope(parse(organization), parse(workspace), parse(environment))
	if err != nil {
		t.Fatalf("NewScope = %v", err)
	}
	return scope
}

func testLimits(limit uint32) Limits {
	return Limits{Connectors: limit, GraphQueries: limit, Tests: limit, AIRequests: limit}
}

func TestKeysRetainExactOrganizationAndKind(t *testing.T) {
	scopeA := testScope(t, organizationA, workspaceA, environmentA)
	scopeAOther := testScope(t, organizationA, workspaceB, environmentB)
	scopeB := testScope(t, organizationB, workspaceA, environmentA)
	kinds := []Kind{Connector, GraphQuery, Test, AIRequest}
	wantNames := []string{"connector", "graph_query", "test", "ai_request"}

	for index, kind := range kinds {
		key, err := NewKey(scopeA, kind)
		if err != nil || key.OrganizationID() != scopeA.OrganizationID() || key.Kind() != kind || kind.String() != wantNames[index] {
			t.Fatalf("NewKey(%q) = %#v, %v", kind, key, err)
		}
		sameOrganization, _ := NewKey(scopeAOther, kind)
		otherOrganization, _ := NewKey(scopeB, kind)
		if key != sameOrganization || key == otherOrganization {
			t.Fatalf("key equality for %q does not preserve Organization boundary", kind)
		}
	}

	connector, _ := NewKey(scopeA, Connector)
	graph, _ := NewKey(scopeA, GraphQuery)
	if connector == graph {
		t.Fatal("different kinds share one key")
	}
	for _, invalid := range []Kind{"", "connector ", "CONNECTOR", "custom"} {
		if key, err := NewKey(scopeA, invalid); !errors.Is(err, ErrInvalidRequest) || key != (Key{}) {
			t.Fatalf("NewKey invalid = %#v, %v", key, err)
		}
	}
	if key, err := NewKey(domain.Scope{}, Connector); !errors.Is(err, ErrInvalidRequest) || key != (Key{}) {
		t.Fatalf("NewKey zero scope = %#v, %v", key, err)
	}
	if (Key{}).OrganizationID() != (domain.ProductID{}) || (Key{}).Kind() != Kind("") || Kind("custom").String() != "" {
		t.Fatal("direct invalid key or kind exposed state")
	}
}

func TestConfigurationRequiresEveryBoundedLimit(t *testing.T) {
	if counter, err := New(testLimits(1)); err != nil || counter == nil {
		t.Fatalf("New valid = %#v, %v", counter, err)
	}
	if counter, err := New(testLimits(1024)); err != nil || counter == nil {
		t.Fatalf("New maximum = %#v, %v", counter, err)
	}
	mutations := []func(*Limits){
		func(value *Limits) { value.Connectors = 0 },
		func(value *Limits) { value.GraphQueries = 0 },
		func(value *Limits) { value.Tests = 0 },
		func(value *Limits) { value.AIRequests = 0 },
		func(value *Limits) { value.Connectors = 1025 },
		func(value *Limits) { value.GraphQueries = 1025 },
		func(value *Limits) { value.Tests = 1025 },
		func(value *Limits) { value.AIRequests = 1025 },
	}
	for _, mutate := range mutations {
		limits := testLimits(1)
		mutate(&limits)
		if counter, err := New(limits); !errors.Is(err, ErrInvalidConfiguration) || counter != nil {
			t.Fatalf("New invalid = %#v, %v", counter, err)
		}
	}
}

func TestTwoOrganizationsHaveIndependentPredictableCounters(t *testing.T) {
	counter, _ := New(testLimits(1))
	scopeA := testScope(t, organizationA, workspaceA, environmentA)
	scopeAOther := testScope(t, organizationA, workspaceB, environmentB)
	scopeB := testScope(t, organizationB, workspaceA, environmentA)

	permitA, err := counter.TryAcquire(scopeA, Connector)
	if err != nil || permitA == nil {
		t.Fatalf("A acquire = %#v, %v", permitA, err)
	}
	if permit, err := counter.TryAcquire(scopeAOther, Connector); !errors.Is(err, ErrQuotaExceeded) || permit != nil {
		t.Fatalf("A over limit = %#v, %v", permit, err)
	}
	permitB, err := counter.TryAcquire(scopeB, Connector)
	if err != nil || permitB == nil {
		t.Fatalf("B acquire = %#v, %v", permitB, err)
	}
	for _, scope := range []domain.Scope{scopeA, scopeB} {
		if usage, err := counter.Usage(scope, Connector); err != nil || usage != (Usage{InUse: 1, Limit: 1}) {
			t.Fatalf("Usage = %#v, %v", usage, err)
		}
	}
	if err := permitA.Release(); err != nil {
		t.Fatalf("A Release = %v", err)
	}
	if permitA, err = counter.TryAcquire(scopeA, Connector); err != nil || permitA == nil {
		t.Fatalf("A reacquire = %#v, %v", permitA, err)
	}
	if err := permitA.Release(); err != nil {
		t.Fatalf("A final Release = %v", err)
	}
	if err := permitB.Release(); err != nil {
		t.Fatalf("B Release = %v", err)
	}
	if len(counter.state.counts) != 0 {
		t.Fatalf("inactive entries retained = %d", len(counter.state.counts))
	}
}

func TestKindsAreIndependentWithinOneOrganization(t *testing.T) {
	counter, _ := New(testLimits(1))
	scope := testScope(t, organizationA, workspaceA, environmentA)
	var permits []*Permit
	for _, kind := range []Kind{Connector, GraphQuery, Test, AIRequest} {
		permit, err := counter.TryAcquire(scope, kind)
		if err != nil {
			t.Fatalf("TryAcquire(%q) = %v", kind, err)
		}
		permits = append(permits, permit)
	}
	if len(counter.state.counts) != 4 {
		t.Fatalf("active keys = %d", len(counter.state.counts))
	}
	for _, permit := range permits {
		if err := permit.Release(); err != nil {
			t.Fatalf("Release = %v", err)
		}
	}
}

func TestPermitCopiesAndConcurrentReleaseCannotUnderflow(t *testing.T) {
	counter, _ := New(testLimits(1))
	scope := testScope(t, organizationA, workspaceA, environmentA)
	permit, _ := counter.TryAcquire(scope, Test)
	copyOfPermit := *permit
	errorsReturned := make(chan error, 2)
	go func() { errorsReturned <- permit.Release() }()
	go func() { errorsReturned <- copyOfPermit.Release() }()
	first, second := <-errorsReturned, <-errorsReturned
	if !((first == nil && errors.Is(second, ErrInvalidPermit)) || (second == nil && errors.Is(first, ErrInvalidPermit))) {
		t.Fatalf("concurrent Release errors = %v, %v", first, second)
	}
	if usage, err := counter.Usage(scope, Test); err != nil || usage != (Usage{Limit: 1}) {
		t.Fatalf("Usage after Release = %#v, %v", usage, err)
	}
	if err := permit.Release(); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("repeated Release = %v", err)
	}
	var nilPermit *Permit
	if err := nilPermit.Release(); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("nil Release = %v", err)
	}
	if err := (&Permit{}).Release(); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("forged Release = %v", err)
	}
}

func TestConcurrentAdmissionStopsExactlyAtLimit(t *testing.T) {
	counter, _ := New(testLimits(8))
	scopeA := testScope(t, organizationA, workspaceA, environmentA)
	scopeB := testScope(t, organizationB, workspaceA, environmentA)

	results := make(chan *Permit, 64)
	errorsReturned := make(chan error, 64)
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			permit, err := counter.TryAcquire(scopeA, AIRequest)
			results <- permit
			errorsReturned <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsReturned)

	var permits []*Permit
	for permit := range results {
		if permit != nil {
			permits = append(permits, permit)
		}
	}
	exceeded := 0
	for err := range errorsReturned {
		if errors.Is(err, ErrQuotaExceeded) {
			exceeded++
		} else if err != nil {
			t.Fatalf("unexpected admission error = %v", err)
		}
	}
	if len(permits) != 8 || exceeded != 56 {
		t.Fatalf("admission = %d permits, %d exceeded", len(permits), exceeded)
	}
	for range 8 {
		permit, err := counter.TryAcquire(scopeB, AIRequest)
		if err != nil {
			t.Fatalf("independent B acquire = %v", err)
		}
		permits = append(permits, permit)
	}
	for _, permit := range permits {
		if err := permit.Release(); err != nil {
			t.Fatalf("Release = %v", err)
		}
	}
}

func TestCounterCopiesShareOneSynchronizedState(t *testing.T) {
	counter, _ := New(testLimits(1))
	copied := *counter
	scope := testScope(t, organizationA, workspaceA, environmentA)
	start := make(chan struct{})
	type result struct {
		permit *Permit
		err    error
	}
	results := make(chan result, 2)
	for _, candidate := range []*Counter{counter, &copied} {
		go func(value *Counter) {
			<-start
			permit, err := value.TryAcquire(scope, GraphQuery)
			results <- result{permit: permit, err: err}
		}(candidate)
	}
	close(start)
	first, second := <-results, <-results
	successes := 0
	for _, candidate := range []result{first, second} {
		if candidate.err == nil && candidate.permit != nil {
			successes++
			if err := candidate.permit.Release(); err != nil {
				t.Fatalf("Release = %v", err)
			}
		} else if !errors.Is(candidate.err, ErrQuotaExceeded) || candidate.permit != nil {
			t.Fatalf("copied counter result = %#v, %v", candidate.permit, candidate.err)
		}
	}
	if successes != 1 {
		t.Fatalf("copied counter successes = %d", successes)
	}
}

func TestInvalidRequestsNeverCreateState(t *testing.T) {
	counter, _ := New(testLimits(1))
	scope := testScope(t, organizationA, workspaceA, environmentA)
	for _, request := range []struct {
		counter *Counter
		scope   domain.Scope
		kind    Kind
	}{
		{counter: nil, scope: scope, kind: Connector},
		{counter: &Counter{}, scope: scope, kind: Connector},
		{counter: counter, scope: domain.Scope{}, kind: Connector},
		{counter: counter, scope: scope, kind: Kind("custom")},
	} {
		permit, err := request.counter.TryAcquire(request.scope, request.kind)
		if !errors.Is(err, ErrInvalidRequest) || permit != nil {
			t.Fatalf("invalid TryAcquire = %#v, %v", permit, err)
		}
		usage, err := request.counter.Usage(request.scope, request.kind)
		if !errors.Is(err, ErrInvalidRequest) || usage != (Usage{}) {
			t.Fatalf("invalid Usage = %#v, %v", usage, err)
		}
	}
	if len(counter.state.counts) != 0 {
		t.Fatalf("invalid requests retained entries = %d", len(counter.state.counts))
	}
}
