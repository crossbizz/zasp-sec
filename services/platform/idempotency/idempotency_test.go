package idempotency

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	organizationIDText = "pid_00010203-0405-4607-8809-0a0b0c0d0e0f"
	workspaceIDText    = "pid_10111213-1415-4617-9819-1a1b1c1d1e1f"
	environmentIDText  = "pid_20212223-2425-4627-a829-2a2b2c2d2e2f"
	otherOrgIDText     = "pid_30313233-3435-4637-b839-3a3b3c3d3e3f"
	resultIDText       = "pid_40414243-4445-4647-8849-4a4b4c4d4e4f"
	otherResultIDText  = "pid_50515253-5455-4657-9859-5a5b5c5d5e5f"
)

func mustProductID(t *testing.T, text string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q): %v", text, err)
	}
	return id
}

func testScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		mustProductID(t, organizationIDText),
		mustProductID(t, workspaceIDText),
		mustProductID(t, environmentIDText),
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	return scope
}

func otherScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		mustProductID(t, otherOrgIDText),
		mustProductID(t, workspaceIDText),
		mustProductID(t, environmentIDText),
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	return scope
}

func testRequest(t *testing.T) Request {
	t.Helper()
	request, err := NewRequest(testScope(t), "finding.assign", "request-123", []byte(`{"owner":"pid"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return request
}

type storeRecord struct {
	request Request
	lease   Lease
	result  domain.ProductID
}

type memoryStore struct {
	mu            sync.Mutex
	records       map[string]storeRecord
	claimCalls    int
	completeCalls int
	completeError error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{records: make(map[string]storeRecord)}
}

func requestSlot(request Request) string {
	scope := request.Scope()
	return scope.OrganizationID().String() + "/" + scope.WorkspaceID().String() + "/" +
		scope.EnvironmentID().String() + "/" + request.Key()
}

func (store *memoryStore) Claim(ctx context.Context, request Request) (Claim, error) {
	if err := ctx.Err(); err != nil {
		return Claim{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claimCalls++
	slot := requestSlot(request)
	record, found := store.records[slot]
	if !found {
		lease, err := NewLease("lease-123")
		if err != nil {
			return Claim{}, err
		}
		store.records[slot] = storeRecord{request: request, lease: lease}
		return NewAcquiredClaim(lease)
	}
	if record.request != request {
		return Claim{}, ErrKeyConflict
	}
	if !record.result.IsZero() {
		return NewCompletedClaim(record.result)
	}
	return NewInProgressClaim(), nil
}

func (store *memoryStore) Complete(ctx context.Context, request Request, lease Lease, result domain.ProductID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.completeCalls++
	if store.completeError != nil {
		return store.completeError
	}
	slot := requestSlot(request)
	record, found := store.records[slot]
	if !found || record.request != request || record.lease != lease || !record.result.IsZero() {
		return errors.New("completion ownership mismatch")
	}
	record.result = result
	store.records[slot] = record
	return nil
}

type scriptedStore struct {
	claim    func(context.Context, Request) (Claim, error)
	complete func(context.Context, Request, Lease, domain.ProductID) error
}

func (store *scriptedStore) Claim(ctx context.Context, request Request) (Claim, error) {
	return store.claim(ctx, request)
}

func (store *scriptedStore) Complete(ctx context.Context, request Request, lease Lease, result domain.ProductID) error {
	return store.complete(ctx, request, lease, result)
}

func TestRequestValidationFingerprintAndAccessors(t *testing.T) {
	scope := testScope(t)
	request, err := NewRequest(scope, "finding.assign", "Request_123:retry", []byte("exact request"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if request.Scope() != scope || request.Operation() != "finding.assign" || request.Key() != "Request_123:retry" {
		t.Fatalf("request accessors changed identity: %#v", request)
	}
	if request.Fingerprint() == ([32]byte{}) {
		t.Fatal("request fingerprint is zero")
	}
	identical, err := NewRequest(scope, "finding.assign", "Request_123:retry", []byte("exact request"))
	if err != nil || identical != request {
		t.Fatalf("identical request = %#v, %v", identical, err)
	}
	different, err := NewRequest(scope, "finding.assign", "Request_123:retry", []byte("different request"))
	if err != nil {
		t.Fatal(err)
	}
	if different == request || different.Fingerprint() == request.Fingerprint() {
		t.Fatal("different payload reused request identity")
	}

	validPayload := []byte("payload")
	for name, fields := range map[string]struct {
		scope     domain.Scope
		operation string
		key       string
		payload   []byte
	}{
		"zero scope":          {operation: "finding.assign", key: "request-1", payload: validPayload},
		"empty operation":     {scope: scope, key: "request-1", payload: validPayload},
		"uppercase operation": {scope: scope, operation: "Finding.assign", key: "request-1", payload: validPayload},
		"operation slash":     {scope: scope, operation: "finding/assign", key: "request-1", payload: validPayload},
		"long operation":      {scope: scope, operation: "a" + strings.Repeat("b", 63), key: "request-1", payload: validPayload},
		"empty key":           {scope: scope, operation: "finding.assign", payload: validPayload},
		"space key":           {scope: scope, operation: "finding.assign", key: "request 1", payload: validPayload},
		"control key":         {scope: scope, operation: "finding.assign", key: "request\n1", payload: validPayload},
		"long key":            {scope: scope, operation: "finding.assign", key: strings.Repeat("a", 129), payload: validPayload},
		"large payload":       {scope: scope, operation: "finding.assign", key: "request-1", payload: make([]byte, 1<<20+1)},
	} {
		t.Run(name, func(t *testing.T) {
			rejected, err := NewRequest(fields.scope, fields.operation, fields.key, fields.payload)
			if !errors.Is(err, ErrInvalidRequest) || rejected != (Request{}) {
				t.Fatalf("NewRequest = %#v, %v", rejected, err)
			}
		})
	}
	if err := (Request{}).Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero request validation = %v", err)
	}
}

func TestClaimAndLeaseValidation(t *testing.T) {
	lease, err := NewLease("lease_123:owner")
	if err != nil {
		t.Fatalf("NewLease: %v", err)
	}
	acquired, err := NewAcquiredClaim(lease)
	if err != nil || acquired.State() != ClaimAcquired || acquired.Lease() != lease || !acquired.Result().IsZero() {
		t.Fatalf("acquired claim = %#v, %v", acquired, err)
	}
	pending := NewInProgressClaim()
	if pending.State() != ClaimInProgress || pending.Lease() != (Lease{}) || !pending.Result().IsZero() {
		t.Fatalf("pending claim = %#v", pending)
	}
	result := mustProductID(t, resultIDText)
	completed, err := NewCompletedClaim(result)
	if err != nil || completed.State() != ClaimCompleted || completed.Lease() != (Lease{}) || completed.Result() != result {
		t.Fatalf("completed claim = %#v, %v", completed, err)
	}

	for name, token := range map[string]string{
		"empty":   "",
		"space":   "lease 1",
		"control": "lease\n1",
		"long":    strings.Repeat("a", 129),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := NewLease(token)
			if !errors.Is(err, ErrInvalidLease) || value != (Lease{}) {
				t.Fatalf("NewLease = %#v, %v", value, err)
			}
		})
	}
	if _, err := NewAcquiredClaim(Lease{}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("zero acquired claim = %v", err)
	}
	if _, err := NewCompletedClaim(domain.ProductID{}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("zero completed claim = %v", err)
	}
	for name, claim := range map[string]Claim{
		"zero":                 {},
		"acquired with result": {state: ClaimAcquired, lease: lease, result: result},
		"pending with lease":   {state: ClaimInProgress, lease: lease},
		"completed with lease": {state: ClaimCompleted, lease: lease, result: result},
	} {
		t.Run(name, func(t *testing.T) {
			if err := claim.Validate(); !errors.Is(err, ErrInvalidClaim) {
				t.Fatalf("claim validation = %v", err)
			}
		})
	}
}

func TestDuplicateKeyReturnsPriorResultReference(t *testing.T) {
	store := newMemoryStore()
	helper, err := NewHelper(store)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(t)
	result := mustProductID(t, resultIDText)
	var calls int
	first, err := helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
		calls++
		return result, nil
	})
	if err != nil || first.Result() != result || first.Prior() {
		t.Fatalf("first outcome = %#v, %v", first, err)
	}
	duplicate, err := helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
		calls++
		return mustProductID(t, otherResultIDText), nil
	})
	if err != nil || duplicate.Result() != result || !duplicate.Prior() {
		t.Fatalf("duplicate outcome = %#v, %v", duplicate, err)
	}
	if calls != 1 || store.completeCalls != 1 || store.claimCalls != 2 {
		t.Fatalf("calls operation=%d claim=%d complete=%d", calls, store.claimCalls, store.completeCalls)
	}
}

func TestInProgressAndConflictingClaimsDoNotExecute(t *testing.T) {
	request := testRequest(t)
	result := mustProductID(t, resultIDText)
	for name, claim := range map[string]func(context.Context, Request) (Claim, error){
		"in progress": func(context.Context, Request) (Claim, error) { return NewInProgressClaim(), nil },
		"conflict":    func(context.Context, Request) (Claim, error) { return Claim{}, ErrKeyConflict },
		"store error": func(context.Context, Request) (Claim, error) { return Claim{}, errors.New("secret database detail") },
	} {
		t.Run(name, func(t *testing.T) {
			store := &scriptedStore{claim: claim, complete: func(context.Context, Request, Lease, domain.ProductID) error {
				t.Fatal("Complete called")
				return nil
			}}
			helper, err := NewHelper(store)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			_, err = helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
				called = true
				return result, nil
			})
			if called {
				t.Fatal("operation executed")
			}
			want := ErrInProgress
			if name == "conflict" {
				want = ErrKeyConflict
			} else if name == "store error" {
				want = ErrStore
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaked store detail: %q", err)
			}
		})
	}
}

func TestRequestIdentityScopesAndFingerprintConflicts(t *testing.T) {
	store := newMemoryStore()
	helper, err := NewHelper(store)
	if err != nil {
		t.Fatal(err)
	}
	base := testRequest(t)
	result := mustProductID(t, resultIDText)
	if _, err := helper.Execute(context.Background(), base, func(context.Context) (domain.ProductID, error) {
		return result, nil
	}); err != nil {
		t.Fatal(err)
	}

	conflict, err := NewRequest(base.Scope(), base.Operation(), base.Key(), []byte("different payload"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err := helper.Execute(context.Background(), conflict, func(context.Context) (domain.ProductID, error) {
		called = true
		return result, nil
	}); !errors.Is(err, ErrKeyConflict) || called {
		t.Fatalf("conflict = %v, called=%v", err, called)
	}
	operationConflict, err := NewRequest(base.Scope(), "finding.close", base.Key(), []byte(`{"owner":"pid"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := helper.Execute(context.Background(), operationConflict, func(context.Context) (domain.ProductID, error) {
		called = true
		return result, nil
	}); !errors.Is(err, ErrKeyConflict) || called {
		t.Fatalf("operation conflict = %v, called=%v", err, called)
	}

	other, err := NewRequest(otherScope(t), base.Operation(), base.Key(), []byte(`{"owner":"pid"}`))
	if err != nil {
		t.Fatal(err)
	}
	otherResult := mustProductID(t, otherResultIDText)
	outcome, err := helper.Execute(context.Background(), other, func(context.Context) (domain.ProductID, error) {
		return otherResult, nil
	})
	if err != nil || outcome.Result() != otherResult || outcome.Prior() {
		t.Fatalf("other scope outcome = %#v, %v", outcome, err)
	}
}

func TestInvalidHelperInputsAndStoreClaimsFailClosed(t *testing.T) {
	request := testRequest(t)
	result := mustProductID(t, resultIDText)
	var nilStore *memoryStore
	for name, store := range map[string]Store{"nil": nil, "typed nil": nilStore} {
		t.Run(name, func(t *testing.T) {
			helper, err := NewHelper(store)
			if !errors.Is(err, ErrInvalidStore) || helper != nil {
				t.Fatalf("NewHelper = %#v, %v", helper, err)
			}
		})
	}

	validStore := &scriptedStore{
		claim:    func(context.Context, Request) (Claim, error) { return Claim{}, nil },
		complete: func(context.Context, Request, Lease, domain.ProductID) error { return nil },
	}
	helper, err := NewHelper(validStore)
	if err != nil {
		t.Fatal(err)
	}
	for name, fields := range map[string]struct {
		helper    *Helper
		ctx       context.Context
		request   Request
		operation Operation
	}{
		"zero helper":   {helper: &Helper{}, ctx: context.Background(), request: request, operation: func(context.Context) (domain.ProductID, error) { return result, nil }},
		"nil context":   {helper: helper, request: request, operation: func(context.Context) (domain.ProductID, error) { return result, nil }},
		"zero request":  {helper: helper, ctx: context.Background(), operation: func(context.Context) (domain.ProductID, error) { return result, nil }},
		"nil operation": {helper: helper, ctx: context.Background(), request: request},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fields.helper.Execute(fields.ctx, fields.request, fields.operation)
			if !errors.Is(err, ErrInvalidHelper) && !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
		t.Fatal("operation executed for invalid claim")
		return result, nil
	}); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("invalid claim error = %v", err)
	}
}

func TestOperationAndCompletionFailuresRetainClaim(t *testing.T) {
	operationFailure := errors.New("operation failed")
	for name, setup := range map[string]func(*memoryStore) Operation{
		"operation error": func(*memoryStore) Operation {
			return func(context.Context) (domain.ProductID, error) { return domain.ProductID{}, operationFailure }
		},
		"invalid result": func(*memoryStore) Operation {
			return func(context.Context) (domain.ProductID, error) { return domain.ProductID{}, nil }
		},
		"completion error": func(store *memoryStore) Operation {
			store.completeError = errors.New("database detail")
			return func(context.Context) (domain.ProductID, error) { return mustProductID(t, resultIDText), nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemoryStore()
			helper, err := NewHelper(store)
			if err != nil {
				t.Fatal(err)
			}
			request := testRequest(t)
			_, err = helper.Execute(context.Background(), request, setup(store))
			switch name {
			case "operation error":
				if !errors.Is(err, operationFailure) {
					t.Fatalf("error = %v", err)
				}
			case "invalid result":
				if !errors.Is(err, ErrInvalidResult) {
					t.Fatalf("error = %v", err)
				}
			case "completion error":
				if !errors.Is(err, ErrStore) || strings.Contains(err.Error(), "database") {
					t.Fatalf("error = %v", err)
				}
			}
			called := false
			_, duplicateError := helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
				called = true
				return mustProductID(t, otherResultIDText), nil
			})
			if !errors.Is(duplicateError, ErrInProgress) || called {
				t.Fatalf("duplicate = %v, called=%v", duplicateError, called)
			}
		})
	}
}

func TestContextCancellationPreventsOperationAndCompletion(t *testing.T) {
	request := testRequest(t)
	result := mustProductID(t, resultIDText)
	lease, err := NewLease("lease-123")
	if err != nil {
		t.Fatal(err)
	}
	for name, cancelAtClaim := range map[string]bool{"before claim": false, "after claim": true} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			claimCalls := 0
			completeCalls := 0
			store := &scriptedStore{
				claim: func(context.Context, Request) (Claim, error) {
					claimCalls++
					if cancelAtClaim {
						cancel()
					}
					return NewAcquiredClaim(lease)
				},
				complete: func(context.Context, Request, Lease, domain.ProductID) error {
					completeCalls++
					return nil
				},
			}
			helper, err := NewHelper(store)
			if err != nil {
				t.Fatal(err)
			}
			if !cancelAtClaim {
				cancel()
			}
			called := false
			_, err = helper.Execute(ctx, request, func(context.Context) (domain.ProductID, error) {
				called = true
				return result, nil
			})
			if !errors.Is(err, context.Canceled) || called || completeCalls != 0 {
				t.Fatalf("error=%v called=%v complete=%d", err, called, completeCalls)
			}
			if !cancelAtClaim && claimCalls != 0 {
				t.Fatalf("pre-canceled request claimed %d times", claimCalls)
			}
		})
	}
}

func TestConcurrentDuplicateExecutesOperationOnce(t *testing.T) {
	store := newMemoryStore()
	helper, err := NewHelper(store)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(t)
	result := mustProductID(t, resultIDText)
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		_, executeError := helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
			calls.Add(1)
			close(started)
			<-release
			return result, nil
		})
		firstDone <- executeError
	}()
	<-started
	called := false
	_, duplicateError := helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
		called = true
		return result, nil
	})
	if !errors.Is(duplicateError, ErrInProgress) || called {
		t.Fatalf("concurrent duplicate = %v, called=%v", duplicateError, called)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("owner execution = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("operation calls = %d", calls.Load())
	}
}

func TestPanicRetainsClaimAndPropagates(t *testing.T) {
	store := newMemoryStore()
	helper, err := NewHelper(store)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(t)
	func() {
		defer func() {
			if recovered := recover(); recovered != "operation panic" {
				t.Fatalf("recovered = %#v", recovered)
			}
		}()
		_, _ = helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
			panic("operation panic")
		})
	}()
	called := false
	_, err = helper.Execute(context.Background(), request, func(context.Context) (domain.ProductID, error) {
		called = true
		return mustProductID(t, resultIDText), nil
	})
	if !errors.Is(err, ErrInProgress) || called {
		t.Fatalf("duplicate after panic = %v, called=%v", err, called)
	}
}
