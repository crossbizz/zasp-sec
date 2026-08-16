package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type fakeDriver struct {
	mu       sync.Mutex
	calls    []DriverMutation
	appendFn func(context.Context, DriverMutation) (DriverAppended, error)
}

func (driver *fakeDriver) Append(ctx context.Context, mutation DriverMutation) (DriverAppended, error) {
	driver.mu.Lock()
	driver.calls = append(driver.calls, mutation)
	appendFn := driver.appendFn
	driver.mu.Unlock()
	if appendFn == nil {
		return appendedFromMutation(mutation), nil
	}
	return appendFn(ctx, mutation)
}

func (driver *fakeDriver) callCount() int {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return len(driver.calls)
}

func (driver *fakeDriver) call(index int) DriverMutation {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.calls[index]
}

func TestEmitterEmitsExactScopedMutationOnce(t *testing.T) {
	scope := auditTestScope(t)
	mutation := auditTestMutation(t)
	driver := &fakeDriver{}
	emitter, err := New(driver, Config{OperationTimeout: time.Second})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	var contract AuditEmitter = emitter
	if err := contract.Emit(context.Background(), scope, mutation); err != nil {
		t.Fatalf("Emit returned error: %v", err)
	}
	if driver.callCount() != 1 {
		t.Fatalf("calls = %d, want 1", driver.callCount())
	}
	want := driverMutation(scope, mutation)
	if got := driver.call(0); got != want {
		t.Fatalf("driver mutation = %#v, want %#v", got, want)
	}
}

func TestEmitterRejectsInvalidConstruction(t *testing.T) {
	validDriver := &fakeDriver{}
	var typedNil *fakeDriver
	for name, test := range map[string]struct {
		driver Driver
		config Config
	}{
		"nil driver":       {driver: nil, config: Config{OperationTimeout: time.Second}},
		"typed nil driver": {driver: typedNil, config: Config{OperationTimeout: time.Second}},
		"zero timeout":     {driver: validDriver},
		"negative timeout": {driver: validDriver, config: Config{OperationTimeout: -time.Nanosecond}},
		"over limit":       {driver: validDriver, config: Config{OperationTimeout: 30*time.Second + time.Nanosecond}},
	} {
		t.Run(name, func(t *testing.T) {
			emitter, err := New(test.driver, test.config)
			if !errors.Is(err, ErrConfiguration) || emitter != nil {
				t.Fatalf("New = %#v, %v; want nil, ErrConfiguration", emitter, err)
			}
		})
	}
}

func TestEmitterRejectsIncompleteOrMalformedMutationBeforeIO(t *testing.T) {
	scope := auditTestScope(t)
	valid := auditTestMutation(t)
	invalidActions := []string{
		"", "A", "policy create", ".policy", "policy.", "policy..create",
		"policy__create", "policy--create", "policy/+create", "policé.create",
		strings.Repeat("a", 128),
	}
	tests := map[string]struct {
		scope    domain.Scope
		mutation Mutation
	}{
		"zero scope":      {mutation: valid},
		"missing actor":   {scope: scope, mutation: Mutation{Action: valid.Action, Target: valid.Target, Outcome: valid.Outcome}},
		"missing target":  {scope: scope, mutation: Mutation{Actor: valid.Actor, Action: valid.Action, Outcome: valid.Outcome}},
		"missing outcome": {scope: scope, mutation: Mutation{Actor: valid.Actor, Action: valid.Action, Target: valid.Target}},
		"unknown outcome": {scope: scope, mutation: Mutation{Actor: valid.Actor, Action: valid.Action, Target: valid.Target, Outcome: Outcome("unknown")}},
	}
	for index, action := range invalidActions {
		mutation := valid
		mutation.Action = action
		tests[fmt.Sprintf("invalid action %d", index)] = struct {
			scope    domain.Scope
			mutation Mutation
		}{scope: scope, mutation: mutation}
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			driver := &fakeDriver{}
			emitter, err := New(driver, Config{OperationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			err = emitter.Emit(context.Background(), test.scope, test.mutation)
			if !errors.Is(err, ErrMutation) {
				t.Fatalf("Emit error = %v, want ErrMutation", err)
			}
			if driver.callCount() != 0 {
				t.Fatalf("driver calls = %d, want 0", driver.callCount())
			}
		})
	}
}

func TestEmitterAcceptsExactActionGrammarAndSelfMutation(t *testing.T) {
	scope := auditTestScope(t)
	valid := auditTestMutation(t)
	valid.Target = valid.Actor
	for _, action := range []string{
		"a", "policy.create", "credential_revoke", "session-isolate", strings.Repeat("a", 127),
	} {
		t.Run(action[:min(len(action), 24)], func(t *testing.T) {
			driver := &fakeDriver{}
			emitter, err := New(driver, Config{OperationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			mutation := valid
			mutation.Action = action
			if err := emitter.Emit(context.Background(), scope, mutation); err != nil {
				t.Fatalf("Emit returned error: %v", err)
			}
		})
	}
}

func TestEmitterRequiresExactAcknowledgement(t *testing.T) {
	scope := auditTestScope(t)
	mutation := auditTestMutation(t)
	want := appendedFromMutation(driverMutation(scope, mutation))
	tests := map[string]func(*DriverAppended){
		"organization":  func(value *DriverAppended) { value.OrganizationID = auditTestID(t, 9).String() },
		"workspace":     func(value *DriverAppended) { value.WorkspaceID = auditTestID(t, 9).String() },
		"environment":   func(value *DriverAppended) { value.EnvironmentID = auditTestID(t, 9).String() },
		"actor":         func(value *DriverAppended) { value.Actor = auditTestID(t, 9).String() },
		"action":        func(value *DriverAppended) { value.Action = "policy.update" },
		"target":        func(value *DriverAppended) { value.Target = auditTestID(t, 9).String() },
		"outcome":       func(value *DriverAppended) { value.Outcome = string(OutcomeFailed) },
		"empty success": func(value *DriverAppended) { *value = DriverAppended{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			driver := &fakeDriver{appendFn: func(context.Context, DriverMutation) (DriverAppended, error) {
				acknowledged := want
				mutate(&acknowledged)
				return acknowledged, nil
			}}
			emitter, err := New(driver, Config{OperationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if err := emitter.Emit(context.Background(), scope, mutation); !errors.Is(err, ErrEmit) {
				t.Fatalf("Emit error = %v, want ErrEmit", err)
			}
			if driver.callCount() != 1 {
				t.Fatalf("driver calls = %d, want 1", driver.callCount())
			}
		})
	}
}

func TestEmitterContainsDriverFailuresAndHonorsContext(t *testing.T) {
	scope := auditTestScope(t)
	mutation := auditTestMutation(t)
	providerError := errors.New("provider endpoint credential-shaped-value")
	tests := map[string]func(context.Context, DriverMutation) (DriverAppended, error){
		"driver error": func(context.Context, DriverMutation) (DriverAppended, error) {
			return DriverAppended{}, providerError
		},
		"driver panic": func(context.Context, DriverMutation) (DriverAppended, error) {
			panic("provider panic credential-shaped-value")
		},
		"deadline": func(ctx context.Context, _ DriverMutation) (DriverAppended, error) {
			<-ctx.Done()
			return DriverAppended{}, ctx.Err()
		},
	}
	for name, appendFn := range tests {
		t.Run(name, func(t *testing.T) {
			timeout := time.Second
			if name == "deadline" {
				timeout = time.Millisecond
			}
			driver := &fakeDriver{appendFn: appendFn}
			emitter, err := New(driver, Config{OperationTimeout: timeout})
			if err != nil {
				t.Fatal(err)
			}
			emitErr := emitter.Emit(context.Background(), scope, mutation)
			if !errors.Is(emitErr, ErrEmit) || emitErr.Error() != ErrEmit.Error() {
				t.Fatalf("Emit error = %q, want fixed %q", emitErr, ErrEmit)
			}
			if driver.callCount() != 1 {
				t.Fatalf("driver calls = %d, want 1", driver.callCount())
			}
		})
	}

	driver := &fakeDriver{}
	emitter, err := New(driver, Config{OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := emitter.Emit(cancelled, scope, mutation); !errors.Is(err, ErrEmit) {
		t.Fatalf("cancelled Emit error = %v, want ErrEmit", err)
	}
	if driver.callCount() != 0 {
		t.Fatalf("cancelled driver calls = %d, want 0", driver.callCount())
	}
	if err := emitter.Emit(nil, scope, mutation); !errors.Is(err, ErrEmit) {
		t.Fatalf("nil-context Emit error = %v, want ErrEmit", err)
	}
	var nilEmitter *Emitter
	if err := nilEmitter.Emit(context.Background(), scope, mutation); !errors.Is(err, ErrEmit) {
		t.Fatalf("nil-receiver Emit error = %v, want ErrEmit", err)
	}
}

func TestEmitterIsSafeForConcurrentCalls(t *testing.T) {
	scope := auditTestScope(t)
	driver := &fakeDriver{}
	emitter, err := New(driver, Config{OperationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const count = 32
	errorsByCall := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsByCall <- emitter.Emit(context.Background(), scope, auditTestMutation(t))
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent Emit error: %v", err)
		}
	}
	if driver.callCount() != count {
		t.Fatalf("driver calls = %d, want %d", driver.callCount(), count)
	}
}

func auditTestScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(auditTestID(t, 1), auditTestID(t, 2), auditTestID(t, 3))
	if err != nil {
		t.Fatalf("NewScope returned error: %v", err)
	}
	return scope
}

func auditTestMutation(t *testing.T) Mutation {
	t.Helper()
	return Mutation{
		Actor: auditTestID(t, 4), Action: "policy.create", Target: auditTestID(t, 5), Outcome: OutcomeSucceeded,
	}
}

func auditTestID(t *testing.T, suffix byte) domain.ProductID {
	t.Helper()
	text := fmt.Sprintf("pid_00000000-0000-4000-8000-%012x", suffix)
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q) returned error: %v", text, err)
	}
	return id
}

func driverMutation(scope domain.Scope, mutation Mutation) DriverMutation {
	return DriverMutation{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		Actor:          mutation.Actor.String(),
		Action:         mutation.Action,
		Target:         mutation.Target.String(),
		Outcome:        string(mutation.Outcome),
	}
}

func appendedFromMutation(mutation DriverMutation) DriverAppended {
	return DriverAppended{
		OrganizationID: mutation.OrganizationID,
		WorkspaceID:    mutation.WorkspaceID,
		EnvironmentID:  mutation.EnvironmentID,
		Actor:          mutation.Actor,
		Action:         mutation.Action,
		Target:         mutation.Target,
		Outcome:        mutation.Outcome,
	}
}
