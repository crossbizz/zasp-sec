package repository

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/database"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recordingQueryer struct {
	query func(context.Context, string, []any, ...any) error
}

func (queryer *recordingQueryer) QueryRow(ctx context.Context, statement string, arguments []any, destinations ...any) error {
	if queryer.query != nil {
		return queryer.query(ctx, statement, arguments, destinations...)
	}
	return nil
}

func TestGuardPrependsCanonicalOrganizationWithoutMutatingCallerArguments(t *testing.T) {
	t.Parallel()

	organizationID := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	callerArguments := []any{"open", 7}
	destination := new(string)
	calls := 0
	queryer := &recordingQueryer{query: func(ctx context.Context, statement string, arguments []any, destinations ...any) error {
		calls++
		if ctx != context.Background() {
			t.Fatal("context was not forwarded exactly")
		}
		if statement != "SELECT status FROM findings WHERE organization_id = $1 AND status = $2 AND priority = $3" {
			t.Fatalf("statement = %q", statement)
		}
		wantArguments := []any{"pid_10000000-0000-4000-8000-000000000001", "open", 7}
		if !reflect.DeepEqual(arguments, wantArguments) {
			t.Fatalf("arguments = %#v, want %#v", arguments, wantArguments)
		}
		if len(destinations) != 1 || destinations[0] != destination {
			t.Fatalf("destinations = %#v, want exact destination", destinations)
		}
		arguments[1] = "mutated"
		*destination = "open"
		return nil
	}}

	guard, err := New(queryer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := guard.QueryRow(
		context.Background(),
		organizationID,
		"SELECT status FROM findings WHERE organization_id = $1 AND status = $2 AND priority = $3",
		callerArguments,
		destination,
	); err != nil {
		t.Fatalf("QueryRow() error = %v", err)
	}
	if calls != 1 || *destination != "open" {
		t.Fatalf("calls = %d, destination = %q", calls, *destination)
	}
	if !reflect.DeepEqual(callerArguments, []any{"open", 7}) {
		t.Fatalf("caller arguments mutated: %#v", callerArguments)
	}
}

func TestNewRejectsNilAndTypedNilQueryers(t *testing.T) {
	t.Parallel()

	if guard, err := New(nil); guard != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New(nil) = %#v, %v, want nil configuration error", guard, err)
	}
	var typedNil *recordingQueryer
	if guard, err := New(typedNil); guard != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New(typed nil) = %#v, %v, want nil configuration error", guard, err)
	}
}

func TestGuardRejectsMissingScopeAndInvalidRequestsBeforeExecution(t *testing.T) {
	t.Parallel()

	validOrganization := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	validStatement := "SELECT id FROM findings WHERE organization_id = $1"
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	invalidUTF8 := string([]byte{0xff})
	oversized := strings.Repeat("x", 64*1024+1)
	tests := []struct {
		name         string
		ctx          context.Context
		organization domain.ProductID
		statement    string
		destinations []any
	}{
		{name: "nil context", organization: validOrganization, statement: validStatement, destinations: []any{new(string)}},
		{name: "canceled context", ctx: canceled, organization: validOrganization, statement: validStatement, destinations: []any{new(string)}},
		{name: "missing organization", ctx: context.Background(), statement: validStatement, destinations: []any{new(string)}},
		{name: "empty statement", ctx: context.Background(), organization: validOrganization, destinations: []any{new(string)}},
		{name: "whitespace statement", ctx: context.Background(), organization: validOrganization, statement: " SELECT 1", destinations: []any{new(string)}},
		{name: "nul statement", ctx: context.Background(), organization: validOrganization, statement: "SELECT\x00 1", destinations: []any{new(string)}},
		{name: "invalid utf8", ctx: context.Background(), organization: validOrganization, statement: invalidUTF8, destinations: []any{new(string)}},
		{name: "oversized statement", ctx: context.Background(), organization: validOrganization, statement: oversized, destinations: []any{new(string)}},
		{name: "missing destination", ctx: context.Background(), organization: validOrganization, statement: validStatement},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			guard, err := New(&recordingQueryer{query: func(context.Context, string, []any, ...any) error {
				calls.Add(1)
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			err = guard.QueryRow(test.ctx, test.organization, test.statement, []any{"fixture-secret"}, test.destinations...)
			if !errors.Is(err, ErrQuery) || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatalf("QueryRow() error = %q, want fixed query error", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("queryer calls = %d, want zero", calls.Load())
			}
		})
	}
}

func TestGuardContainsDownstreamErrorsAndPanics(t *testing.T) {
	t.Parallel()

	const secret = "downstream-secret-must-not-escape"
	organizationID := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	tests := []struct {
		name  string
		query func(context.Context, string, []any, ...any) error
	}{
		{name: "error", query: func(context.Context, string, []any, ...any) error { return errors.New(secret) }},
		{name: "panic", query: func(context.Context, string, []any, ...any) error { panic(secret) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard, err := New(&recordingQueryer{query: test.query})
			if err != nil {
				t.Fatal(err)
			}
			err = guard.QueryRow(
				context.Background(),
				organizationID,
				"SELECT id FROM findings WHERE organization_id = $1",
				nil,
				new(string),
			)
			if !errors.Is(err, ErrQuery) || strings.Contains(err.Error(), secret) {
				t.Fatalf("QueryRow() error = %q, want fixed query error", err)
			}
		})
	}
}

func TestZeroGuardFailsClosedWithoutPanic(t *testing.T) {
	t.Parallel()

	var guard Guard
	organizationID := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	if err := guard.QueryRow(
		context.Background(),
		organizationID,
		"SELECT id FROM findings WHERE organization_id = $1",
		nil,
		new(string),
	); !errors.Is(err, ErrQuery) {
		t.Fatalf("zero Guard.QueryRow() error = %v, want query error", err)
	}
}

func TestGuardSeparatesConcurrentOrganizationArguments(t *testing.T) {
	t.Parallel()

	first := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	second := mustProductID(t, "pid_20000000-0000-4000-8000-000000000002")
	counts := map[string]int{}
	var mu sync.Mutex
	guard, err := New(&recordingQueryer{query: func(_ context.Context, _ string, arguments []any, _ ...any) error {
		organization, ok := arguments[0].(string)
		if !ok {
			t.Errorf("organization argument type = %T", arguments[0])
			return nil
		}
		mu.Lock()
		counts[organization]++
		mu.Unlock()
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for index := range 40 {
		organization := first
		if index%2 == 1 {
			organization = second
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := guard.QueryRow(
				context.Background(),
				organization,
				"SELECT id FROM findings WHERE organization_id = $1",
				nil,
				new(string),
			); err != nil {
				t.Errorf("QueryRow() error = %v", err)
			}
		}()
	}
	wait.Wait()

	mu.Lock()
	defer mu.Unlock()
	if counts[first.String()] != 20 || counts[second.String()] != 20 || len(counts) != 2 {
		t.Fatalf("organization counts = %#v, want exact independent calls", counts)
	}
}

func mustProductID(t *testing.T, text string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q): %v", text, err)
	}
	return id
}

var _ Queryer = (*database.Pool)(nil)
