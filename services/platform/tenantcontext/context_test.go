package tenantcontext

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestWithinSetsOrganizationOnlyForTransaction(t *testing.T) {
	transaction := &fakeTransaction{}
	database := &fakeDatabase{transactions: []*fakeTransaction{transaction}}
	runner, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureScope(t, 1)
	seen := ""
	err = runner.Within(context.Background(), scope, func(_ context.Context, current Transaction) error {
		if current != transaction {
			t.Fatal("callback transaction changed")
		}
		seen = transaction.organization
		if transaction.committed || transaction.rolledBack {
			t.Fatal("transaction completed before callback")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Within() error = %v", err)
	}
	if seen != scope.OrganizationID().String() || transaction.organization != "" || !transaction.committed || transaction.rolledBack {
		t.Fatalf("transaction state = seen %q organization %q committed %t rolledBack %t", seen, transaction.organization, transaction.committed, transaction.rolledBack)
	}
	wantEvents := []string{"begin", "set:" + scope.OrganizationID().String(), "work", "commit"}
	if fmt.Sprint(database.events) != fmt.Sprint(wantEvents) {
		t.Fatalf("events = %#v, want %#v", database.events, wantEvents)
	}
}

func TestWithinSeparatesOrganizationsAcrossTransactions(t *testing.T) {
	first := &fakeTransaction{}
	second := &fakeTransaction{}
	database := &fakeDatabase{transactions: []*fakeTransaction{first, second}}
	runner, err := New(database)
	if err != nil {
		t.Fatal(err)
	}

	var seen []string
	for _, scope := range []domain.Scope{fixtureScope(t, 1), fixtureScope(t, 4)} {
		if err := runner.Within(context.Background(), scope, func(_ context.Context, transaction Transaction) error {
			seen = append(seen, transaction.(*fakeTransaction).organization)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0] == seen[1] || first.organization != "" || second.organization != "" {
		t.Fatalf("scoped organizations = %#v; final = %q, %q", seen, first.organization, second.organization)
	}
}

func TestWithinRejectsInvalidInputBeforeBegin(t *testing.T) {
	database := &fakeDatabase{}
	runner, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, test := range map[string]struct {
		ctx       context.Context
		scope     domain.Scope
		operation Operation
	}{
		"nil context":      {scope: fixtureScope(t, 1), operation: func(context.Context, Transaction) error { return nil }},
		"canceled context": {ctx: canceled, scope: fixtureScope(t, 1), operation: func(context.Context, Transaction) error { return nil }},
		"zero scope":       {ctx: context.Background(), operation: func(context.Context, Transaction) error { return nil }},
		"nil operation":    {ctx: context.Background(), scope: fixtureScope(t, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runner.Within(test.ctx, test.scope, test.operation); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Within() error = %v, want invalid request", err)
			}
		})
	}
	if database.beginCalls != 0 {
		t.Fatalf("begin calls = %d, want 0", database.beginCalls)
	}
	if _, err := New(nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New(nil) error = %v", err)
	}
}

func TestWithinRollsBackOnFailuresAndPanic(t *testing.T) {
	for name, test := range map[string]struct {
		transaction *fakeTransaction
		operation   Operation
		want        error
	}{
		"set":       {transaction: &fakeTransaction{setErr: errors.New("secret")}, operation: func(context.Context, Transaction) error { return nil }, want: ErrTransaction},
		"operation": {transaction: &fakeTransaction{}, operation: func(context.Context, Transaction) error { return errors.New("secret") }, want: ErrOperation},
		"panic":     {transaction: &fakeTransaction{}, operation: func(context.Context, Transaction) error { panic("secret") }, want: ErrOperation},
		"commit":    {transaction: &fakeTransaction{commitErr: errors.New("secret")}, operation: func(context.Context, Transaction) error { return nil }, want: ErrTransaction},
	} {
		t.Run(name, func(t *testing.T) {
			database := &fakeDatabase{transactions: []*fakeTransaction{test.transaction}}
			runner, err := New(database)
			if err != nil {
				t.Fatal(err)
			}
			err = runner.Within(context.Background(), fixtureScope(t, 1), test.operation)
			if !errors.Is(err, test.want) || test.transaction.committed || !test.transaction.rolledBack || test.transaction.organization != "" {
				t.Fatalf("Within() = %v; committed=%t rolledBack=%t org=%q", err, test.transaction.committed, test.transaction.rolledBack, test.transaction.organization)
			}
		})
	}
}

type fakeDatabase struct {
	transactions []*fakeTransaction
	events       []string
	beginCalls   int
}

func (database *fakeDatabase) Begin(context.Context) (Transaction, error) {
	database.beginCalls++
	database.events = append(database.events, "begin")
	if len(database.transactions) == 0 {
		return nil, errors.New("no transaction")
	}
	transaction := database.transactions[0]
	database.transactions = database.transactions[1:]
	transaction.events = &database.events
	return transaction, nil
}

type fakeTransaction struct {
	events       *[]string
	organization string
	setErr       error
	commitErr    error
	committed    bool
	rolledBack   bool
}

func (transaction *fakeTransaction) Exec(_ context.Context, statement string, arguments ...any) error {
	if statement != setOrganizationSQL || len(arguments) != 1 {
		return errors.New("unexpected statement")
	}
	if transaction.setErr != nil {
		return transaction.setErr
	}
	organization, ok := arguments[0].(string)
	if !ok {
		return errors.New("unexpected organization")
	}
	transaction.organization = organization
	*transaction.events = append(*transaction.events, "set:"+organization, "work")
	return nil
}

func (transaction *fakeTransaction) Commit(context.Context) error {
	if transaction.commitErr != nil {
		return transaction.commitErr
	}
	transaction.committed = true
	transaction.organization = ""
	*transaction.events = append(*transaction.events, "commit")
	return nil
}

func (transaction *fakeTransaction) Rollback(context.Context) error {
	transaction.rolledBack = true
	transaction.organization = ""
	return nil
}

func fixtureScope(t *testing.T, offset int) domain.Scope {
	t.Helper()
	ids := make([]domain.ProductID, 3)
	for index := range ids {
		text := fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", offset+index, offset+index)
		parsed, err := domain.ParseProductID(text)
		if err != nil {
			t.Fatalf("ParseProductID(%q): %v", text, err)
		}
		ids[index] = parsed
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
