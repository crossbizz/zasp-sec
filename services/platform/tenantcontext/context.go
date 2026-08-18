package tenantcontext

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	setOrganizationSQL = "SELECT set_config('app.current_organization_id', $1, true)"
	rollbackTimeout    = 5 * time.Second
)

var (
	ErrConfiguration  = errors.New("tenant context configuration rejected")
	ErrInvalidRequest = errors.New("tenant context request rejected")
	ErrTransaction    = errors.New("tenant context transaction rejected")
	ErrOperation      = errors.New("tenant context operation rejected")
)

type Database interface {
	Begin(context.Context) (Transaction, error)
}

type Transaction interface {
	Exec(context.Context, string, ...any) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type Operation func(context.Context, Transaction) error

type Runner struct {
	database Database
}

func New(database Database) (*Runner, error) {
	if nilInterface(database) {
		return nil, ErrConfiguration
	}
	return &Runner{database: database}, nil
}

func (runner *Runner) Within(ctx context.Context, scope domain.Scope, operation Operation) (resultErr error) {
	if runner == nil || nilInterface(runner.database) || ctx == nil || ctx.Err() != nil ||
		scope.Validate() != nil || operation == nil {
		return ErrInvalidRequest
	}

	transaction, err := begin(runner.database, ctx)
	if nilInterface(transaction) || err != nil {
		if !nilInterface(transaction) {
			_ = rollback(ctx, transaction)
		}
		return ErrTransaction
	}
	committed := false
	defer func() {
		if !committed && rollback(ctx, transaction) != nil {
			resultErr = ErrTransaction
		}
	}()

	if err := execute(transaction, ctx, scope.OrganizationID().String()); err != nil || ctx.Err() != nil {
		return ErrTransaction
	}
	if err := runOperation(operation, ctx, transaction); err != nil || ctx.Err() != nil {
		return ErrOperation
	}
	if err := commit(transaction, ctx); err != nil || ctx.Err() != nil {
		return ErrTransaction
	}
	committed = true
	return nil
}

func begin(database Database, ctx context.Context) (transaction Transaction, resultErr error) {
	defer func() {
		if recover() != nil {
			transaction = nil
			resultErr = ErrTransaction
		}
	}()
	return database.Begin(ctx)
}

func execute(transaction Transaction, ctx context.Context, organization string) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrTransaction
		}
	}()
	return transaction.Exec(ctx, setOrganizationSQL, organization)
}

func runOperation(operation Operation, ctx context.Context, transaction Transaction) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrOperation
		}
	}()
	if err := operation(ctx, transaction); err != nil {
		return ErrOperation
	}
	return nil
}

func commit(transaction Transaction, ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrTransaction
		}
	}()
	return transaction.Commit(ctx)
}

func rollback(ctx context.Context, transaction Transaction) (resultErr error) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			resultErr = ErrTransaction
		}
	}()
	return transaction.Rollback(rollbackCtx)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
