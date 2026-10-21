package main

import (
	"context"
	"reflect"

	"github.com/jackc/pgx/v5"
)

// Production selects only the actual connection already held by this runner.
// Explicit recorder implementations of this private capability live in _test.go;
// generic BeginTx providers and independent connection factories are not admitted.
type principalAuthorityTestRecorder interface {
	beginPrincipalAuthorityTransaction(context.Context) (retentionOperatorTransaction, error)
}

func principalAuthorityTransactionBegin(q principalQueryer) func(context.Context) (retentionOperatorTransaction, error) {
	if q == nil {
		return nil
	}
	value := reflect.ValueOf(q)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil
		}
	}
	if connection, ok := q.(*pgx.Conn); ok {
		return func(ctx context.Context) (retentionOperatorTransaction, error) {
			return connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		}
	}
	if recorder, ok := q.(principalAuthorityTestRecorder); ok {
		return recorder.beginPrincipalAuthorityTransaction
	}
	return nil
}
