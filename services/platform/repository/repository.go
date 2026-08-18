package repository

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumStatementBytes = 64 * 1024

var (
	ErrConfiguration = errors.New("repository configuration rejected")
	ErrQuery         = errors.New("repository query rejected")
)

type Queryer interface {
	QueryRow(context.Context, string, []any, ...any) error
}

type Guard struct {
	queryer Queryer
}

func New(queryer Queryer) (*Guard, error) {
	if nilInterface(queryer) {
		return nil, ErrConfiguration
	}
	return &Guard{queryer: queryer}, nil
}

func (guard *Guard) QueryRow(
	ctx context.Context,
	organizationID domain.ProductID,
	statement string,
	arguments []any,
	destinations ...any,
) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrQuery
		}
	}()
	if guard == nil || nilInterface(guard.queryer) || ctx == nil || ctx.Err() != nil ||
		!validOrganizationID(organizationID) || !validStatement(statement) || len(destinations) == 0 {
		return ErrQuery
	}
	scopedArguments := make([]any, 1, len(arguments)+1)
	scopedArguments[0] = organizationID.String()
	scopedArguments = append(scopedArguments, arguments...)
	if err := guard.queryer.QueryRow(ctx, statement, scopedArguments, destinations...); err != nil || ctx.Err() != nil {
		return ErrQuery
	}
	return nil
}

func validOrganizationID(organizationID domain.ProductID) bool {
	text := organizationID.String()
	parsed, err := domain.ParseProductID(text)
	return err == nil && parsed == organizationID
}

func validStatement(statement string) bool {
	return len(statement) > 0 && len(statement) <= maximumStatementBytes &&
		utf8.ValidString(statement) && strings.TrimSpace(statement) == statement &&
		!strings.ContainsRune(statement, '\x00')
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
