package idempotency

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationBytes = 63
	maximumKeyBytes       = 128
	maximumPayloadBytes   = 1 << 20
	maximumLeaseBytes     = 128
)

var (
	ErrInvalidRequest = errors.New("invalid idempotency request")
	ErrInvalidLease   = errors.New("invalid idempotency lease")
	ErrInvalidClaim   = errors.New("invalid idempotency claim")
	ErrInvalidStore   = errors.New("invalid idempotency store")
	ErrInvalidHelper  = errors.New("invalid idempotency helper")
	ErrInvalidResult  = errors.New("invalid idempotency result")
	ErrInProgress     = errors.New("idempotency request in progress")
	ErrKeyConflict    = errors.New("idempotency key conflict")
	ErrStore          = errors.New("idempotency store failed")
)

type Request struct {
	scope       domain.Scope
	operation   string
	key         string
	fingerprint [sha256.Size]byte
}

func NewRequest(scope domain.Scope, operation, key string, payload []byte) (Request, error) {
	request := Request{
		scope:       scope,
		operation:   operation,
		key:         key,
		fingerprint: sha256.Sum256(payload),
	}
	if len(payload) > maximumPayloadBytes || request.Validate() != nil {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

func (request Request) Validate() error {
	if request.scope.Validate() != nil || !validOperation(request.operation) ||
		!validOpaqueToken(request.key, maximumKeyBytes) || request.fingerprint == ([sha256.Size]byte{}) {
		return ErrInvalidRequest
	}
	return nil
}

func (request Request) Scope() domain.Scope {
	return request.scope
}

func (request Request) Operation() string {
	return request.operation
}

func (request Request) Key() string {
	return request.key
}

func (request Request) Fingerprint() [sha256.Size]byte {
	return request.fingerprint
}

func validOperation(value string) bool {
	if len(value) == 0 || len(value) > maximumOperationBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, part := range []byte(value) {
		if (part >= 'a' && part <= 'z') || (part >= '0' && part <= '9') || part == '.' || part == '_' || part == '-' {
			continue
		}
		return false
	}
	return true
}

func validOpaqueToken(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for _, part := range []byte(value) {
		if asciiAlphaNumeric(part) || part == '.' || part == '_' || part == ':' || part == '-' {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
}

type Lease struct {
	value string
}

func NewLease(value string) (Lease, error) {
	if !validOpaqueToken(value, maximumLeaseBytes) {
		return Lease{}, ErrInvalidLease
	}
	return Lease{value: value}, nil
}

func (lease Lease) String() string {
	return lease.value
}

func (lease Lease) valid() bool {
	return validOpaqueToken(lease.value, maximumLeaseBytes)
}

type ClaimState uint8

const (
	ClaimAcquired ClaimState = iota + 1
	ClaimInProgress
	ClaimCompleted
)

type Claim struct {
	state  ClaimState
	lease  Lease
	result domain.ProductID
}

func NewAcquiredClaim(lease Lease) (Claim, error) {
	claim := Claim{state: ClaimAcquired, lease: lease}
	if claim.Validate() != nil {
		return Claim{}, ErrInvalidClaim
	}
	return claim, nil
}

func NewInProgressClaim() Claim {
	return Claim{state: ClaimInProgress}
}

func NewCompletedClaim(result domain.ProductID) (Claim, error) {
	claim := Claim{state: ClaimCompleted, result: result}
	if claim.Validate() != nil {
		return Claim{}, ErrInvalidClaim
	}
	return claim, nil
}

func (claim Claim) Validate() error {
	switch claim.state {
	case ClaimAcquired:
		if !claim.lease.valid() || !claim.result.IsZero() {
			return ErrInvalidClaim
		}
	case ClaimInProgress:
		if claim.lease != (Lease{}) || !claim.result.IsZero() {
			return ErrInvalidClaim
		}
	case ClaimCompleted:
		if claim.lease != (Lease{}) || claim.result.IsZero() {
			return ErrInvalidClaim
		}
	default:
		return ErrInvalidClaim
	}
	return nil
}

func (claim Claim) State() ClaimState {
	return claim.state
}

func (claim Claim) Lease() Lease {
	return claim.lease
}

func (claim Claim) Result() domain.ProductID {
	return claim.result
}

// Store atomically indexes a claim by request scope and key. Claim must return
// ErrKeyConflict when an existing scoped key has another operation or
// fingerprint. Complete must require the exact acquired request and lease.
type Store interface {
	Claim(context.Context, Request) (Claim, error)
	Complete(context.Context, Request, Lease, domain.ProductID) error
}

type Operation func(context.Context) (domain.ProductID, error)

type Outcome struct {
	result domain.ProductID
	prior  bool
}

func (outcome Outcome) Result() domain.ProductID {
	return outcome.result
}

func (outcome Outcome) Prior() bool {
	return outcome.prior
}

type Helper struct {
	store Store
}

func NewHelper(store Store) (*Helper, error) {
	if nilInterface(store) {
		return nil, ErrInvalidStore
	}
	return &Helper{store: store}, nil
}

func (helper *Helper) Execute(ctx context.Context, request Request, operation Operation) (Outcome, error) {
	if helper == nil || nilInterface(helper.store) {
		return Outcome{}, ErrInvalidHelper
	}
	if ctx == nil || operation == nil || request.Validate() != nil {
		return Outcome{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Outcome{}, err
	}
	claim, err := helper.store.Claim(ctx, request)
	if err != nil {
		return Outcome{}, claimError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return Outcome{}, err
	}
	if claim.Validate() != nil {
		return Outcome{}, ErrInvalidClaim
	}
	switch claim.State() {
	case ClaimInProgress:
		return Outcome{}, ErrInProgress
	case ClaimCompleted:
		return Outcome{result: claim.Result(), prior: true}, nil
	case ClaimAcquired:
		result, operationError := operation(ctx)
		if operationError != nil {
			return Outcome{}, operationError
		}
		if err := ctx.Err(); err != nil {
			return Outcome{}, err
		}
		if result.IsZero() {
			return Outcome{}, ErrInvalidResult
		}
		if err := helper.store.Complete(ctx, request, claim.Lease(), result); err != nil {
			if contextError := ctx.Err(); contextError != nil {
				return Outcome{}, contextError
			}
			return Outcome{}, ErrStore
		}
		return Outcome{result: result}, nil
	default:
		return Outcome{}, ErrInvalidClaim
	}
}

func claimError(ctx context.Context, err error) error {
	if contextError := ctx.Err(); contextError != nil {
		return contextError
	}
	if errors.Is(err, ErrKeyConflict) {
		return ErrKeyConflict
	}
	return ErrStore
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
