package sqsdriver

import "errors"

type ErrorClass string

const (
	ErrorClassNone           ErrorClass = ""
	ErrorClassConfiguration  ErrorClass = "configuration"
	ErrorClassInput          ErrorClass = "input"
	ErrorClassCanceled       ErrorClass = "canceled"
	ErrorClassDraining       ErrorClass = "draining"
	ErrorClassRetryable      ErrorClass = "retryable"
	ErrorClassRejected       ErrorClass = "rejected"
	ErrorClassUnknownOutcome ErrorClass = "unknown_outcome"
)

type Disposition string

const (
	DispositionRetry      Disposition = "retry"
	DispositionDeadLetter Disposition = "dead_letter"
	DispositionReconcile  Disposition = "reconcile"
)

var (
	ErrCanceled       = errors.New("sqs driver operation canceled")
	ErrDraining       = errors.New("sqs driver is draining")
	ErrRetryable      = errors.New("sqs driver operation retryable")
	ErrRejected       = errors.New("sqs driver operation rejected")
	ErrUnknownOutcome = errors.New("sqs driver operation outcome unknown")
)

type EntryFailure struct {
	EntryID     string
	Disposition Disposition
}

type batchError struct {
	cause    error
	failures []EntryFailure
}

func (failure *batchError) Error() string {
	if failure == nil || failure.cause == nil {
		return ErrUnknownOutcome.Error()
	}
	return failure.cause.Error()
}

func (failure *batchError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func ErrorClassOf(err error) ErrorClass {
	switch {
	case err == nil:
		return ErrorClassNone
	case errors.Is(err, ErrConfiguration):
		return ErrorClassConfiguration
	case errors.Is(err, ErrInput):
		return ErrorClassInput
	case errors.Is(err, ErrCanceled):
		return ErrorClassCanceled
	case errors.Is(err, ErrDraining):
		return ErrorClassDraining
	case errors.Is(err, ErrRetryable):
		return ErrorClassRetryable
	case errors.Is(err, ErrRejected):
		return ErrorClassRejected
	case errors.Is(err, ErrUnknownOutcome):
		return ErrorClassUnknownOutcome
	default:
		return ErrorClassUnknownOutcome
	}
}

func EntryFailures(err error) []EntryFailure {
	var failure *batchError
	if !errors.As(err, &failure) || failure == nil {
		return nil
	}
	return append([]EntryFailure(nil), failure.failures...)
}

func newBatchError(cause error, failures []EntryFailure) error {
	return &batchError{cause: cause, failures: append([]EntryFailure(nil), failures...)}
}
