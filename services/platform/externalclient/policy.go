package externalclient

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"syscall"
	"time"
)

const (
	maximumTimeout     = 2 * time.Minute
	maximumAttempts    = 5
	maximumBackoff     = 30 * time.Second
	maximumConcurrency = 1024
)

var (
	ErrInvalidPolicy   = errors.New("invalid external client policy")
	ErrInvalidExecutor = errors.New("invalid external client executor")
	ErrInvalidRequest  = errors.New("invalid external client request")
	ErrInvalidResult   = errors.New("invalid external client result")
	ErrResponseClose   = errors.New("external client response close failed")
)

type Policy struct {
	timeout       time.Duration
	maxAttempts   int
	baseBackoff   time.Duration
	maxBackoff    time.Duration
	maxConcurrent int
}

func NewPolicy(timeout time.Duration, maxAttempts int, baseBackoff time.Duration, maxBackoff time.Duration, maxConcurrent int) (Policy, error) {
	policy := Policy{
		timeout:       timeout,
		maxAttempts:   maxAttempts,
		baseBackoff:   baseBackoff,
		maxBackoff:    maxBackoff,
		maxConcurrent: maxConcurrent,
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func (policy Policy) Timeout() time.Duration {
	if !policy.valid() {
		return 0
	}
	return policy.timeout
}

func (policy Policy) MaxAttempts() int {
	if !policy.valid() {
		return 0
	}
	return policy.maxAttempts
}

func (policy Policy) BaseBackoff() time.Duration {
	if !policy.valid() {
		return 0
	}
	return policy.baseBackoff
}

func (policy Policy) MaxBackoff() time.Duration {
	if !policy.valid() {
		return 0
	}
	return policy.maxBackoff
}

func (policy Policy) MaxConcurrent() int {
	if !policy.valid() {
		return 0
	}
	return policy.maxConcurrent
}

func (policy Policy) Validate() error {
	if !policy.valid() {
		return ErrInvalidPolicy
	}
	return nil
}

func (policy Policy) valid() bool {
	return policy.timeout > 0 && policy.timeout <= maximumTimeout &&
		policy.maxAttempts > 0 && policy.maxAttempts <= maximumAttempts &&
		policy.baseBackoff > 0 && policy.baseBackoff <= policy.maxBackoff &&
		policy.maxBackoff <= maximumBackoff &&
		policy.maxConcurrent > 0 && policy.maxConcurrent <= maximumConcurrency
}

type RequestKind uint8

const (
	ReadOnly RequestKind = iota + 1
	IdempotentMutation
	NonIdempotentMutation
)

func (kind RequestKind) valid() bool {
	return kind == ReadOnly || kind == IdempotentMutation || kind == NonIdempotentMutation
}

type Operation func(context.Context) (*http.Response, error)

type Executor struct {
	policy Policy
	slots  chan struct{}
	wait   func(context.Context, time.Duration) error
	jitter func(time.Duration) time.Duration
}

func NewExecutor(policy Policy) (*Executor, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Executor{
		policy: policy,
		slots:  make(chan struct{}, policy.maxConcurrent),
		wait:   waitContext,
		jitter: fullJitter,
	}, nil
}

func (executor *Executor) Do(parent context.Context, kind RequestKind, operation Operation) (*http.Response, error) {
	if !executor.valid() {
		return nil, ErrInvalidExecutor
	}
	if parent == nil || !kind.valid() || operation == nil {
		return nil, ErrInvalidRequest
	}
	requestContext, cancel := context.WithTimeout(parent, executor.policy.timeout)
	defer cancel()
	if err := executor.acquire(requestContext); err != nil {
		return nil, err
	}
	defer executor.release()

	attemptLimit := executor.policy.maxAttempts
	if kind == NonIdempotentMutation {
		attemptLimit = 1
	}
	for attempt := 1; attempt <= attemptLimit; attempt++ {
		if err := requestContext.Err(); err != nil {
			return nil, err
		}
		response, operationError := operation(requestContext)
		if err := requestContext.Err(); err != nil {
			if closeError := closeResponse(response); closeError != nil {
				return nil, closeError
			}
			return nil, err
		}
		if operationError != nil {
			if closeError := closeResponse(response); closeError != nil {
				return nil, closeError
			}
			if attempt < attemptLimit && isTransientError(operationError) {
				if err := executor.waitBeforeRetry(requestContext, attempt); err != nil {
					return nil, err
				}
				continue
			}
			return nil, operationError
		}
		if !validResponse(response) {
			if closeError := closeResponse(response); closeError != nil {
				return nil, closeError
			}
			return nil, ErrInvalidResult
		}
		if attempt < attemptLimit && transientStatus(response.StatusCode) {
			if closeError := closeResponse(response); closeError != nil {
				return nil, closeError
			}
			if err := executor.waitBeforeRetry(requestContext, attempt); err != nil {
				return nil, err
			}
			continue
		}
		return response, nil
	}
	return nil, ErrInvalidResult
}

func (executor *Executor) valid() bool {
	return executor != nil && executor.policy.valid() && executor.slots != nil &&
		cap(executor.slots) == executor.policy.maxConcurrent && executor.wait != nil && executor.jitter != nil
}

func (executor *Executor) acquire(requestContext context.Context) error {
	if err := requestContext.Err(); err != nil {
		return err
	}
	select {
	case executor.slots <- struct{}{}:
		if err := requestContext.Err(); err != nil {
			executor.release()
			return err
		}
		return nil
	case <-requestContext.Done():
		return requestContext.Err()
	}
}

func (executor *Executor) release() {
	<-executor.slots
}

func (executor *Executor) waitBeforeRetry(requestContext context.Context, attempt int) error {
	maximum := executor.policy.baseBackoff
	for step := 1; step < attempt && maximum < executor.policy.maxBackoff; step++ {
		if maximum > executor.policy.maxBackoff/2 {
			maximum = executor.policy.maxBackoff
			break
		}
		maximum *= 2
	}
	if maximum > executor.policy.maxBackoff {
		maximum = executor.policy.maxBackoff
	}
	delay := executor.jitter(maximum)
	if delay < 0 {
		delay = 0
	}
	if delay > maximum {
		delay = maximum
	}
	return executor.wait(requestContext, delay)
}

func transientStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isTransientError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary()) {
		return true
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE)
}

func validResponse(response *http.Response) bool {
	return response != nil && response.Body != nil && response.StatusCode >= 100 && response.StatusCode <= 599
}

func closeResponse(response *http.Response) error {
	if response != nil && response.Body != nil {
		if err := response.Body.Close(); err != nil {
			return ErrResponseClose
		}
	}
	return nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func fullJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(maximum) + 1))
}
