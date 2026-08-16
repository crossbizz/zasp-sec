package externalclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type transientError struct{}

func (transientError) Error() string   { return "transient fixture" }
func (transientError) Timeout() bool   { return true }
func (transientError) Temporary() bool { return true }

type permanentError struct{}

func (permanentError) Error() string { return "permanent fixture" }

type trackingBody struct {
	reader io.Reader
	closed atomic.Bool
}

type failingCloseBody struct{}

func (failingCloseBody) Read([]byte) (int, error) { return 0, io.EOF }
func (failingCloseBody) Close() error             { return errors.New("close fixture") }

func newTrackingBody(value string) *trackingBody {
	return &trackingBody{reader: strings.NewReader(value)}
}

func (body *trackingBody) Read(destination []byte) (int, error) {
	return body.reader.Read(destination)
}

func (body *trackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

func testPolicy(t *testing.T, timeout time.Duration, maxAttempts int, concurrency int) Policy {
	t.Helper()
	policy, err := NewPolicy(timeout, maxAttempts, time.Millisecond, 8*time.Millisecond, concurrency)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func response(status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Body: body}
}

func TestPolicyValidationAndAccessors(t *testing.T) {
	policy := testPolicy(t, 2*time.Second, 4, 7)
	if policy.Timeout() != 2*time.Second || policy.MaxAttempts() != 4 || policy.BaseBackoff() != time.Millisecond || policy.MaxBackoff() != 8*time.Millisecond || policy.MaxConcurrent() != 7 {
		t.Fatalf("unexpected policy accessors: %#v", policy)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []struct {
		name        string
		timeout     time.Duration
		attempts    int
		base        time.Duration
		maximum     time.Duration
		concurrency int
	}{
		{name: "zero timeout", timeout: 0, attempts: 2, base: time.Millisecond, maximum: time.Second, concurrency: 1},
		{name: "excess timeout", timeout: 2*time.Minute + time.Nanosecond, attempts: 2, base: time.Millisecond, maximum: time.Second, concurrency: 1},
		{name: "zero attempts", timeout: time.Second, attempts: 0, base: time.Millisecond, maximum: time.Second, concurrency: 1},
		{name: "excess attempts", timeout: time.Second, attempts: 6, base: time.Millisecond, maximum: time.Second, concurrency: 1},
		{name: "zero base", timeout: time.Second, attempts: 2, base: 0, maximum: time.Second, concurrency: 1},
		{name: "maximum below base", timeout: time.Second, attempts: 2, base: time.Second, maximum: time.Millisecond, concurrency: 1},
		{name: "excess maximum", timeout: time.Second, attempts: 2, base: time.Millisecond, maximum: 30*time.Second + time.Nanosecond, concurrency: 1},
		{name: "zero concurrency", timeout: time.Second, attempts: 2, base: time.Millisecond, maximum: time.Second, concurrency: 0},
		{name: "excess concurrency", timeout: time.Second, attempts: 2, base: time.Millisecond, maximum: time.Second, concurrency: 1025},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPolicy(test.timeout, test.attempts, test.base, test.maximum, test.concurrency); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("NewPolicy() error = %v", err)
			}
		})
	}

	invalid := policy
	invalid.maxAttempts = 0
	if err := invalid.Validate(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid Validate() error = %v", err)
	}
	if err := (Policy{}).Validate(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("zero Validate() error = %v", err)
	}
}

func TestPolicyIsComparable(t *testing.T) {
	first := testPolicy(t, time.Second, 2, 3)
	second := testPolicy(t, time.Second, 2, 3)
	if first != second {
		t.Fatalf("equal policies differ: %#v %#v", first, second)
	}
	set := map[Policy]struct{}{first: {}}
	if _, present := set[second]; !present {
		t.Fatal("policy is not usable as a comparable key")
	}
}

func TestExecutorRetriesTransientStatusesOnly(t *testing.T) {
	transientStatuses := []int{http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}
	for _, status := range transientStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			executor, err := NewExecutor(testPolicy(t, time.Second, 3, 1))
			if err != nil {
				t.Fatalf("NewExecutor() error = %v", err)
			}
			executor.wait = func(context.Context, time.Duration) error { return nil }
			executor.jitter = func(maximum time.Duration) time.Duration { return maximum }
			firstBody := newTrackingBody("retry")
			calls := 0
			final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
				calls++
				if calls == 1 {
					return response(status, firstBody), nil
				}
				return response(http.StatusOK, newTrackingBody("ok")), nil
			})
			if err != nil || calls != 2 || final.StatusCode != http.StatusOK {
				t.Fatalf("Do() = (%v, %v), calls = %d", final, err, calls)
			}
			if !firstBody.closed.Load() {
				t.Fatal("intermediate response body was not closed")
			}
			if final.Body.(*trackingBody).closed.Load() {
				t.Fatal("final response body was closed")
			}
		})
	}

	permanentStatuses := []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusNotImplemented}
	for _, status := range permanentStatuses {
		t.Run("permanent "+http.StatusText(status), func(t *testing.T) {
			executor, _ := NewExecutor(testPolicy(t, time.Second, 3, 1))
			calls := 0
			body := newTrackingBody("caller-owned")
			final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
				calls++
				return response(status, body), nil
			})
			if err != nil || calls != 1 || final.StatusCode != status || body.closed.Load() {
				t.Fatalf("Do() = (%v, %v), calls = %d, closed = %v", final, err, calls, body.closed.Load())
			}
		})
	}
}

func TestExecutorRetriesTransientErrorsOnly(t *testing.T) {
	tests := []struct {
		name      string
		first     error
		wantCalls int
	}{
		{name: "network timeout", first: transientError{}, wantCalls: 2},
		{name: "EOF", first: io.EOF, wantCalls: 2},
		{name: "unexpected EOF", first: io.ErrUnexpectedEOF, wantCalls: 2},
		{name: "connection reset", first: syscall.ECONNRESET, wantCalls: 2},
		{name: "connection refused", first: syscall.ECONNREFUSED, wantCalls: 2},
		{name: "permanent", first: permanentError{}, wantCalls: 1},
		{name: "context canceled", first: context.Canceled, wantCalls: 1},
		{name: "context deadline", first: context.DeadlineExceeded, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, _ := NewExecutor(testPolicy(t, time.Second, 3, 1))
			executor.wait = func(context.Context, time.Duration) error { return nil }
			calls := 0
			final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
				calls++
				if calls == 1 {
					return nil, test.first
				}
				return response(http.StatusNoContent, newTrackingBody("")), nil
			})
			if calls != test.wantCalls {
				t.Fatalf("calls = %d, want %d", calls, test.wantCalls)
			}
			if test.wantCalls == 2 && (err != nil || final.StatusCode != http.StatusNoContent) {
				t.Fatalf("Do() = (%v, %v)", final, err)
			}
			if test.wantCalls == 1 && !errors.Is(err, test.first) {
				t.Fatalf("Do() error = %v, want %v", err, test.first)
			}
		})
	}
}

func TestExecutorRequestKindsAndAttemptLimit(t *testing.T) {
	tests := []struct {
		name      string
		kind      RequestKind
		wantCalls int
	}{
		{name: "read only", kind: ReadOnly, wantCalls: 3},
		{name: "idempotent mutation", kind: IdempotentMutation, wantCalls: 3},
		{name: "non-idempotent mutation", kind: NonIdempotentMutation, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, _ := NewExecutor(testPolicy(t, time.Second, 3, 1))
			executor.wait = func(context.Context, time.Duration) error { return nil }
			calls := 0
			final, err := executor.Do(context.Background(), test.kind, func(context.Context) (*http.Response, error) {
				calls++
				return response(http.StatusServiceUnavailable, newTrackingBody("retry")), nil
			})
			if err != nil || calls != test.wantCalls || final.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("Do() = (%v, %v), calls = %d", final, err, calls)
			}
			if final.Body.(*trackingBody).closed.Load() {
				t.Fatal("final attempt body was closed")
			}
		})
	}
}

func TestExecutorBackoffIsCappedAndContextAware(t *testing.T) {
	policy, err := NewPolicy(time.Second, 5, 2*time.Millisecond, 5*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	executor, _ := NewExecutor(policy)
	executor.jitter = func(maximum time.Duration) time.Duration { return maximum }
	var waits []time.Duration
	executor.wait = func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		return nil
	}
	calls := 0
	final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		calls++
		return response(http.StatusTooManyRequests, newTrackingBody("retry")), nil
	})
	if err != nil || calls != 5 || final.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Do() = (%v, %v), calls = %d", final, err, calls)
	}
	want := []time.Duration{2 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond, 5 * time.Millisecond}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for index := range want {
		if waits[index] != want[index] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}

	executor.wait = func(context.Context, time.Duration) error { return context.DeadlineExceeded }
	calls = 0
	final, err = executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		calls++
		return response(http.StatusServiceUnavailable, newTrackingBody("retry")), nil
	})
	if final != nil || !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("Do(wait failure) = (%v, %v), calls = %d", final, err, calls)
	}
}

func TestExecutorEnforcesTotalAndCallerDeadline(t *testing.T) {
	executor, _ := NewExecutor(testPolicy(t, 35*time.Millisecond, 3, 1))
	start := time.Now()
	final, err := executor.Do(context.Background(), ReadOnly, func(callContext context.Context) (*http.Response, error) {
		deadline, present := callContext.Deadline()
		if !present || time.Until(deadline) > 35*time.Millisecond {
			t.Fatalf("operation deadline = %v, present = %v", deadline, present)
		}
		<-callContext.Done()
		return nil, callContext.Err()
	})
	if final != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Do() = (%v, %v)", final, err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("elapsed = %v", elapsed)
	}

	caller, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = executor.Do(caller, ReadOnly, func(callContext context.Context) (*http.Response, error) {
		<-callContext.Done()
		return nil, callContext.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 150*time.Millisecond {
		t.Fatalf("caller deadline error = %v, elapsed = %v", err, time.Since(start))
	}
}

func TestExecutorBoundsConcurrencyAndSlotWait(t *testing.T) {
	executor, _ := NewExecutor(testPolicy(t, time.Second, 1, 2))
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	var active atomic.Int32
	var maximum atomic.Int32
	var waitGroup sync.WaitGroup
	for index := 0; index < 4; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
				current := active.Add(1)
				for {
					prior := maximum.Load()
					if current <= prior || maximum.CompareAndSwap(prior, current) {
						break
					}
				}
				started <- struct{}{}
				<-release
				active.Add(-1)
				return response(http.StatusOK, newTrackingBody("ok")), nil
			})
			if err != nil {
				t.Errorf("Do() error = %v", err)
			}
		}()
	}
	<-started
	<-started
	select {
	case <-started:
		t.Fatal("third operation started before a slot was released")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	waitGroup.Wait()
	if maximum.Load() != 2 {
		t.Fatalf("maximum concurrency = %d", maximum.Load())
	}

	blocking, _ := NewExecutor(testPolicy(t, time.Second, 1, 1))
	hold := make(chan struct{})
	occupied := make(chan struct{})
	go func() {
		_, _ = blocking.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
			close(occupied)
			<-hold
			return response(http.StatusOK, newTrackingBody("ok")), nil
		})
	}()
	<-occupied
	caller, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	invoked := false
	_, err := blocking.Do(caller, ReadOnly, func(context.Context) (*http.Response, error) {
		invoked = true
		return response(http.StatusOK, newTrackingBody("ok")), nil
	})
	close(hold)
	if !errors.Is(err, context.DeadlineExceeded) || invoked {
		t.Fatalf("slot wait error = %v, invoked = %v", err, invoked)
	}
}

func TestExecutorRejectsInvalidInputsAndMalformedResults(t *testing.T) {
	policy := testPolicy(t, time.Second, 2, 1)
	if _, err := NewExecutor(Policy{}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("NewExecutor(invalid) error = %v", err)
	}
	executor, _ := NewExecutor(policy)
	if _, err := executor.Do(nil, ReadOnly, func(context.Context) (*http.Response, error) { return nil, nil }); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Do(nil context) error = %v", err)
	}
	if _, err := executor.Do(context.Background(), RequestKind(99), func(context.Context) (*http.Response, error) { return nil, nil }); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Do(invalid kind) error = %v", err)
	}
	if _, err := executor.Do(context.Background(), ReadOnly, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Do(nil operation) error = %v", err)
	}
	if _, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) { return nil, nil }); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("Do(malformed result) error = %v", err)
	}
	if _, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	}); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("Do(nil body) error = %v", err)
	}
	for _, status := range []int{99, 600} {
		body := newTrackingBody("invalid")
		if _, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
			return response(status, body), nil
		}); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("Do(status %d) error = %v", status, err)
		}
		if !body.closed.Load() {
			t.Fatalf("malformed status %d body was not closed", status)
		}
	}
	var nilExecutor *Executor
	if _, err := nilExecutor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) { return nil, nil }); !errors.Is(err, ErrInvalidExecutor) {
		t.Fatalf("nil executor error = %v", err)
	}
	zero := &Executor{}
	if _, err := zero.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) { return nil, nil }); !errors.Is(err, ErrInvalidExecutor) {
		t.Fatalf("zero executor error = %v", err)
	}
}

func TestExecutorStopsWhenResponseCloseFails(t *testing.T) {
	executor, _ := NewExecutor(testPolicy(t, time.Second, 3, 1))
	executor.wait = func(context.Context, time.Duration) error { return nil }
	calls := 0
	final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		calls++
		return response(http.StatusServiceUnavailable, failingCloseBody{}), nil
	})
	if final != nil || !errors.Is(err, ErrResponseClose) || calls != 1 {
		t.Fatalf("Do() = (%v, %v), calls = %d", final, err, calls)
	}

	final, err = executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		return response(http.StatusBadGateway, failingCloseBody{}), permanentError{}
	})
	if final != nil || !errors.Is(err, ErrResponseClose) {
		t.Fatalf("Do(response and error) = (%v, %v)", final, err)
	}
}

func TestExecutorClosesResponseReturnedWithError(t *testing.T) {
	executor, _ := NewExecutor(testPolicy(t, time.Second, 2, 1))
	body := newTrackingBody("error")
	final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		return response(http.StatusBadGateway, body), permanentError{}
	})
	if final != nil || !errors.As(err, new(permanentError)) || !body.closed.Load() {
		t.Fatalf("Do() = (%v, %v), closed = %v", final, err, body.closed.Load())
	}
}

func TestExecutorReleasesSlotAfterPanic(t *testing.T) {
	executor, _ := NewExecutor(testPolicy(t, 100*time.Millisecond, 1, 1))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("operation panic was not propagated")
			}
		}()
		_, _ = executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
			panic("fixture panic")
		})
	}()

	final, err := executor.Do(context.Background(), ReadOnly, func(context.Context) (*http.Response, error) {
		return response(http.StatusOK, newTrackingBody("ok")), nil
	})
	if err != nil || final.StatusCode != http.StatusOK {
		t.Fatalf("Do(after panic) = (%v, %v)", final, err)
	}
}
