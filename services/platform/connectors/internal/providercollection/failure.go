package providercollection

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

const maximumProviderRetryAfter = time.Hour

func StableProviderFailure(code collection.FailureCode) error {
	failure, err := collection.NewFailure(code, time.Time{})
	if err != nil {
		fallback, _ := collection.NewFailure(collection.FailureMalformed, time.Time{})
		return fallback
	}
	return failure
}

func ClassifyProviderError(ctx context.Context, cause error) error {
	var failure *collection.Failure
	if errors.As(cause, &failure) {
		return failure
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(cause, context.DeadlineExceeded) {
		return StableProviderFailure(collection.FailureRetryable)
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) || errors.Is(cause, context.Canceled) {
		return StableProviderFailure(collection.FailureCancelled)
	}
	return StableProviderFailure(collection.FailureRetryable)
}

func ClassifyProviderHTTPFailure(ctx context.Context, transport error, status int, retryAfter string, now time.Time) error {
	if transport != nil || ctx != nil && ctx.Err() != nil {
		return ClassifyProviderError(ctx, transport)
	}
	switch {
	case status == http.StatusTooManyRequests:
		retryAt, ok := parseProviderRetryAfter(retryAfter, now)
		if !ok {
			return StableProviderFailure(collection.FailureMalformed)
		}
		failure, _ := collection.NewFailure(collection.FailureRateLimited, retryAt)
		return failure
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return StableProviderFailure(collection.FailureDenied)
	case status >= 500 && status <= 599:
		return StableProviderFailure(collection.FailureRetryable)
	case status >= 400 && status <= 499:
		return StableProviderFailure(collection.FailureTerminal)
	default:
		return StableProviderFailure(collection.FailureMalformed)
	}
}

func parseProviderRetryAfter(value string, now time.Time) (time.Time, bool) {
	if now.IsZero() || now.Location() != time.UTC || value == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay < time.Second || delay > maximumProviderRetryAfter {
			return time.Time{}, false
		}
		return now.Add(delay), true
	}
	parsed, err := http.ParseTime(value)
	delay := parsed.Sub(now)
	if err != nil || delay < time.Second || delay > maximumProviderRetryAfter {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}
