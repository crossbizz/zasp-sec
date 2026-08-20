package providercollection

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

func TestClassifyProviderHTTPFailureUsesStableTypedTaxonomy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		ctx        context.Context
		transport  error
		status     int
		retryAfter string
		code       collection.FailureCode
		retryAt    time.Time
	}{
		"cancelled":    {ctx: cancelledProviderContext(), transport: context.Canceled, code: collection.FailureCancelled},
		"transport":    {ctx: context.Background(), transport: errors.New("provider detail"), code: collection.FailureRetryable},
		"rate limited": {ctx: context.Background(), status: http.StatusTooManyRequests, retryAfter: "17", code: collection.FailureRateLimited, retryAt: now.Add(17 * time.Second)},
		"denied":       {ctx: context.Background(), status: http.StatusForbidden, code: collection.FailureDenied},
		"server":       {ctx: context.Background(), status: http.StatusBadGateway, code: collection.FailureRetryable},
		"terminal":     {ctx: context.Background(), status: http.StatusNotFound, code: collection.FailureTerminal},
		"bad retry":    {ctx: context.Background(), status: http.StatusTooManyRequests, retryAfter: "0", code: collection.FailureMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			err := ClassifyProviderHTTPFailure(test.ctx, test.transport, test.status, test.retryAfter, now)
			var failure *collection.Failure
			if !errors.As(err, &failure) || failure.Code() != test.code || failure.RetryAt() != test.retryAt || err.Error() != "collection failed: "+string(test.code) {
				t.Fatalf("failure = %#v / %v, want %s at %s", failure, err, test.code, test.retryAt)
			}
		})
	}
}

func TestClassifyProviderErrorPreservesTypedFailure(t *testing.T) {
	t.Parallel()
	want, _ := collection.NewFailure(collection.FailureDenied, time.Time{})
	if got := ClassifyProviderError(context.Background(), want); got != want {
		t.Fatalf("failure identity = %p, want %p", got, want)
	}
	if err := StableProviderFailure(collection.FailureMalformed); err.Error() != "collection failed: malformed" {
		t.Fatalf("malformed failure = %v", err)
	}
}

func cancelledProviderContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
