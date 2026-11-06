package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
)

// Observes only an actual failed LoadDelivery call and its existing native
// reservation boundary. It never queries a source or prints identity/evidence.
func approvalActivationFailureObservation(ctx context.Context, reservation approvalmaintenance.Reservation, cause error, runMatches bool) string {
	now := time.Now()
	var parentErr error
	if ctx != nil {
		parentErr = ctx.Err()
	}
	parentLive := ctx != nil && parentErr == nil
	leaseLive := reservation.ExpiresAt.After(now)
	marginLive := reservation.ExpiresAt.Add(-2 * time.Second).After(now)
	outcome := "other-error"
	switch {
	case errors.Is(parentErr, context.DeadlineExceeded):
		outcome = "context-deadline"
	case errors.Is(parentErr, context.Canceled):
		outcome = "context-canceled"
	case !parentLive:
		outcome = "other-error"
	case !marginLive:
		outcome = "lease-margin"
	case errors.Is(cause, approvalmaintenance.ErrDenied):
		outcome = "denied"
	case errors.Is(cause, approvalmaintenance.ErrUnavailable):
		outcome = "unavailable"
	case cause == nil && !runMatches:
		outcome = "run-mismatch"
	}
	return fmt.Sprintf("approval payload observation stage=payload-load outcome=%s parent_live=%t lease_live=%t provider_live=%t", outcome, parentLive, leaseLive, parentLive && marginLive)
}

func TestApprovalActivationFailureObservationBoundaries(t *testing.T) {
	reservation := approvalmaintenance.Reservation{Reference: "private-reference-never-printed", ExpiresAt: time.Now().Add(time.Hour)}
	for _, tc := range []struct {
		name    string
		err     error
		matches bool
		outcome string
	}{
		{"wrapped-denial", fmt.Errorf("private error detail: %w", approvalmaintenance.ErrDenied), false, "denied"},
		{"wrapped-unavailable", fmt.Errorf("private error detail: %w", approvalmaintenance.ErrUnavailable), false, "unavailable"},
		{"other", errors.New("private error detail"), false, "other-error"},
		{"mismatched-run", nil, false, "run-mismatch"},
		{"not-a-failure", nil, true, "other-error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := approvalActivationFailureObservation(context.Background(), reservation, tc.err, tc.matches)
			want := "approval payload observation stage=payload-load outcome=" + tc.outcome + " parent_live=true lease_live=true provider_live=true"
			if got != want || strings.Contains(got, "private") {
				t.Fatal("closed actual failure observation changed")
			}
		})
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	if got := approvalActivationFailureObservation(expired, reservation, approvalmaintenance.ErrDenied, false); got != "approval payload observation stage=payload-load outcome=context-deadline parent_live=false lease_live=true provider_live=false" {
		t.Fatal("actual parent deadline must take precedence")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if got := approvalActivationFailureObservation(canceled, reservation, approvalmaintenance.ErrDenied, false); got != "approval payload observation stage=payload-load outcome=context-canceled parent_live=false lease_live=true provider_live=false" {
		t.Fatal("actual parent cancellation must take precedence")
	}
	margin := reservation
	margin.ExpiresAt = time.Now().Add(2 * time.Second)
	if got := approvalActivationFailureObservation(context.Background(), margin, approvalmaintenance.ErrDenied, false); got != "approval payload observation stage=payload-load outcome=lease-margin parent_live=true lease_live=true provider_live=false" {
		t.Fatal("native provider margin must take precedence")
	}
	margin.ExpiresAt = time.Now().Add(-time.Hour)
	if got := approvalActivationFailureObservation(context.Background(), margin, approvalmaintenance.ErrUnavailable, false); got != "approval payload observation stage=payload-load outcome=lease-margin parent_live=true lease_live=false provider_live=false" {
		t.Fatal("native expiry observation changed")
	}
}
