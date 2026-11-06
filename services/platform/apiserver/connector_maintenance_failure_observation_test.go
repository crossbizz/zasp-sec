package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Test-only diagnostics disclose fixed classifications and live fences. An
// absent provider bound is distinct from an expired actual provider deadline.
func connectorMaintenanceFailureObservation(ctx context.Context, lease ConnectorEffectLease, providerDeadline time.Time, stage string, cause error) string {
	switch stage {
	case "preparation-finish", "preparation-forward", "captured-compensation", "revocation-pending", "revocation-applied", "recovery-forward":
	default:
		stage = "unknown"
	}
	outcome := "other"
	switch {
	case errors.Is(cause, ErrAuthorizationDenied):
		outcome = "denied"
	case errors.Is(cause, ErrRepositoryUnavailable):
		outcome = "unavailable"
	case errors.Is(cause, ErrRepositoryOperation):
		outcome = "operation"
	}
	now := time.Now()
	parentLive := ctx != nil && ctx.Err() == nil
	providerBound := !providerDeadline.IsZero()
	return fmt.Sprintf("connector lease observation stage=%s outcome=%s parent_live=%t lease_live=%t provider_bound=%t provider_live=%t", stage, outcome, parentLive, lease.LeaseExpiresAt.After(now), providerBound, providerBound && parentLive && providerDeadline.After(now))
}
func connectorMaintenanceLeaseLive(ctx context.Context, lease ConnectorEffectLease) bool {
	return ctx != nil && ctx.Err() == nil && lease.LeaseExpiresAt.After(time.Now())
}

func TestConnectorMaintenanceFailureObservationBoundaries(t *testing.T) {
	live := ConnectorEffectLease{LeaseExpiresAt: time.Now().Add(time.Minute)}
	future, past := time.Now().Add(time.Minute), time.Now().Add(-time.Minute)
	for _, stage := range []string{"preparation-finish", "preparation-forward", "captured-compensation", "revocation-pending", "revocation-applied", "recovery-forward", "unknown"} {
		for _, c := range []struct {
			err     error
			outcome string
		}{{ErrAuthorizationDenied, "denied"}, {ErrRepositoryUnavailable, "unavailable"}, {ErrRepositoryOperation, "operation"}, {errors.New("private SQL/payload detail"), "other"}} {
			value := connectorMaintenanceFailureObservation(context.Background(), live, future, stage, fmt.Errorf("secret outer detail: %w", c.err))
			expected := fmt.Sprintf("connector lease observation stage=%s outcome=%s parent_live=true lease_live=true provider_bound=true provider_live=true", stage, c.outcome)
			if value != expected || strings.Contains(value, "secret") || strings.Contains(value, "private") {
				t.Fatal("diagnostic escaped the fixed grammar")
			}
		}
	}
	if value := connectorMaintenanceFailureObservation(context.Background(), live, time.Time{}, "private-stage", nil); value != "connector lease observation stage=unknown outcome=other parent_live=true lease_live=true provider_bound=false provider_live=false" {
		t.Fatal("missing deadline or arbitrary stage became authority")
	}
	if value := connectorMaintenanceFailureObservation(context.Background(), live, past, "preparation-finish", ErrRepositoryUnavailable); value != "connector lease observation stage=preparation-finish outcome=unavailable parent_live=true lease_live=true provider_bound=true provider_live=false" {
		t.Fatal("provider expiry was confused with live lease")
	}
	expired := ConnectorEffectLease{LeaseExpiresAt: past}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if value := connectorMaintenanceFailureObservation(ctx, expired, future, "captured-compensation", ErrRepositoryUnavailable); value != "connector lease observation stage=captured-compensation outcome=unavailable parent_live=false lease_live=false provider_bound=true provider_live=false" {
		t.Fatal("cancelled or expired fence reported live")
	}
	if !connectorMaintenanceLeaseLive(context.Background(), live) || connectorMaintenanceLeaseLive(ctx, live) || connectorMaintenanceLeaseLive(context.Background(), expired) || connectorMaintenanceLeaseLive(nil, live) {
		t.Fatal("permission assertion admitted a nonlive parent or lease")
	}
}
