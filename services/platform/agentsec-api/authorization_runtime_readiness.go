package main

import (
	"context"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Diagnostics are an optional private observation of existing readiness work.
// The observer receives only fixed enums, never dependency errors or inputs.
type readinessPhase uint8

const (
	readinessServices readinessPhase = iota
	readinessCoreMetadata
	readinessSecurityAgentMetadata
	readinessComponents
)

type readinessOutcome uint8

const (
	readinessPassed readinessOutcome = iota
	readinessRefused
	readinessDeadline
	readinessCancelled
)

type readinessObserver func(readinessPhase, readinessOutcome)

func observeReadiness(ctx context.Context, phase readinessPhase, observer readinessObserver, check func(context.Context) error) error {
	err := check(ctx)
	if observer != nil {
		outcome := readinessPassed
		if err != nil {
			outcome = readinessRefused
			if (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) || errors.Is(err, context.DeadlineExceeded) {
				outcome = readinessDeadline
			} else if (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) || errors.Is(err, context.Canceled) {
				outcome = readinessCancelled
			}
		}
		observer(phase, outcome)
	}
	return err
}

func checkAuthorizationRuntimeReady(ctx context.Context, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string) error {
	return checkAuthorizationRuntimeReadyWithDiagnostic(ctx, database, securityAgentDatabase, keyVersion, nil)
}

func checkAuthorizationRuntimeReadyWithDiagnostic(ctx context.Context, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string, observer readinessObserver) error {
	if ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	// Each pool checks only its own fixed bootstrap metadata. Both must pass
	// within the same budget; cancel and join both before callers close pools.
	probes, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		results <- observeReadiness(probes, readinessCoreMetadata, observer, func(probe context.Context) error {
			return database.CurrentAuthorizationRuntimeReady(probe, "zasp_discovery_api", keyVersion)
		})
	}()
	go func() {
		results <- observeReadiness(probes, readinessSecurityAgentMetadata, observer, func(probe context.Context) error {
			return securityAgentDatabase.CurrentAuthorizationRuntimeReady(probe, "zasp_security_agent_api", keyVersion)
		})
	}()
	failed := false
	for range 2 {
		if <-results != nil {
			failed = true
			cancel()
		}
	}
	if failed || probes.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}

// Connection setup and metadata preparation have their own lifetime. Both
// readiness probes share a fresh budget bounded by the runtime parent.
func checkAuthorizationRuntimeReadyWithinTimeout(ctx context.Context, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string, timeout time.Duration) error {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return checkAuthorizationRuntimeReady(bounded, database, securityAgentDatabase, keyVersion)
}

func authorizationRuntimeReadiness(servicesReady, previous func(context.Context) error, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string, timeout time.Duration) func(context.Context) error {
	return authorizationRuntimeReadinessWithDiagnostic(servicesReady, previous, database, securityAgentDatabase, keyVersion, timeout, nil)
}

func authorizationRuntimeReadinessWithDiagnostic(servicesReady, previous func(context.Context) error, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string, timeout time.Duration, observer readinessObserver) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := observeReadiness(ctx, readinessServices, observer, servicesReady); err != nil {
			return err
		}
		if database.CurrentAuthorizationRequired() && securityAgentDatabase.CurrentAuthorizationRequired() {
			bounded, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return boundedParallelReadiness(bounded,
				func(probe context.Context) error {
					return checkAuthorizationRuntimeReadyWithDiagnostic(probe, database, securityAgentDatabase, keyVersion, observer)
				},
				func(probe context.Context) error {
					return observeReadiness(probe, readinessComponents, observer, previous)
				},
			)
		}
		if err := func() error {
			bounded, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return checkAuthorizationRuntimeReadyWithDiagnostic(bounded, database, securityAgentDatabase, keyVersion, observer)
		}(); err != nil {
			return err
		}
		return observeReadiness(ctx, readinessComponents, observer, previous)
	}
}
