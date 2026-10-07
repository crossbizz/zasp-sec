package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func checkAuthorizationRuntimeReady(ctx context.Context, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string) error {
	if ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	// Each pool checks only its own fixed bootstrap metadata. Both must pass
	// within the same budget; cancel and join both before callers close pools.
	probes, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- database.CurrentAuthorizationRuntimeReady(probes, "zasp_discovery_api", keyVersion) }()
	go func() {
		results <- securityAgentDatabase.CurrentAuthorizationRuntimeReady(probes, "zasp_security_agent_api", keyVersion)
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
	return func(ctx context.Context) error {
		if err := servicesReady(ctx); err != nil {
			return err
		}
		if database.CurrentAuthorizationRequired() && securityAgentDatabase.CurrentAuthorizationRequired() {
			bounded, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return boundedParallelReadiness(bounded,
				func(probe context.Context) error {
					return checkAuthorizationRuntimeReady(probe, database, securityAgentDatabase, keyVersion)
				},
				previous,
			)
		}
		if err := checkAuthorizationRuntimeReadyWithinTimeout(ctx, database, securityAgentDatabase, keyVersion, timeout); err != nil {
			return err
		}
		return previous(ctx)
	}
}
