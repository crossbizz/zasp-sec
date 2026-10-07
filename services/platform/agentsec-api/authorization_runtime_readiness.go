package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func checkAuthorizationRuntimeReady(ctx context.Context, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string) error {
	if err := database.CurrentAuthorizationRuntimeReady(ctx, "zasp_discovery_api", keyVersion); err != nil {
		return errRuntimeUnavailable
	}
	if err := securityAgentDatabase.CurrentAuthorizationRuntimeReady(ctx, "zasp_security_agent_api", keyVersion); err != nil {
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
		if err := checkAuthorizationRuntimeReadyWithinTimeout(ctx, database, securityAgentDatabase, keyVersion, timeout); err != nil {
			return err
		}
		return previous(ctx)
	}
}
