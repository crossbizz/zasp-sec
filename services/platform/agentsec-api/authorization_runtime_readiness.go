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

func authorizationRuntimeReadiness(servicesReady, previous func(context.Context) error, database, securityAgentDatabase *apiserver.PostgresJSONDatabase, keyVersion string, timeout time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := servicesReady(ctx); err != nil {
			return err
		}
		bounded, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := checkAuthorizationRuntimeReady(bounded, database, securityAgentDatabase, keyVersion); err != nil {
			return err
		}
		return previous(ctx)
	}
}
