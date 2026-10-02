package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func (database *tracedJSONDatabase) VerifySecurityAgentOrderedHTTPRelease(ctx context.Context) (err error) {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return apiserver.ErrRepositoryUnavailable
	}
	verifier, ok := database.next.(apiserver.SecurityAgentOrderedHTTPReleaseVerifier)
	if !ok {
		return apiserver.ErrRepositoryUnavailable
	}
	if database.exporter != nil {
		var end func(error)
		ctx, end = startOperationalSpan(ctx, database.exporter, "repository.ordered_http_release", "client", map[string]string{"db.system": "postgresql", "db.operation.name": "deployment_ready"})
		defer func() { end(err) }()
	}
	defer func() { database.metrics.observeDependency("repository", err) }()
	if verifier.VerifySecurityAgentOrderedHTTPRelease(ctx) != nil || ctx.Err() != nil {
		return apiserver.ErrRepositoryUnavailable
	}
	return nil
}
