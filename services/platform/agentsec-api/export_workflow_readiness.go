package main

import (
	"context"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func newExportWorkflowReadiness(transport http.RoundTripper) func(context.Context) bool {
	return newSecurityAgentWorkflowReadiness(transport, []string{
		"http://agentsec-security-agent:8081/readyz",
		"http://agentsec-security-agent-action:8081/readyz",
		"http://zasp-compliance-export-worker:8081/readyz",
		"http://zasp-compliance-cleanup-worker:8081/readyz",
	})
}

func (d *tracedJSONDatabase) SecurityAgentExportDefinitionsAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || invalidRuntimeValue(d.next) {
		return false, apiserver.ErrRepositoryUnavailable
	}
	probe, ok := d.next.(interface {
		SecurityAgentExportDefinitionsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.SecurityAgentExportDefinitionsAvailable(ctx)
}

func (d *tracedJSONDatabase) SecurityAgentExportsWorkflowAvailable(ctx context.Context) (bool, error) {
	installed, err := d.SecurityAgentExportDefinitionsAvailable(ctx)
	if err != nil || !installed {
		return false, err
	}
	if d.exportReady == nil {
		return false, nil
	}
	// Retrieval may have been mounted at startup but its authority withdrawn.
	installed, err = d.SecurityAgentExportsAvailable(ctx)
	if err != nil || !installed {
		return false, err
	}
	return d.exportReady(ctx), nil
}
