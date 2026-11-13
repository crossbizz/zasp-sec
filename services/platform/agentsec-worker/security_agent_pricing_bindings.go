package main

import (
	"bytes"
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// securityAgentPricingBindings resolves the pricing binding of one
// Organization, Workspace and Environment at the moment a planner request is
// priced. A binding is a set of references and pins, never a credential and
// never an approval: every caller passes it to the registered pricing lookup,
// which verifies it against the administrator-approved policy and account.
type securityAgentPricingBindings interface {
	// binding reports false when the scope has no usable binding.
	binding(ctx context.Context, organization, workspace, environment string) (securityAgentMultistepPricingBinding, bool, error)
}

// staticSecurityAgentPricingBindings is the optional mounted override file
// (ZASP_TEMPORAL_PRICING_BINDINGS_FILE): a fixed list, verified at startup.
type staticSecurityAgentPricingBindings []securityAgentMultistepPricingBinding

func (s staticSecurityAgentPricingBindings) binding(_ context.Context, organization, workspace, environment string) (securityAgentMultistepPricingBinding, bool, error) {
	var selected securityAgentMultistepPricingBinding
	found := false
	for _, candidate := range s {
		if candidate.OrganizationID == organization && candidate.WorkspaceID == workspace && candidate.EnvironmentID == environment {
			if found {
				// The loader refuses duplicates; a duplicate here selects nothing.
				return securityAgentMultistepPricingBinding{}, false, nil
			}
			selected, found = candidate, true
		}
	}
	return selected, found, nil
}

const securityAgentPricingBindingSQL = `SELECT COALESCE(zasp_authorization80.security_agent_pricing_binding($1,$2,$3,$4,$5),'null'::jsonb)`

// databaseSecurityAgentPricingBindings reads the binding of a scope from the
// administrator-approved pricing policy and account in the product database,
// on the Security Agent worker's own database role. Nothing is cached: an
// approval that an administrator replaces, disables or lets expire stops
// being offered at the next planner request.
type databaseSecurityAgentPricingBindings struct {
	database apiserver.JSONDatabase
	planner  *productionSecurityAgentPlanner
	timeout  time.Duration
}

func newDatabaseSecurityAgentPricingBindings(database apiserver.JSONDatabase, planner *productionSecurityAgentPlanner, timeout time.Duration) (*databaseSecurityAgentPricingBindings, error) {
	if database == nil || planner == nil || timeout < time.Second || timeout > time.Minute {
		return nil, errRuntimeUnavailable
	}
	return &databaseSecurityAgentPricingBindings{database: database, planner: planner, timeout: timeout}, nil
}

func (d *databaseSecurityAgentPricingBindings) binding(ctx context.Context, organization, workspace, environment string) (securityAgentMultistepPricingBinding, bool, error) {
	var zero securityAgentMultistepPricingBinding
	if d == nil || d.database == nil || d.planner == nil || ctx == nil || ctx.Err() != nil {
		return zero, false, errWorkerExecution
	}
	for _, id := range []string{organization, workspace, environment} {
		if _, err := domain.ParseProductID(id); err != nil {
			return zero, false, errWorkerExecution
		}
	}
	d.planner.mu.RLock()
	model, closed := d.planner.model, d.planner.closed
	d.planner.mu.RUnlock()
	if closed || model == "" {
		return zero, false, errWorkerExecution
	}
	bounded, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	raw, err := d.database.QueryJSON(bounded, securityAgentPricingBindingSQL, organization, workspace, environment, "openrouter", model)
	if err != nil || bounded.Err() != nil {
		return zero, false, errWorkerExecution
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return zero, false, nil
	}
	var selected securityAgentMultistepPricingBinding
	if len(raw) > 4096 || decodeStrictWorkerJSON(raw, &selected) != nil || selected.OrganizationID != organization || selected.WorkspaceID != workspace || selected.EnvironmentID != environment {
		return zero, false, errWorkerExecution
	}
	// The same identity verification a mounted binding passes at startup:
	// this planner, its credential and its request policy must be able to
	// form a valid lookup for the binding.
	if !release61PlannerAvailable(d.planner, selected) {
		return zero, false, errWorkerExecution
	}
	return selected, true, nil
}

// pricingBinding resolves the binding of the run's scope. A product without
// a resolver has no binding for any scope.
func (p *temporalSecurityAgentProduct) pricingBinding(ctx context.Context, q orchestration.StartRequest) (securityAgentMultistepPricingBinding, bool, error) {
	if p == nil || p.bindings == nil {
		return securityAgentMultistepPricingBinding{}, false, nil
	}
	return p.bindings.binding(ctx, q.Ref.OrganizationID, q.Ref.WorkspaceID, q.Ref.EnvironmentID)
}

// securityAgentPricingBindingsFor selects the resolver for a worker: the
// mounted override file when one is configured (every binding verified
// against this planner, as before), otherwise the database resolver.
func securityAgentPricingBindingsFor(config workerRuntimeConfig, database apiserver.JSONDatabase, planner *productionSecurityAgentPlanner) (securityAgentPricingBindings, error) {
	if planner == nil {
		return nil, errRuntimeUnavailable
	}
	if config.TemporalPricingBindingsFile != "" {
		bindings, err := loadTemporalPricingBindings(config.TemporalPricingBindingsFile)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		for _, binding := range bindings {
			if !release61PlannerAvailable(planner, binding) {
				return nil, errRuntimeUnavailable
			}
		}
		return staticSecurityAgentPricingBindings(bindings), nil
	}
	timeout := config.RuntimeServices.Timeout
	if timeout < time.Second || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	return newDatabaseSecurityAgentPricingBindings(database, planner, timeout)
}
