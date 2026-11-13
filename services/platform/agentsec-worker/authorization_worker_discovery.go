package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// This adapter has no generic SQL entry. The product supplies its immutable
// workflow start; native metadata derives the distinct sync/task identity.
type workerDiscoveryDatabase struct {
	forward, compensation *authorization.WorkerExecutor
}

func (d *workerDiscoveryDatabase) ready(ctx context.Context) error {
	if d == nil || d.forward == nil || d.compensation == nil {
		return authorization.ErrInvalid
	}
	if err := d.forward.ReadyFor(ctx, "discovery72.prepare_page"); err != nil {
		return err
	}
	return d.compensation.ReadyFor(ctx, "discovery72.record_page")
}

func (d *workerDiscoveryDatabase) query(ctx context.Context, phase string, start orchestration.DiscoveryStart, extra map[string]any) (json.RawMessage, error) {
	if d == nil || d.forward == nil || d.compensation == nil || ctx == nil {
		return nil, authorization.ErrInvalid
	}
	if _, _, err := discoveryProductArgs(start); err != nil {
		return nil, authorization.ErrInvalid
	}
	q := map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "job_id": start.Ref.RunID, "integration_id": start.IntegrationID, "input_digest": start.InputDigest, "operation": phase}
	for key, value := range extra {
		if _, duplicate := q[key]; duplicate {
			return nil, authorization.ErrInvalid
		}
		q[key] = value
	}
	executor := d.forward
	switch phase {
	case "prepare_page", "guard_page", "prepare_apply", "commit_apply":
	case "record_page", "settle", "finish":
		executor = d.compensation
	default:
		return nil, authorization.ErrInvalid
	}
	once := func(executor *authorization.WorkerExecutor, phase string) (json.RawMessage, error) {
		q["operation"] = phase
		raw, err := json.Marshal(q)
		if err != nil {
			return nil, authorization.ErrInvalid
		}
		decision, err := executor.Authorize(ctx, authorization.WorkerOperation("discovery72."+phase), raw)
		if err != nil {
			return nil, err
		}
		return executor.Execute(ctx, decision)
	}
	// Every phase decides again while the Organization's permission
	// projection is moving (see retryDiscoveryAuthorization). Each phase is
	// one statement that either commits or is refused before it changes
	// anything, and each is idempotent in the product schema, so deciding
	// again repeats nothing. Without it a permission change anywhere in the
	// Organization at the wrong moment ends the run: an apply is attempted
	// once, and a page whose receipt could not be recorded is unknown.
	run := func(executor *authorization.WorkerExecutor, phase string) (json.RawMessage, error) {
		return retryDiscoveryAuthorization(ctx, discoveryGuardRetryBudget, discoveryGuardRetryInterval, func() (json.RawMessage, error) { return once(executor, phase) })
	}
	if phase == "prepare_page" || phase == "prepare_apply" {
		replay := "replay_page"
		if phase == "prepare_apply" {
			replay = "replay_apply"
		}
		raw, err := run(d.compensation, replay)
		if err != nil {
			return nil, err
		}
		var receipt struct {
			Found bool            `json:"found"`
			Value json.RawMessage `json:"value"`
		}
		if decodeStrictWorkerJSON(raw, &receipt) != nil {
			return nil, authorization.ErrInvalid
		}
		if receipt.Found {
			if !json.Valid(receipt.Value) || string(receipt.Value) == "null" {
				return nil, authorization.ErrInvalid
			}
			return receipt.Value, nil
		}
		if receipt.Value != nil {
			return nil, authorization.ErrInvalid
		}
	}
	return run(executor, phase)
}

const (
	discoveryGuardRetryBudget   = 15 * time.Second
	discoveryGuardRetryInterval = 250 * time.Millisecond
)

// retryDiscoveryAuthorization repeats one authorized call while the
// Organization's permission projection is moving. ErrPending means a change
// is not applied yet; ErrConflict means the revision changed between the
// check and its use. Both say "decide again", not "denied": every attempt
// runs the complete check against the current revision, and nothing is
// executed under a stale decision. Any other error, and a denial, returns at
// once. Without this a provider request that coincides with any permission
// change in the Organization, including the one that creating the sync itself
// causes, ends the whole discovery run as revoked.
func retryDiscoveryAuthorization(ctx context.Context, budget, interval time.Duration, call func() (json.RawMessage, error)) (json.RawMessage, error) {
	if ctx == nil || call == nil || budget <= 0 || interval <= 0 {
		return nil, authorization.ErrInvalid
	}
	deadline := time.Now().Add(budget)
	for {
		raw, err := call()
		if err == nil || !errors.Is(err, authorization.ErrPending) && !errors.Is(err, authorization.ErrConflict) {
			return raw, err
		}
		if !time.Now().Add(interval).Before(deadline) {
			return nil, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
	}
}

func (p *temporalDiscoveryProduct) queryDiscovery(ctx context.Context, phase string, start orchestration.DiscoveryStart, extra map[string]any, sql string, destination any, args ...any) error {
	if p == nil {
		return authorization.ErrInvalid
	}
	if p.authorization == nil {
		return p.query(ctx, sql, destination, args...)
	}
	raw, err := p.authorization.query(ctx, phase, start, extra)
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, destination) != nil {
		return authorization.ErrInvalid
	}
	return nil
}
