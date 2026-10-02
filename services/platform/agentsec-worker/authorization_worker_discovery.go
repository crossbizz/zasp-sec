package main

import (
	"context"
	"encoding/json"

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
	run := func(executor *authorization.WorkerExecutor, phase string) (json.RawMessage, error) {
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
