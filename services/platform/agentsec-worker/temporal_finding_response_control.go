package main

import (
	"context"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type findingResponseControlRelay struct {
	database apiserver.JSONDatabase
	notify   func(context.Context, string, orchestration.StartRequest) error
}

func (p *temporalSecurityAgentProduct) findingResponseControlRelay(notify func(context.Context, string, orchestration.StartRequest) error) workerProcessor {
	return &findingResponseControlRelay{database: p.executor, notify: notify}
}

func (r *findingResponseControlRelay) RunOnce(ctx context.Context) error {
	if r == nil || ctx == nil || nilWorkerDependency(r.database) || r.notify == nil {
		return orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(bounded, `SELECT zasp_temporal78.pending_controls()`)
	if err != nil {
		return orchestration.ErrUnavailable
	}
	var controls []struct {
		Start    orchestration.StartRequest `json:"start"`
		ID       string                     `json:"control_id"`
		Kind     string                     `json:"kind"`
		Terminal *bool                      `json:"terminal"`
	}
	if len(raw) > 8192 || decodeStrictWorkerJSON(raw, &controls) != nil || controls == nil || len(controls) > 5 {
		return orchestration.ErrConflict
	}
	var failures error
	seen := map[string]bool{}
	for _, control := range controls {
		q := control.Start
		id, err := orchestration.FindingResponseWorkflowID(q.Ref)
		if err != nil || q.DefinitionVersion < 1 || q.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(q.InputDigest) || !validRecoveryProductID(control.ID) || control.Terminal == nil || !stringInWorker(control.Kind, "approval", "cancel") || seen[control.ID] {
			failures = errors.Join(failures, orchestration.ErrConflict)
			continue
		}
		seen[control.ID] = true
		// SQL authenticates the original decision and accepted start. Only its
		// verified terminal proof permits acknowledgement without an RPC.
		if !*control.Terminal {
			if err := r.notify(bounded, control.Kind, q); err != nil {
				failures = errors.Join(failures, err)
				continue
			}
		}
		if bounded.Err() != nil {
			return errors.Join(failures, orchestration.ErrUnavailable)
		}
		fields := temporalStartFields(q)
		fields["control_id"] = control.ID
		raw, err := temporalQuery(bounded, r.database, `SELECT zasp_temporal78.accept_control($1::jsonb)`, fields)
		var receipt struct {
			ID         string `json:"control_id"`
			WorkflowID string `json:"workflow_id"`
			AcceptedAt string `json:"accepted_at"`
		}
		_, closed := securityAgentOrderedClosedObject(raw, "control_id", "workflow_id", "accepted_at")
		if err != nil || len(raw) > 4096 || !closed || decodeStrictWorkerJSON(raw, &receipt) != nil || receipt.ID != control.ID || receipt.WorkflowID != id {
			failures = errors.Join(failures, orchestration.ErrUnavailable)
			continue
		}
		accepted, err := time.Parse(time.RFC3339Nano, receipt.AcceptedAt)
		if err != nil || accepted.IsZero() || accepted.Location() != time.UTC {
			failures = errors.Join(failures, orchestration.ErrConflict)
		}
	}
	return failures
}
