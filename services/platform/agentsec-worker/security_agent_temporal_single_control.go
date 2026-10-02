package main

import (
	"context"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type singleTestControlRelay struct {
	database apiserver.JSONDatabase
	notify   func(context.Context, string, orchestration.StartRequest) error
}

func (p *temporalSecurityAgentProduct) singleTestControlRelay(notify func(context.Context, string, orchestration.StartRequest) error) workerProcessor {
	return &singleTestControlRelay{database: p.executor, notify: notify}
}

func (r *singleTestControlRelay) RunOnce(ctx context.Context) error {
	if r == nil || ctx == nil || nilWorkerDependency(r.database) || r.notify == nil {
		return orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(bounded, `SELECT zasp_temporal74.pending_controls()`)
	if err != nil {
		return orchestration.ErrUnavailable
	}
	var controls []struct {
		Start    orchestration.StartRequest `json:"start"`
		ID       string                     `json:"control_id"`
		Kind     string                     `json:"kind"`
		Terminal *bool                      `json:"terminal"`
	}
	if len(raw) > 65536 || decodeStrictWorkerJSON(raw, &controls) != nil || controls == nil || len(controls) > 100 {
		return orchestration.ErrConflict
	}
	var failures error
	for _, control := range controls {
		q := control.Start
		id, err := orchestration.SingleTestWorkflowID(q.Ref)
		if err != nil || q.DefinitionVersion < 1 || q.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(q.InputDigest) || !validRecoveryProductID(control.ID) || control.Terminal == nil || (control.Kind != "approval" && control.Kind != "cancel") {
			failures = errors.Join(failures, orchestration.ErrConflict)
			continue
		}
		// SQL authenticates immutable decision and original accepted-start proof.
		// Neither a missing workflow nor an RPC response proves terminal cleanup.
		if !*control.Terminal {
			if err := r.notify(bounded, control.Kind, q); err != nil {
				failures = errors.Join(failures, err)
				continue
			}
		}
		fields := temporalStartFields(q)
		fields["control_id"] = control.ID
		raw, err := temporalQuery(bounded, r.database, `SELECT zasp_temporal74.accept_control($1::jsonb)`, fields)
		var receipt struct {
			ID         string `json:"control_id"`
			WorkflowID string `json:"workflow_id"`
			AcceptedAt string `json:"accepted_at"`
		}
		if err != nil || len(raw) > 4096 || decodeStrictWorkerJSON(raw, &receipt) != nil || receipt.ID != control.ID || receipt.WorkflowID != id {
			failures = errors.Join(failures, orchestration.ErrUnavailable)
			continue
		}
		if accepted, err := time.Parse(time.RFC3339Nano, receipt.AcceptedAt); err != nil || accepted.Location() != time.UTC {
			failures = errors.Join(failures, orchestration.ErrConflict)
		}
	}
	return failures
}
