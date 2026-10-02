package main

import (
	"context"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type findingResponseStartRelay struct {
	database apiserver.JSONDatabase
	start    func(context.Context, orchestration.StartRequest) error
}

func (p *temporalSecurityAgentProduct) findingResponseRelay(start func(context.Context, orchestration.StartRequest) error) workerProcessor {
	return &findingResponseStartRelay{database: p.executor, start: start}
}

func (r *findingResponseStartRelay) RunOnce(ctx context.Context) error {
	if r == nil || ctx == nil || nilWorkerDependency(r.database) || r.start == nil {
		return orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(bounded, `SELECT zasp_temporal78.pending()`)
	if err != nil {
		return orchestration.ErrUnavailable
	}
	var starts []orchestration.StartRequest
	if len(raw) > 8192 || decodeStrictWorkerJSON(raw, &starts) != nil || starts == nil || len(starts) > 5 {
		return orchestration.ErrConflict
	}
	var failures error
	seen := map[string]bool{}
	for _, q := range starts {
		id, err := orchestration.FindingResponseWorkflowID(q.Ref)
		if err != nil || q.DefinitionVersion < 1 || q.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(q.InputDigest) || seen[id] {
			failures = errors.Join(failures, orchestration.ErrInvalid)
			continue
		}
		seen[id] = true
		if err := r.start(bounded, q); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		// An ambiguous/cancelled transport never acknowledges durable delivery.
		if bounded.Err() != nil {
			return errors.Join(failures, orchestration.ErrUnavailable)
		}
		raw, err := temporalQuery(bounded, r.database, `SELECT zasp_temporal78.accept_start($1::jsonb)`, temporalStartFields(q))
		var receipt struct {
			WorkflowID string `json:"workflow_id"`
			AcceptedAt string `json:"accepted_at"`
		}
		_, closed := securityAgentOrderedClosedObject(raw, "workflow_id", "accepted_at")
		if err != nil || len(raw) > 4096 || !closed || decodeStrictWorkerJSON(raw, &receipt) != nil || receipt.WorkflowID != id {
			failures = errors.Join(failures, orchestration.ErrUnavailable)
			continue
		}
		accepted, err := time.Parse(time.RFC3339Nano, receipt.AcceptedAt)
		if err != nil || accepted.IsZero() {
			failures = errors.Join(failures, orchestration.ErrConflict)
		}
	}
	return failures
}
