package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"time"
)

type singleTestStartRelay struct {
	database apiserver.JSONDatabase
	start    func(context.Context, orchestration.StartRequest) error
}

func (p *temporalSecurityAgentProduct) singleTestRelay(start func(context.Context, orchestration.StartRequest) error) workerProcessor {
	return &singleTestStartRelay{database: p.executor, start: start}
}
func (r *singleTestStartRelay) RunOnce(ctx context.Context) error {
	if r == nil || ctx == nil || nilWorkerDependency(r.database) || r.start == nil {
		return orchestration.ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := r.database.QueryJSON(bounded, `SELECT zasp_temporal74.pending()`)
	if err != nil {
		return orchestration.ErrUnavailable
	}
	var starts []orchestration.StartRequest
	if len(raw) > 65536 || decodeStrictWorkerJSON(raw, &starts) != nil || starts == nil || len(starts) > 100 {
		return orchestration.ErrConflict
	}
	var failures error
	for _, q := range starts {
		id, err := orchestration.SingleTestWorkflowID(q.Ref)
		if err != nil || q.DefinitionVersion < 1 || q.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(q.InputDigest) {
			failures = errors.Join(failures, orchestration.ErrInvalid)
			continue
		}
		if err := r.start(bounded, q); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		raw, err := temporalQuery(bounded, r.database, `SELECT zasp_temporal74.accept_start($1::jsonb)`, temporalStartFields(q))
		var receipt struct {
			WorkflowID string `json:"workflow_id"`
			AcceptedAt string `json:"accepted_at"`
		}
		if err != nil || len(raw) > 4096 || decodeStrictWorkerJSON(raw, &receipt) != nil || receipt.WorkflowID != id {
			failures = errors.Join(failures, orchestration.ErrUnavailable)
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, receipt.AcceptedAt); err != nil {
			failures = errors.Join(failures, orchestration.ErrConflict)
		}
	}
	return failures
}
