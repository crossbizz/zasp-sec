package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type discoveryWorkflowStarter interface {
	Start(context.Context, orchestration.DiscoveryStart) error
}
type temporalDiscoveryStartProcessor struct {
	database apiserver.JSONDatabase
	queue    discoveryQueue
	starter  discoveryWorkflowStarter
	batch    int
	legacy   *discoveryProcessor
}

func newTemporalDiscoveryStartProcessor(db apiserver.JSONDatabase, q discoveryQueue, s discoveryWorkflowStarter, batch int) (*temporalDiscoveryStartProcessor, error) {
	if nilWorkerDependency(db) || nilWorkerDependency(q) || nilWorkerDependency(s) || batch < 1 || batch > 10 {
		return nil, errWorkerExecution
	}
	return &temporalDiscoveryStartProcessor{database: db, queue: q, starter: s, batch: batch}, nil
}
func (p *temporalDiscoveryStartProcessor) RunOnce(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	deliveries, err := p.queue.ConsumeBatch(bounded, p.batch)
	if err != nil {
		return errWorkerExecution
	}
	var result error
	for _, d := range deliveries {
		result = errors.Join(result, p.process(bounded, d))
	}
	return result
}
func (p *temporalDiscoveryStartProcessor) process(ctx context.Context, d jobqueue.Delivery) error {
	j := d.Job
	if j.Scope.Validate() != nil || j.JobID.IsZero() || j.Kind != "discovery" || len(j.Payload) == 0 || len(j.Payload) > 65536 || !json.Valid(j.Payload) {
		return errWorkerExecution
	}
	raw, err := p.database.QueryJSON(ctx, `SELECT zasp_temporal72.delivery_route($1,$2,$3,$4,$5::jsonb)`, j.Scope.OrganizationID().String(), j.Scope.WorkspaceID().String(), j.Scope.EnvironmentID().String(), j.JobID.String(), j.Payload)
	var route struct {
		Ownership string                        `json:"ownership"`
		Start     *orchestration.DiscoveryStart `json:"start"`
	}
	if err != nil || json.Unmarshal(raw, &route) != nil {
		return errWorkerExecution
	}
	if route.Ownership == "legacy" && route.Start == nil && p.legacy != nil {
		// Temporary coexistence only. SQL positively matched a retained job and
		// its canonical envelope; the processor retains every old authority check.
		return p.legacy.process(ctx, d)
	}
	start := route.Start
	if route.Ownership != "temporal" || start == nil || start.Ref.OrganizationID != j.Scope.OrganizationID().String() || start.Ref.WorkspaceID != j.Scope.WorkspaceID().String() || start.Ref.EnvironmentID != j.Scope.EnvironmentID().String() || start.Ref.RunID != j.JobID.String() || start.Continuation == nil {
		return errWorkerExecution
	}
	if err := p.starter.Start(ctx, *start); err != nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	// This ACK confirms only durable Temporal start. Product completion stays in
	// scoped SQL and is read through its own evidence-backed public projection.
	if p.queue.AcknowledgeBatch(ctx, []jobqueue.Receipt{d.Receipt}) != nil {
		return errWorkerExecution
	}
	return nil
}
