package main

import (
	"context"
	"errors"

	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

type actionEvidenceStore interface {
	UpsertActionEvidence(context.Context, domain.Scope, graphstore.Projection, graphstore.ActionEvidence) error
}
type actionEvidenceGraphProcessor struct {
	database            recoveryJSONDatabase
	store               actionEvidenceStore
	limit, leaseSeconds int
}
type actionGraphRow struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Fact         struct {
		Source     string    `json:"source"`
		EventType  string    `json:"event_type"`
		Evidence   string    `json:"evidence_id"`
		Subject    string    `json:"subject_id"`
		Session    string    `json:"session_id,omitempty"`
		Agent      string    `json:"agent_id,omitempty"`
		Decision   string    `json:"decision_id,omitempty"`
		Verdict    string    `json:"verdict"`
		ObservedAt time.Time `json:"observed_at"`
	} `json:"fact"`
}

const actionGraphClaimSQL = "SELECT public.zasp_action_graph_claim($1,$2,$3)"
const actionGraphAckSQL = "SELECT public.zasp_action_graph_ack($1,$2,$3,$4,$5)"

func (p actionEvidenceGraphProcessor) RunOnce(ctx context.Context) error {
	token, err := newWorkerLeaseToken()
	if err != nil {
		return errWorkerExecution
	}
	raw, err := p.database.QueryJSON(ctx, actionGraphClaimSQL, token, p.limit, p.leaseSeconds)
	var rows []actionGraphRow
	if err != nil || decodeStrictWorkerJSON(raw, &rows) != nil || rows == nil || len(rows) > p.limit {
		return errWorkerExecution
	}
	var failure error
	for _, row := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		scope, projection, fact, ok := row.projection()
		if !ok || p.store.UpsertActionEvidence(ctx, scope, projection, fact) != nil {
			failure = errWorkerExecution
			continue
		}
		ack, err := p.database.QueryJSON(ctx, actionGraphAckSQL, row.Organization, row.Workspace, row.Environment, row.Fact.Evidence, token)
		if err != nil || string(ack) != "true" {
			failure = errWorkerExecution
		}
	}
	return failure
}

func (row actionGraphRow) projection() (domain.Scope, graphstore.Projection, graphstore.ActionEvidence, bool) {
	scope, validScope := recoveryScope(row.Organization, row.Workspace, row.Environment)
	input := row.Fact
	id, err := domain.ParseProductID(input.Evidence)
	fact := graphstore.ActionEvidence{EvidenceID: id, ObservedAt: input.ObservedAt, Source: input.Source, EventType: input.EventType, Verdict: input.Verdict}
	p := graphstore.Projection{}
	if !validScope || err != nil || !fact.Valid() {
		return scope, p, fact, false
	}
	p.Nodes = append(p.Nodes, graphstore.Node{Scope: scope, NodeID: id, Kind: input.EventType})
	// Edges reflect the provenance of this single receipt. Metadata-only
	// classifications and effect/usage estimates cannot create graph vertices.
	add := func(target, nodeKind, edgeKind string) bool {
		targetID, err := domain.ParseProductID(target)
		if err != nil || targetID == id {
			return false
		}
		edgeID, err := runtimeCorrelationGraphEdgeID(scope, id, edgeKind, id, targetID)
		if err != nil {
			return false
		}
		p.Nodes = append(p.Nodes, graphstore.Node{Scope: scope, NodeID: targetID, Kind: nodeKind})
		p.Edges = append(p.Edges, graphstore.Edge{Scope: scope, EdgeID: edgeID, Kind: edgeKind, SourceID: id, TargetID: targetID})
		return true
	}
	if input.Source == "signed_endpoint" {
		if input.Decision != "" || input.Agent != "" || !add(input.Subject, "managed_device", "reported_by_device") || !add(input.Session, "device_local_session", "observed_in_local_session") {
			return scope, p, fact, false
		}
	} else {
		if !add(input.Subject, "workload_credential", "admitted_with_credential") || (input.Session == "") != (input.Agent == "") {
			return scope, p, fact, false
		}
		if input.Session != "" && (!add(input.Session, "session", "bound_to_session") || !add(input.Agent, "agent", "bound_to_agent")) {
			return scope, p, fact, false
		}
		if (input.EventType == "action_outcome") != (input.Decision != "") || input.Decision != "" && !add(input.Decision, "action_decision", "reports_outcome_for") {
			return scope, p, fact, false
		}
	}
	return scope, p, fact, true
}

// Run both queues even when a driver or one stream fails. The bounded action
// lease expires without acknowledgement on graph failure or lost response.
type discoveryAndActionGraph struct{ discovery, actions workerProcessor }

func (p discoveryAndActionGraph) RunOnce(ctx context.Context) error {
	a := p.discovery.RunOnce(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(a, p.actions.RunOnce(ctx))
}
