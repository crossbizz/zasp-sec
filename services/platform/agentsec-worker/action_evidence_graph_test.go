package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

func actionGraphExample(t *testing.T) actionGraphRow {
	t.Helper()
	var row actionGraphRow
	id := func() string {
		v, err := domain.NewProductID()
		if err != nil {
			t.Fatal(err)
		}
		return v.String()
	}
	row.Organization, row.Workspace, row.Environment = id(), id(), id()
	f := &row.Fact
	f.Evidence, f.Subject, f.Session = id(), id(), id()
	f.Source, f.EventType, f.Verdict = "signed_endpoint", "hook_decision", "deny"
	f.ObservedAt = time.Date(2026, 2, 1, 12, 0, 0, 12, time.UTC)
	return row
}

type actionGraphQueueFixture struct {
	raw json.RawMessage
	ack []any
}

func (q *actionGraphQueueFixture) QueryJSON(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
	switch sql {
	case actionGraphClaimSQL:
		return q.raw, nil
	case actionGraphAckSQL:
		q.ack = args
		return json.RawMessage("true"), nil
	}
	return nil, errors.New("unexpected query")
}

type actionGraphSinkFixture struct {
	err  error
	rows []graphstore.Projection
}

func (s *actionGraphSinkFixture) UpsertActionEvidence(_ context.Context, _ domain.Scope, p graphstore.Projection, _ graphstore.ActionEvidence) error {
	s.rows = append(s.rows, p)
	return s.err
}
func TestActionEvidenceGraphLagRetryAndScope(t *testing.T) {
	row := actionGraphExample(t)
	payload, _ := json.Marshal([]actionGraphRow{row})
	db := &actionGraphQueueFixture{raw: payload}
	sink := &actionGraphSinkFixture{err: errors.New("graph down")}
	p := actionEvidenceGraphProcessor{database: db, store: sink, limit: 2, leaseSeconds: 5}
	if p.RunOnce(context.Background()) == nil || db.ack != nil {
		t.Fatal("failed graph write acknowledged")
	}
	sink.err = nil
	if p.RunOnce(context.Background()) != nil || len(db.ack) != 5 || db.ack[0] != row.Organization || db.ack[2] != row.Environment || db.ack[3] != row.Fact.Evidence {
		t.Fatal("successful projection not scoped to original evidence")
	}
	if len(sink.rows) != 2 || len(sink.rows[0].Edges) != 2 || sink.rows[0].Edges[0] != sink.rows[1].Edges[0] {
		t.Fatal("retry changed topology")
	}
	for _, edge := range sink.rows[0].Edges {
		if edge.Kind != "reported_by_device" && edge.Kind != "observed_in_local_session" {
			t.Fatal("deny created fact about skill/data usage")
		}
	}
	// Workload source references alone cannot create an exact bound session.
	row.Fact.Source, row.Fact.EventType, row.Fact.Verdict = "authenticated_workload", "action_decision", "block"
	if _, _, _, ok := row.projection(); ok {
		t.Fatal("partial workload binding accepted")
	}
	row.Fact.Session = ""
	if _, p, _, ok := row.projection(); !ok || len(p.Edges) != 1 {
		t.Fatal("unbound workload decision")
	}
	row.Fact.EventType, row.Fact.Verdict = "action_outcome", "returned"
	if _, _, _, ok := row.projection(); ok {
		t.Fatal("outcome accepted without decision evidence")
	}
}
