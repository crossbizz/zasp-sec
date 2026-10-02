package redteamadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type orderedJournalNoFallback struct{ calls int }

func (d *orderedJournalNoFallback) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	d.calls++
	return json.RawMessage(`true`), nil
}

func TestWorkerJournalFamilyCannotCrossProtocol(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		db := &orderedJournalNoFallback{}
		forward, comp := &authorization.WorkerExecutor{}, &authorization.WorkerExecutor{}
		constructor := NewWorkerSingleTestPostgresJournal
		prefix := "test74.adapter."
		if ordered {
			constructor = NewWorkerOrderedTestPostgresJournal
			prefix = "ordered68.adapter."
		}
		j, err := constructor(db, strings.Repeat("a", 64), strings.Repeat("b", 64), forward, comp)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"resolve", "start", "complete"} {
			got, err := j.workerOperation(op)
			if err != nil || string(got) != prefix+op {
				t.Fatal("family crossed", ordered, op, got, err)
			}
		}
		for _, op := range []string{"receipt", "start.extra", "sql", "test74.adapter.start", "ordered68.adapter.start"} {
			if _, err := j.workerOperation(op); err == nil {
				t.Fatal("unreleased phase accepted", op)
			}
		}
		if ordered {
			if _, err := j.CompletedReceipt(context.Background(), CompletedReceiptRequest{}); err == nil {
				t.Fatal("ordered completed recovery opened")
			}
		}
		j.workerFamily = workerJournalFamily(99)
		if j.Ready(context.Background()) == nil || db.calls != 0 {
			t.Fatal("unknown family reached legacy readiness")
		}
		r := journalRequestFixture(t)
		if _, err := j.query(context.Background(), r.Invocation.Scope, r.Invocation.RunID, strings.Repeat("c", 64), "resolve", map[string]any{}); err == nil || db.calls != 0 {
			t.Fatal("unknown worker family fell back to raw SQL")
		}
	}
}

type orderedProtocolDatabase struct {
	response json.RawMessage
	calls    int
}

func (d *orderedProtocolDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	d.calls++
	if statement != `SELECT zasp_temporal74.adapter_protocol($1,$2,$3,$4,$5)` || len(args) != 5 {
		return nil, ErrAdapter
	}
	return d.response, nil
}
func TestWorkerRouterRequiresBothFixedFamilies(t *testing.T) {
	db := &orderedProtocolDatabase{}
	forward, comp := &authorization.WorkerExecutor{}, &authorization.WorkerExecutor{}
	single, _ := NewWorkerSingleTestPostgresJournal(db, strings.Repeat("a", 64), strings.Repeat("b", 64), forward, comp)
	ordered, _ := NewWorkerOrderedTestPostgresJournal(db, strings.Repeat("a", 64), strings.Repeat("b", 64), forward, comp)
	for _, pair := range [][2]*TemporalPostgresJournal{{nil, ordered}, {single, nil}, {ordered, single}, {single, single}, {ordered, ordered}} {
		if _, err := NewWorkerTestEffectRouter(db, pair[0], pair[1]); err == nil {
			t.Fatal("mixed family accepted")
		}
	}
	router, err := NewWorkerTestEffectRouter(db, single, ordered)
	if err != nil {
		t.Fatal(err)
	}
	q := journalRequestFixture(t)
	for _, tc := range []struct {
		body string
		want *TemporalPostgresJournal
	}{{`{"protocol":"single_test74"}`, single}, {`{"protocol":"ordered68"}`, ordered}, {`{"protocol":"unknown"}`, nil}, {`{"protocol":"ordered68","extra":true}`, nil}, {`{"protocol":"ordered68","protocol":"single_test74"}`, nil}, {`null`, nil}} {
		db.response = json.RawMessage(tc.body)
		got, err := router.selectJournal(context.Background(), q.Invocation.Scope, q.Invocation.RunID, strings.Repeat("c", 64))
		if tc.want == nil {
			if err == nil {
				t.Fatal("malformed protocol accepted", tc.body)
			}
		} else if err != nil || got != tc.want {
			t.Fatal("family selection changed", err)
		}
	}
}
