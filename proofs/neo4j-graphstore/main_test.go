package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

func TestRunFixtureProvesScopedReplayReadsAndCleanup(t *testing.T) {
	store := &fakeGraphStore{}
	auditor := &fakeAuditor{}
	result, err := runFixture(context.Background(), store, auditor)
	if err != nil {
		t.Fatalf("runFixture = %v", err)
	}
	want := proofResult{Nodes: 3, Edges: 2, Replay: true, Scoped: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}
	if result != want {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
	if store.upserts != 2 || !reflect.DeepEqual(store.reads, []string{"outgoing:2", "incoming:2", "both:1", "outgoing:0", "cross:2"}) {
		t.Fatalf("store calls upsert=%d reads=%#v", store.upserts, store.reads)
	}
	if auditor.verifyCalls != 1 || auditor.deleteCalls != 1 || auditor.absentCalls != 1 {
		t.Fatalf("auditor calls verify=%d delete=%d absent=%d", auditor.verifyCalls, auditor.deleteCalls, auditor.absentCalls)
	}
}

func TestRunFixtureCleanupWinsAndContinuesAfterOperationFailure(t *testing.T) {
	operationErr := errors.New("operation")
	cleanupErr := errors.New("cleanup")
	store := &fakeGraphStore{upsertErr: operationErr}
	auditor := &fakeAuditor{deleteErr: cleanupErr}
	_, err := runFixture(context.Background(), store, auditor)
	if !errors.Is(err, errCleanup) {
		t.Fatalf("runFixture error = %v, want cleanup", err)
	}
	if auditor.deleteCalls != 1 || auditor.absentCalls != 1 {
		t.Fatalf("cleanup calls delete=%d absent=%d", auditor.deleteCalls, auditor.absentCalls)
	}

	store = &fakeGraphStore{readErr: operationErr}
	auditor = &fakeAuditor{}
	_, err = runFixture(context.Background(), store, auditor)
	if !errors.Is(err, errOperation) || auditor.deleteCalls != 1 || auditor.absentCalls != 1 {
		t.Fatalf("operation failure = %v, cleanup delete=%d absent=%d", err, auditor.deleteCalls, auditor.absentCalls)
	}
}

func TestRunMainUsesExactConfigurationAndFixedOutput(t *testing.T) {
	tests := []struct {
		name     string
		getenv   func(string) string
		execute  func(context.Context, string) error
		wantCode int
		wantLine string
	}{
		{
			name: "success", getenv: func(key string) string {
				if key == "NEO4J_GRAPHSTORE_URI" {
					return "bolt://127.0.0.1:47687"
				}
				return ""
			},
			execute: func(_ context.Context, uri string) error {
				if uri != "bolt://127.0.0.1:47687" {
					t.Fatalf("uri = %q", uri)
				}
				return nil
			},
			wantCode: 0, wantLine: successLine,
		},
		{name: "missing", getenv: func(string) string { return "" }, execute: noExecute, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: configuration rejected."},
		{name: "hostname", getenv: func(string) string { return "bolt://localhost:47687" }, execute: noExecute, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: configuration rejected."},
		{name: "credentials", getenv: func(string) string { return "bolt://user:secret@127.0.0.1:47687" }, execute: noExecute, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: configuration rejected."},
		{name: "provider", getenv: func(string) string { return "bolt://127.0.0.1:47687" }, execute: func(context.Context, string) error { return errProvider }, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: provider rejected."},
		{name: "ownership", getenv: func(string) string { return "bolt://127.0.0.1:47687" }, execute: func(context.Context, string) error { return errOwnership }, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: ownership rejected."},
		{name: "cleanup", getenv: func(string) string { return "bolt://127.0.0.1:47687" }, execute: func(context.Context, string) error { return errCleanup }, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: cleanup rejected."},
		{name: "panic", getenv: func(string) string { return "bolt://127.0.0.1:47687" }, execute: func(context.Context, string) error { panic("secret") }, wantCode: 1, wantLine: "Neo4j GraphStore proof failed: operation rejected."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			code := runMain(test.getenv, &output, test.execute)
			if code != test.wantCode || output.String() != test.wantLine+"\n" || strings.Contains(output.String(), "secret") {
				t.Fatalf("runMain = %d/%q, want %d/%q", code, output.String(), test.wantCode, test.wantLine)
			}
		})
	}
}

func TestAuditorRetainsMalformedBeginTransactionCandidate(t *testing.T) {
	transaction := &fakeAuditTransaction{}
	record, err := auditSingleWithTransaction(
		context.Background(),
		transaction,
		errors.New("seeded provider detail"),
		func(neo4j.ExplicitTransaction) (*neo4j.Record, error) {
			t.Fatal("work called after malformed begin")
			return nil, nil
		},
	)
	if record != nil || !errors.Is(err, errProvider) {
		t.Fatalf("auditSingleWithTransaction = (%v, %v), want fixed provider failure", record, err)
	}
	if transaction.rollbackCalls != 1 || transaction.rollbackContextErr != nil {
		t.Fatalf("rollback calls/context = %d/%v, want one independent rollback", transaction.rollbackCalls, transaction.rollbackContextErr)
	}
}

func noExecute(context.Context, string) error { panic("execute called") }

type fakeGraphStore struct {
	upserts   int
	reads     []string
	upsertErr error
	readErr   error
}

func (store *fakeGraphStore) Upsert(_ context.Context, scope domain.Scope, projection graphstore.Projection) error {
	store.upserts++
	if scope.Validate() != nil || len(projection.Nodes) != 3 || len(projection.Edges) != 2 {
		return errors.New("unexpected projection")
	}
	return store.upsertErr
}

func (store *fakeGraphStore) Read(_ context.Context, scope domain.Scope, request graphstore.ReadRequest) (graphstore.Projection, error) {
	if store.readErr != nil {
		return graphstore.Projection{}, store.readErr
	}
	fixture := mustFixture()
	if scope.OrganizationID() != fixture.scopeA.OrganizationID() {
		store.reads = append(store.reads, "cross:2")
		return graphstore.Projection{Nodes: []graphstore.Node{}, Edges: []graphstore.Edge{}}, nil
	}
	store.reads = append(store.reads, directionText(request.Direction)+":"+string(rune('0'+request.MaximumDepth)))
	if request.MaximumDepth == 0 {
		return graphstore.Projection{Nodes: []graphstore.Node{fixture.projection.Nodes[0]}, Edges: []graphstore.Edge{}}, nil
	}
	return fixture.projection, nil
}

func directionText(direction graphstore.Direction) string {
	switch direction {
	case graphstore.DirectionOutgoing:
		return "outgoing"
	case graphstore.DirectionIncoming:
		return "incoming"
	case graphstore.DirectionBoth:
		return "both"
	default:
		return "invalid"
	}
}

type fakeAuditor struct {
	verifyCalls int
	deleteCalls int
	absentCalls int
	verifyErr   error
	deleteErr   error
	absentErr   error
}

type fakeAuditTransaction struct {
	rollbackCalls      int
	rollbackContextErr error
}

func (*fakeAuditTransaction) Run(context.Context, string, map[string]any) (neo4j.Result, error) {
	panic("work must not run")
}

func (*fakeAuditTransaction) Commit(context.Context) error { panic("commit must not run") }

func (transaction *fakeAuditTransaction) Rollback(ctx context.Context) error {
	transaction.rollbackCalls++
	transaction.rollbackContextErr = ctx.Err()
	return nil
}

func (*fakeAuditTransaction) Close(context.Context) error { return nil }

func (auditor *fakeAuditor) Verify(context.Context, fixtureState) error {
	auditor.verifyCalls++
	return auditor.verifyErr
}
func (auditor *fakeAuditor) Delete(context.Context, fixtureState) error {
	auditor.deleteCalls++
	return auditor.deleteErr
}
func (auditor *fakeAuditor) Absent(context.Context, fixtureState) error {
	auditor.absentCalls++
	return auditor.absentErr
}
