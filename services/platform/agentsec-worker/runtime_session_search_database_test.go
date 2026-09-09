package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type sessionSearchDatabaseStub struct {
	body      json.RawMessage
	statement string
	args      []any
	calls     int
	err       error
}

func TestRuntimeSessionSearchReadinessUsesJSONDatabaseWireType(t *testing.T) {
	db := &sessionSearchDatabaseStub{body: json.RawMessage(`true`)}
	authority, _ := newPostgresRuntimeSessionSearchAuthority(db)
	if authority.Ready(context.Background()) != nil || !strings.HasPrefix(db.statement, "SELECT to_jsonb(") {
		t.Fatalf("readiness is not a JSONB result: %s", db.statement)
	}
}

func (db *sessionSearchDatabaseStub) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	db.calls++
	db.statement = statement
	db.args = args
	return db.body, db.err
}

func sessionSearchLeaseJSON(t *testing.T, lease runtimeSessionSearchLease) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{"organization_id": lease.Binding.Scope.OrganizationID().String(), "workspace_id": lease.Binding.Scope.WorkspaceID().String(), "environment_id": lease.Binding.Scope.EnvironmentID().String(), "batch_id": lease.Binding.BatchID.String(), "generation": lease.Binding.Generation, "receipt_digest": hex.EncodeToString(lease.Binding.ReceiptDigest[:]), "receipt_reference": lease.ReceiptReference, "receipt_version": lease.ReceiptVersion, "document_ids": lease.DocumentIDs, "attempt": lease.Attempt, "lease_until": lease.LeaseUntil})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRuntimeSessionSearchDatabaseClaimsExactCommittedAuthority(t *testing.T) {
	lease, _, _ := sessionSearchWorkerFixture(t)
	db := &sessionSearchDatabaseStub{body: sessionSearchLeaseJSON(t, lease)}
	authority, err := newPostgresRuntimeSessionSearchAuthority(db)
	if err != nil {
		t.Fatal(err)
	}
	got, err := authority.Claim(context.Background(), "search-worker", "search-lease-token-0001", 30)
	if err != nil || got == nil || !reflect.DeepEqual(*got, lease) || db.statement != `SELECT COALESCE(zasp_runtime_session_search_claim($1,$2,$3),'null'::jsonb)` || !reflect.DeepEqual(db.args, []any{"search-worker", "search-lease-token-0001", 30}) {
		t.Fatalf("claim=%#v err=%v query=%s", got, err, db.statement)
	}
	db.body = json.RawMessage(`null`)
	if got, err := authority.Claim(context.Background(), "search-worker", "search-lease-token-0001", 30); err != nil || got != nil {
		t.Fatal("empty committed queue was not empty")
	}
	db.body = nil
	if got, err := authority.Claim(context.Background(), "search-worker", "search-lease-token-0001", 30); err == nil || got != nil {
		t.Fatal("empty database payload was mistaken for an idle queue")
	}
	for _, fault := range []string{"scope", "attempt", "expired", "digest", "documents", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			body := map[string]any{}
			if json.Unmarshal(sessionSearchLeaseJSON(t, lease), &body) != nil {
				t.Fatal("fixture")
			}
			switch fault {
			case "scope":
				body["organization_id"] = "foreign"
			case "attempt":
				body["attempt"] = 0
			case "expired":
				body["lease_until"] = time.Now().Add(-time.Second)
			case "digest":
				body["receipt_digest"] = "bad"
			case "documents":
				body["document_ids"] = []string{}
			case "unknown":
				body["query"] = "match_all"
			}
			db.body, _ = json.Marshal(body)
			if got, err := authority.Claim(context.Background(), "search-worker", "search-lease-token-0001", 30); err == nil || got != nil {
				t.Fatal("invalid database lease accepted")
			}
		})
	}
}

func TestRuntimeSessionSearchDatabaseFencesCompletionAndRejectsForgedAck(t *testing.T) {
	lease, _, _ := sessionSearchWorkerFixture(t)
	now := time.Now().UTC()
	body := map[string]any{"state": "indexed", "batch_id": lease.Binding.BatchID.String(), "generation": lease.Binding.Generation, "attempt": lease.Attempt, "receipt_digest": hex.EncodeToString(lease.Binding.ReceiptDigest[:]), "indexed_at": now}
	raw, _ := json.Marshal(body)
	db := &sessionSearchDatabaseStub{body: raw}
	authority, _ := newPostgresRuntimeSessionSearchAuthority(db)
	if err := authority.Finish(context.Background(), lease, "search-worker", "search-lease-token-0001", "indexed", lease.DocumentIDs, 0); err != nil {
		t.Fatal(err)
	}
	if db.statement != `SELECT zasp_runtime_session_search_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)` || len(db.args) != 12 || db.args[0] != lease.Binding.Scope.OrganizationID().String() || db.args[5] != "search-worker" || db.args[6] != "search-lease-token-0001" || db.args[7] != 1 {
		t.Fatal("checkpoint lost lease binding")
	}
	for _, field := range []string{"state", "batch_id", "generation", "attempt", "receipt_digest", "indexed_at"} {
		t.Run(field, func(t *testing.T) {
			mutated := map[string]any{}
			for key, value := range body {
				mutated[key] = value
			}
			delete(mutated, field)
			db.body, _ = json.Marshal(mutated)
			if err := authority.Finish(context.Background(), lease, "search-worker", "search-lease-token-0001", "indexed", lease.DocumentIDs, 0); err == nil {
				t.Fatal("incomplete acknowledgement accepted")
			}
		})
	}
	before := db.calls
	if err := authority.Finish(context.Background(), lease, "search-worker", "bad", "indexed", lease.DocumentIDs, 0); err == nil || db.calls != before {
		t.Fatal("invalid lease secret reached database")
	}
}
