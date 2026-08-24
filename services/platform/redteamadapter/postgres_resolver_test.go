package redteamadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type jsonDatabaseStub struct {
	responses  map[string]json.RawMessage
	statements []string
	arguments  [][]any
	err        error
}

func (stub *jsonDatabaseStub) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	stub.statements = append(stub.statements, statement)
	stub.arguments = append(stub.arguments, append([]any(nil), arguments...))
	if stub.err != nil {
		return nil, stub.err
	}
	return append(json.RawMessage(nil), stub.responses[statement]...), nil
}

func TestPostgresResolverChecksExactReleaseAndResolvesTenantFreshBinding(t *testing.T) {
	database := &jsonDatabaseStub{responses: map[string]json.RawMessage{
		postgresTargetAdapterReadinessSQL: json.RawMessage(`true`),
		postgresResolveTargetSQL:          json.RawMessage(`{"target_id":"` + testTargetID + `","target_kind":"agent_endpoint","endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/target-0001","version":7}`),
	}}
	checksum, fingerprint := strings64("a"), strings64("b")
	resolver, err := NewPostgresResolver(database, checksum, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	binding, err := resolver.ResolveTarget(context.Background(), testScope(t), testTargetID, "agent_endpoint")
	if err != nil || binding.Version != 7 || binding.TargetID != testTargetID {
		t.Fatalf("binding=%#v err=%v", binding, err)
	}
	if !reflect.DeepEqual(database.statements, []string{postgresTargetAdapterReadinessSQL, postgresResolveTargetSQL}) || !reflect.DeepEqual(database.arguments[0], []any{checksum, fingerprint}) || !reflect.DeepEqual(database.arguments[1], []any{testOrganizationID, testWorkspaceID, testEnvironmentID, testTargetID, "agent_endpoint"}) {
		t.Fatalf("calls = %#v %#v", database.statements, database.arguments)
	}
}

func TestPostgresResolverRejectsReleaseDriftAndCrossTargetOutput(t *testing.T) {
	for name, database := range map[string]*jsonDatabaseStub{
		"not ready":      {responses: map[string]json.RawMessage{postgresTargetAdapterReadinessSQL: json.RawMessage(`false`)}},
		"database error": {err: errors.New("database-secret")},
	} {
		resolver, err := NewPostgresResolver(database, strings64("a"), strings64("b"))
		if err != nil {
			t.Fatal(err)
		}
		if err := resolver.Ready(context.Background()); !errors.Is(err, ErrAdapter) || stringsContains(err, "database-secret") {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	database := &jsonDatabaseStub{responses: map[string]json.RawMessage{postgresResolveTargetSQL: json.RawMessage(`{"target_id":"` + testRunID + `","target_kind":"agent_endpoint","endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/target-0001","version":1}`)}}
	resolver, err := NewPostgresResolver(database, strings64("a"), strings64("b"))
	if err != nil {
		t.Fatal(err)
	}
	if binding, err := resolver.ResolveTarget(context.Background(), testScope(t), testTargetID, "agent_endpoint"); !errors.Is(err, ErrAdapter) || binding != (TargetBinding{}) {
		t.Fatalf("binding=%#v err=%v", binding, err)
	}
}

func strings64(value string) string {
	return value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value + value
}

func stringsContains(err error, value string) bool {
	return err != nil && strings.Contains(err.Error(), value)
}
