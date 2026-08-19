package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type round4ReadinessDatabase struct {
	responses map[string]json.RawMessage
	errors    map[string]error
	queries   []string
	cancel    context.CancelFunc
}

func (*round4ReadinessDatabase) SchemaVersion(context.Context) (string, error) {
	return CoreSchemaVersion, nil
}

func (database *round4ReadinessDatabase) QueryJSON(ctx context.Context, query string, _ ...any) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	database.queries = append(database.queries, query)
	if query == postgresWorkflowReceiptCleanupSQL && database.cancel != nil {
		database.cancel()
	}
	if err := database.errors[query]; err != nil {
		return nil, err
	}
	return database.responses[query], nil
}

func (*round4ReadinessDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected exec")
}

func (*round4ReadinessDatabase) Close() error { return nil }

func TestEnvironmentListCarriesThePrincipalAuthorizationBoundary(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[]}`)}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	after := "pid_10000013-0000-4000-8000-000000000013"
	_, err = repository.ReadAdministration(context.Background(), identity, "listEnvironments", map[string]string{
		"workspace_id": identity.Scope.WorkspaceID().String(),
		"after_id":     after,
		"limit":        "25",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		identity.Scope.OrganizationID().String(),
		identity.Scope.WorkspaceID().String(),
		identity.PrincipalID.String(),
		after,
		26,
	}
	if database.query != postgresListEnvironmentsSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("environment list query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresListEnvironmentsSQL, want)
	}
}

func TestRevealGrantCleanupIsGloballyBoundedAndStrictlyDecoded(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(`{"cleaned":1000}`)}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := repository.CleanupExpiredAPITokenRevealGrants(context.Background(), 1000)
	if err != nil || cleaned != 1000 || database.query != postgresRevealGrantCleanupSQL || !reflect.DeepEqual(database.args, []any{1000}) {
		t.Fatalf("cleanup = (%d, %v) query=%q args=%#v", cleaned, err, database.query, database.args)
	}

	for name, payload := range map[string]json.RawMessage{
		"too many":       json.RawMessage(`{"cleaned":1001}`),
		"negative":       json.RawMessage(`{"cleaned":-1}`),
		"extra property": json.RawMessage(`{"cleaned":0,"unexpected":true}`),
		"wrong type":     json.RawMessage(`{"cleaned":"1"}`),
	} {
		t.Run(name, func(t *testing.T) {
			database.response = payload
			if _, err := repository.CleanupExpiredAPITokenRevealGrants(context.Background(), 1000); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("malformed cleanup response %s = %v", payload, err)
			}
		})
	}
	database.query = ""
	for _, limit := range []int{0, 1001} {
		if _, err := repository.CleanupExpiredAPITokenRevealGrants(context.Background(), limit); !errors.Is(err, ErrRepositoryOperation) || database.query != "" {
			t.Fatalf("invalid limit %d = %v query=%q", limit, err, database.query)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	database.query = ""
	if _, err := repository.CleanupExpiredAPITokenRevealGrants(cancelled, 1000); !errors.Is(err, context.Canceled) || database.query != "" {
		t.Fatalf("cancelled cleanup = %v query=%q", err, database.query)
	}
	if !strings.Contains(postgresRevealGrantCleanupSQL, "SKIP LOCKED") || !strings.Contains(postgresRevealGrantCleanupSQL, "LIMIT $1") {
		t.Fatalf("cleanup is not bounded and overlap-safe: %s", postgresRevealGrantCleanupSQL)
	}
}

func TestReadinessRunsBothGlobalCleanupsAndFailsClosed(t *testing.T) {
	database := &round4ReadinessDatabase{responses: map[string]json.RawMessage{
		postgresWorkflowReceiptCleanupSQL: json.RawMessage(`{"deleted":0}`),
		postgresRevealGrantCleanupSQL:     json.RawMessage(`{"cleaned":0}`),
	}, errors: map[string]error{}}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	wantQueries := []string{postgresWorkflowReceiptCleanupSQL, postgresRevealGrantCleanupSQL}
	if !reflect.DeepEqual(database.queries, wantQueries) {
		t.Fatalf("readiness queries = %#v, want %#v", database.queries, wantQueries)
	}

	database.queries = nil
	database.errors[postgresRevealGrantCleanupSQL] = errors.New("database unavailable")
	if err := repository.Ready(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("reveal cleanup error = %v", err)
	}
	if !reflect.DeepEqual(database.queries, wantQueries) {
		t.Fatalf("failed readiness queries = %#v, want %#v", database.queries, wantQueries)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	database.errors = map[string]error{}
	database.queries = nil
	database.cancel = cancel
	if err := repository.Ready(cancelled); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("cancelled readiness = %v", err)
	}
	if !reflect.DeepEqual(database.queries, []string{postgresWorkflowReceiptCleanupSQL}) {
		t.Fatalf("cancelled readiness queried after cancellation: %#v", database.queries)
	}
}
