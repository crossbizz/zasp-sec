package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type referenceAuthorizationDatabaseStub struct {
	query     string
	arguments []any
	responses map[string]json.RawMessage
}

func (*referenceAuthorizationDatabaseStub) SchemaVersion(context.Context) (string, error) {
	return ReferenceSchemaVersion, nil
}

func (*referenceAuthorizationDatabaseStub) Exec(context.Context, string, ...any) error { return nil }

func (database *referenceAuthorizationDatabaseStub) QueryJSON(_ context.Context, query string, arguments ...any) (json.RawMessage, error) {
	database.query = query
	database.arguments = append([]any(nil), arguments...)
	response, exists := database.responses[query]
	if !exists {
		return nil, errors.New("missing response")
	}
	return response, nil
}

func TestReferenceAuthorizationRepositoryReplaysWithoutLiveConfigurationAndStrictlyDecodes(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	validBody := `{"id":"` + integrationID + `","connector_key":"aws","name":"AWS","configuration":{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z"}`
	database := &referenceAuthorizationDatabaseStub{responses: map[string]json.RawMessage{
		postgresReferenceAuthorizationReadySQL:  json.RawMessage(`true`),
		postgresReplayReferenceAuthorizationSQL: json.RawMessage(`{"found":true,"result":{"body":` + validBody + `,"version":2,"secret_generation":0,"audit_id":"pid_74000006-0000-4000-8000-000000000006","correlation_id":"pid_74000007-0000-4000-8000-000000000007","receipt_id":"pid_74000008-0000-4000-8000-000000000008","replayed":true}}`),
	}}
	repository, err := NewReferenceAuthorizationRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	input := ReferenceAuthorizationReplay{IntegrationID: integrationID, IdempotencyKey: "reference-authorize-0001", ExpectedVersion: 1}
	result, found, err := repository.Replay(context.Background(), identity, input)
	if err != nil || !found || !result.Replayed || result.Version != 2 {
		t.Fatalf("reference replay=%#v found=%t err=%v", result, found, err)
	}
	wantArguments := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), integrationID, input.IdempotencyKey, int64(1)}
	if database.query != postgresReplayReferenceAuthorizationSQL || !reflect.DeepEqual(database.arguments, wantArguments) {
		t.Fatalf("reference replay query=%q args=%#v", database.query, database.arguments)
	}
	for _, hostile := range []json.RawMessage{
		json.RawMessage(`{"found":true,"result":{"body":{"id":"pid_74000009-0000-4000-8000-000000000009","connector_key":"aws","status":"active"},"version":2,"secret_generation":0,"audit_id":"pid_74000006-0000-4000-8000-000000000006","correlation_id":"pid_74000007-0000-4000-8000-000000000007","receipt_id":"pid_74000008-0000-4000-8000-000000000008","replayed":true}}`),
		json.RawMessage(`{"found":true,"result":{"body":{"id":"` + integrationID + `","connector_key":"aws","status":"active"},"version":2,"secret_generation":0,"audit_id":"pid_74000006-0000-4000-8000-000000000006","correlation_id":"pid_74000007-0000-4000-8000-000000000007","receipt_id":"pid_74000008-0000-4000-8000-000000000008","replayed":true,"token":"leak"}}`),
		json.RawMessage(`{"found":true,"result":{"body":{"id":"` + integrationID + `","connector_key":"aws","name":"AWS","configuration":{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z","access_token":"leak"},"version":2,"secret_generation":0,"audit_id":"pid_74000006-0000-4000-8000-000000000006","correlation_id":"pid_74000007-0000-4000-8000-000000000007","receipt_id":"pid_74000008-0000-4000-8000-000000000008","replayed":true}}`),
		json.RawMessage(`{"found":true,"result":{"body":{"id":"` + integrationID + `","connector_key":"github","status":"active"},"version":2,"secret_generation":0,"audit_id":"pid_74000006-0000-4000-8000-000000000006","correlation_id":"pid_74000007-0000-4000-8000-000000000007","receipt_id":"pid_74000008-0000-4000-8000-000000000008","replayed":true}}`),
	} {
		database.responses[postgresReplayReferenceAuthorizationSQL] = hostile
		if _, _, err := repository.Replay(context.Background(), identity, input); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("hostile reference replay %s err=%v", hostile, err)
		}
	}
}

func TestReferenceAuthorizationRepositoryRejectsIncompleteOrSensitiveIntegrationResults(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	database := &referenceAuthorizationDatabaseStub{responses: map[string]json.RawMessage{
		postgresReferenceAuthorizationReadySQL: json.RawMessage(`true`),
	}}
	repository, err := NewReferenceAuthorizationRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	input := ReferenceAuthorizationCompletion{
		IntegrationID: integrationID, Provider: "aws", ConnectionID: "pid_74000009-0000-4000-8000-000000000009", ConnectionReference: "ref:aws/external-id/customer-0001",
		IdempotencyKey: "reference-authorize-0001", ExpectedVersion: 1,
		Configuration: json.RawMessage(`{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"}`),
		Intent:        json.RawMessage(`{"configuration":{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"},"expected_version":1,"idempotency_key":"reference-authorize-0001","integration_id":"` + integrationID + `","provider":"aws","scope":{"environment_id":"` + identity.Scope.EnvironmentID().String() + `","organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `"}}`),
		AuditID:       "pid_74000006-0000-4000-8000-000000000006", CorrelationID: "pid_74000007-0000-4000-8000-000000000007", ReceiptID: "pid_74000008-0000-4000-8000-000000000008",
	}
	canonicalBody := `{"id":"` + integrationID + `","connector_key":"aws","name":"AWS","configuration":{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z"}`
	database.responses[postgresCompleteReferenceAuthorizationSQL] = json.RawMessage(`{"body":{"updated_at":"2026-08-19T00:01:00Z","status":"active","name":"AWS","id":"` + integrationID + `","created_at":"2026-08-19T00:00:00Z","configuration":{"region":"us-east-1","external_id_reference":"ref:aws/external-id/customer-0001","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"},"connector_key":"aws"},"version":2,"secret_generation":0,"audit_id":"` + input.AuditID + `","correlation_id":"` + input.CorrelationID + `","receipt_id":"` + input.ReceiptID + `","replayed":false}`)
	result, err := repository.Complete(context.Background(), identity, input)
	if err != nil || string(result.Body) != canonicalBody {
		t.Fatalf("canonical reference completion body=%s err=%v", result.Body, err)
	}
	for _, body := range []string{
		`{"id":"` + integrationID + `","connector_key":"aws","name":"AWS","configuration":{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z","refresh_token":"leak"}`,
		`{"id":"` + integrationID + `","connector_key":"aws","name":"AWS","configuration":{"role_arn":"arn:aws:iam::123456789012:role/zasp-discovery","external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1"},"status":"active","created_at":"2026-08-19T00:00:00Z"}`,
	} {
		database.responses[postgresCompleteReferenceAuthorizationSQL] = json.RawMessage(`{"body":` + body + `,"version":2,"secret_generation":0,"audit_id":"` + input.AuditID + `","correlation_id":"` + input.CorrelationID + `","receipt_id":"` + input.ReceiptID + `","replayed":false}`)
		if _, err := repository.Complete(context.Background(), identity, input); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("hostile reference completion %s err=%v", body, err)
		}
	}
}
