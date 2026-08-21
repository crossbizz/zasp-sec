package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

type securityAgentRepositoryDatabase struct {
	responses  map[string]json.RawMessage
	statements []string
	arguments  [][]any
}

func TestSecurityAgentPostgresRepositoryActivatesWithExactScopeAndReceiptAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Date(2026, 8, 21, 12, 4, 0, 0, time.UTC)
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	correlationID := "pid_78000003-0000-4000-8000-000000000003"
	receiptID := "pid_78000004-0000-4000-8000-000000000004"
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentAuthorityReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActivateSQL:       json.RawMessage(`{"id":"` + definitionID + `","activation":"validated","enabled":false,"version":2,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	input := SecurityAgentActivation{DefinitionID: definitionID, IdempotencyKey: "activate-agent-idem-0001", ExpectedVersion: 1, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	result, err := repository.ActivateSecurityAgent(context.Background(), identity, input)
	if err != nil || result.Version != 2 || result.Replayed {
		t.Fatalf("activation=%#v err=%v", result, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID, identity.PrincipalID.String(), input.IdempotencyKey, int64(1), "validated", identity.FreshAuthExpiresAt, auditID, correlationID, receiptID}
	if database.statements[1] != postgresSecurityAgentActivateSQL || !reflect.DeepEqual(database.arguments[1], want) {
		t.Fatalf("statement=%q args=%#v", database.statements[1], database.arguments[1])
	}
}

func (*securityAgentRepositoryDatabase) SchemaVersion(context.Context) (string, error) {
	return "", errors.New("security agent authority must not read schema metadata")
}
func (database *securityAgentRepositoryDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	database.statements = append(database.statements, statement)
	database.arguments = append(database.arguments, append([]any(nil), arguments...))
	value, ok := database.responses[statement]
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	return append(json.RawMessage(nil), value...), nil
}
func (*securityAgentRepositoryDatabase) Exec(context.Context, string, ...any) error { return nil }

func TestSecurityAgentPostgresRepositoryUsesOnlyV18ScopedAuthority(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentAuthorityReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentDefinitionPageSQL: json.RawMessage(`{"items":[{"id":"pid_78000001-0000-4000-8000-000000000001","enabled":false}],"next_id":null}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	page, err := repository.ListWorkflowPage(context.Background(), scope, "security_agent", "", 10)
	if err != nil || len(page.Items) != 1 || page.NextID != "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if len(database.statements) != 2 || database.statements[0] != postgresSecurityAgentAuthorityReadySQL || database.statements[1] != postgresSecurityAgentDefinitionPageSQL {
		t.Fatalf("statements=%#v", database.statements)
	}
	if _, err := repository.ListWorkflowPage(context.Background(), scope, "policy", "", 10); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("foreign kind error=%v", err)
	}
}

func TestSecurityAgentPostgresRepositoryRejectsUnreadyOrMalformedAuthority(t *testing.T) {
	for _, payload := range []string{`{"release":false,"principal":true}`, `{"release":true,"principal":false}`, `{"release":true,"principal":true,"extra":true}`, `null`} {
		database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentAuthorityReadySQL: json.RawMessage(payload)}}
		if _, err := NewSecurityAgentPostgresRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("payload=%s error=%v", payload, err)
		}
	}
}
