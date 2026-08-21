package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type securityAgentRepositoryDatabase struct {
	responses  map[string]json.RawMessage
	statements []string
	arguments  [][]any
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
