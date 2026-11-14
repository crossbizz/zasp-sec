package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type inventoryJSONDatabase struct {
	schema    string
	responses map[string]json.RawMessage
	statement string
	arguments []any
	err       error
}

func (database *inventoryJSONDatabase) SchemaVersion(context.Context) (string, error) {
	if database.err != nil {
		return "", database.err
	}
	return database.schema, nil
}

func (database *inventoryJSONDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	database.statement = statement
	database.arguments = append([]any(nil), arguments...)
	if database.err != nil {
		return nil, database.err
	}
	return append(json.RawMessage(nil), database.responses[statement]...), nil
}

func (*inventoryJSONDatabase) Exec(context.Context, string, ...any) error { return nil }

func inventoryScope(t *testing.T) domain.Scope {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_00000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_00000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_00000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func inventorySummaryJSON(id, kind string) string {
	return `{"id":"` + id + `","name":"Production","kind":"` + kind + `","owner":"","team":"","tags":[],"evidence_id":"pid_20000001-0000-4000-8000-000000000001","confidence_basis_points":9000,"first_seen":"2026-08-19T00:00:00Z","last_seen":"2026-08-19T01:00:00Z","observed_at":"2026-08-19T01:00:00Z","fresh_until":"2026-08-20T01:00:00Z","freshness_state":"fresh","version":1,` + inventoryDiscoveryJSON(kind) + `}`
}

// inventoryDiscoveryJSON is how the fixture object was found: an agent the
// provider's control plane lists and nobody owns yet, or a provider record.
func inventoryDiscoveryJSON(kind string) string {
	if kind == "agent" {
		return `"provider":"aws","source_kind":"aws_bedrock_agent","discovery":{"method":"provider_api","platform":"bedrock_agent","signals":[]},"management_state":"unmanaged"`
	}
	return `"provider":"aws","source_kind":"aws_role","discovery":{"method":"provider_api","platform":"aws_role","signals":[]},"management_state":"not_applicable"`
}

func TestInventoryRepositoryStrictPageAndDetailAuthority(t *testing.T) {
	entityID := "pid_10000001-0000-4000-8000-000000000001"
	nextID := "pid_10000002-0000-4000-8000-000000000002"
	database := &inventoryJSONDatabase{schema: TypedInventorySchemaVersion, responses: map[string]json.RawMessage{
		postgresInventoryReadinessSQL: json.RawMessage(`true`),
		postgresInventoryPageSQL:      json.RawMessage(`{"items":[` + inventorySummaryJSON(entityID, "agent") + `,` + inventorySummaryJSON(nextID, "agent") + `],"next_id":"` + nextID + `"}`),
		postgresInventoryDetailSQL:    json.RawMessage(`{"summary":` + inventorySummaryJSON(entityID, "agent") + `,"sources":[{"integration_id":"pid_30000001-0000-4000-8000-000000000001","provider":"aws","source":"aws","source_identifier":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","snapshot_id":"pid_40000001-0000-4000-8000-000000000001","generation":1,"evidence_id":"pid_20000001-0000-4000-8000-000000000001","confidence_basis_points":9000,"observed_at":"2026-08-19T01:00:00Z","fresh_until":"2026-08-20T01:00:00Z","projection_version":1,"winning":true}],"evidence":[{"id":"pid_20000001-0000-4000-8000-000000000001","checksum":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","media_type":"application/json","schema_version":"raw-v1","parser_version":"parser-v1","tool_version":"tool-v1","collected_at":"2026-08-19T01:00:00Z","size_bytes":128}]}`),
	}}
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	page, err := repository.ListInventoryPage(context.Background(), inventoryScope(t), InventoryKindAgent, "", 2)
	if err != nil || len(page.Items) != 2 || page.NextKey != nextID || database.statement != postgresInventoryPageSQL || len(database.arguments) != 6 || database.arguments[3] != InventoryKindAgent || database.arguments[4] != "" || database.arguments[5] != 2 {
		t.Fatalf("page=%#v statement=%q args=%#v err=%v", page, database.statement, database.arguments, err)
	}
	id, _ := domain.ParseProductID(entityID)
	detail, err := repository.GetInventory(context.Background(), inventoryScope(t), id, InventoryKindAgent)
	if err != nil || detail.Summary.ID != entityID || len(detail.Sources) != 1 || !detail.Sources[0].Winning || len(detail.Evidence) != 1 {
		t.Fatalf("detail=%#v err=%v", detail, err)
	}
}

func TestInventoryRepositoryUpdatesOnlyCanonicalAgentOwnership(t *testing.T) {
	entityID := "pid_10000001-0000-4000-8000-000000000001"
	updated := replaceInventoryJSON(replaceInventoryJSON(replaceInventoryJSON(replaceInventoryJSON(inventorySummaryJSON(entityID, "agent"), `"owner":""`, `"owner":"security"`), `"team":""`, `"team":"platform"`), `"tags":[]`, `"tags":["critical","production"]`), `"version":1`, `"version":2`)
	updated = replaceInventoryJSON(updated, `"management_state":"unmanaged"`, `"management_state":"managed"`)
	database := &inventoryJSONDatabase{schema: TypedInventorySchemaVersion, responses: map[string]json.RawMessage{
		postgresInventoryReadinessSQL:   json.RawMessage(`true`),
		postgresInventoryUpdateAgentSQL: json.RawMessage(`{"agent":` + updated + `,"audit_id":"pid_60000001-0000-4000-8000-000000000001","correlation_id":"pid_60000002-0000-4000-8000-000000000002","replayed":false}`),
	}}
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	id, _ := domain.ParseProductID(entityID)
	result, err := repository.UpdateAgentOwnership(context.Background(), identity, id, 1, "agent-owner-key-0001", AgentOwnershipInput{Owner: "security", Team: "platform", Tags: []string{"critical", "production"}}, "pid_60000001-0000-4000-8000-000000000001", "pid_60000002-0000-4000-8000-000000000002")
	if err != nil || result.Agent.ID != entityID || result.Agent.Version != 2 || result.AuditID != "pid_60000001-0000-4000-8000-000000000001" || result.Replayed || database.statement != postgresInventoryUpdateAgentSQL || len(database.arguments) != 12 {
		t.Fatalf("result=%#v statement=%q args=%#v err=%v", result, database.statement, database.arguments, err)
	}
}

func TestInventoryRepositoryRejectsMalformedTypedAuthority(t *testing.T) {
	entityID := "pid_10000001-0000-4000-8000-000000000001"
	tests := map[string]string{
		"missing evidence":  `{"items":[` + inventorySummaryJSON(entityID, "agent")[:len(inventorySummaryJSON(entityID, "agent"))-1] + `,"evidence_id":""}],"next_id":null}`,
		"wrong kind":        `{"items":[` + inventorySummaryJSON(entityID, "tool") + `],"next_id":null}`,
		"noncanonical time": `{"items":[` + replaceInventoryJSON(inventorySummaryJSON(entityID, "agent"), "2026-08-19T00:00:00Z", "2026-08-19T00:00:00+00:00") + `],"next_id":null}`,
		"secret field":      `{"items":[` + inventorySummaryJSON(entityID, "agent")[:len(inventorySummaryJSON(entityID, "agent"))-1] + `,"credential_reference":"ref:secret/value"}],"next_id":null}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			database := &inventoryJSONDatabase{schema: TypedInventorySchemaVersion, responses: map[string]json.RawMessage{postgresInventoryReadinessSQL: json.RawMessage(`true`), postgresInventoryPageSQL: json.RawMessage(payload)}}
			repository, err := NewPostgresInventoryRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repository.ListInventoryPage(context.Background(), inventoryScope(t), InventoryKindAgent, "", 100); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func replaceInventoryJSON(value, old, replacement string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + replacement + value[index+len(old):]
		}
	}
	return value
}

func TestInventoryRepositoryRequiresExactTypedAuthority(t *testing.T) {
	for _, schema := range []string{DiscoveryExecutionSchemaVersion, "future-v16"} {
		database := &inventoryJSONDatabase{schema: schema, responses: map[string]json.RawMessage{postgresInventoryReadinessSQL: json.RawMessage(`true`)}}
		if _, err := NewPostgresInventoryRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("schema=%q error=%v", schema, err)
		}
	}
	for _, test := range []struct {
		schema    string
		statement string
	}{
		{schema: TypedInventorySchemaVersion, statement: postgresInventoryReadinessSQL},
		{schema: RuntimeDataPlaneSchemaVersion, statement: postgresRuntimeDataPlaneReadinessSQL},
		{schema: RuntimeGatewayReconciliationSchemaVersion, statement: postgresRuntimeGatewayReconciliationReadinessSQL},
		{schema: RuntimeIngestReconciliationSchemaVersion, statement: postgresRuntimeIngestReconciliationReadinessSQL},
	} {
		database := &inventoryJSONDatabase{schema: test.schema, responses: map[string]json.RawMessage{test.statement: json.RawMessage(`true`)}}
		if _, err := NewPostgresInventoryRepository(database); err != nil || database.statement != test.statement {
			t.Fatalf("schema=%q statement=%q error=%v", test.schema, database.statement, err)
		}
	}
	database := &inventoryJSONDatabase{schema: RuntimeDataPlaneSchemaVersion, responses: map[string]json.RawMessage{postgresRuntimeDataPlaneReadinessSQL: json.RawMessage(`false`)}}
	if _, err := NewPostgresInventoryRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("false readiness error=%v", err)
	}
}

func TestInventorySummaryDiscoveryIsConsistentWithKindAndOwner(t *testing.T) {
	entityID := "pid_10000001-0000-4000-8000-000000000001"
	decode := func(raw string, kind InventoryKind) bool {
		var item InventorySummary
		return decodeStrictInventory(json.RawMessage(raw), &item) == nil && validInventorySummary(item, kind)
	}
	agent := inventorySummaryJSON(entityID, "agent")
	owned := replaceInventoryJSON(replaceInventoryJSON(agent, `"owner":""`, `"owner":"security"`), `"management_state":"unmanaged"`, `"management_state":"managed"`)
	inferred := replaceInventoryJSON(replaceInventoryJSON(agent, `"method":"provider_api"`, `"method":"inferred"`), `"signals":[]`, `"signals":["env:openai","package:langgraph"]`)
	declared := replaceInventoryJSON(replaceInventoryJSON(agent, `"method":"provider_api"`, `"method":"declared"`), `"management_state":"unmanaged"`, `"management_state":"managed"`)
	for name, raw := range map[string]string{"unowned provider agent": agent, "owned provider agent": owned, "inferred agent": inferred, "declared agent": declared} {
		if !decode(raw, InventoryKindAgent) {
			t.Errorf("%s refused: %s", name, raw)
		}
	}
	if !decode(inventorySummaryJSON(entityID, "identity"), InventoryKindIdentity) {
		t.Error("provider identity refused")
	}
	for name, raw := range map[string]string{
		"ownerless agent called managed":  replaceInventoryJSON(agent, `"management_state":"unmanaged"`, `"management_state":"managed"`),
		"owned agent called unmanaged":    replaceInventoryJSON(agent, `"owner":""`, `"owner":"security"`),
		"declared agent called unmanaged": replaceInventoryJSON(agent, `"method":"provider_api"`, `"method":"declared"`),
		"inferred agent without a signal": replaceInventoryJSON(agent, `"method":"provider_api"`, `"method":"inferred"`),
		"unsorted signals":                replaceInventoryJSON(inferred, `["env:openai","package:langgraph"]`, `["package:langgraph","env:openai"]`),
		"provider value as signal":        replaceInventoryJSON(inferred, `"env:openai"`, `"env:OPENAI_API_KEY=sk-live"`),
		"unknown provider":                replaceInventoryJSON(agent, `"provider":"aws"`, `"provider":"azure"`),
		"unknown method":                  replaceInventoryJSON(agent, `"method":"provider_api"`, `"method":"guessed"`),
		"missing discovery":               replaceInventoryJSON(agent, `"discovery":{"method":"provider_api","platform":"bedrock_agent","signals":[]},`, ``),
		"agent called not applicable":     replaceInventoryJSON(agent, `"management_state":"unmanaged"`, `"management_state":"not_applicable"`),
	} {
		if decode(raw, InventoryKindAgent) {
			t.Errorf("%s accepted: %s", name, raw)
		}
	}
	identity := inventorySummaryJSON(entityID, "identity")
	for name, raw := range map[string]string{
		"identity called unmanaged": replaceInventoryJSON(identity, `"management_state":"not_applicable"`, `"management_state":"unmanaged"`),
		"identity called inferred":  replaceInventoryJSON(replaceInventoryJSON(identity, `"method":"provider_api"`, `"method":"inferred"`), `"signals":[]`, `"signals":["env:openai"]`),
	} {
		if decode(raw, InventoryKindIdentity) {
			t.Errorf("%s accepted: %s", name, raw)
		}
	}
}
