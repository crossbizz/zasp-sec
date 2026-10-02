package apiserver

import (
	"context"
	"encoding/json"
	"testing"
)

type approvalContextDatabase struct {
	*securityAgentRepositoryDatabase
	available bool
	failure   error
}

func (db *approvalContextDatabase) SecurityAgentRunContextAvailable(context.Context) (bool, error) {
	return db.available, db.failure
}

func TestSecurityAgentApprovalContextRepository(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	approval, contextValue := approvalContextFixture("update_finding_response")
	envelope, _ := json.Marshal(map[string]any{"detail": approval, "context": contextValue})
	page, _ := json.Marshal(map[string]any{"items": []json.RawMessage{envelope}, "next_id": nil, "next_created_at": nil})
	db := &approvalContextDatabase{securityAgentRepositoryDatabase: &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		"SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)":                                                   envelope,
		"SELECT zasp_production_security_agent_run_context_approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8)": page,
	}}, available: true}
	repo := &PostgresRepository{database: db, securityAgentExecution: true}
	detail, err := repo.GetSecurityAgentApproval(context.Background(), identity, approval.ID)
	if err != nil {
		t.Fatal("registered context detail unavailable", err)
	}
	raw, _ := json.Marshal(detail)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if len(fields["approval_context"]) == 0 {
		t.Fatal("registered context missing")
	}
	got, err := repo.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{State: "pending", RunID: approval.RunID, Limit: 2})
	if err != nil || len(got.Items) != 1 {
		t.Fatal("registered context page unavailable", err)
	}
	raw, _ = json.Marshal(got.Items[0])
	fields = nil
	json.Unmarshal(raw, &fields)
	if len(fields["approval_context"]) == 0 {
		t.Fatal("page context missing")
	}
	for _, args := range db.arguments {
		if len(args) < 4 || args[0] != identity.Scope.OrganizationID().String() || args[1] != identity.Scope.WorkspaceID().String() || args[2] != identity.Scope.EnvironmentID().String() {
			t.Fatal("context query lost scope")
		}
	}
	contextValue["approval_id"] = "pid_99000009-0000-4000-8000-000000000009"
	invalid, _ := json.Marshal(map[string]any{"detail": approval, "context": contextValue})
	db.responses["SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)"] = invalid
	if _, err := repo.GetSecurityAgentApproval(context.Background(), identity, approval.ID); err != ErrRepositoryUnavailable {
		t.Fatal("foreign context accepted", err)
	}
	invalidPage, _ := json.Marshal(map[string]any{"items": []json.RawMessage{invalid}, "next_id": nil, "next_created_at": nil})
	db.responses[postgresApprovalContextPageSQL] = invalidPage
	if _, err := repo.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{Limit: 2}); err != ErrRepositoryUnavailable {
		t.Fatal("foreign page context accepted", err)
	}
	db.failure = ErrRepositoryUnavailable
	before := len(db.statements)
	if _, err := repo.GetSecurityAgentApproval(context.Background(), identity, approval.ID); err != ErrRepositoryUnavailable || len(db.statements) != before {
		t.Fatal("failed release probe fell back")
	}
	if _, err := repo.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{Limit: 2}); err != ErrRepositoryUnavailable || len(db.statements) != before {
		t.Fatal("failed list release probe fell back")
	}
}

func TestSecurityAgentApprovalContextLegacyRouting(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	approval, _ := approvalContextFixture("update_finding_response")
	detail, _ := json.Marshal(approval)
	page, _ := json.Marshal(map[string]any{"items": []SecurityAgentApproval{approval}, "next_created_at": nil, "next_id": nil})
	for _, capabilityAbsent := range []bool{true, false} {
		db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentApprovalDetailV24SQL: detail, postgresSecurityAgentApprovalPageV24SQL: page}}
		var database JSONDatabase = db
		if !capabilityAbsent {
			database = &approvalContextDatabase{securityAgentRepositoryDatabase: db, available: false}
		}
		repository := &PostgresRepository{database: database, securityAgentExecution: true, schema: SecurityAgentSessionIsolationSchemaVersion}
		got, err := repository.GetSecurityAgentApproval(context.Background(), identity, approval.ID)
		if err != nil || got.Context != nil || got.ID != approval.ID {
			t.Fatal("legacy detail routing changed", err)
		}
		listed, err := repository.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{Limit: 2})
		if err != nil || len(listed.Items) != 1 || listed.Items[0].Context != nil {
			t.Fatal("legacy page routing changed", err)
		}
		if len(db.statements) != 2 || db.statements[0] != postgresSecurityAgentApprovalDetailV24SQL || db.statements[1] != postgresSecurityAgentApprovalPageV24SQL {
			t.Fatal("legacy capability used context SQL")
		}
	}
}
