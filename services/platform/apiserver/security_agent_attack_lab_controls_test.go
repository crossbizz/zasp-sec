package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type attackLabControlDatabase struct{ existingTestReadRouteDatabase }

func (*attackLabControlDatabase) SecurityAgentAttackLabAvailable(context.Context) (bool, error) {
	return true, nil
}

func TestSecurityAgentAttackLabControlsRequireRegisteredSevenActionShape(t *testing.T) {
	value := SecurityAgentExecutionControls{Global: SecurityAgentExecutionControl{Target: "global", ActionKey: "*", Version: 1}, Environment: SecurityAgentExecutionControl{Target: "environment", ActionKey: "*"}}
	for _, key := range []string{"create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"} {
		value.Actions = append(value.Actions, SecurityAgentExecutionControl{Target: "action", ActionKey: key})
	}
	if !validSecurityAgentExecutionControls(value) {
		t.Fatal("seven registered controls rejected")
	}
	raw, _ := json.Marshal(value)
	db := &attackLabControlDatabase{existingTestReadRouteDatabase{workflowCallDatabase: workflowCallDatabase{response: raw}, available: true}}
	repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
	if _, err := repo.GetSecurityAgentExecutionControls(context.Background(), fixtureRequestIdentity(t)); err != nil {
		t.Fatal(err)
	}
	value.Actions = append(value.Actions[:5], value.Actions[6:]...)
	db.response, _ = json.Marshal(value)
	if _, err := repo.GetSecurityAgentExecutionControls(context.Background(), fixtureRequestIdentity(t)); err == nil {
		t.Fatal("installed57 silently accepted missing action control")
	}
}

func TestSecurityAgentAttackLabControlMutationReachesRegisteredAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(time.Minute)
	input := SecurityAgentExecutionControlMutation{Target: "action", ActionKey: "start_attack_lab", Enabled: true, IdempotencyKey: "attack-lab-controls-0001", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: "pid_8ba10000-0000-4000-8000-000000000001", CorrelationID: "pid_8ba10000-0000-4000-8000-000000000002", ReceiptID: "pid_8ba10000-0000-4000-8000-000000000003"}
	raw, _ := json.Marshal(SecurityAgentExecutionControlResult{Target: input.Target, ActionKey: input.ActionKey, Enabled: true, Version: 1, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID})
	db := &attackLabControlDatabase{existingTestReadRouteDatabase{workflowCallDatabase: workflowCallDatabase{response: raw}, available: true}}
	repo := &PostgresRepository{database: db, securityAgentExecution: true, schema: ProductionRecoverySchemaVersion}
	if _, err := repo.SetSecurityAgentExecutionControl(context.Background(), identity, input); err != nil {
		t.Fatal(err)
	}
	if db.query != postgresExistingTestSetControlSQL {
		t.Fatalf("wrong authority %s", db.query)
	}
}
