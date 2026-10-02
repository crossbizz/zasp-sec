package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSecurityAgentPlannerContextRecognizesOnlyBoundDurableStop(t *testing.T) {
	claim := SecurityAgentRunClaim{OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003", RunID: "pid_78000001-0000-4000-8000-000000000001", DefinitionID: "pid_78000002-0000-4000-8000-000000000002", DefinitionVersion: 3, TriggerID: "pid_78000003-0000-4000-8000-000000000003", State: "planning", Version: 2, Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	for _, name := range []string{"valid", "heartbeat", "foreign organization", "foreign workspace", "foreign environment", "foreign run", "wrong attempt", "wrong version", "huge version", "wrong state", "unknown reason", "null reason", "extra context", "missing attempt"} {
		t.Run(name, func(t *testing.T) {
			stop := map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "attempt": 1, "version": 3, "state": "needs_human", "reason": "budget_deadline_exceeded"}
			envelope := map[string]any{"budget_stop": stop}
			switch name {
			case "foreign organization":
				stop["organization_id"] = claim.RunID
			case "foreign workspace":
				stop["workspace_id"] = claim.RunID
			case "foreign environment":
				stop["environment_id"] = claim.RunID
			case "foreign run":
				stop["run_id"] = claim.TriggerID
			case "wrong attempt":
				stop["attempt"] = 2
			case "wrong version":
				stop["version"] = 2
			case "heartbeat":
				stop["version"] = 4
			case "huge version":
				stop["version"] = 1000001
			case "wrong state":
				stop["state"] = "planning"
			case "unknown reason":
				stop["reason"] = "provider_unavailable"
			case "null reason":
				stop["reason"] = nil
			case "extra context":
				envelope["context"] = map[string]any{}
			case "missing attempt":
				delete(stop, "attempt")
			}
			payload, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentWorkerReadyV33SQL: json.RawMessage(`{"release":true,"principal":true}`), postgresSecurityAgentPlannerContextV33SQL: payload}}
			repository, err := NewSecurityAgentWorkerRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			result, err := repository.LoadSecurityAgentPlannerContext(context.Background(), claim, "security-agent-worker-1", "lease-token-000000000001")
			if !reflect.DeepEqual(result, SecurityAgentPlannerContext{}) {
				t.Fatalf("stop returned usable authority: %#v", result)
			}
			if name == "valid" || name == "heartbeat" {
				if !errors.Is(err, ErrSecurityAgentBudgetStopped) {
					t.Fatalf("stop was not typed: %v", err)
				}
			} else if !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("malformed stop accepted: %v", err)
			}
		})
	}
}
