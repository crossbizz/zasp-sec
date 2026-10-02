package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestFindingResponseProductUsesOnlyScopedFindingOperations(t *testing.T) {
	ref := orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}
	start := orchestration.StartRequest{Ref: ref, DefinitionVersion: 7, InputDigest: strings.Repeat("a", 64)}
	workflowID := "security-agent-finding/v1/" + ref.OrganizationID + "/" + ref.WorkspaceID + "/" + ref.EnvironmentID + "/" + ref.RunID
	scope, err := temporalScope(start)
	if err != nil {
		t.Fatal(err)
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", ref.RunID+"\x1f0")
	outcome, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_effect", ref.RunID+"\x1f"+step+"\x1fupdate_finding_response")
	applies := 0
	wrongIdentity := false
	db := singleDeliveryDatabaseFunc(func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
		raw, _ := json.Marshal(args[0])
		want, _ := json.Marshal(temporalStartFields(start))
		if !jsonEqualWorker(raw, want) {
			t.Fatal("unscoped finding request")
		}
		switch sql {
		case `SELECT zasp_temporal78.inspect($1::jsonb)`:
			id := workflowID
			if wrongIdentity {
				id = "security-agent-test/v1/" + ref.RunID
			}
			return json.Marshal(map[string]any{"phase": "apply", "workflow_id": id, "step_id": step, "action_key": "update_finding_response", "run_state": "queued", "planning_state": "admitted", "deadline": nil, "unresolved": false})
		case `SELECT zasp_temporal78.apply($1::jsonb)`:
			applies++
			return json.Marshal(map[string]any{"contract_version": 78, "workflow_id": workflowID, "run_id": ref.RunID, "step_id": step, "state": "remediated", "outcome_id": outcome, "result_digest": "sha256:" + strings.Repeat("b", 64)})
		default:
			t.Fatalf("finding used unrelated operation %s", sql)
			return nil, nil
		}
	})
	shared := &temporalSecurityAgentProduct{executor: db}
	factory, ok := any(shared).(interface {
		FindingResponseProduct() orchestration.FindingResponseProduct
	})
	if !ok {
		t.Fatal("finding product integration missing")
	}
	product := factory.FindingResponseProduct()
	state, err := product.Observe(context.Background(), start)
	if err != nil || state.Phase != "apply" {
		t.Fatal("finding observation", state, err)
	}
	if err := product.Apply(context.Background(), start); err != nil || applies != 1 {
		t.Fatal("finding apply", applies, err)
	}
	wrongIdentity = true
	if err := product.Apply(context.Background(), start); err == nil || applies != 1 {
		t.Fatal("cross-family observation executed finding effect", applies, err)
	}
}
