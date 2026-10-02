package apiserver

import (
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"testing"
	"time"
)

func TestSingleTestRecoveryStatementContracts(t *testing.T) {
	id := orderedPublicIdentity()
	q := recoveryWire(id, SingleTestRecoveryMutation{RunID: public62Finding, DefinitionVersion: 2, InputDigest: strings.Repeat("a", 64), ExpectedVersion: 3, IdempotencyKey: "single-recovery-test-0001", AuditID: public62Definition, CorrelationID: id.PrincipalID.String(), ReceiptID: public62Finding})
	grant := RequestAuthorization{OperationID: "requestSingleTestCleanupRecovery", Identity: id, PathParameters: map[string]string{"id": q.RunID}, Allowed: []AuthorizationTarget{{Scope: id.Scope, Kind: "security_agent_run", ID: q.RunID}}}
	for _, mode := range []string{"preflight", "admit", "get", "foreign", "revoked", "collection", "unknown", "extra", "duplicate", "bad_observation", "wrong_operation"} {
		t.Run(mode, func(t *testing.T) {
			g := grant
			sql := singleTestRecoveryPreflightSQL
			wire, _ := json.Marshal(q)
			args := []any{json.RawMessage(wire)}
			if mode == "admit" || mode == "bad_observation" {
				sql = singleTestRecoveryAdmitSQL
				wid, _ := orchestration.SingleTestWorkflowID(q.start().Ref)
				o := orchestration.SingleTestOriginalObservation{WorkflowID: wid, Status: "absent", ObservedAt: time.Now().UTC()}
				if mode == "bad_observation" {
					o.Status = "running"
				}
				wire, _ = json.Marshal(singleTestRecoveryAdmission{q, o})
				args = []any{json.RawMessage(wire)}
			}
			switch mode {
			case "get":
				g.OperationID = "getSingleTestCleanupRecovery"
				sql = singleTestRecoveryGetSQL
				args = []any{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.ActorID}
			case "foreign":
				foreign := q
				foreign.OrganizationID = public62Definition
				wire, _ = json.Marshal(foreign)
				args = []any{json.RawMessage(wire)}
			case "revoked":
				g.Allowed = nil
			case "collection":
				g.Collection = true
			case "unknown":
				sql = "SELECT zasp_temporal_single_recovery.owner($1::jsonb)"
			case "extra":
				args = append(args, "extra")
			case "duplicate":
				args = []any{json.RawMessage(strings.Replace(string(wire), `"run_id":`, `"run_id":"`+q.RunID+`","run_id":`, 1))}
			case "wrong_operation":
				g.OperationID = "cancelSecurityAgentRun"
			}
			handled, allowed := singleTestRecoveryStatementAllowed(g, sql, args)
			want := mode == "preflight" || mode == "admit" || mode == "get"
			if handled != (mode != "unknown") || allowed != want {
				t.Fatal("classification", handled, allowed)
			}
		})
	}
}
