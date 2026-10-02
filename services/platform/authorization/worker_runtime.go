package authorization

import (
	"context"
	"encoding/hex"
)

// Native source ownership chooses the protocol. Every source target still
// receives both grantor and task Checks, after this exact shape validation.
func runtimeTestCheckShape(spec workerOperationSpec, facts workerFacts) bool {
	if facts.TaskID != "" || facts.SourceSessionID == "" || facts.SourceAgentID == "" || facts.TriggerID == "" || facts.TargetKind != "agent" && facts.TargetKind != "tool" || len(facts.SourceDeviceIDs) < 1 || len(facts.SourceDeviceIDs) > 101 || len(facts.Checks) != 6+len(facts.SourceDeviceIDs) {
		return false
	}
	switch facts.RuntimeProtocol {
	case "retained74-session-latest":
		if facts.TriggerID != facts.SourceSessionID || len(facts.SourceDeviceIDs) != 1 {
			return false
		}
	case "configured77-event-occurrence":
	default:
		return false
	}
	digest, err := hex.DecodeString(facts.RuntimeDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != facts.RuntimeDigest {
		return false
	}
	permission := "view"
	if spec.testExecution {
		permission = "run_tests"
	}
	want := [][3]string{{"security_agent", facts.DefinitionID, "manage_workflows"}, {"security_agent_run", facts.RunID, "manage_workflows"}, {"test", facts.TestID, permission}, {facts.TargetKind, facts.TargetID, permission}, {"session", facts.SourceSessionID, "investigate_sessions"}, {"agent", facts.SourceAgentID, "view"}}
	for i, device := range facts.SourceDeviceIDs {
		if device == "" || i > 0 && device <= facts.SourceDeviceIDs[i-1] {
			return false
		}
		want = append(want, [3]string{"gateway_device", device, "view"})
	}
	for i, target := range facts.Checks {
		if target.ID == "" || [3]string{target.Kind, target.ID, target.Permission} != want[i] {
			return false
		}
	}
	return true
}

// Configured matching retains up to100 events and a separate anchor. The
// anchor can add one device. Every exact grantor/task pair stays in this call.
func checkRuntimeTestRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, spec workerOperationSpec, facts workerFacts, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if !spec.current || !spec.testPlanning && !spec.testExecution || facts.TriggerKind != "runtime_decision" || !runtimeTestCheckShape(spec, facts) || len(requests) != 2*len(facts.Checks) {
		return Revision{}, ErrInvalid
	}
	for i, target := range facts.Checks {
		for j, subject := range []struct{ kind, id, task string }{{"user", facts.GrantorID, ""}, {"service", facts.PrincipalID, facts.RunID}} {
			want := CheckRequest{PrincipalKind: subject.kind, PrincipalID: subject.id, TaskID: subject.task, OrganizationID: facts.OrganizationID, WorkspaceID: facts.WorkspaceID, EnvironmentID: facts.EnvironmentID, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}
			if requests[2*i+j] != want {
				return Revision{}, ErrInvalid
			}
		}
	}
	return checkWorkerRevisionSet(ctx, reader, checker, requests, storeID, modelID)
}
