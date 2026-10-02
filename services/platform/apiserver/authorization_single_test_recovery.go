package apiserver

import (
	"encoding/json"
	"time"
)

func singleTestRecoveryStatementAllowed(g RequestAuthorization, sql string, args []any) (bool, bool) {
	if sql != singleTestRecoveryPreflightSQL && sql != singleTestRecoveryAdmitSQL && sql != singleTestRecoveryGetSQL {
		return false, false
	}
	if g.Collection || !authorizationNativeTargetAllowed(g, "security_agent_run", g.PathParameters["id"]) || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) {
		return true, false
	}
	want := []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.PathParameters["id"], g.Identity.PrincipalID.String()}
	if sql == singleTestRecoveryGetSQL {
		if g.OperationID != "getSingleTestCleanupRecovery" || len(args) != 5 {
			return true, false
		}
		for n, v := range want {
			got, ok := args[n].(string)
			if !ok || got != v || !validProductID(got) {
				return true, false
			}
		}
		return true, true
	}
	if g.OperationID != "requestSingleTestCleanupRecovery" || len(args) != 1 {
		return true, false
	}
	raw, ok := args[0].(json.RawMessage)
	if !ok {
		return true, false
	}
	var q singleTestRecoveryWire
	if sql == singleTestRecoveryPreflightSQL {
		if recoveryDecode(raw, 4096, &q) != nil {
			return true, false
		}
	} else {
		var a singleTestRecoveryAdmission
		if recoveryDecode(raw, 8192, &a) != nil {
			return true, false
		}
		q = a.singleTestRecoveryWire
		id := "security-agent-test/v1/" + q.OrganizationID + "/" + q.WorkspaceID + "/" + q.EnvironmentID + "/" + q.RunID
		if !recoveryObservationValid(a.Observation, id, time.Now()) {
			return true, false
		}
	}
	got := []string{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.ActorID}
	for n, v := range want {
		if got[n] != v {
			return true, false
		}
	}
	return true, q.valid()
}
