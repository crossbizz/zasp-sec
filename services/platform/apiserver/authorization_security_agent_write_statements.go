package apiserver

import (
	"bytes"
	"encoding/json"
	"time"
)

// Authorized Security Agent writes added by migrations/baseline/completion.sql
// (section H). Each is one zasp_authorization80 function that binds the request
// to the attested proof and then calls the chain's writer for the definition's
// family. The API sends exactly one of these per request; the family is chosen
// inside PostgreSQL, under the proof, never by an unauthorized probe.
const (
	currentSecurityAgentDefinitionValueSQL     = `SELECT zasp_authorization80.security_agent_definition_value($1,$2,$3,$4)`
	currentSecurityAgentActivationSQL          = `SELECT zasp_authorization80.security_agent_activation($1,$2,$3,$4,$5)`
	currentSecurityAgentDefinitionReplaySQL    = `SELECT zasp_authorization80.security_agent_definition_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`
	currentSecurityAgentDefinitionMutateSQL    = `SELECT zasp_authorization80.security_agent_definition_mutate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`
	currentSecurityAgentActivateSQL            = `SELECT zasp_authorization80.security_agent_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	currentSecurityAgentRunSQL                 = `SELECT zasp_authorization80.security_agent_run($1,$2,$3,$4,$5,$6::jsonb,$7)`
	currentSecurityAgentSetExecutionControlSQL = `SELECT zasp_authorization80.security_agent_set_execution_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
)

// securityAgentRunAdmission is the closed request of
// zasp_authorization80.security_agent_run. Trigger version and source travel
// together or not at all.
type securityAgentRunAdmission struct {
	OrganizationID    string  `json:"organization_id"`
	WorkspaceID       string  `json:"workspace_id"`
	EnvironmentID     string  `json:"environment_id"`
	ActorID           string  `json:"actor_id"`
	DefinitionID      string  `json:"definition_id"`
	DefinitionVersion int64   `json:"definition_version"`
	IdempotencyKey    string  `json:"idempotency_key"`
	RunID             string  `json:"run_id"`
	TriggerKind       string  `json:"trigger_kind"`
	TriggerID         string  `json:"trigger_id"`
	TriggerVersion    *int64  `json:"trigger_version,omitempty"`
	TriggerSource     *string `json:"trigger_source,omitempty"`
	AuditID           string  `json:"audit_id"`
	CorrelationID     string  `json:"correlation_id"`
	ReceiptID         string  `json:"receipt_id"`
}

func securityAgentWriteStrings(args []any, positions ...int) ([]string, bool) {
	values := make([]string, 0, len(positions))
	for _, position := range positions {
		if position < 0 || position >= len(args) {
			return nil, false
		}
		value, ok := args[position].(string)
		if !ok {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

// securityAgentWriteStatementAllowed admits the Security Agent write contracts.
// It reports handled for every statement above, so none of them can reach the
// generic rule table with weaker preconditions. Operation, scope, actor,
// credential kind, fresh authentication, the path object and the allowed
// target are compared with the checked request here; PostgreSQL compares them
// again with the attested proof.
func securityAgentWriteStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	if q == currentSecurityAgentRemediationRunSQL {
		return true, securityAgentRemediationStatementAllowed(g, args)
	}
	switch q {
	case currentSecurityAgentDefinitionValueSQL, currentSecurityAgentActivationSQL, currentSecurityAgentDefinitionReplaySQL, currentSecurityAgentDefinitionMutateSQL, currentSecurityAgentActivateSQL, currentSecurityAgentRunSQL, currentSecurityAgentSetExecutionControlSQL:
	default:
		return false, false
	}
	if g.Collection || !stringIn(string(g.Identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) {
		return true, false
	}
	o, w, e, actor := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	path := g.PathParameters["id"]
	object := func(id string) bool {
		return validProductID(id) && id == path && authorizationNativeTargetAllowed(g, "security_agent", id)
	}
	environment := func() bool { return authorizationNativeTargetAllowed(g, "environment", e) }
	browserFresh := func() bool {
		return g.Identity.CredentialKind == CredentialBrowserSession && g.Identity.FreshAuthenticated && !g.Identity.FreshAuthExpiresAt.IsZero()
	}
	scope := func(first int) bool {
		values, ok := securityAgentWriteStrings(args, first, first+1, first+2)
		return ok && values[0] == o && values[1] == w && values[2] == e
	}
	text := func(position int) (string, bool) {
		values, ok := securityAgentWriteStrings(args, position)
		if !ok {
			return "", false
		}
		return values[0], true
	}
	switch q {
	case currentSecurityAgentDefinitionValueSQL:
		id, ok := text(3)
		return true, len(args) == 4 && ok && stringIn(g.OperationID, "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent") && scope(0) && object(id)
	case currentSecurityAgentActivationSQL:
		if len(args) != 5 {
			return true, false
		}
		id, ok := text(3)
		principal, principalOK := text(4)
		return true, ok && principalOK && g.OperationID == "getSecurityAgentActivation" && scope(0) && principal == actor && object(id)
	case currentSecurityAgentDefinitionReplaySQL:
		if len(args) != 7 || !stringIn(g.OperationID, "createSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent") || !scope(0) {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4, 5)
		raw, rawOK := args[6].(json.RawMessage)
		var intent struct {
			ResourceID string `json:"resource_id"`
		}
		if !ok || !rawOK || len(raw) > 128*1024 || values[0] != actor || values[1] != g.OperationID || !validPublicIdempotency(values[2]) || json.Unmarshal(raw, &intent) != nil {
			return true, false
		}
		if g.OperationID == "createSecurityAgent" {
			return true, intent.ResourceID == "" && environment()
		}
		return true, object(intent.ResourceID)
	case currentSecurityAgentDefinitionMutateSQL:
		if len(args) != 14 || !scope(2) {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 0, 1, 5, 6, 7, 11, 12, 13)
		version, versionOK := args[8].(int64)
		if !ok || !versionOK || values[2] != actor || values[3] != g.OperationID || !validPublicIdempotency(values[4]) || !validProductID(values[1]) || !validProductID(values[5]) || !validProductID(values[6]) {
			return true, false
		}
		// A browser session carries a mutation receipt, an API token none.
		if g.Identity.CredentialKind == CredentialBrowserSession && !validProductID(values[7]) || g.Identity.CredentialKind == CredentialBearerToken && values[7] != "" {
			return true, false
		}
		switch g.OperationID {
		case "createSecurityAgent":
			return true, values[0] == "create" && version == 0 && path == "" && environment()
		case "updateSecurityAgent":
			return true, values[0] == "update" && version >= 1 && version <= 1000000 && object(values[1])
		case "deleteSecurityAgent":
			return true, values[0] == "delete" && version >= 1 && version <= 1000000 && object(values[1])
		}
		return true, false
	case currentSecurityAgentActivateSQL:
		if len(args) != 12 || g.OperationID != "activateSecurityAgent" || !browserFresh() || !scope(0) {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4, 5, 7, 9, 10, 11)
		version, versionOK := args[6].(int64)
		fresh, freshOK := args[8].(time.Time)
		if !ok || !versionOK || !freshOK || values[1] != actor || !validPublicIdempotency(values[2]) || version < 1 || version > 999999 || !stringIn(values[3], "validated", "supervised", "autonomous") || fresh.IsZero() || fresh.Location() != time.UTC || fresh != g.Identity.FreshAuthExpiresAt {
			return true, false
		}
		ids := map[string]struct{}{}
		for _, id := range values[4:] {
			if !validProductID(id) {
				return true, false
			}
			ids[id] = struct{}{}
		}
		return true, len(ids) == 3 && object(values[0])
	case currentSecurityAgentRunSQL:
		if len(args) != 7 || g.OperationID != "runSecurityAgent" || !scope(0) {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4)
		raw, rawOK := args[5].(json.RawMessage)
		if !ok || !rawOK || len(raw) > 8192 || values[1] != actor || !object(values[0]) {
			return true, false
		}
		var admission securityAgentRunAdmission
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&admission) != nil || decoder.More() {
			return true, false
		}
		// A finding or attack path trigger travels with the attestation of a
		// second decision for that object; any other trigger carries none.
		// SQL verifies the attestation itself.
		triggerProof, attested := args[6].(string)
		if securityAgentRunTriggerOperation(admission.TriggerKind) != "" {
			if !attested || triggerProof == "" || len(triggerProof) > 12*1024*1024 {
				return true, false
			}
		} else if args[6] != nil {
			return true, false
		}
		return true, admission.OrganizationID == o && admission.WorkspaceID == w && admission.EnvironmentID == e && admission.ActorID == actor && admission.DefinitionID == values[0] &&
			admission.DefinitionVersion >= 1 && admission.DefinitionVersion <= 1000000 && validPublicIdempotency(admission.IdempotencyKey) && stringIn(admission.TriggerKind, "finding", "session", "attack_path") &&
			validProductID(admission.RunID) && validProductID(admission.TriggerID) && validProductID(admission.AuditID) && validProductID(admission.CorrelationID) && validProductID(admission.ReceiptID) &&
			(admission.TriggerVersion == nil) == (admission.TriggerSource == nil) && (admission.TriggerVersion == nil || *admission.TriggerVersion >= 1)
	case currentSecurityAgentSetExecutionControlSQL:
		if len(args) != 13 || g.OperationID != "setSecurityAgentExecutionControl" || !browserFresh() || !scope(0) {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4, 5, 6, 10, 11, 12)
		_, enabledOK := args[7].(bool)
		version, versionOK := args[8].(int64)
		fresh, freshOK := args[9].(time.Time)
		if !ok || !enabledOK || !versionOK || !freshOK || values[0] != actor || !validPublicIdempotency(values[1]) || version < 0 || version > 1000000 || fresh.IsZero() || fresh.Location() != time.UTC || fresh != g.Identity.FreshAuthExpiresAt {
			return true, false
		}
		if !(values[2] == "environment" && values[3] == "*") && !(values[2] == "action" && stringIn(values[3], securityAgentExecutionControlActions...)) {
			return true, false
		}
		ids := map[string]struct{}{}
		for _, id := range values[4:] {
			if !validProductID(id) {
				return true, false
			}
			ids[id] = struct{}{}
		}
		return true, len(ids) == 3 && environment()
	}
	return true, false
}

// securityAgentRunTriggerOperation names the read operation whose decision a
// run's trigger needs: the requester must be allowed to view the finding or
// the attack path the run is started on. A session trigger has none.
func securityAgentRunTriggerOperation(kind string) string {
	switch kind {
	case "finding":
		return "getFinding"
	case "attack_path":
		return "getAttackPath"
	default:
		return ""
	}
}
