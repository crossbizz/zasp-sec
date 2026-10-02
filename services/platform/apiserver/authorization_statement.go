package apiserver

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type authorizationStatementRule struct {
	query         string
	operations    []string
	arguments     int
	actor, target int // One-based SQL argument positions, zero means absent.
	kind          string
}

// Closed application contracts, not a SQL parser or another permission engine.
// Unknown queries refuse until their product boundary has been implemented.
var authorizationStatementRules = []authorizationStatementRule{
	{currentPATPageSQL, []string{"listAPITokens"}, 5, 0, 3, "environment"},
	{currentRevealPageSQL, []string{"listAPITokenRevealGrants"}, 6, 4, 3, "environment"},
	{currentRevealPATSQL, []string{"revealAPIToken"}, 5, 4, 3, "environment"},
	{postgresCurrentReferenceReplaySQL, []string{"authorizeIntegrationReference"}, 7, 4, 5, "integration"},
	{postgresCurrentReferenceValueSQL, []string{"authorizeIntegrationReference"}, 4, 0, 4, "integration"},
	{postgresCurrentReferenceCompleteSQL, []string{"authorizeIntegrationReference"}, 17, 4, 5, "integration"},
	{postgresCurrentIntegrationMutateSQL, []string{"createIntegration", "updateIntegration"}, 15, 7, 0, ""},
	{postgresCurrentIntegrationValueSQL, []string{"getIntegration"}, 4, 0, 4, "integration"},
	{`SELECT zasp_authorization80.integration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`, []string{"createIntegration", "updateIntegration"}, 7, 4, 0, ""},
	{`SELECT zasp_authorization80.integration_update_value($1,$2,$3,$4)`, []string{"updateIntegration"}, 4, 0, 4, "integration"},
	{postgresCreateWorkspaceCurrentSQL, []string{"createWorkspace"}, 9, 7, 3, "environment"},
	{postgresCreateEnvironmentCurrentSQL, []string{"createEnvironment"}, 9, 7, 3, "environment"},
	{`SELECT zasp_authorization80.get_data_controls($1,$2,$3)`, []string{"getDataControls"}, 3, 0, 3, "environment"},
	{`SELECT zasp_authorization80.update_data_controls($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, []string{"updateDataControls"}, 10, 10, 3, "environment"},
	{`SELECT zasp_authorization80.home_summary($1,$2,$3)`, []string{"getHomeSummary"}, 3, 0, 0, ""},
	{`SELECT zasp_authorization80.workflow_page($1,$2,$3,$4,NULLIF($5,''),$6)`, []string{"listPolicies", "listIntegrations", "listSecurityAgents"}, 6, 0, 0, ""},
	{`SELECT zasp_authorization80.sensor_page($1,$2,$3,NULLIF($4,''),$5)`, []string{"listSensors"}, 5, 0, 0, ""},
	{`SELECT zasp_authorization80.sensor_detail($1,$2,$3,$4)`, []string{"getSensor"}, 4, 0, 4, "sensor"},
	{`SELECT zasp_authorization80.sensor_coverage($1,$2,$3,$4)`, []string{"getSensorCoverage"}, 4, 0, 4, "sensor"},
	{`SELECT zasp_authorization80.sensor_token_authority($1,$2,$3,$4)`, []string{"rotateSensorToken"}, 4, 0, 4, "sensor"},
	{`SELECT zasp_authorization80.create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, []string{"createSensorEnrollment"}, 16, 4, 0, ""},
	{`SELECT zasp_authorization80.create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, []string{"createSensorEnrollment"}, 17, 4, 0, ""},
	{`SELECT zasp_authorization80.update_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, []string{"updateSensor"}, 10, 4, 5, "sensor"},
	{`SELECT zasp_authorization80.delete_sensor($1,$2,$3,$4,$5,$6,$7,$8)`, []string{"deleteSensor"}, 8, 4, 5, "sensor"},
	{`SELECT zasp_authorization80.rotate_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, []string{"rotateSensorToken"}, 14, 4, 5, "sensor"},
	{`SELECT zasp_authorization80.recovery_create_backup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, []string{"startRecoveryBackup"}, 11, 4, 0, ""},
	{`SELECT zasp_authorization80.recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, []string{"startRecoveryRestore"}, 13, 4, 0, ""},
	{`SELECT zasp_authorization80.recovery_get_backup($1,$2,$3,$4)`, []string{"getRecoveryBackup"}, 4, 0, 4, "recovery_backup"},
	{`SELECT zasp_authorization80.recovery_get_restore($1,$2,$3,$4)`, []string{"getRecoveryRestore"}, 4, 0, 4, "recovery_restore"},
	{`SELECT zasp_authorization80.product_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`, []string{"listSessions"}, 9, 0, 0, ""},
	{`SELECT zasp_authorization80.product_session_get($1,$2,$3,$4)`, []string{"getSession"}, 4, 0, 4, "product_session"},
	{`SELECT zasp_authorization80.runtime_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`, []string{"listSessions"}, 9, 4, 0, ""},
	{`SELECT zasp_authorization80.runtime_session_get($1,$2,$3,$4,$5)`, []string{"getSession"}, 5, 4, 5, "session"},
	{`SELECT zasp_authorization80.runtime_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`, []string{"listSessionEvents"}, 8, 4, 5, "session"},
	{`SELECT zasp_authorization80.runtime_sandbox_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`, []string{"listSessionEvents"}, 8, 4, 5, "session"},
	{`SELECT zasp_authorization80.runtime_session_event_get($1,$2,$3,$4,$5,$6)`, []string{"getSessionEvent"}, 6, 4, 5, "session"},
	{`SELECT zasp_authorization80.runtime_sandbox_session_event_get($1,$2,$3,$4,$5,$6)`, []string{"getSessionEvent"}, 6, 4, 5, "session"},
	{`SELECT zasp_authorization80.runtime_session_query_status($1,$2,$3,$4)`, []string{"listSessions"}, 4, 4, 0, ""},
	{`SELECT zasp_authorization80.runtime_sandbox_query_status($1,$2,$3,$4)`, []string{"listSessions"}, 4, 4, 0, ""},
	{`SELECT zasp_authorization80.runtime_session_query_hydrate($1,$2,$3,$4,$5)`, []string{"listSessions"}, 5, 4, 0, ""},
	{`SELECT zasp_authorization80.runtime_sandbox_query_hydrate($1,$2,$3,$4,$5)`, []string{"listSessions"}, 5, 4, 0, ""},
	{`SELECT zasp_authorization80.global_search($1,$2,$3,$4,$5)`, []string{"globalSearch"}, 5, 0, 0, ""},
	{`SELECT zasp_authorization80.risk_page('finding',$1,$2,$3,NULLIF($4,''),$5)`, []string{"listFindings"}, 5, 0, 0, ""},
	{`SELECT zasp_authorization80.risk_page('attack_path',$1,$2,$3,NULLIF($4,''),$5)`, []string{"listAttackPaths"}, 5, 0, 0, ""},
	{`SELECT to_jsonb(zasp_authorization80.high_path_count($1,$2,$3))`, []string{"listAttackPaths"}, 3, 0, 0, ""},
	{`SELECT zasp_authorization80.product_session_event_page($1,$2,$3,$4,$5,$6,$7)`, []string{"listSessionEvents"}, 7, 0, 4, "product_session"},
	{`SELECT zasp_authorization80.audit_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, []string{"listAuditEvents"}, 12, 4, 0, ""},
	{`SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`, []string{"listComplianceControls", "listComplianceEvidence", "getComplianceEvidence"}, 9, 4, 0, ""},
	{`SELECT zasp_authorization80.inventory_page($1,$2,$3,$4,NULLIF($5,''),$6)`, []string{"listAgents", "listTools", "listIdentities", "listRuntimes", "listAssets"}, 6, 0, 0, ""},
	{`SELECT zasp_authorization80.receipt_page($1,$2,$3,$4,$5)`, []string{"listWorkflowMutationReceipts"}, 5, 4, 0, ""},
	{postgresRiskFindingGetSQL, []string{"getFinding"}, 4, 0, 4, "finding"},
	{postgresRiskAttackPathGetSQL, []string{"getAttackPath"}, 4, 0, 4, "attack_path"},
	{postgresRiskBreakOptionsGetSQL, []string{"getAttackPathBreakOptions"}, 4, 0, 4, "attack_path"},
}

func authorizationStatementAllowed(g RequestAuthorization, q string, args []any) bool {
	if handled, allowed := inventoryStatementAllowed(g, q, args); handled {
		return allowed
	}
	if handled, allowed := singleTestRecoveryStatementAllowed(g, q, args); handled {
		return allowed
	}
	if handled, allowed := ordered62ApprovalStatementAllowed(g, q, args); handled {
		return allowed
	}
	if handled, allowed := test74ActivationStatementAllowed(g, q, args); handled {
		return allowed
	}
	if handled, allowed := discovery72StatementAllowed(g, q, args); handled {
		return allowed
	}
	if handled, allowed := identityAdministrationStatementAllowed(g, q, args); handled {
		return allowed
	}
	// Normalize only these fixed positional contracts. The original statement
	// and argument array are passed unchanged to PostgreSQL after validation.
	switch q {
	case currentPATPageSQL, currentRevealPageSQL, currentRevealPATSQL:
		if g.Collection || g.Identity.CredentialKind != CredentialBrowserSession {
			return false
		}
		if q == currentRevealPATSQL && (len(args) != 5 || args[4] != g.PathParameters["id"] || !g.Identity.FreshAuthenticated) {
			return false
		}
	case postgresCurrentReferenceValueSQL:
		if len(args) != 4 || g.Collection || args[3] != g.PathParameters["id"] || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated {
			return false
		}
	case postgresCurrentReferenceReplaySQL, postgresCurrentReferenceCompleteSQL:
		if g.Collection || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated {
			return false
		}
		if q == postgresCurrentReferenceReplaySQL {
			if len(args) != 7 || args[4] != g.PathParameters["id"] {
				return false
			}
			v, ok := args[6].(int64)
			if !ok || v < 1 || v > 1000000 {
				return false
			}
		} else {
			if len(args) != 17 || args[4] != g.PathParameters["id"] {
				return false
			}
			provider, ok := args[5].(string)
			if !ok || !stringIn(provider, "aws", "kubernetes") {
				return false
			}
			id, ok := args[4].(string)
			if !ok || args[6] != referenceConnectionID(g.Identity.Scope, id, provider) {
				return false
			}
			key, ok := args[8].(string)
			if !ok {
				return false
			}
			v, ok := args[9].(int64)
			if !ok || v < 1 || v > 1000000 {
				return false
			}
			config, ok := args[10].(json.RawMessage)
			if !ok {
				return false
			}
			intent, ok := args[11].(json.RawMessage)
			if !ok {
				return false
			}
			var actual, expected any
			if json.Unmarshal(intent, &actual) != nil || json.Unmarshal(referenceAuthorizationIntent(g.Identity, id, provider, key, v, config), &expected) != nil {
				return false
			}
			a, _ := json.Marshal(actual)
			e, _ := json.Marshal(expected)
			if !bytes.Equal(a, e) {
				return false
			}
		}
	case postgresCurrentIntegrationValueSQL:
		if len(args) != 4 || g.Collection || args[3] != g.PathParameters["id"] {
			return false
		}
	case postgresCurrentIntegrationMutateSQL:
		if len(args) != 15 || g.Collection || args[1] != "integration" || args[7] != g.OperationID {
			return false
		}
		version, ok := args[9].(int64)
		if !ok {
			return false
		}
		id, validID := args[2].(string)
		rawIntent, validIntent := args[10].(json.RawMessage)
		var intent struct {
			ResourceID      string `json:"resource_id"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if !validID || !validProductID(id) || !validIntent || json.Unmarshal(rawIntent, &intent) != nil || intent.ExpectedVersion != version {
			return false
		}
		if g.OperationID == "createIntegration" {
			if args[0] != "create" || version != 0 || intent.ResourceID != "" || !authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) {
				return false
			}
		} else if g.OperationID == "updateIntegration" {
			if args[0] != "update" || version < 1 || intent.ResourceID != id || id != g.PathParameters["id"] || !authorizationNativeTargetAllowed(g, "integration", id) {
				return false
			}
		} else {
			return false
		}
		args = []any{args[3], args[4], args[5], args[0], args[1], args[2], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14]}
	case `SELECT zasp_authorization80.integration_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`:
		if len(args) != 7 || g.Collection || args[4] != g.OperationID {
			return false
		}
		kind, target := "environment", g.Identity.Scope.EnvironmentID().String()
		if g.OperationID == "updateIntegration" {
			kind, target = "integration", g.PathParameters["id"]
		}
		if !authorizationNativeTargetAllowed(g, kind, target) {
			return false
		}
	case `SELECT zasp_authorization80.integration_update_value($1,$2,$3,$4)`:
		if len(args) != 4 || g.Collection || args[3] != g.PathParameters["id"] {
			return false
		}
	case postgresCreateWorkspaceCurrentSQL:
		if len(args) != 9 {
			return false
		}
		args = []any{args[1], args[3], args[4], args[0], args[2], args[5], args[6], args[7], args[8]}
	case postgresCreateEnvironmentCurrentSQL:
		if len(args) != 9 || args[2] != args[6] {
			return false
		}
		args = []any{args[1], args[6], args[7], args[0], args[2], args[4], args[5], args[3], args[8]}
	case `SELECT zasp_authorization80.workflow_page($1,$2,$3,$4,NULLIF($5,''),$6)`:
		kind := map[string]string{"listPolicies": "policy", "listIntegrations": "integration", "listSecurityAgents": "security_agent"}[g.OperationID]
		if len(args) != 6 || !g.Collection || kind == "" || args[0] != kind {
			return false
		}
		args = []any{args[1], args[2], args[3], args[0], args[4], args[5]}
	case `SELECT zasp_authorization80.runtime_session_event_get($1,$2,$3,$4,$5,$6)`, `SELECT zasp_authorization80.runtime_sandbox_session_event_get($1,$2,$3,$4,$5,$6)`:
		if len(args) != 6 || g.PathParameters["eventId"] == "" || args[5] != g.PathParameters["eventId"] {
			return false
		}
	case `SELECT zasp_authorization80.hierarchy_page('workspace',$1,NULL,$2,$3,$4)`:
		return g.OperationID == "listWorkspaces" && g.Collection && len(args) == 4 && args[0] == g.Identity.Scope.OrganizationID().String() && args[1] == g.Identity.PrincipalID.String()
	case `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`:
		return g.OperationID == "listEnvironments" && g.Collection && g.WorkspaceSelector != "" && len(args) == 5 && args[0] == g.Identity.Scope.OrganizationID().String() && args[1] == g.WorkspaceSelector && args[2] == g.Identity.PrincipalID.String()
	case `SELECT to_jsonb(zasp_authorization80.session_source_readiness(50,$1,$2))`:
		return slices.Contains([]string{"listSessions", "listSessionEvents", "getSessionEvent"}, g.OperationID) && len(args) == 2 && args[0] == migrations.ProductionRuntimeSandboxBinding().Checksum() && args[1] == migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()
	case `SELECT zasp_authorization80.product_session_event_page($1,$2,$3,$4,$5,$6,$7)`:
		if len(args) != 7 {
			return false
		}
		args = []any{args[0], args[2], args[3], args[1], args[4], args[5], args[6]}
	case postgresRiskFindingGetSQL, postgresRiskAttackPathGetSQL, postgresRiskBreakOptionsGetSQL:
		if len(args) != 4 {
			return false
		}
		args = []any{args[1], args[2], args[3], args[0]}
	case `SELECT zasp_authorization80.inventory_page($1,$2,$3,$4,NULLIF($5,''),$6)`:
		kind := map[string]string{"listAgents": "agent", "listTools": "tool", "listIdentities": "identity", "listRuntimes": "runtime", "listAssets": "asset"}[g.OperationID]
		if len(args) != 6 || kind == "" || args[3] != kind {
			return false
		}
	case `SELECT zasp_authorization80.audit_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`:
		if len(args) != 12 || !authorizationDigestArgument(g, args[4]) || args[5] != g.Identity.CSRFToken || args[10] != migrations.ProductionAuditExports().Checksum() || args[11] != migrations.ProductionAuditExportsSemanticFingerprint() {
			return false
		}
	case `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`:
		operation := map[string]string{"listComplianceControls": "listControls", "listComplianceEvidence": "listEvidence", "getComplianceEvidence": "getEvidence"}[g.OperationID]
		if len(args) != 9 || operation == "" || !authorizationDigestArgument(g, args[4]) || args[7] != migrations.ProductionCompliance().Checksum() || args[8] != migrations.ComplianceFingerprint() {
			return false
		}
		// Each public list assembles controls and evidence under the same
		// three-permission intersection and already checked parent set.
		if operation == "getEvidence" && args[5] != operation || operation != "getEvidence" && args[5] != "listControls" && args[5] != "listEvidence" {
			return false
		}
		if operation == "getEvidence" && !authorizationEvidenceSelector(g, args[6]) {
			return false
		}
	}
	for _, rule := range authorizationStatementRules {
		if q != rule.query {
			continue
		}
		if len(args) != rule.arguments || !slices.Contains(rule.operations, g.OperationID) {
			return false
		}
		for n, expected := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()} {
			value, ok := args[n].(string)
			if !ok || value != expected {
				return false
			}
		}
		if rule.actor > 0 {
			value, ok := args[rule.actor-1].(string)
			if !ok || value != g.Identity.PrincipalID.String() {
				return false
			}
		}
		if rule.target > 0 {
			value, ok := args[rule.target-1].(string)
			if !ok || !authorizationNativeTargetAllowed(g, rule.kind, value) {
				return false
			}
		}
		return true
	}
	return false
}

func authorizationEvidenceSelector(g RequestAuthorization, value any) bool {
	raw, ok := value.(json.RawMessage)
	if !ok || g.PathParameters["sourceKind"] == "" || g.PathParameters["id"] == "" {
		return false
	}
	fields, err := auditExportClosedObject(raw, 4096, "source_kind", "source_id")
	if err != nil {
		fields, err = auditExportClosedObject(raw, 4096, "source_kind", "source_id", "source_version")
	}
	if err != nil {
		return false
	}
	var kind, id string
	return json.Unmarshal(fields["source_kind"], &kind) == nil && json.Unmarshal(fields["source_id"], &id) == nil && kind == g.PathParameters["sourceKind"] && id == g.PathParameters["id"]
}

func authorizationDigestArgument(g RequestAuthorization, value any) bool {
	digest, ok := value.([]byte)
	return ok && bytes.Equal(digest, g.Credential.Digest[:])
}

func authorizationNativeTargetAllowed(g RequestAuthorization, kind, value string) bool {
	for _, target := range g.Allowed {
		if target.Kind != kind || target.Scope != g.Identity.Scope {
			continue
		}
		native := target.SourceID
		if native == "" {
			native = target.ID
		}
		if value == native {
			return true
		}
	}
	return false
}
