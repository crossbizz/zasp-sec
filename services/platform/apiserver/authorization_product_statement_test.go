package apiserver

import (
	"encoding/json"
	"testing"
)

// Every statement of completion.sql sections Z2 to Z7 is admitted only for
// its own operation, as a non-collection request, with the scope and the
// principal of the checked request, a browser session and fresh
// authentication where its policy requires them, and for the object of the
// request path, which must be an allowed target of its kind.
func TestProductStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	i.FreshAuthenticated = true
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const (
		object  = "pid_20000001-0000-4000-8000-000000000001"
		other   = "pid_20000002-0000-4000-8000-000000000002"
		audit   = "pid_20000003-0000-4000-8000-000000000003"
		receipt = "pid_20000004-0000-4000-8000-000000000004"
		policy  = "policy-block-shell"
		key     = "idempotency-key-0001"
	)
	target := func(kind, id string) AuthorizationTarget {
		return AuthorizationTarget{Scope: i.Scope, Kind: kind, ID: id, Version: 1}
	}
	policyTarget := AuthorizationTarget{Scope: i.Scope, Kind: "policy", ID: "pid_20000009-0000-4000-8000-000000000009", SourceID: policy, Version: 1}
	intent := func(resource string, version int64) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"resource_id": resource, "expected_version": version, "body": map[string]any{}})
		return raw
	}
	body := json.RawMessage(`{}`)
	type contract struct {
		name, query, operation string
		path                   string // The object of the request path; empty for a creation.
		args                   []any
		allowed                []AuthorizationTarget
		scope, actor, object   int // Zero-based argument positions; -1 when absent.
		browserOnly, fresh     bool
	}
	contracts := []contract{
		{"acknowledge", currentReceiptAcknowledgeSQL, "acknowledgeWorkflowMutationReceipt", receipt, []any{o, w, e, p, receipt}, []AuthorizationTarget{target("integration", object)}, 0, 3, 4, true, false},
		{"policy value", currentPolicyValueSQL, "getPolicy", policy, []any{o, w, e, policy}, []AuthorizationTarget{policyTarget}, 0, -1, 3, false, false},
		{"policy value for rollout", currentPolicyValueSQL, "rolloutPolicy", policy, []any{o, w, e, policy}, []AuthorizationTarget{policyTarget}, 0, -1, 3, false, false},
		{"policy value for decisions", currentPolicyValueSQL, "listPolicyDecisions", policy, []any{o, w, e, policy}, []AuthorizationTarget{policyTarget}, 0, -1, 3, false, false},
		{"policy decisions", currentPolicyDecisionsSQL, "listPolicyDecisions", policy, []any{o, w, e, policy, 100}, []AuthorizationTarget{policyTarget}, 0, -1, 3, false, false},
		{"replay create policy", currentWorkflowReplaySQL, "createPolicy", "", []any{o, w, e, p, "createPolicy", key, intent("", 0)}, []AuthorizationTarget{target("environment", e)}, 0, 3, -1, false, false},
		{"replay delete policy", currentWorkflowReplaySQL, "deletePolicy", policy, []any{o, w, e, p, "deletePolicy", key, intent(policy, 3)}, []AuthorizationTarget{policyTarget}, 0, 3, -1, false, false},
		{"replay delete integration", currentWorkflowReplaySQL, "deleteIntegration", object, []any{o, w, e, p, "deleteIntegration", key, intent(object, 3)}, []AuthorizationTarget{target("integration", object)}, 0, 3, -1, false, false},
		{"create policy", currentPolicyMutateSQL, "createPolicy", "", []any{"create", "policy", policy, o, w, e, p, "createPolicy", key, int64(0), intent("", 0), body, audit, audit, receipt}, []AuthorizationTarget{target("environment", e)}, 3, 6, -1, false, false},
		{"update policy", currentPolicyMutateSQL, "updatePolicy", policy, []any{"update", "policy", policy, o, w, e, p, "updatePolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}, []AuthorizationTarget{policyTarget}, 3, 6, 2, false, false},
		{"rollout policy", currentPolicyMutateSQL, "rolloutPolicy", policy, []any{"update", "policy", policy, o, w, e, p, "rolloutPolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}, []AuthorizationTarget{policyTarget}, 3, 6, 2, false, false},
		{"disable policy", currentPolicyMutateSQL, "disablePolicy", policy, []any{"update", "policy", policy, o, w, e, p, "disablePolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}, []AuthorizationTarget{policyTarget}, 3, 6, 2, false, false},
		{"delete policy", currentPolicyMutateSQL, "deletePolicy", policy, []any{"delete", "policy", policy, o, w, e, p, "deletePolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}, []AuthorizationTarget{policyTarget}, 3, 6, 2, false, false},
		{"delete integration", currentIntegrationDeleteSQL, "deleteIntegration", object, []any{"delete", "integration", object, o, w, e, p, "deleteIntegration", key, int64(2), intent(object, 2), body, audit, audit, receipt}, []AuthorizationTarget{target("integration", object)}, 3, 6, 2, false, false},
		{"identity detail", currentInventoryDetailSQL, "getIdentity", object, []any{o, w, e, object, InventoryKind("identity")}, []AuthorizationTarget{target("identity", object)}, 0, -1, 3, false, false},
		{"agent detail", currentInventoryDetailSQL, "getAgent", object, []any{o, w, e, object, InventoryKind("agent")}, []AuthorizationTarget{target("agent", object)}, 0, -1, 3, false, false},
		{"tool detail", currentInventoryDetailSQL, "getTool", object, []any{o, w, e, object, InventoryKind("tool")}, []AuthorizationTarget{target("tool", object)}, 0, -1, 3, false, false},
		{"runtime detail", currentInventoryDetailSQL, "getRuntime", object, []any{o, w, e, object, InventoryKind("runtime")}, []AuthorizationTarget{target("runtime", object)}, 0, -1, 3, false, false},
		{"asset detail", currentInventoryDetailSQL, "getAsset", object, []any{o, w, e, object, InventoryKind("asset")}, []AuthorizationTarget{target("asset", object)}, 0, -1, 3, false, false},
		{"agent capabilities", currentInventoryAgentPageSQL, "getAgentCapabilities", object, []any{o, w, e, object, "capabilities", "", 50}, []AuthorizationTarget{target("agent", object)}, 0, -1, 3, false, false},
		{"agent relationships", currentInventoryAgentPageSQL, "getAgentRelationships", object, []any{o, w, e, object, "relationships", "", 50}, []AuthorizationTarget{target("agent", object)}, 0, -1, 3, false, false},
		{"agent sessions", currentInventoryAgentPageSQL, "listAgentSessions", object, []any{o, w, e, object, "sessions", "", 50}, []AuthorizationTarget{target("agent", object)}, 0, -1, 3, false, false},
		{"update agent", currentInventoryUpdateAgentSQL, "updateAgent", object, []any{o, w, e, p, object, key, int64(1), "owner", "team", json.RawMessage(`[]`), audit, audit}, []AuthorizationTarget{target("agent", object)}, 0, 3, 4, false, false},
		{"webhook status", currentIntegrationWebhookStatusSQL, "getIntegrationWebhookStatus", object, []any{o, w, e, object}, []AuthorizationTarget{target("integration", object)}, 0, -1, 3, false, false},
		{"webhook reserve", currentIntegrationWebhookReserveSQL, "testIntegrationWebhook", object, []any{o, w, e, p, object, int64(1), key, audit, audit, receipt, "lease", 10}, []AuthorizationTarget{target("integration", object)}, 0, 3, 4, false, false},
		{"webhook complete", currentIntegrationWebhookCompleteSQL, "testIntegrationWebhook", object, []any{o, w, e, receipt, "lease", "digest", true}, []AuthorizationTarget{target("integration", object)}, 0, -1, -1, false, false},
		{"workspace", currentHierarchyValueSQL, "getWorkspace", w, []any{o, w, e, "workspace", w}, []AuthorizationTarget{target("workspace", w)}, 0, -1, 4, true, false},
		{"environment", currentHierarchyValueSQL, "getEnvironment", e, []any{o, w, e, "environment", e}, []AuthorizationTarget{target("environment", e)}, 0, -1, 4, true, false},
		{"rename workspace", currentHierarchyRenameSQL, "updateWorkspace", w, []any{o, w, e, p, "workspace", w, "Name", int64(1), audit}, []AuthorizationTarget{target("workspace", w)}, 0, 3, 5, true, true},
		{"rename environment", currentHierarchyRenameSQL, "updateEnvironment", e, []any{o, w, e, p, "environment", e, "Name", int64(1), audit}, []AuthorizationTarget{target("environment", e)}, 0, 3, 5, true, true},
		{"update finding", currentFindingMutateSQL, "updateFinding", object, []any{"updateFinding", object, o, w, e, p, key, int64(1), "open", "", audit, audit, receipt}, []AuthorizationTarget{target("finding", object)}, 2, 5, 1, false, false},
		{"accept finding risk", currentFindingMutateSQL, "acceptFindingRisk", object, []any{"acceptFindingRisk", object, o, w, e, p, key, int64(1), "accepted", "reason", audit, audit, receipt}, []AuthorizationTarget{target("finding", object)}, 2, 5, 1, false, false},
	}
	every := []string{"listPolicies", "getHomeSummary", "getIntegration", "updateIntegration", "getFinding", "listAgents", "listWorkflowMutationReceipts", "getSecurityAgent"}
	for _, c := range contracts {
		every = append(every, c.operation)
	}
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			grant := func() RequestAuthorization {
				g := RequestAuthorization{OperationID: c.operation, Identity: i, Allowed: append([]AuthorizationTarget(nil), c.allowed...), PathParameters: map[string]string{}}
				if c.path != "" {
					g.PathParameters["id"] = c.path
				}
				return g
			}
			arguments := func() []any { return append([]any(nil), c.args...) }
			refused := func(reason string, g RequestAuthorization, args []any) {
				t.Helper()
				if handled, allowed := productStatementAllowed(g, c.query, args); !handled || allowed {
					t.Fatalf("%s: handled=%v allowed=%v", reason, handled, allowed)
				}
				if authorizationStatementAllowed(g, c.query, args) {
					t.Fatalf("%s: the statement allowlist admitted the statement", reason)
				}
			}
			if handled, allowed := productStatementAllowed(grant(), c.query, arguments()); !handled || !allowed {
				t.Fatalf("own contract handled=%v allowed=%v", handled, allowed)
			}
			if !authorizationStatementAllowed(grant(), c.query, arguments()) {
				t.Fatal("statement allowlist refused the contract")
			}
			rule := productStatementRules[c.query]
			for _, operation := range every {
				if stringIn(operation, rule.operations...) {
					continue
				}
				g := grant()
				g.OperationID = operation
				refused("operation "+operation, g, arguments())
			}
			g := grant()
			g.Collection = true
			refused("collection request", g, arguments())
			refused("missing argument", grant(), arguments()[:len(c.args)-1])
			refused("extra argument", grant(), append(arguments(), "extra"))
			for n := range 3 {
				args := arguments()
				args[c.scope+n] = other
				refused("foreign scope", grant(), args)
			}
			if c.actor >= 0 {
				args := arguments()
				args[c.actor] = other
				refused("foreign principal", grant(), args)
			}
			if c.object >= 0 {
				args := arguments()
				args[c.object] = other
				refused("object other than the path's", grant(), args)
			}
			if c.path != "" {
				g = grant()
				g.PathParameters["id"] = other
				refused("path names another object", g, arguments())
			}
			if rule.kind != "" || rule.check != nil {
				g = grant()
				g.Allowed = nil
				refused("object not allowed", g, arguments())
				g = grant()
				for n := range g.Allowed {
					g.Allowed[n].Kind = "sensor"
				}
				refused("allowed target of another kind", g, arguments())
			}
			if c.browserOnly {
				g = grant()
				g.Identity.CredentialKind = CredentialBearerToken
				refused("API token", g, arguments())
			}
			if c.fresh {
				g = grant()
				g.Identity.FreshAuthenticated = false
				refused("stale authentication", g, arguments())
			}
		})
	}

	// Statement-specific bindings.
	grant := func(operation, path string, allowed ...AuthorizationTarget) RequestAuthorization {
		return RequestAuthorization{OperationID: operation, Identity: i, Allowed: allowed, PathParameters: map[string]string{"id": path}}
	}
	for name, c := range map[string]struct {
		grant RequestAuthorization
		query string
		args  []any
	}{
		"replay of another operation":        {grant("deletePolicy", policy, policyTarget), currentWorkflowReplaySQL, []any{o, w, e, p, "updatePolicy", key, intent(policy, 3)}},
		"replay of another policy":           {grant("deletePolicy", policy, policyTarget), currentWorkflowReplaySQL, []any{o, w, e, p, "deletePolicy", key, intent("policy-other", 3)}},
		"replay with a short key":            {grant("deletePolicy", policy, policyTarget), currentWorkflowReplaySQL, []any{o, w, e, p, "deletePolicy", "short", intent(policy, 3)}},
		"replay without a resource":          {grant("deletePolicy", policy, policyTarget), currentWorkflowReplaySQL, []any{o, w, e, p, "deletePolicy", key, json.RawMessage(`{"expected_version":3}`)}},
		"creation replay naming a resource":  {RequestAuthorization{OperationID: "createPolicy", Identity: i, Allowed: []AuthorizationTarget{target("environment", e)}}, currentWorkflowReplaySQL, []any{o, w, e, p, "createPolicy", key, intent(policy, 0)}},
		"creation without the environment":   {RequestAuthorization{OperationID: "createPolicy", Identity: i, Allowed: []AuthorizationTarget{policyTarget}}, currentPolicyMutateSQL, []any{"create", "policy", policy, o, w, e, p, "createPolicy", key, int64(0), intent("", 0), body, audit, audit, receipt}},
		"creation with a version":            {RequestAuthorization{OperationID: "createPolicy", Identity: i, Allowed: []AuthorizationTarget{target("environment", e)}}, currentPolicyMutateSQL, []any{"create", "policy", policy, o, w, e, p, "createPolicy", key, int64(1), intent("", 1), body, audit, audit, receipt}},
		"creation of an invalid identifier":  {RequestAuthorization{OperationID: "createPolicy", Identity: i, Allowed: []AuthorizationTarget{target("environment", e)}}, currentPolicyMutateSQL, []any{"create", "policy", "Policy", o, w, e, p, "createPolicy", key, int64(0), intent("", 0), body, audit, audit, receipt}},
		"write of another kind":              {grant("updatePolicy", policy, policyTarget), currentPolicyMutateSQL, []any{"update", "integration", policy, o, w, e, p, "updatePolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}},
		"write with another action":          {grant("updatePolicy", policy, policyTarget), currentPolicyMutateSQL, []any{"delete", "policy", policy, o, w, e, p, "updatePolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}},
		"write naming another operation":     {grant("updatePolicy", policy, policyTarget), currentPolicyMutateSQL, []any{"update", "policy", policy, o, w, e, p, "rolloutPolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}},
		"write whose intent differs":         {grant("updatePolicy", policy, policyTarget), currentPolicyMutateSQL, []any{"update", "policy", policy, o, w, e, p, "updatePolicy", key, int64(2), intent(policy, 3), body, audit, audit, receipt}},
		"update without a version":           {grant("updatePolicy", policy, policyTarget), currentPolicyMutateSQL, []any{"update", "policy", policy, o, w, e, p, "updatePolicy", key, int64(0), intent(policy, 0), body, audit, audit, receipt}},
		"integration deletion as a policy":   {grant("deleteIntegration", object, target("integration", object)), currentPolicyMutateSQL, []any{"delete", "integration", object, o, w, e, p, "deleteIntegration", key, int64(2), intent(object, 2), body, audit, audit, receipt}},
		"policy deletion as an integration":  {grant("deletePolicy", policy, policyTarget), currentIntegrationDeleteSQL, []any{"delete", "policy", policy, o, w, e, p, "deletePolicy", key, int64(2), intent(policy, 2), body, audit, audit, receipt}},
		"detail of another inventory kind":   {grant("getIdentity", object, target("identity", object)), currentInventoryDetailSQL, []any{o, w, e, object, InventoryKind("agent")}},
		"agent page of another section":      {grant("getAgentCapabilities", object, target("agent", object)), currentInventoryAgentPageSQL, []any{o, w, e, object, "sessions", "", 50}},
		"agent page beyond the bound":        {grant("getAgentCapabilities", object, target("agent", object)), currentInventoryAgentPageSQL, []any{o, w, e, object, "capabilities", "", 101}},
		"workspace read as an environment":   {grant("getWorkspace", w, target("workspace", w)), currentHierarchyValueSQL, []any{o, w, e, "environment", w}},
		"rename of the other hierarchy kind": {grant("updateWorkspace", w, target("workspace", w)), currentHierarchyRenameSQL, []any{o, w, e, p, "environment", w, "Name", int64(1), audit}},
		"rename without a version":           {grant("updateWorkspace", w, target("workspace", w)), currentHierarchyRenameSQL, []any{o, w, e, p, "workspace", w, "Name", int64(0), audit}},
		"finding change naming another op":   {grant("updateFinding", object, target("finding", object)), currentFindingMutateSQL, []any{"acceptFindingRisk", object, o, w, e, p, key, int64(1), "accepted", "reason", audit, audit, receipt}},
		"finding change without a version":   {grant("updateFinding", object, target("finding", object)), currentFindingMutateSQL, []any{"updateFinding", object, o, w, e, p, key, int64(0), "open", "", audit, audit, receipt}},
		"webhook completion elsewhere":       {grant("testIntegrationWebhook", object, target("integration", other)), currentIntegrationWebhookCompleteSQL, []any{o, w, e, receipt, "lease", "digest", true}},
	} {
		c.grant.Identity.CredentialKind = CredentialBrowserSession
		c.grant.Identity.FreshAuthenticated = true
		if handled, allowed := productStatementAllowed(c.grant, c.query, c.args); !handled || allowed {
			t.Errorf("%s: handled=%v allowed=%v", name, handled, allowed)
		}
	}

	// The chain's direct statements stay refused for a checked request.
	for _, legacy := range []string{postgresWorkflowReplaySQL, postgresWorkflowGetSQL, postgresWorkflowMutateSQL, postgresConnectorWorkflowMutateSQL, postgresWorkflowReceiptAcknowledgeSQL, postgresInventoryDetailSQL, postgresInventoryUpdateAgentSQL, postgresInventoryCapabilitiesSQL, postgresInventoryRelationshipsSQL, postgresInventorySessionsSQL, postgresListPolicyDecisionsSQL, postgresIntegrationWebhookTestStatusSQL, postgresIntegrationWebhookTestReserveSQL, postgresIntegrationWebhookTestCompleteSQL, postgresGetWorkspaceV19SQL, postgresGetEnvironmentSQL, postgresUpdateWorkspaceSQL, postgresUpdateEnvironmentSQL, postgresRiskFindingMutateSQL} {
		for _, operation := range every {
			if authorizationStatementAllowed(RequestAuthorization{OperationID: operation, Identity: i}, legacy, []any{o, w, e, p, object}) {
				t.Fatalf("legacy statement admitted for %s: %s", operation, legacy)
			}
		}
	}
}

// The repository issues the authorized statement for a checked request and
// the workflow operations of the writers match the SQL list.
func TestProductWorkflowOperations(t *testing.T) {
	for operation, rule := range productWorkflowOperations {
		kind, action, _, ok := workflowMutationTarget(operation)
		if !ok || kind != rule.kind || action != rule.action {
			t.Fatalf("%s: handler target (%s,%s,%v), rule (%s,%s)", operation, kind, action, ok, rule.kind, rule.action)
		}
		query := currentPolicyMutateSQL
		if rule.kind == "integration" {
			query = currentIntegrationDeleteSQL
		}
		if !stringIn(operation, productStatementRules[query].operations...) || !stringIn(operation, productStatementRules[currentWorkflowReplaySQL].operations...) {
			t.Fatalf("%s is not admitted by its writer and the replay", operation)
		}
	}
}
