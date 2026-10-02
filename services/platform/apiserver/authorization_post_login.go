package apiserver

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// This private interface admits exactly the self-read routes. It does not
// manufacture a product RequestAuthorization for a permission-free operation.
type postLoginPreparer interface {
	preparePostLogin(context.Context, RequestIdentity, RoutedOperation) (postLoginAuthorization, error)
}

func (a *OpenFGAAuthorizer) preparePostLogin(ctx context.Context, i RequestIdentity, route RoutedOperation) (postLoginAuthorization, error) {
	g := postLoginAuthorization{identity: i, purpose: route.OperationID, permissions: []string{}, capabilities: []string{}}
	if a == nil || a.Reader == nil || a.Checker == nil || !postLoginOperation(route.OperationID) {
		return g, authorization.ErrUnavailable
	}
	r, ok := a.Resolver.(*PostgresAuthorizationResolver)
	if !ok || r == nil || r.database == nil {
		return g, authorization.ErrUnavailable
	}
	var err error
	g.binding, err = postLoginBinding(i)
	if err != nil {
		return g, err
	}
	// Inherit any shorter request deadline. No individual Check can turn an
	// unbounded route into an unlimited sequence of provider requests.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	snapshot, err := readPostLoginSnapshot(ctx, r.database, i, g.binding)
	if err != nil {
		return g, err
	}
	g.revision = snapshot.Revision
	if g.revision.Desired != g.revision.Applied || g.revision.Desired < 1 || g.revision.Generation < 1 || g.revision.StoreID != a.StoreID || g.revision.ModelID != a.ModelID {
		return g, authorization.ErrPending
	}
	c := postLoginCapabilityChecks{authorizer: a, identity: i, revision: g.revision, decisions: map[authorization.CheckRequest]bool{}, targets: map[string][]AuthorizationTarget{}, candidates: map[string]bool{}, permissions: map[string]bool{}}
	environment := AuthorizationTarget{Scope: i.Scope, Kind: "environment", ID: i.Scope.EnvironmentID().String()}
	// Even self reads with no product grant verify current provider availability.
	if _, err = c.check(ctx, environment, "view"); err != nil {
		return g, err
	}
	if route.OperationID == "bootstrapSession" {
		g.capabilities, err = c.capabilities(ctx, environment)
		if err != nil {
			return g, err
		}
		for p := range c.permissions {
			g.permissions = append(g.permissions, p)
		}
		slices.Sort(g.permissions)
		g.environmentAudit = c.decisions[c.request(environment, "view_audit")]
		g.capabilities = append(g.capabilities, "scope.switch")
	}
	current, err := a.Reader.Revision(ctx, i.Scope.OrganizationID().String())
	if err != nil {
		return g, authorization.ErrUnavailable
	}
	if current != g.revision {
		return g, authorization.ErrConflict
	}
	if ctx.Err() != nil {
		return g, authorization.ErrUnavailable
	}
	return g, nil
}

type postLoginCapabilityChecks struct {
	authorizer  *OpenFGAAuthorizer
	identity    RequestIdentity
	revision    authorization.Revision
	decisions   map[authorization.CheckRequest]bool
	targets     map[string][]AuthorizationTarget
	candidates  map[string]bool
	permissions map[string]bool
}

func (c *postLoginCapabilityChecks) request(t AuthorizationTarget, p string) authorization.CheckRequest {
	return authorization.CheckRequest{PrincipalKind: "user", PrincipalID: c.identity.PrincipalID.String(), OrganizationID: t.Scope.OrganizationID().String(), WorkspaceID: t.Scope.WorkspaceID().String(), EnvironmentID: t.Scope.EnvironmentID().String(), ResourceType: t.Kind, ResourceID: t.ID, Permission: p}
}
func (c *postLoginCapabilityChecks) check(ctx context.Context, t AuthorizationTarget, p string) (bool, error) {
	if ctx.Err() != nil || t.Scope.Validate() != nil || t.Scope.OrganizationID() != c.identity.Scope.OrganizationID() {
		return false, authorization.ErrUnavailable
	}
	r := c.request(t, p)
	if result, ok := c.decisions[r]; ok {
		return result, nil
	}
	checked, err := authorization.CheckRevision(ctx, c.authorizer.Reader, c.authorizer.Checker, r, c.authorizer.StoreID, c.authorizer.ModelID)
	if err != nil {
		return false, err
	}
	if checked.Revision != c.revision {
		return false, authorization.ErrConflict
	}
	allowed := checked.Decision.Allowed && (c.identity.CredentialKind != CredentialBearerToken || slices.Contains(c.identity.credentialBinding.PATCeiling, p))
	c.decisions[r] = allowed
	if allowed {
		c.permissions[p] = true
	}
	return allowed, nil
}
func (c *postLoginCapabilityChecks) all(ctx context.Context, t AuthorizationTarget, permissions []string) (bool, error) {
	for _, p := range permissions {
		allowed, err := c.check(ctx, t, p)
		if err != nil || !allowed {
			return false, err
		}
	}
	return true, nil
}
func (c *postLoginCapabilityChecks) resolve(ctx context.Context, operation string) ([]AuthorizationTarget, error) {
	if targets, ok := c.targets[operation]; ok {
		return targets, nil
	}
	op := operation
	if strings.HasSuffix(op, ":runtime") {
		op = strings.TrimSuffix(op, ":runtime")
		ctx = context.WithValue(ctx, authorizationQueryContextKey{}, url.Values{"kind": {"runtime"}})
	}
	targets, err := c.authorizer.Resolver.ResolveAuthorization(ctx, c.identity, RoutedOperation{OperationID: op})
	if err != nil {
		return nil, err
	}
	if !targets.Complete || len(targets.Targets) > 10000 {
		return nil, authorization.ErrUnavailable
	}
	for _, t := range targets.Targets {
		if t.Scope.Validate() != nil || t.Scope.OrganizationID() != c.identity.Scope.OrganizationID() {
			return nil, authorization.ErrUnavailable
		}
		key := expectedScopeValue(t.Scope) + "/" + t.Kind + "/" + t.ID
		c.candidates[key] = true
		if len(c.candidates) > 10000 {
			return nil, authorization.ErrUnavailable
		}
	}
	c.targets[operation] = targets.Targets
	return targets.Targets, nil
}

// A surface capability means there is a checked action/collection available;
// resource-specific allows never authorize another resource or API request.
func (c *postLoginCapabilityChecks) capabilities(ctx context.Context, environment AuthorizationTarget) ([]string, error) {
	var result []string
	for _, rule := range []struct{ capability, permissions, collections string }{
		{"inventory.read", "view", "listAgents listTools listIdentities listRuntimes"},
		{"policies.read", "view", "listPolicies"}, {"integrations.read", "view", "listIntegrations"}, {"sensors.read", "view", "listSensors"},
		{"findings.read", "view", "listFindings"}, {"attack-paths.read", "view", "listAttackPaths"},
		{"security-agents.read", "view", "listSecurityAgents listSecurityAgentRuns listSecurityAgentApprovals"},
		{"security-agents.catalog.read", "view", ""},
		{"red-team.read", "view", "listTests listTestRuns listAttackLabRuns"},
		{"sessions.read", "investigate_sessions", "listSessions listSessions:runtime"},
		{"audit.read", "view_audit", "listAuditEvents"},
		{"compliance.read", "view view_audit view_compliance", "listComplianceControls listComplianceEvidence"},
		{"inventory.write", "manage_workflows", "listAgents"}, {"policies.write", "manage_workflows", "listPolicies"},
		{"integrations.write", "manage_workflows", "listIntegrations"}, {"sensors.write", "manage_workflows", "listSensors"},
		{"security-agents.write", "manage_workflows", "listSecurityAgents"}, {"findings.write", "manage_findings", "listFindings"},
		{"red-team.write", "run_tests", "listTests"}, {"sessions.revoke", "revoke_sessions", "listSessions"},
		{"api-access.manage", "manage_api_tokens", ""}, {"data-controls.manage", "manage_data_controls", ""},
		{"recovery.read", "view", ""}, {"administration.read", "view", ""}, {"system.read", "view", ""},
		{"recovery.write", "manage_identity", ""}, {"security-agents.controls.manage", "manage_identity", ""},
		{"identity.groups.manage", "manage_identity", ""}, {"identity.scopes.manage", "view manage_identity", ""},
	} {
		permissions := strings.Fields(rule.permissions)
		allowed, err := c.all(ctx, environment, permissions)
		if err != nil {
			return nil, err
		}
		if !allowed {
			for _, op := range strings.Fields(rule.collections) {
				targets, err := c.resolve(ctx, op)
				if err != nil {
					return nil, err
				}
				for _, t := range targets {
					allowed, err = c.all(ctx, t, permissions)
					if err != nil {
						return nil, err
					}
					if allowed {
						break
					}
				}
				if allowed {
					break
				}
			}
		}
		if allowed {
			result = append(result, rule.capability)
		}
	}
	organization := AuthorizationTarget{Scope: c.identity.Scope, Kind: "organization_identity", ID: c.identity.Scope.OrganizationID().String()}
	if allowed, err := c.check(ctx, organization, "manage_identity"); err != nil {
		return nil, err
	} else if allowed {
		result = append(result, "identity.manage")
	}
	slices.Sort(result)
	return result, nil
}
