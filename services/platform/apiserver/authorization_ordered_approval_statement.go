package apiserver

import (
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Only these two fixed shapes may consume a current approval decision. Native
// SQL independently binds the sealed proof before and after blocking work.
func ordered62ApprovalStatementAllowed(g RequestAuthorization, query string, args []any) (handled, allowed bool) {
	if query != securityAgentPublicSQL {
		return false, false
	}
	if g.OperationID != "decideSecurityAgentApproval" || g.Collection || len(args) != 3 || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated || len(g.Targets) != 1 || len(g.Allowed) != 1 {
		return true, false
	}
	checksum, checksumOK := args[0].(string)
	fingerprint, fingerprintOK := args[1].(string)
	raw, rawOK := args[2].(json.RawMessage)
	if !checksumOK || !fingerprintOK || !rawOK || len(raw) > 16384 || checksum != migrations.ProductionSecurityAgentPublic().Checksum() || fingerprint != migrations.SecurityAgentPublicFingerprint() {
		return true, false
	}
	id := g.PathParameters["id"]
	target := g.Targets[0]
	if !validProductID(id) || target != g.Allowed[0] || target.Kind != "security_agent_approval" || target.Scope != g.Identity.Scope || target.ID != id || (target.SourceID != "" && target.SourceID != id) || target.Version < 1 || target.Version > 1000000 {
		return true, false
	}
	var head struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return true, false
	}
	o, w, e, actor := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	switch head.Operation {
	case "classify":
		var q struct {
			Operation    string `json:"operation"`
			Organization string `json:"organization_id"`
			Workspace    string `json:"workspace_id"`
			Environment  string `json:"environment_id"`
			Actor        string `json:"actor_id"`
			Kind         string `json:"resource_kind"`
			ID           string `json:"resource_id"`
		}
		return true, public62Decode(raw, &q) == nil && q.Organization == o && q.Workspace == w && q.Environment == e && q.Actor == actor && q.Kind == "approval" && q.ID == id
	case "decide_resource":
		var q struct {
			Operation    string `json:"operation"`
			Organization string `json:"organization_id"`
			Workspace    string `json:"workspace_id"`
			Environment  string `json:"environment_id"`
			Actor        string `json:"actor_id"`
			ID           string `json:"approval_id"`
			Version      int64  `json:"approval_version"`
			Decision     string `json:"decision"`
			Key          string `json:"idempotency_key"`
			Fresh        string `json:"fresh_auth_at"`
		}
		return true, public62Decode(raw, &q) == nil && q.Organization == o && q.Workspace == w && q.Environment == e && q.Actor == actor && q.ID == id && q.Version > 0 && q.Version < 1000000 && stringIn(q.Decision, "approved", "rejected") && validPublicIdempotency(q.Key) && !g.Identity.FreshAuthExpiresAt.IsZero() && q.Fresh == g.Identity.FreshAuthExpiresAt.Add(-5*time.Minute).Format(time.RFC3339Nano)
	default:
		return true, false
	}
}
