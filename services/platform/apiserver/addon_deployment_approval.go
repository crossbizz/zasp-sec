package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

const (
	deploymentGetSQL    = "SELECT zasp_authorization80.deployment_get($1,$2,$3,$4,$5)"
	deploymentReviewSQL = "SELECT zasp_authorization80.deployment_review($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
)

// Every decision requires both the Environment grant for add-ons and the
// selected agent grant. An empty target set must never admit half a review.
func (r *PostgresAuthorizationResolver) deploymentReviewTargets(ctx context.Context, identity RequestIdentity, route RoutedOperation, policy authorizationOperationTarget, env, agent string) (AuthorizationTargets, error) {
	targets, err := resolveAuthorizationDatabase(ctx, r.database, identity, route, policy, env)
	if err != nil || !targets.Complete || len(targets.Targets) != 1 {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	agentTargets, err := resolveAuthorizationDatabase(ctx, r.database, identity, route, authorizationOperationTarget{Mode: "object", Kind: "agent"}, agent)
	if err != nil {
		return AuthorizationTargets{}, err
	}
	if !agentTargets.Complete || len(agentTargets.Targets) != 1 {
		return AuthorizationTargets{Complete: true}, nil
	}
	targets.Targets = append(targets.Targets, agentTargets.Targets...)
	return targets, nil
}

func init() {
	bound := func(g RequestAuthorization, args []any) bool {
		agent, ok := args[4].(string)
		return ok && addonEnvAllowed(g, args) && authorizationNativeTargetAllowed(g, "agent", agent)
	}
	productStatementRules[deploymentGetSQL] = productStatementRule{operations: []string{"getAddonDeploymentApproval"}, arguments: 5, scope: 1, object: 4, browserOnly: true, check: bound}
	productStatementRules[deploymentReviewSQL] = productStatementRule{operations: []string{"reviewAddonDeploymentApproval"}, arguments: 10, scope: 1, object: 4, actor: 6, browserOnly: true, fresh: true, check: bound}
}

func serveDeploymentReview(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := IdentityFromRequest(r)
	if !ok || actor.CredentialKind != CredentialBrowserSession {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	agent, id := q.Get("agent_id"), route.PathParameters["id"]
	if err != nil || len(q) != 1 || len(q["agent_id"]) != 1 || !validProductID(agent) || !validProductID(id) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := actor.Scope
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, agent}
	stmt := deploymentGetSQL
	switch route.OperationID {
	case "getAddonDeploymentApproval":
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	case "reviewAddonDeploymentApproval":
		if !actor.FreshAuthenticated {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		key, expected, ok := discoveryMutationHeaders(r, true)
		var input struct {
			Digest string `json:"permission_context_digest"`
			State  string `json:"state"`
		}
		if r.Method != http.MethodPost || !ok || decodeProductionJSON(r, &input) != nil || !addonDigest.MatchString(input.Digest) || !stringIn(input.State, "approved", "revoked") {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		args = append(args, actor.PrincipalID.String(), key, expected, input.Digest, input.State)
		stmt = deploymentReviewSQL
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := db.QueryJSON(r.Context(), stmt, args...)
	writeDeploymentReceipt(w, r, raw, err, id, agent)
}

func writeDeploymentReceipt(w http.ResponseWriter, r *http.Request, raw json.RawMessage, err error, id, agent string) {
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var receipt struct {
		VersionID string `json:"addon_version_id"`
		AgentID   string `json:"agent_id"`
		Revision  int64  `json:"revision"`
		Digest    string `json:"permission_context_digest"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.VersionID != id || receipt.AgentID != agent || receipt.Revision < 0 || !addonDigest.MatchString(receipt.Digest) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	w.Header().Set("ETag", quoteVersion(receipt.Revision))
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}
