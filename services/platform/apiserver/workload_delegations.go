package apiserver

import (
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
)

type delegationHop struct {
	delegation.Scope
	Parent   string `json:"parent_agent_id"`
	Child    string `json:"child_agent_id"`
	Depth    int    `json:"depth"`
	MaxDepth int    `json:"max_depth"`
	Expires  int64  `json:"expires_at"`
}

type delegationRecord struct {
	ID       string          `json:"id"`
	Task     string          `json:"parent_task_id"`
	Status   string          `json:"status"`
	Observed time.Time       `json:"observed_at"`
	Grants   []delegationHop `json:"grants"`
}

type delegationPage struct {
	Credential string             `json:"credential_id"`
	Agent      string             `json:"agent_id"`
	Truncated  bool               `json:"truncated"`
	Items      []delegationRecord `json:"items"`
}

const workloadDelegationsSQL = "SELECT zasp_authorization80.workload_delegations($1,$2,$3,$4,$5)"

func init() {
	productStatementRules[workloadDelegationsSQL] = productStatementRule{operations: []string{"getWorkloadDelegations"}, arguments: 5, scope: 1, actor: 4, object: 5, browserOnly: true, check: func(g RequestAuthorization, _ []any) bool {
		return authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}}
}

func serveWorkloadDelegations(db JSONDatabase, w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := op.PathParameters["id"]
	if r.Method != http.MethodGet || !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	t := delegationTenant(i)
	raw, err := db.QueryJSON(r.Context(), workloadDelegationsSQL, t.Organization, t.Workspace, t.Environment, i.PrincipalID.String(), id)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	var page delegationPage
	if decodeStrictDiscovery(raw, &page) != nil || page.Credential != id || !validProductID(page.Agent) || page.Items == nil || len(page.Items) > 25 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}
