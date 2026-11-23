package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

const workforceInventorySQL = "SELECT zasp_authorization80.workforce_page($1,$2,$3,NULLIF($4,''),$5)"

func init() {
	productStatementRules[workforceInventorySQL] = productStatementRule{operations: []string{"listWorkforceInventory"}, arguments: 5, scope: 1, browserOnly: true, collection: true}
}

// Built-ins retain per-agent visibility. The Environment target covers only
// tenant-authored Studio definitions, whose own read API uses that scope.
func (r *PostgresAuthorizationResolver) workforceTargets(ctx context.Context, id RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
	items, err := resolveAuthorizationDatabase(ctx, r.database, id, route, authorizationOperationTarget{Mode: "collection", Kind: "security_agent"}, "")
	if err != nil {
		return AuthorizationTargets{}, err
	}
	env, err := resolveAuthorizationDatabase(ctx, r.database, id, route, authorizationOperationTarget{Mode: "scope", Kind: "environment"}, id.Scope.EnvironmentID().String())
	if err != nil {
		return AuthorizationTargets{}, err
	}
	if !items.Complete || !env.Complete || len(env.Targets) != 1 || len(items.Targets) >= 10000 {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	items.Targets = append(items.Targets, env.Targets...)
	return items, nil
}
func serveWorkforceInventory(db JSONDatabase, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	who, ok := IdentityFromRequest(r)
	if !ok || who.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	for k, v := range q {
		if !stringIn(k, "limit", "cursor") || len(v) != 1 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	}
	limit := 25
	if q.Has("limit") {
		var nerr error
		limit, nerr = strconv.Atoi(q.Get("limit"))
		if nerr != nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	}
	cursor := q.Get("cursor")
	id, kind, found := strings.Cut(cursor, ".")
	if r.Method != http.MethodGet || err != nil || limit < 1 || limit > 100 || (q.Has("cursor") && (!found || !validProductID(id) || !stringIn(kind, "built_in", "studio"))) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := who.Scope
	raw, err := db.QueryJSON(r.Context(), workforceInventorySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), cursor, limit)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &page) != nil || page.Items == nil || len(page.Items) > limit {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}
