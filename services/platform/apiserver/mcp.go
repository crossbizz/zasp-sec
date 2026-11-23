package apiserver

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/mcpserver"
)

// The router authenticates the outer MCP request. Each tool then runs a GET
// through the same router so its current credential, OpenFGA target and
// PostgreSQL statement checks independently govern that particular record.
func serveZaspMCP(w http.ResponseWriter, r *http.Request) {
	i, ok := IdentityFromRequest(r)
	if !ok {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	security, _ := r.Context().Value(browserSecurityContextKey{}).(browserSecurityContext)
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && (origins[0] == "" || origins[0] != security.publicOrigin) ||
		i.CredentialKind == CredentialBrowserSession && len(origins) != 1 {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if r.URL.RawQuery != "" || len(r.Header.Values("Mcp-Session-Id")) > 0 {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	routes := make(map[string]string)
	for _, op := range coreOperations {
		if op.Method != http.MethodGet || !slices.Contains(i.Permissions, op.Permission) {
			continue
		}
		scheme := "BrowserSession"
		if i.CredentialKind == CredentialBearerToken {
			scheme = "ProductAPIToken"
		}
		if slices.Contains(op.Security, scheme) {
			routes[op.OperationID] = op.Pattern
		}
	}
	reader := &agentEvidencePackHandler{}
	mcpserver.Serve(w, r, func(op string) bool { return routes[op] != "" }, func(ctx context.Context, op, id string, q url.Values) (int, []byte) {
		path, ok := routes[op]
		if !ok {
			return http.StatusForbidden, nil
		}
		readCtx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(ctx, cancel)
		defer cancel()
		defer stop()
		return reader.read(r.WithContext(readCtx), strings.Replace(path, "{id}", id, 1), q)
	})
}
