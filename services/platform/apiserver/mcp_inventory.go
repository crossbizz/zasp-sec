package apiserver

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// MCP servers, their tools and users, and the approved-servers registry
// (completion.sql section WS5b). The three statements are the API's only way
// to that data; each checks the request's authorization proof itself.
const (
	postgresMCPServerPageSQL   = `SELECT zasp_authorization80.mcp_server_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresMCPRegistryPageSQL = `SELECT zasp_authorization80.mcp_registry_page($1,$2,$3)`
	postgresMCPRegistryPutSQL  = `SELECT zasp_authorization80.mcp_registry_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
)

// MCPTool is a tool an MCP server declares, with the risk class its name
// falls in. A tool's description is never stored.
type MCPTool struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Risk string `json:"risk"`
}

type MCPAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MCPServer is one discovered MCP server. Identity is what a person approves
// or blocks; Approval is the registry's decision for it, or unapproved.
// Tools and Agents are bounded lists; the counts are the totals.
type MCPServer struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Provider      string     `json:"provider"`
	SourceKind    string     `json:"source_kind"`
	Source        string     `json:"source"`
	Transport     *string    `json:"transport"`
	EndpointHost  *string    `json:"endpoint_host"`
	Command       *string    `json:"command"`
	Package       *string    `json:"package"`
	PackagePinned *bool      `json:"package_pinned"`
	PlainHTTP     bool       `json:"plain_http"`
	Auth          string     `json:"auth"`
	Identity      string     `json:"identity"`
	Approval      string     `json:"approval"`
	Tools         []MCPTool  `json:"tools"`
	ToolCount     int        `json:"tool_count"`
	Agents        []MCPAgent `json:"agents"`
	AgentCount    int        `json:"agent_count"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
}

type MCPServerPage struct {
	Items   []MCPServer
	NextKey string
}

// MCPRegistryEntry is a decision about one MCP server identity. A removed
// decision is returned with status unapproved and version 0.
type MCPRegistryEntry struct {
	Identity    string    `json:"identity"`
	Status      string    `json:"status"`
	Note        string    `json:"note"`
	Version     int64     `json:"version"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
	ServerCount int       `json:"server_count"`
	AuditID     string    `json:"audit_id,omitempty"`
}

type MCPRegistryInput struct {
	Identity        string
	Status          string
	Note            string
	ExpectedVersion int64
}

// MCPInventoryAuthority reads the MCP servers and reads and saves the
// registry.
type MCPInventoryAuthority interface {
	ListMCPServersPage(context.Context, domain.Scope, string, int) (MCPServerPage, error)
	ListMCPRegistry(context.Context, domain.Scope) ([]MCPRegistryEntry, error)
	PutMCPRegistryEntry(context.Context, RequestIdentity, MCPRegistryInput, string, string) (MCPRegistryEntry, error)
}

var mcpIdentityPattern = regexp.MustCompile(`^(host|package|repository|workload|arn|saas|name):[^\x00-\x1f\x7f]{1,480}$`)

func validMCPIdentity(value string) bool {
	return len(value) <= 512 && mcpIdentityPattern.MatchString(value) && printableInventoryString(value, 1, 512, false)
}

func validMCPRegistryInput(input MCPRegistryInput) bool {
	return validMCPIdentity(input.Identity) && stringIn(input.Status, "approved", "blocked", "unapproved") && printableInventoryString(input.Note, 0, 512, true) && input.ExpectedVersion >= 0 && input.ExpectedVersion <= 999_999
}

func validMCPServer(server MCPServer) bool {
	optional := func(value *string, maximum int) bool {
		return value == nil || printableInventoryString(*value, 1, maximum, false)
	}
	if !validProductID(server.ID) || !printableInventoryString(server.Name, 1, 256, false) || !stringIn(server.Provider, "aws", "github", "kubernetes", "saas") ||
		!stringIn(server.SourceKind, "aws_agentcore_gateway", "aws_mcp_server", "github_mcp_server", "kubernetes_mcp_server", "saas_mcp_server") ||
		!stringIn(server.Source, "agentcore_gateway", "egress", "gateway_target", "repository_config", "workload", "saas_api", "provider_api") ||
		server.Transport != nil && !stringIn(*server.Transport, "stdio", "http", "sse") || !optional(server.EndpointHost, 253) || !optional(server.Command, 64) || !optional(server.Package, 256) ||
		(server.Package == nil) != (server.PackagePinned == nil) || !stringIn(server.Auth, "declared", "none", "not_applicable", "unknown") || !validMCPIdentity(server.Identity) ||
		!stringIn(server.Approval, "approved", "unapproved", "blocked") || server.Tools == nil || server.Agents == nil || len(server.Tools) > 64 || len(server.Agents) > 50 ||
		server.ToolCount < len(server.Tools) || server.AgentCount < len(server.Agents) || server.FirstSeenAt.IsZero() || server.LastSeenAt.Before(server.FirstSeenAt) {
		return false
	}
	for _, tool := range server.Tools {
		if !validProductID(tool.ID) || !printableInventoryString(tool.Name, 1, 256, false) || !stringIn(tool.Risk, "execute", "write", "network", "read", "unclassified") {
			return false
		}
	}
	for _, agent := range server.Agents {
		if !validProductID(agent.ID) || !printableInventoryString(agent.Name, 1, 256, false) {
			return false
		}
	}
	return true
}

func validMCPRegistryEntry(entry MCPRegistryEntry) bool {
	return validMCPIdentity(entry.Identity) && printableInventoryString(entry.Note, 0, 512, true) && validProductID(entry.UpdatedBy) && !entry.UpdatedAt.IsZero() && entry.ServerCount >= 0 &&
		(stringIn(entry.Status, "approved", "blocked") && entry.Version >= 1 && entry.Version <= 1_000_000 || entry.Status == "unapproved" && entry.Version == 0)
}

func (repository *PostgresInventoryRepository) ListMCPServersPage(ctx context.Context, scope domain.Scope, after string, limit int) (MCPServerPage, error) {
	if !validInventoryCall(repository, ctx, scope, InventoryKindTool, after, limit) {
		return MCPServerPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresMCPServerPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), after, limit)
	if err != nil {
		return MCPServerPage{}, inventoryProviderError(err)
	}
	var envelope struct {
		Items  []MCPServer `json:"items"`
		NextID *string     `json:"next_id"`
	}
	if decodeStrictInventory(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return MCPServerPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for _, server := range envelope.Items {
		if !validMCPServer(server) || prior != "" && server.ID <= prior {
			return MCPServerPage{}, ErrRepositoryUnavailable
		}
		prior = server.ID
	}
	next := ""
	if envelope.NextID != nil {
		next = *envelope.NextID
		if len(envelope.Items) != limit || next == "" || envelope.Items[len(envelope.Items)-1].ID != next {
			return MCPServerPage{}, ErrRepositoryUnavailable
		}
	}
	return MCPServerPage{Items: envelope.Items, NextKey: next}, nil
}

func (repository *PostgresInventoryRepository) ListMCPRegistry(ctx context.Context, scope domain.Scope) ([]MCPRegistryEntry, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresMCPRegistryPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return nil, inventoryProviderError(err)
	}
	var envelope struct {
		Items []MCPRegistryEntry `json:"items"`
	}
	if decodeStrictInventory(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > 500 {
		return nil, ErrRepositoryUnavailable
	}
	prior := ""
	for _, entry := range envelope.Items {
		if !validMCPRegistryEntry(entry) || entry.Status == "unapproved" || entry.AuditID != "" || entry.Identity <= prior {
			return nil, ErrRepositoryUnavailable
		}
		prior = entry.Identity
	}
	return envelope.Items, nil
}

func (repository *PostgresInventoryRepository) PutMCPRegistryEntry(ctx context.Context, identity RequestIdentity, input MCPRegistryInput, auditID, correlationID string) (MCPRegistryEntry, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !validMCPRegistryInput(input) || !validProductID(auditID) || !validProductID(correlationID) {
		return MCPRegistryEntry{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresMCPRegistryPutSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		input.Identity, input.Status, input.Note, input.ExpectedVersion, auditID, correlationID)
	if err != nil {
		return MCPRegistryEntry{}, inventoryProviderError(err)
	}
	var entry MCPRegistryEntry
	wantVersion := input.ExpectedVersion + 1
	if input.Status == "unapproved" {
		wantVersion = 0
	}
	if decodeStrictInventory(payload, &entry) != nil || !validMCPRegistryEntry(entry) || entry.Identity != input.Identity || entry.Status != input.Status || entry.Version != wantVersion || entry.UpdatedBy != identity.PrincipalID.String() || entry.AuditID != auditID ||
		input.Status != "unapproved" && entry.Note != input.Note {
		return MCPRegistryEntry{}, ErrRepositoryUnavailable
	}
	return entry, nil
}

func (handler *inventoryHTTPHandler) mcpServerPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	authority, supported := handler.repository.(MCPInventoryAuthority)
	if !supported {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	after, limit, ok := handler.pageQuery(request, identity.Scope, routed.OperationID, InventoryKindTool, "")
	if !ok {
		handler.writePageQueryError(writer, request)
		return
	}
	page, err := authority.ListMCPServersPage(request.Context(), identity.Scope, after, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	handler.writePage(writer, request, identity.Scope, routed.OperationID, InventoryKindTool, "", limit, page.Items, page.NextKey)
}

func (handler *inventoryHTTPHandler) mcpRegistry(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	authority, supported := handler.repository.(MCPInventoryAuthority)
	if !supported || request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	entries, err := authority.ListMCPRegistry(request.Context(), identity.Scope)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": entries}, nil)
}

func (handler *inventoryHTTPHandler) putMCPRegistryEntry(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	authority, supported := handler.repository.(MCPInventoryAuthority)
	var body struct {
		Identity        *string `json:"identity"`
		Status          *string `json:"status"`
		Note            *string `json:"note"`
		ExpectedVersion *int64  `json:"expected_version"`
	}
	if !supported || request.Method != http.MethodPut || request.URL.RawQuery != "" || decodeProductionJSON(request, &body) != nil || body.Identity == nil || body.Status == nil || body.Note == nil || body.ExpectedVersion == nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	input := MCPRegistryInput{Identity: *body.Identity, Status: *body.Status, Note: *body.Note, ExpectedVersion: *body.ExpectedVersion}
	if !validMCPRegistryInput(input) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	auditID, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	entry, err := authority.PutMCPRegistryEntry(request.Context(), identity, input, auditID, correlationIDFromContext(request.Context()))
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(entry.Version))
	writer.Header().Set("X-Audit-ID", entry.AuditID)
	writeJSONValue(writer, request, http.StatusOK, entry, nil)
}
