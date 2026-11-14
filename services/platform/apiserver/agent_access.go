package apiserver

import (
	"context"
	"net/http"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// What an agent may use (completion.sql section WS5d): the model actions its
// role is granted against the ones it used, the MCP servers it uses, the
// data stores its identities reach and the skills of its repository.
const postgresAgentAccessSQL = `SELECT zasp_authorization80.agent_access($1,$2,$3,$4)`

// AgentAIActions compares granted with used model and agent actions. Unused
// lists only granted actions the audit log can show and did not.
type AgentAIActions struct {
	WindowDays int      `json:"window_days"`
	Granted    []string `json:"granted"`
	Used       []string `json:"used"`
	Unused     []string `json:"unused"`
}

type AgentMCPServer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Identity string `json:"identity"`
	Approval string `json:"approval"`
}

type AgentDataStore struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Service string `json:"service"`
	Access  string `json:"access"`
	Scope   string `json:"scope"`
}

// AgentSkill is a skill or instruction file: its path and kind, never its
// contents.
type AgentSkill struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// AgentTool is a topic or an action of an agent whose platform lists them
// (Agentforce). Target is what an action invokes (flow, apex, ...) and
// Confirmation whether it asks first; both are nil where the platform did
// not state them, and for a topic.
type AgentTool struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Kind         string  `json:"kind"`
	Target       *string `json:"target"`
	Confirmation *bool   `json:"confirmation"`
}

// AgentAccess is what one agent may use. AIActions is nil for an agent whose
// role's audit log was not read. Tools are the topics and actions the
// agent's platform lists for it and ToolKinds the kinds of tool it states
// (code_interpreter, file_search, mcp, ...); both are empty for an agent
// that has none.
type AgentAccess struct {
	AgentID    string           `json:"agent_id"`
	AIActions  *AgentAIActions  `json:"ai_actions"`
	MCPServers []AgentMCPServer `json:"mcp_servers"`
	DataStores []AgentDataStore `json:"data_stores"`
	Skills     []AgentSkill     `json:"skills"`
	Tools      []AgentTool      `json:"tools"`
	ToolKinds  []string         `json:"tool_kinds"`
}

// AgentAccessAuthority reads what an agent may use.
type AgentAccessAuthority interface {
	GetAgentAccess(context.Context, domain.Scope, domain.ProductID) (AgentAccess, error)
}

var (
	agentActionPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}:[A-Za-z]{1,64}$`)
	agentServicePattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	agentToolKindPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	agentToolTargetPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

func validAgentAccess(access AgentAccess, id string) bool {
	if access.AgentID != id || access.MCPServers == nil || access.DataStores == nil || access.Skills == nil || len(access.MCPServers) > 64 || len(access.DataStores) > 64 || len(access.Skills) > 64 {
		return false
	}
	if actions := access.AIActions; actions != nil {
		if actions.WindowDays < 1 || actions.WindowDays > 90 || len(actions.Granted) < 1 || actions.Used == nil || actions.Unused == nil || len(actions.Granted) > 32 || len(actions.Used) > 32 || len(actions.Unused) > 32 {
			return false
		}
		for _, list := range [][]string{actions.Granted, actions.Used, actions.Unused} {
			for _, action := range list {
				if !agentActionPattern.MatchString(action) {
					return false
				}
			}
		}
	}
	for _, server := range access.MCPServers {
		if !validProductID(server.ID) || !printableInventoryString(server.Name, 1, 256, false) || !validMCPIdentity(server.Identity) || !stringIn(server.Approval, "approved", "unapproved", "blocked") {
			return false
		}
	}
	for _, store := range access.DataStores {
		if !validProductID(store.ID) || !printableInventoryString(store.Name, 1, 256, false) || !agentServicePattern.MatchString(store.Service) || !stringIn(store.Access, "read", "write") || !stringIn(store.Scope, "resource", "service") {
			return false
		}
	}
	for _, skill := range access.Skills {
		if !validProductID(skill.ID) || !printableInventoryString(skill.Path, 1, 512, false) || !stringIn(skill.Kind, "skill", "agent_instructions", "editor_rules") {
			return false
		}
	}
	if access.Tools == nil || access.ToolKinds == nil || len(access.Tools) > 64 || len(access.ToolKinds) > 16 {
		return false
	}
	for _, tool := range access.Tools {
		if !validProductID(tool.ID) || !printableInventoryString(tool.Name, 1, 256, false) || !stringIn(tool.Kind, "topic", "action") || tool.Target != nil && !agentToolTargetPattern.MatchString(*tool.Target) || tool.Kind == "topic" && (tool.Target != nil || tool.Confirmation != nil) {
			return false
		}
	}
	for index, kind := range access.ToolKinds {
		if !agentToolKindPattern.MatchString(kind) || index > 0 && kind <= access.ToolKinds[index-1] {
			return false
		}
	}
	return true
}

func (repository *PostgresInventoryRepository) GetAgentAccess(ctx context.Context, scope domain.Scope, id domain.ProductID) (AgentAccess, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || id.IsZero() {
		return AgentAccess{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAgentAccessSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id.String())
	if err != nil {
		return AgentAccess{}, inventoryProviderError(err)
	}
	var access AgentAccess
	if decodeStrictInventory(payload, &access) != nil {
		return AgentAccess{}, ErrRepositoryUnavailable
	}
	// A database the baseline completion has not reached with section WS7c
	// answers without the two tool members: the agent then has none to show.
	if access.Tools == nil {
		access.Tools = []AgentTool{}
	}
	if access.ToolKinds == nil {
		access.ToolKinds = []string{}
	}
	if !validAgentAccess(access, id.String()) {
		return AgentAccess{}, ErrRepositoryUnavailable
	}
	return access, nil
}

func (handler *inventoryHTTPHandler) agentAccess(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	authority, supported := handler.repository.(AgentAccessAuthority)
	id, err := domain.ParseProductID(routed.PathParameters["id"])
	if !supported || request.Method != http.MethodGet || request.URL.RawQuery != "" || err != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	access, err := authority.GetAgentAccess(request.Context(), identity.Scope, id)
	writeJSONValue(writer, request, http.StatusOK, access, err)
}
