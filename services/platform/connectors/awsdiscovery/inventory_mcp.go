package awsdiscovery

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// MCP servers, their tools, who uses them, and what an agent's role may do
// with models and data: the parts of the agent source added for the MCP
// inventory, the used-against-granted comparison and attack paths.

// Bounds of the MCP and access parts of one account's source.
const (
	MaximumInventoryGatewayTargets = 200
	MaximumInventoryMCPServers     = 500
	MaximumInventoryUses           = 5_000
	MaximumInventoryDataAccess     = 2_000
	MaximumInventoryRoleUsage      = 5_000
)

// AgentInventoryGatewayTarget is one target of an AgentCore gateway. Tools
// are the names of the tools the target declares inline (a Lambda target);
// RemoteHost is the host of the MCP server an MCP server target fronts. A
// tool description or schema is never kept.
type AgentInventoryGatewayTarget struct {
	Name       string   `json:"name"`
	RemoteHost string   `json:"remote_host,omitempty"`
	TargetID   string   `json:"target_id"`
	Tools      []string `json:"tools,omitempty"`
}

// AgentInventoryMCPServer is a remote MCP server named by a host: one a
// workload was seen resolving and reaching (source egress) or one a gateway
// target fronts (source gateway_target).
type AgentInventoryMCPServer struct {
	Host   string `json:"host"`
	Region string `json:"region"`
	Source string `json:"source"`
}

// AgentInventoryUse says an agent of the source uses an MCP server of the
// source. Server is a gateway ARN, or "<region>/<host>" of an MCP server.
type AgentInventoryUse struct {
	Agent  string `json:"agent"`
	Server string `json:"server"`
}

// AgentInventoryDataAccess says the policies of an agent's role allow data
// actions on a resource (scope resource) or on every resource of a data
// service (scope service, ARN "arn:aws:<service>:::*").
type AgentInventoryDataAccess struct {
	Access  string `json:"access"`
	ARN     string `json:"arn"`
	RoleARN string `json:"role_arn"`
	Scope   string `json:"scope"`
	Service string `json:"service"`
}

// AgentInventoryRoleUsage compares what a role's policies grant with what
// the audit log shows it used in the window. Granted and Used are IAM action
// names from the catalog (agentsignals.GrantedAIActions); Unused are the
// granted actions the audit log can show and did not.
type AgentInventoryRoleUsage struct {
	Granted []string `json:"granted"`
	RoleARN string   `json:"role_arn"`
	Unused  []string `json:"unused"`
	Used    []string `json:"used"`
}

const (
	// The policies of an agent's role allow model actions the audit log
	// shows the role never used in the window.
	AgentCheckRoleUnusedAI = "agent_role_unused_ai_permissions"
	// The policies of an agent's role allow data actions on every resource
	// of a data service. The check is on the data store entity.
	AgentCheckDataServiceWide = "agent_data_service_wide_access"
)

// The AgentCore gateway authorizer types the control plane names.
var agentGatewayAuthorizers = map[string]bool{"": true, "AWS_IAM": true, "AUTHENTICATE_ONLY": true, "CUSTOM_JWT": true, "NONE": true}

var (
	agentHostPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){1,8}$`)
	agentTargetIDPattern  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z_-]{0,127}$`)
	agentServicePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	agentDataARNPattern   = regexp.MustCompile(`^arn:aws:[a-z0-9-]{2,32}:[a-z0-9-]{0,32}:[0-9]{0,12}:[A-Za-z0-9+=,.@_/:*?-]{1,400}$`)
	agentActionPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}:[A-Za-z]{1,64}$`)
	agentECSServiceARN    = regexp.MustCompile(`^arn:aws:ecs:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):service/([A-Za-z0-9_-]{1,255})/([A-Za-z0-9_-]{1,255})$`)
	agentEKSClusterARN    = regexp.MustCompile(`^arn:aws:eks:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):cluster/([A-Za-z0-9][A-Za-z0-9_-]{0,99})$`)
	agentDataAccessValues = map[string]bool{"read": true, "write": true}
)

func sortedUniqueNames(values []string, valid func(string) bool) bool {
	previous := ""
	for _, value := range values {
		if !valid(value) || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

// validAgentInventoryMCP checks the MCP and access parts of a source. agents
// are the ARNs of the source's agents and roles the role ARNs they run as.
func validAgentInventoryMCP(source AgentInventorySource, accountID string, agents, roles map[string]bool) bool {
	if len(source.MCPServers) > MaximumInventoryMCPServers || len(source.Uses) > MaximumInventoryUses || len(source.DataAccess) > MaximumInventoryDataAccess || len(source.RoleUsage) > MaximumInventoryRoleUsage {
		return false
	}
	servers := map[string]bool{}
	for _, gateway := range source.Gateways {
		servers[gateway.ARN] = true
		if !agentGatewayAuthorizers[gateway.Authorizer] || gateway.EndpointHost != "" && !agentHostPattern.MatchString(gateway.EndpointHost) || len(gateway.Targets) > MaximumInventoryGatewayTargets {
			return false
		}
		previous := ""
		for _, target := range gateway.Targets {
			if !agentTargetIDPattern.MatchString(target.TargetID) || target.TargetID <= previous || !validAgentInventoryText(target.Name, 256) || target.RemoteHost != "" && !agentHostPattern.MatchString(target.RemoteHost) ||
				len(target.Tools) > agentsignals.MaximumMCPToolsPerServer || !sortedUniqueNames(target.Tools, agentsignals.ValidMCPToolName) {
				return false
			}
			previous = target.TargetID
		}
	}
	previous := ""
	for _, server := range source.MCPServers {
		key := server.Region + "/" + server.Host
		if !agentRegionPattern.MatchString(server.Region) || !agentHostPattern.MatchString(server.Host) || server.Source != "egress" && server.Source != "gateway_target" || key <= previous {
			return false
		}
		previous = key
		servers[key] = true
	}
	previous = ""
	for _, use := range source.Uses {
		key := use.Agent + "\x1f" + use.Server
		if !agents[use.Agent] || !servers[use.Server] || key <= previous {
			return false
		}
		previous = key
	}
	previous = ""
	stores := map[string]string{}
	for _, access := range source.DataAccess {
		key := access.RoleARN + "\x1f" + access.ARN
		if !roles[access.RoleARN] || access.RoleARN == "" || !agentDataARNPattern.MatchString(access.ARN) || !agentServicePattern.MatchString(access.Service) || !agentDataAccessValues[access.Access] ||
			access.Scope != "resource" && access.Scope != "service" || (access.Scope == "service") != (access.ARN == "arn:aws:"+access.Service+":::*") || key <= previous {
			return false
		}
		// One store has one service and one scope, whoever reaches it.
		if prior, seen := stores[access.ARN]; seen && prior != access.Service+"/"+access.Scope {
			return false
		}
		stores[access.ARN] = access.Service + "/" + access.Scope
		previous = key
	}
	previous = ""
	validAction := func(action string) bool { return agentActionPattern.MatchString(action) }
	for _, usage := range source.RoleUsage {
		if !roles[usage.RoleARN] || usage.RoleARN <= previous || usage.Granted == nil || usage.Used == nil || usage.Unused == nil || len(usage.Granted) < 1 || len(usage.Granted) > 32 || len(usage.Used) > 32 ||
			!sortedUniqueNames(usage.Granted, validAction) || !sortedUniqueNames(usage.Used, validAction) || !sortedUniqueNames(usage.Unused, validAction) {
			return false
		}
		granted := map[string]bool{}
		for _, action := range usage.Granted {
			granted[action] = true
		}
		for _, action := range usage.Unused {
			if !granted[action] {
				return false
			}
		}
		previous = usage.RoleARN
	}
	// A check names an agent or, for the data check, a service-wide store.
	previous = ""
	for _, check := range source.Checks {
		key := check.ARN + "\x1f" + check.Check
		if key <= previous {
			return false
		}
		previous = key
		switch {
		case check.Check == AgentCheckDataServiceWide:
			if !strings.HasSuffix(stores[check.ARN], "/service") {
				return false
			}
		case !agents[check.ARN] || !agentChecks[check.Check]:
			return false
		}
	}
	return true
}

// agentCheckEntityKind returns the inventory kind of the entity a check is
// on.
func agentCheckEntityKind(check AgentInventoryCheck) string {
	if check.Check == AgentCheckDataServiceWide {
		return "aws_data_store"
	}
	return agentInventoryKind(check.ARN)
}

// mcpServerNative is the native id of a remote MCP server of the account.
func mcpServerNative(region, host string) string {
	return "aws:mcp_server:" + region + ":" + host
}

var agentDataServiceNames = map[string]string{"s3": "S3 buckets", "dynamodb": "DynamoDB tables", "secretsmanager": "Secrets Manager secrets", "ssm": "Systems Manager parameters", "rds-data": "RDS Data API databases"}

// agentDataStoreName is the display name of a data store: the last element
// of its ARN, or the service's resources for a service-wide grant.
func agentDataStoreName(access AgentInventoryDataAccess) string {
	if access.Scope == "service" {
		if name, known := agentDataServiceNames[access.Service]; known {
			return "All " + name
		}
		return "All " + access.Service + " resources"
	}
	name := access.ARN[strings.LastIndex(access.ARN, ":")+1:]
	if len(name) > 256 {
		name = name[len(name)-256:]
	}
	return strings.TrimSpace(name)
}

// mcpInventory emits the MCP servers, tools and uses of the source and the
// data stores its agent roles reach. agentIDs maps an agent ARN to its
// entity id; knownRoles are the roles the IAM phase emitted.
func mcpInventory(scope domain.Scope, subject collection.SubjectBinding, source AgentInventorySource, accountEntityID string, agentIDs map[string]string, knownRoles map[string]bool) ([]json.RawMessage, []json.RawMessage) {
	var entities, relationships []json.RawMessage
	serverIDs := map[string]string{}
	for _, gateway := range source.Gateways {
		gatewayID := deterministicAWSInventoryID(scope, subject, "aws_agentcore_gateway", gateway.ARN)
		serverIDs[gateway.ARN] = gatewayID
		for _, target := range gateway.Targets {
			for _, tool := range target.Tools {
				native := gateway.ARN + "/target/" + target.TargetID + "/tool/" + tool
				id := deterministicAWSInventoryID(scope, subject, "aws_mcp_tool", native)
				entities = append(entities, marshalInventoryEntity(id, "aws_mcp_tool", native, tool,
					map[string]any{"account_id": subject.ID, "arn": gateway.ARN, "name": tool, "region": gateway.Region, "server": gateway.GatewayID, "target": target.TargetID},
					map[string]any{"risk": agentsignals.MCPToolRisk(tool)}))
				relationships = append(relationships, marshalInventoryRelationship(scope, subject, "contains", gateway.ARN+"|contains|"+native, gatewayID, id))
			}
		}
	}
	for _, server := range source.MCPServers {
		native := mcpServerNative(server.Region, server.Host)
		id := deterministicAWSInventoryID(scope, subject, "aws_mcp_server", native)
		serverIDs[server.Region+"/"+server.Host] = id
		entities = append(entities, marshalInventoryEntity(id, "aws_mcp_server", native, server.Host,
			map[string]any{"account_id": subject.ID, "name": server.Host, "region": server.Region},
			map[string]any{"source": server.Source, "transport": agentsignals.MCPTransportHTTP, "endpoint_host": server.Host}))
		relationships = append(relationships, marshalInventoryRelationship(scope, subject, "contains", subject.ID+"|contains|"+native, accountEntityID, id))
	}
	// A gateway depends on the remote servers its targets front.
	for _, gateway := range source.Gateways {
		seen := map[string]bool{}
		for _, target := range gateway.Targets {
			key := gateway.Region + "/" + target.RemoteHost
			if target.RemoteHost == "" || seen[key] || serverIDs[key] == "" {
				continue
			}
			seen[key] = true
			relationships = append(relationships, marshalInventoryRelationship(scope, subject, "depends_on", gateway.ARN+"|depends_on|"+mcpServerNative(gateway.Region, target.RemoteHost), serverIDs[gateway.ARN], serverIDs[key]))
		}
	}
	for _, use := range source.Uses {
		if agentIDs[use.Agent] == "" || serverIDs[use.Server] == "" {
			continue
		}
		relationships = append(relationships, marshalInventoryRelationship(scope, subject, "depends_on", use.Agent+"|depends_on|"+use.Server, agentIDs[use.Agent], serverIDs[use.Server]))
	}
	// One entity per store; it is writable when any role may write to it.
	type store struct {
		access AgentInventoryDataAccess
		write  bool
	}
	stores := map[string]*store{}
	var order []string
	for _, access := range source.DataAccess {
		if stores[access.ARN] == nil {
			stores[access.ARN] = &store{access: access}
			order = append(order, access.ARN)
		}
		stores[access.ARN].write = stores[access.ARN].write || access.Access == "write"
	}
	for _, arn := range order {
		found := stores[arn]
		access := "read"
		if found.write {
			access = "write"
		}
		id := deterministicAWSInventoryID(scope, subject, "aws_data_store", arn)
		name := agentDataStoreName(found.access)
		if name == "" {
			name = found.access.Service
		}
		entities = append(entities, marshalInventoryEntity(id, "aws_data_store", arn, name,
			map[string]any{"account_id": subject.ID, "arn": arn, "name": name, "service": found.access.Service},
			map[string]any{"access": access, "scope": found.access.Scope}))
		relationships = append(relationships, marshalInventoryRelationship(scope, subject, "contains", subject.ID+"|contains|"+arn, accountEntityID, id))
	}
	for _, access := range source.DataAccess {
		if !knownRoles[access.RoleARN] {
			continue
		}
		relationships = append(relationships, marshalInventoryRelationship(scope, subject, "depends_on", access.RoleARN+"|depends_on|"+access.ARN,
			deterministicAWSInventoryID(scope, subject, "aws_role", access.RoleARN), deterministicAWSInventoryID(scope, subject, "aws_data_store", access.ARN)))
	}
	return entities, relationships
}

// gatewayMCPAttributes are the MCP server attributes of a gateway whose
// description was read. An authorizer of NONE is a remote server with no
// authentication; any other authorizer is declared authentication.
func gatewayMCPAttributes(gateway AgentInventoryGateway) map[string]any {
	attributes := map[string]any{}
	if gateway.Status != "" {
		attributes["status"] = gateway.Status
	}
	if gateway.Authorizer == "" {
		return attributes
	}
	attributes["source"], attributes["transport"] = "agentcore_gateway", agentsignals.MCPTransportHTTP
	attributes["auth"] = agentsignals.MCPAuthDeclared
	if gateway.Authorizer == "NONE" {
		attributes["auth"] = agentsignals.MCPAuthNone
	}
	if gateway.EndpointHost != "" {
		attributes["endpoint_host"] = gateway.EndpointHost
	}
	return attributes
}

// roleUsageAttributes are the used-against-granted attributes of an agent
// whose role the audit log was read for: comma-separated IAM action names.
func roleUsageAttributes(attributes map[string]any, usage AgentInventoryRoleUsage) {
	attributes["ai_actions_granted"] = strings.Join(usage.Granted, ",")
	if len(usage.Used) > 0 {
		attributes["ai_actions_used"] = strings.Join(usage.Used, ",")
	}
	if len(usage.Unused) > 0 {
		attributes["ai_actions_unused"] = strings.Join(usage.Unused, ",")
	}
}
