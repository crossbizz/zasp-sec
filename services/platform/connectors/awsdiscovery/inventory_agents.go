package awsdiscovery

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// The AI services the agents phase reads, in the order the source lists them.
const (
	AgentServiceBedrockAgents = "bedrock-agent"
	AgentServiceAgentCore     = "bedrock-agentcore"
	AgentServiceLambda        = "lambda"
)

// What one AI service answered across the account's enabled regions. The
// worst answer of any region is the service's status.
const (
	AgentServiceCollected    = "collected"
	AgentServiceUnavailable  = "unavailable"
	AgentServiceAccessDenied = "access_denied"
)

// Bounds of one account's agent source. More than this is refused, never cut.
const (
	MaximumInventoryBedrockAgents   = 1_000
	MaximumInventoryAgentRuntimes   = 1_000
	MaximumInventoryAgentGateways   = 1_000
	MaximumInventoryLambdaFunctions = 5_000
)

// AgentInventorySource is the canonical JSON the agents phase is derived
// from. Members and their fields are in the alphabetical order of their JSON
// names, every list is sorted by ARN and Services lists the three AI services
// in name order. It holds identifiers, names, states, role ARNs and catalog
// signal tokens only: no environment variable name or value, no agent
// instruction, no provider error text.
type AgentInventorySource struct {
	AccountID     string                       `json:"account_id"`
	BedrockAgents []AgentInventoryBedrockAgent `json:"bedrock_agents"`
	// Checks are the failed agent posture checks; absent when there are none.
	Checks []AgentInventoryCheck `json:"checks,omitempty"`
	// DataAccess is what the policies of the agents' roles allow on data
	// services; absent when there is none.
	DataAccess []AgentInventoryDataAccess `json:"data_access,omitempty"`
	Gateways   []AgentInventoryGateway    `json:"gateways"`
	// Workloads are roles and instances inferred to be agents from the
	// account's audit and network logs; absent when there are none.
	InferredWorkloads []AgentInventoryWorkload       `json:"inferred_workloads,omitempty"`
	LambdaFunctions   []AgentInventoryLambdaFunction `json:"lambda_functions"`
	// MCPServers are remote MCP servers named by host; absent when none.
	MCPServers []AgentInventoryMCPServer `json:"mcp_servers,omitempty"`
	// RoleUsage compares granted with used model actions per agent role the
	// audit log was read for; absent when it was not read.
	RoleUsage []AgentInventoryRoleUsage `json:"role_usage,omitempty"`
	Runtimes  []AgentInventoryRuntime   `json:"runtimes"`
	Services  []AgentInventoryService   `json:"services"`
	// Uses relate agents to the MCP servers they use; absent when none.
	Uses []AgentInventoryUse `json:"uses,omitempty"`
}

// Model, RoleARN and Status are "" when the provider did not say.
type AgentInventoryBedrockAgent struct {
	AgentID string `json:"agent_id"`
	ARN     string `json:"arn"`
	Model   string `json:"model"`
	Name    string `json:"name"`
	Region  string `json:"region"`
	RoleARN string `json:"role_arn"`
	Status  string `json:"status"`
}

// AgentInventoryCheck is one failed posture check on an agent of this
// source, named by the agent's ARN.
type AgentInventoryCheck struct {
	ARN   string `json:"arn"`
	Check string `json:"check"`
}

// Agent posture checks. Each is a finding rule the product explains.
const (
	// A Bedrock agent has no guardrail attached.
	AgentCheckGuardrailMissing = "agent_guardrail_missing"
	// The agent's execution role was not used in the last 90 days.
	AgentCheckRoleUnused = "agent_role_unused_90_days"
	// The agent's execution role allows every action on every resource.
	AgentCheckRoleAdministrator = "agent_role_administrator_access"
)

// AgentInventoryWorkload is an IAM role or an EC2 instance the collector
// concluded is an agent: the audit log shows the role invoking a model, or
// the network logs show the instance resolving and reaching a model API.
// ResourceType is iam_role, ec2_instance, ecs_service (the network interface
// of an ECS task names its service) or eks_pod (a pod address of an EKS
// cluster; the ARN is the cluster's, the logs do not name the pod). Region is
// where it was seen.
type AgentInventoryWorkload struct {
	ARN          string   `json:"arn"`
	Name         string   `json:"name"`
	Region       string   `json:"region"`
	ResourceType string   `json:"resource_type"`
	RoleARN      string   `json:"role_arn"`
	Signals      []string `json:"signals"`
}

// Authorizer is the gateway's inbound authorizer type (AWS_IAM, CUSTOM_JWT,
// NONE, AUTHENTICATE_ONLY), "" when its description could not be read.
// EndpointHost is the host of the gateway's MCP URL.
type AgentInventoryGateway struct {
	ARN          string                        `json:"arn"`
	Authorizer   string                        `json:"authorizer,omitempty"`
	EndpointHost string                        `json:"endpoint_host,omitempty"`
	GatewayID    string                        `json:"gateway_id"`
	Name         string                        `json:"name"`
	Region       string                        `json:"region"`
	Status       string                        `json:"status"`
	Targets      []AgentInventoryGatewayTarget `json:"targets,omitempty"`
}

// AgentInventoryLambdaFunction is a function the collector concluded is an
// agent. Signals are agentsignals catalog tokens, at least one.
type AgentInventoryLambdaFunction struct {
	ARN     string   `json:"arn"`
	Name    string   `json:"name"`
	Region  string   `json:"region"`
	RoleARN string   `json:"role_arn"`
	Signals []string `json:"signals"`
	State   string   `json:"state"`
}

type AgentInventoryRuntime struct {
	ARN       string `json:"arn"`
	Name      string `json:"name"`
	Region    string `json:"region"`
	RoleARN   string `json:"role_arn"`
	RuntimeID string `json:"runtime_id"`
	Status    string `json:"status"`
}

type AgentInventoryService struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

var (
	agentBedrockARNPattern = regexp.MustCompile(`^arn:aws:bedrock:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):agent/([0-9A-Za-z]{1,64})$`)
	agentRuntimeARNPattern = regexp.MustCompile(`^arn:aws:bedrock-agentcore:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):runtime/([0-9A-Za-z][0-9A-Za-z_-]{0,127})$`)
	agentGatewayARNPattern = regexp.MustCompile(`^arn:aws:bedrock-agentcore:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):gateway/([0-9A-Za-z][0-9A-Za-z_-]{0,127})$`)
	agentLambdaARNPattern  = regexp.MustCompile(`^arn:aws:lambda:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):function:([0-9A-Za-z_-]{1,140})$`)
	agentStatePattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z_]{0,63}$`)
	agentSignalPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$`)
)

var agentInventoryServices = []struct{ service, name string }{
	{AgentServiceBedrockAgents, "Bedrock Agents"},
	{AgentServiceAgentCore, "Bedrock AgentCore"},
	{AgentServiceLambda, "Lambda"},
}

// The log sources the runtime signal is read from. A source reports them
// after the three AI services, in this order, and only the ones it tried.
const (
	AgentServiceCloudTrail   = "cloudtrail"
	AgentServiceFlowLogs     = "vpc-flow-logs"
	AgentServiceResolverLogs = "resolver-query-logs"
)

var agentInventoryLogServices = []struct{ service, name string }{
	{AgentServiceCloudTrail, "CloudTrail model invocations"},
	{AgentServiceResolverLogs, "Route 53 Resolver query logs"},
	{AgentServiceFlowLogs, "VPC Flow Logs"},
}

// agentInventoryServiceName returns the display name of the service at a
// position of a source's service list.
func agentInventoryServiceName(service string) string {
	for _, known := range agentInventoryServices {
		if known.service == service {
			return known.name
		}
	}
	for _, known := range agentInventoryLogServices {
		if known.service == service {
			return known.name
		}
	}
	return service
}

var (
	agentInstanceARNPattern = regexp.MustCompile(`^arn:aws:ec2:([a-z]{2}(?:-gov)?-[a-z]+-[1-9]):([0-9]{12}):instance/(i-[0-9a-f]{8,17})$`)
	agentRegionPattern      = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9]$`)
	agentChecks             = map[string]bool{AgentCheckGuardrailMissing: true, AgentCheckRoleUnused: true, AgentCheckRoleAdministrator: true, AgentCheckRoleUnusedAI: true}
)

// EncodeAgentInventorySource returns the canonical source for an account, or
// false when the source is not one the agents phase accepts.
func EncodeAgentInventorySource(source AgentInventorySource) (json.RawMessage, bool) {
	if !validAgentInventorySource(source, source.AccountID) {
		return nil, false
	}
	encoded, err := json.Marshal(source)
	if err != nil || !canonicalSecurityObject(encoded) {
		return nil, false
	}
	return encoded, true
}

func decodeAgentInventorySource(raw json.RawMessage, accountID string) (AgentInventorySource, bool) {
	var source AgentInventorySource
	if !canonicalSecurityObject(raw) || !decodeExactSecurityResult(raw, &source) || !validAgentInventorySource(source, accountID) {
		return AgentInventorySource{}, false
	}
	return source, true
}

func validAgentInventoryDocument(raw json.RawMessage, accountID string) bool {
	_, ok := decodeAgentInventorySource(raw, accountID)
	return ok
}

func validAgentInventorySource(source AgentInventorySource, accountID string) bool {
	if !awsAccountIDPattern.MatchString(accountID) || source.AccountID != accountID || source.BedrockAgents == nil || source.Gateways == nil || source.LambdaFunctions == nil || source.Runtimes == nil ||
		len(source.BedrockAgents) > MaximumInventoryBedrockAgents || len(source.Gateways) > MaximumInventoryAgentGateways || len(source.LambdaFunctions) > MaximumInventoryLambdaFunctions || len(source.Runtimes) > MaximumInventoryAgentRuntimes ||
		len(source.Services) < len(agentInventoryServices) || len(source.Services) > len(agentInventoryServices)+len(agentInventoryLogServices) {
		return false
	}
	nextLog := 0
	for index, service := range source.Services {
		if service.Status != AgentServiceCollected && service.Status != AgentServiceUnavailable && service.Status != AgentServiceAccessDenied {
			return false
		}
		if index < len(agentInventoryServices) {
			if service.Service != agentInventoryServices[index].service {
				return false
			}
			continue
		}
		for nextLog < len(agentInventoryLogServices) && agentInventoryLogServices[nextLog].service != service.Service {
			nextLog++
		}
		if nextLog == len(agentInventoryLogServices) {
			return false
		}
		nextLog++
	}
	agentARNs := map[string]bool{}
	agentRoles := map[string]bool{}
	previous := ""
	for _, agent := range source.BedrockAgents {
		match := agentBedrockARNPattern.FindStringSubmatch(agent.ARN)
		if len(match) != 4 || match[1] != agent.Region || match[2] != accountID || match[3] != agent.AgentID || agent.ARN <= previous || !validAgentInventoryText(agent.Name, 256) ||
			agent.Model != "" && !validAgentInventoryText(agent.Model, 2048) || !validAgentInventoryRole(agent.RoleARN) || !validAgentInventoryState(agent.Status) {
			return false
		}
		previous = agent.ARN
		agentARNs[agent.ARN] = true
		agentRoles[agent.RoleARN] = true
	}
	previous = ""
	for _, gateway := range source.Gateways {
		match := agentGatewayARNPattern.FindStringSubmatch(gateway.ARN)
		if len(match) != 4 || match[1] != gateway.Region || match[2] != accountID || match[3] != gateway.GatewayID || gateway.ARN <= previous || !validAgentInventoryText(gateway.Name, 256) || !validAgentInventoryState(gateway.Status) {
			return false
		}
		previous = gateway.ARN
	}
	previous = ""
	for _, function := range source.LambdaFunctions {
		match := agentLambdaARNPattern.FindStringSubmatch(function.ARN)
		if len(match) != 4 || match[1] != function.Region || match[2] != accountID || match[3] != function.Name || function.ARN <= previous || !validAgentInventoryRole(function.RoleARN) || !validAgentInventoryState(function.State) ||
			len(function.Signals) < 1 || len(function.Signals) > agentsignals.MaximumSignals {
			return false
		}
		previous = function.ARN
		agentARNs[function.ARN] = true
		agentRoles[function.RoleARN] = true
		prior := ""
		for _, signal := range function.Signals {
			if !agentSignalPattern.MatchString(signal) || signal <= prior {
				return false
			}
			prior = signal
		}
	}
	previous = ""
	for _, runtime := range source.Runtimes {
		match := agentRuntimeARNPattern.FindStringSubmatch(runtime.ARN)
		if len(match) != 4 || match[1] != runtime.Region || match[2] != accountID || match[3] != runtime.RuntimeID || runtime.ARN <= previous || !validAgentInventoryText(runtime.Name, 256) || !validAgentInventoryRole(runtime.RoleARN) || !validAgentInventoryState(runtime.Status) {
			return false
		}
		previous = runtime.ARN
		agentARNs[runtime.ARN] = true
		agentRoles[runtime.RoleARN] = true
	}
	previous = ""
	for _, workload := range source.InferredWorkloads {
		switch workload.ResourceType {
		case "iam_role":
			match := securityRoleARNPattern.FindStringSubmatch(workload.ARN)
			if len(match) != 3 || match[1] != accountID || workload.RoleARN != workload.ARN {
				return false
			}
		case "ec2_instance":
			match := agentInstanceARNPattern.FindStringSubmatch(workload.ARN)
			if len(match) != 4 || match[1] != workload.Region || match[2] != accountID || !validAgentInventoryRole(workload.RoleARN) {
				return false
			}
		case "ecs_service":
			match := agentECSServiceARN.FindStringSubmatch(workload.ARN)
			if len(match) != 5 || match[1] != workload.Region || match[2] != accountID || !validAgentInventoryRole(workload.RoleARN) {
				return false
			}
		case "eks_pod":
			match := agentEKSClusterARN.FindStringSubmatch(workload.ARN)
			if len(match) != 4 || match[1] != workload.Region || match[2] != accountID || workload.RoleARN != "" {
				return false
			}
		default:
			return false
		}
		if workload.ARN <= previous || agentARNs[workload.ARN] || !validAgentInventoryText(workload.Name, 256) || !agentRegionPattern.MatchString(workload.Region) || len(workload.Signals) < 1 || len(workload.Signals) > agentsignals.MaximumSignals {
			return false
		}
		previous = workload.ARN
		agentARNs[workload.ARN] = true
		agentRoles[workload.RoleARN] = true
		prior := ""
		for _, signal := range workload.Signals {
			if !agentSignalPattern.MatchString(signal) || signal <= prior {
				return false
			}
			prior = signal
		}
	}
	// A check names an agent (or a data store) of this source and a known
	// rule, once; the MCP and access parts are checked with it.
	return validAgentInventoryMCP(source, accountID, agentARNs, agentRoles)
}

// agentInventoryKind returns the inventory kind of an agent of the source
// by the form of its ARN.
func agentInventoryKind(arn string) string {
	switch {
	case agentBedrockARNPattern.MatchString(arn):
		return "aws_bedrock_agent"
	case agentRuntimeARNPattern.MatchString(arn):
		return "aws_agentcore_runtime"
	}
	return "aws_inferred_agent"
}

func validAgentInventoryText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f || character == utf8.RuneError }) == -1
}

func validAgentInventoryRole(arn string) bool {
	return arn == "" || securityRoleARNPattern.MatchString(arn)
}

func validAgentInventoryState(state string) bool {
	return state == "" || agentStatePattern.MatchString(state)
}

// canonicalAgentObject re-encodes a struct as a JSON object whose members are
// sorted at every depth, the form the snapshot contract requires of
// attributes. A struct is otherwise encoded in field order.
func canonicalAgentObject(value any) map[string]any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded map[string]any
	if decoder.Decode(&decoded) != nil {
		return nil
	}
	return decoded
}

// agentPage emits the account's AI agents, the AgentCore gateways and, for
// each AI service, whether the read role could read it. An agent is linked to
// its execution role only when the IAM phase emitted that role.
func (api *InventoryCollectionAPI) agentPage(request CollectionPageRequest, inventory CollectionInventory, digest [16]byte) (CollectionPage, error) {
	source, ok := decodeAgentInventorySource(inventory.AgentSource, request.Subject.ID)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	// The IAM phase emits exactly the roles of the Cartography source.
	var iam struct {
		Roles []struct {
			ARN string `json:"Arn"`
		} `json:"roles"`
	}
	if json.Unmarshal(inventory.CartographySource, &iam) != nil {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	knownRoles := make(map[string]bool, len(iam.Roles))
	for _, role := range iam.Roles {
		if match := securityRoleARNPattern.FindStringSubmatch(role.ARN); len(match) == 3 && match[1] == request.Subject.ID {
			knownRoles[role.ARN] = true
		}
	}
	scope, subject := api.authority.Scope, request.Subject
	accountID := deterministicAWSInventoryID(scope, subject, "aws_account", subject.ID)
	count := len(source.Services) + len(source.BedrockAgents) + len(source.Runtimes) + len(source.Gateways) + len(source.LambdaFunctions) + len(source.InferredWorkloads)
	entities := make([]json.RawMessage, 0, count)
	relationships := make([]json.RawMessage, 0, count*2)
	agentIDs := make(map[string]string, count)
	usage := make(map[string]AgentInventoryRoleUsage, len(source.RoleUsage))
	for _, entry := range source.RoleUsage {
		usage[entry.RoleARN] = entry
	}
	add := func(kind, arn, display, roleARN string, stable, attributes map[string]any) {
		id := deterministicAWSInventoryID(scope, subject, kind, arn)
		if kind != "aws_agentcore_gateway" {
			agentIDs[arn] = id
			if entry, read := usage[roleARN]; read && roleARN != "" {
				roleUsageAttributes(attributes, entry)
			}
		}
		entities = append(entities, marshalInventoryEntity(id, kind, arn, display, stable, attributes))
		relationships = append(relationships, marshalInventoryRelationship(scope, subject, "contains", subject.ID+"|contains|"+arn, accountID, id))
		if knownRoles[roleARN] {
			relationships = append(relationships, marshalInventoryRelationship(scope, subject, "uses_identity", arn+"|uses_identity|"+roleARN, id, deterministicAWSInventoryID(scope, subject, "aws_role", roleARN)))
		}
	}
	agentAttributes := func(roleARN, stateName, state string, discovery agentsignals.Discovery) map[string]any {
		// A posture fact the control plane does not state stays false.
		attributes := map[string]any{"posture": canonicalAgentObject(agentsignals.Posture{CredentialActive: roleARN != ""}), "discovery": canonicalAgentObject(discovery)}
		if state != "" {
			attributes[stateName] = state
		}
		return attributes
	}
	for _, service := range source.Services {
		native := "aws:" + service.Service
		id := deterministicAWSInventoryID(scope, subject, "aws_service", native)
		name := agentInventoryServiceName(service.Service)
		entities = append(entities, marshalInventoryEntity(id, "aws_service", native, name, map[string]any{"account_id": subject.ID, "name": name, "service": service.Service}, map[string]any{"status": service.Status}))
		relationships = append(relationships, marshalInventoryRelationship(scope, subject, "contains", subject.ID+"|contains|"+native, accountID, id))
	}
	for _, agent := range source.BedrockAgents {
		attributes := agentAttributes(agent.RoleARN, "status", agent.Status, agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "bedrock_agent", nil))
		if agent.Model != "" {
			attributes["model"] = agent.Model
		}
		add("aws_bedrock_agent", agent.ARN, agent.Name, agent.RoleARN, map[string]any{"account_id": subject.ID, "agent_id": agent.AgentID, "arn": agent.ARN, "name": agent.Name, "region": agent.Region}, attributes)
	}
	for _, runtime := range source.Runtimes {
		add("aws_agentcore_runtime", runtime.ARN, runtime.Name, runtime.RoleARN, map[string]any{"account_id": subject.ID, "arn": runtime.ARN, "name": runtime.Name, "region": runtime.Region, "runtime_id": runtime.RuntimeID},
			agentAttributes(runtime.RoleARN, "status", runtime.Status, agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "agentcore_runtime", nil)))
	}
	for _, gateway := range source.Gateways {
		add("aws_agentcore_gateway", gateway.ARN, gateway.Name, "", map[string]any{"account_id": subject.ID, "arn": gateway.ARN, "gateway_id": gateway.GatewayID, "name": gateway.Name, "region": gateway.Region}, gatewayMCPAttributes(gateway))
	}
	for _, function := range source.LambdaFunctions {
		add("aws_inferred_agent", function.ARN, function.Name, function.RoleARN, map[string]any{"account_id": subject.ID, "arn": function.ARN, "name": function.Name, "region": function.Region, "resource_type": "lambda_function"},
			agentAttributes(function.RoleARN, "state", function.State, agentsignals.NewDiscovery(agentsignals.MethodInferred, "lambda_function", function.Signals)))
	}
	for _, workload := range source.InferredWorkloads {
		add("aws_inferred_agent", workload.ARN, workload.Name, workload.RoleARN, map[string]any{"account_id": subject.ID, "arn": workload.ARN, "name": workload.Name, "region": workload.Region, "resource_type": workload.ResourceType},
			agentAttributes(workload.RoleARN, "state", "", agentsignals.NewDiscovery(agentsignals.MethodInferred, workload.ResourceType, workload.Signals)))
	}
	mcpEntities, mcpRelationships := mcpInventory(scope, subject, source, accountID, agentIDs, knownRoles)
	entities, relationships = append(entities, mcpEntities...), append(relationships, mcpRelationships...)
	sortRawInventory(entities)
	sortRawInventory(relationships)
	return NewCollectionPage(request.Subject, inventoryCursor("posture", request.Subject, digest), false, entities, relationships)
}
