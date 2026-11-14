package main

import (
	"context"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

// MCP servers of an account, who uses them, and what the agents' roles may
// do. All of it is read with the read role; nothing is installed.
//
//   - An AgentCore gateway is an MCP server. Its description says how callers
//     authenticate and where it listens; its targets say which tools it serves
//     (a Lambda target declares them inline) or which remote MCP server it
//     fronts. A tool's description and schema are not read.
//   - An agent uses a gateway when a policy of its role allows
//     bedrock-agentcore:InvokeGateway on it, and a remote MCP server when the
//     network logs show it resolving and reaching the server's host.
//   - The model actions a role's policies grant are compared with the ones
//     CloudTrail shows it used; the data actions they grant name the data
//     stores the role reaches.

// discoveryAWSGatewayDetailAPI is the optional part of the AgentCore reader:
// a reader that cannot describe gateways still lists them.
type discoveryAWSGatewayDetailAPI interface {
	GetGateway(context.Context, *bedrockagentcorecontrol.GetGatewayInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error)
	ListGatewayTargets(context.Context, *bedrockagentcorecontrol.ListGatewayTargetsInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error)
	GetGatewayTarget(context.Context, *bedrockagentcorecontrol.GetGatewayTargetInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayTargetOutput, error)
}

// discoveryAWSNetworkInterfaceAPI is the optional part of the flow log
// reader that names the owner of a source address.
type discoveryAWSNetworkInterfaceAPI interface {
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

var (
	discoveryAWSHostPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){1,8}$`)
	discoveryAWSTargetIDPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z_-]{0,127}$`)
	discoveryAWSAuthorizers     = map[string]bool{"AWS_IAM": true, "AUTHENTICATE_ONLY": true, "CUSTOM_JWT": true, "NONE": true}
)

// discoveryAWSURLHost returns the host of an https or http URL, or "".
func discoveryAWSURLHost(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if len(host) > 253 || !discoveryAWSHostPattern.MatchString(host) {
		return ""
	}
	return host
}

// describeDiscoveryAWSGateways reads each listed gateway's authorizer, URL
// host and targets. A gateway whose description or targets may not be read
// stays as the list gave it, and the worst answer is the returned status.
func describeDiscoveryAWSGateways(ctx context.Context, api discoveryAWSGatewayDetailAPI, gateways []awsdiscovery.AgentInventoryGateway) ([]bool, string, error) {
	return describeDiscoveryAWSAgents(ctx, len(gateways), func(bounded context.Context, index int) (bool, error) {
		gateway := &gateways[index]
		output, err := api.GetGateway(bounded, &bedrockagentcorecontrol.GetGatewayInput{GatewayIdentifier: aws.String(gateway.GatewayID)}, func(options *bedrockagentcorecontrol.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			return false, err
		}
		if output == nil || aws.ToString(output.GatewayId) != gateway.GatewayID {
			return false, awsdiscovery.ErrDenied
		}
		// Only these members are read: the authorizer type and the URL.
		authorizer, host := string(output.AuthorizerType), discoveryAWSURLHost(aws.ToString(output.GatewayUrl))
		if !discoveryAWSAuthorizers[authorizer] {
			return true, nil
		}
		targets, err := collectDiscoveryAWSGatewayTargets(bounded, api, gateway.GatewayID)
		if err != nil {
			return false, err
		}
		gateway.Authorizer, gateway.EndpointHost, gateway.Targets = authorizer, host, targets
		return true, nil
	})
}

func collectDiscoveryAWSGatewayTargets(ctx context.Context, api discoveryAWSGatewayDetailAPI, gatewayID string) ([]awsdiscovery.AgentInventoryGatewayTarget, error) {
	names := map[string]string{}
	var token *string
	for page := 0; ; page++ {
		if page >= maximumAWSAgentListPages {
			return nil, awsdiscovery.ErrDenied
		}
		output, err := api.ListGatewayTargets(ctx, &bedrockagentcorecontrol.ListGatewayTargetsInput{GatewayIdentifier: aws.String(gatewayID), NextToken: token, MaxResults: aws.Int32(100)}, func(options *bedrockagentcorecontrol.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			return nil, err
		}
		if output == nil {
			return nil, awsdiscovery.ErrDenied
		}
		for _, summary := range output.Items {
			id, name := aws.ToString(summary.TargetId), discoveryAWSAgentText(aws.ToString(summary.Name))
			if !discoveryAWSTargetIDPattern.MatchString(id) || name == "" || len(name) > 256 {
				continue
			}
			names[id] = name
			if len(names) > awsdiscovery.MaximumInventoryGatewayTargets {
				return nil, awsdiscovery.ErrDenied
			}
		}
		if output.NextToken == nil {
			break
		}
		if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
			return nil, awsdiscovery.ErrDenied
		}
		token = output.NextToken
	}
	ids := make([]string, 0, len(names))
	for id := range names {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	targets := make([]awsdiscovery.AgentInventoryGatewayTarget, 0, len(ids))
	for _, id := range ids {
		target := awsdiscovery.AgentInventoryGatewayTarget{Name: names[id], TargetID: id}
		output, err := api.GetGatewayTarget(ctx, &bedrockagentcorecontrol.GetGatewayTargetInput{GatewayIdentifier: aws.String(gatewayID), TargetId: aws.String(id)}, func(options *bedrockagentcorecontrol.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			if discoveryAWSAgentGone(err) {
				continue
			}
			return nil, err
		}
		if output == nil {
			return nil, awsdiscovery.ErrDenied
		}
		target.Tools, target.RemoteHost = discoveryAWSGatewayTargetTools(output.TargetConfiguration)
		targets = append(targets, target)
	}
	return targets, nil
}

// discoveryAWSGatewayTargetTools returns the tool names a Lambda target
// declares inline, or the host of the MCP server an MCP server target
// fronts. Tool descriptions and schemas are never read.
func discoveryAWSGatewayTargetTools(configuration agentcoretypes.TargetConfiguration) ([]string, string) {
	mcp, ok := configuration.(*agentcoretypes.TargetConfigurationMemberMcp)
	if !ok || mcp == nil {
		return nil, ""
	}
	switch target := mcp.Value.(type) {
	case *agentcoretypes.McpTargetConfigurationMemberLambda:
		inline, ok := target.Value.ToolSchema.(*agentcoretypes.ToolSchemaMemberInlinePayload)
		if !ok || inline == nil {
			return nil, ""
		}
		seen := map[string]bool{}
		for _, tool := range inline.Value {
			if name := aws.ToString(tool.Name); agentsignals.ValidMCPToolName(name) {
				seen[name] = true
			}
		}
		names := make([]string, 0, len(seen))
		for name := range seen {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > agentsignals.MaximumMCPToolsPerServer {
			names = names[:agentsignals.MaximumMCPToolsPerServer]
		}
		if len(names) == 0 {
			return nil, ""
		}
		return names, ""
	case *agentcoretypes.McpTargetConfigurationMemberMcpServer:
		return nil, discoveryAWSURLHost(aws.ToString(target.Value.Endpoint))
	}
	return nil, ""
}

// discoveryAWSStatementValues returns the strings of a policy statement
// member that is a string or a list of strings.
func discoveryAWSStatementValues(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		values := make([]string, 0, len(typed))
		for _, entry := range typed {
			if text, ok := entry.(string); ok {
				values = append(values, text)
			}
		}
		return values
	}
	return nil
}

// discoveryAWSAllowStatements calls visit with the Action and Resource
// entries of every allowing statement of a role's managed policies.
// NotAction and NotResource statements are not read.
func discoveryAWSAllowStatements(role discoveryAWSNativeRole, visit func(actions, resources []string)) {
	names := make([]string, 0, len(role.ManagedPolicies))
	for name := range role.ManagedPolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, raw := range role.ManagedPolicies[name] {
			statement, ok := raw.(map[string]any)
			if effect, _ := statement["Effect"].(string); !ok || effect != "Allow" {
				continue
			}
			actions, resources := discoveryAWSStatementValues(statement["Action"]), discoveryAWSStatementValues(statement["Resource"])
			if len(actions) > 0 && len(resources) > 0 {
				visit(actions, resources)
			}
		}
	}
}

var discoveryAWSDataARNPattern = regexp.MustCompile(`^arn:aws:[a-z0-9-]{2,32}:[a-z0-9-]{0,32}:[0-9]{0,12}:[A-Za-z0-9+=,.@_/:*?-]{1,400}$`)

// A role's data grants are kept up to this many stores; a role that names
// more is over-broad by any measure and the first ones by ARN are kept.
const maximumAWSRoleDataStores = 20

// discoveryAWSDataResource normalizes one Resource entry of a data
// statement to the store it names. A wildcard that covers every resource of
// the service is the service-wide store.
func discoveryAWSDataResource(service, resource string) (string, string, bool) {
	wide := "arn:aws:" + service + ":::*"
	if resource == "*" {
		return wide, "service", true
	}
	prefix := "arn:aws:" + service + ":"
	if service == "rds-data" {
		prefix = "arn:aws:rds:"
	}
	if !strings.HasPrefix(resource, prefix) || strings.Count(resource, ":") < 5 {
		return "", "", false
	}
	parts := strings.SplitN(resource, ":", 6)
	name := parts[5]
	switch service {
	case "s3":
		name, _, _ = strings.Cut(name, "/")
	case "dynamodb":
		for _, marker := range []string{"/index/", "/stream/"} {
			if index := strings.Index(name, marker); index > 0 {
				name = name[:index]
			}
		}
	}
	switch name {
	case "*", "table/*", "secret:*", "parameter/*", "cluster:*":
		return wide, "service", true
	}
	arn := strings.Join(parts[:5], ":") + ":" + name
	if !discoveryAWSDataARNPattern.MatchString(arn) {
		return "", "", false
	}
	return arn, "resource", true
}

// discoveryAWSAgentAccess derives, from the managed policies of the agents'
// roles, the gateways each agent may invoke and the data stores each role
// reaches. Only roles of listed agents are read.
func discoveryAWSAgentAccess(source awsdiscovery.AgentInventorySource, roles []discoveryAWSNativeRole) ([]awsdiscovery.AgentInventoryUse, []awsdiscovery.AgentInventoryDataAccess) {
	agentRole := discoveryAWSAgentRoles(source)
	byARN := make(map[string]discoveryAWSNativeRole, len(roles))
	for _, role := range roles {
		byARN[role.ARN] = role
	}
	gatewaysOf := map[string][]string{}
	dataOf := map[string]map[string]awsdiscovery.AgentInventoryDataAccess{}
	for _, roleARN := range agentRole {
		role, known := byARN[roleARN]
		if _, done := dataOf[roleARN]; done || !known || roleARN == "" {
			continue
		}
		dataOf[roleARN] = map[string]awsdiscovery.AgentInventoryDataAccess{}
		invocable := map[string]bool{}
		discoveryAWSAllowStatements(role, func(actions, resources []string) {
			invokes := false
			for _, action := range actions {
				lower := strings.ToLower(strings.TrimSpace(action))
				if service, _, named := strings.Cut(lower, ":"); named && !strings.ContainsAny(service, "*?") && agentsignals.IAMPatternMatches(lower, "bedrock-agentcore:invokegateway") {
					invokes = true
				}
				service, access, data := agentsignals.DataAction(action)
				if !data {
					continue
				}
				for _, resource := range resources {
					arn, scope, ok := discoveryAWSDataResource(service, resource)
					if !ok {
						continue
					}
					entry, seen := dataOf[roleARN][arn]
					if !seen || access == "write" {
						entry = awsdiscovery.AgentInventoryDataAccess{Access: access, ARN: arn, RoleARN: roleARN, Scope: scope, Service: service}
					}
					dataOf[roleARN][arn] = entry
				}
			}
			if invokes {
				for _, gateway := range source.Gateways {
					for _, resource := range resources {
						if agentsignals.IAMPatternMatches(resource, gateway.ARN) {
							invocable[gateway.ARN] = true
						}
					}
				}
			}
		})
		for gateway := range invocable {
			gatewaysOf[roleARN] = append(gatewaysOf[roleARN], gateway)
		}
	}
	var uses []awsdiscovery.AgentInventoryUse
	for agent, roleARN := range agentRole {
		for _, gateway := range gatewaysOf[roleARN] {
			uses = append(uses, awsdiscovery.AgentInventoryUse{Agent: agent, Server: gateway})
		}
	}
	var access []awsdiscovery.AgentInventoryDataAccess
	for _, stores := range dataOf {
		arns := make([]string, 0, len(stores))
		for arn := range stores {
			arns = append(arns, arn)
		}
		sort.Strings(arns)
		if len(arns) > maximumAWSRoleDataStores {
			arns = arns[:maximumAWSRoleDataStores]
		}
		for _, arn := range arns {
			access = append(access, stores[arn])
		}
	}
	sort.Slice(access, func(i, j int) bool {
		if access[i].RoleARN != access[j].RoleARN {
			return access[i].RoleARN < access[j].RoleARN
		}
		return access[i].ARN < access[j].ARN
	})
	// One store has one service and scope whoever reaches it: the ARN decides.
	if len(access) > awsdiscovery.MaximumInventoryDataAccess {
		access = access[:awsdiscovery.MaximumInventoryDataAccess]
	}
	return uses, access
}

// discoveryAWSAgentRoles maps each agent ARN of the source to its role ARN
// ("" when it has none).
func discoveryAWSAgentRoles(source awsdiscovery.AgentInventorySource) map[string]string {
	agentRole := map[string]string{}
	for _, agent := range source.BedrockAgents {
		agentRole[agent.ARN] = agent.RoleARN
	}
	for _, runtime := range source.Runtimes {
		agentRole[runtime.ARN] = runtime.RoleARN
	}
	for _, function := range source.LambdaFunctions {
		agentRole[function.ARN] = function.RoleARN
	}
	for _, workload := range source.InferredWorkloads {
		agentRole[workload.ARN] = workload.RoleARN
	}
	return agentRole
}

// discoveryAWSRoleUsage compares, for each agent role, the model and agent
// actions its managed policies grant with the ones the audit log showed in
// use. Unused lists only actions the log can show, and only when every
// region's lookup was read to its end: a sampled log proves no absence.
func discoveryAWSRoleUsage(source awsdiscovery.AgentInventorySource, roleActions map[string][]string, used map[string]map[string]bool, complete bool) []awsdiscovery.AgentInventoryRoleUsage {
	distinct := map[string]bool{}
	for _, role := range discoveryAWSAgentRoles(source) {
		if role != "" {
			distinct[role] = true
		}
	}
	usage := make([]awsdiscovery.AgentInventoryRoleUsage, 0, len(distinct))
	for role := range distinct {
		granted := agentsignals.GrantedAIActions(roleActions[role]...)
		if len(granted) == 0 {
			continue
		}
		entry := awsdiscovery.AgentInventoryRoleUsage{Granted: granted, RoleARN: role, Unused: []string{}, Used: []string{}}
		for action := range used[role] {
			entry.Used = append(entry.Used, action)
		}
		sort.Strings(entry.Used)
		if complete {
			for _, action := range granted {
				if agentsignals.ObservableAIAction(action) && !used[role][action] {
					entry.Unused = append(entry.Unused, action)
				}
			}
		}
		usage = append(usage, entry)
	}
	sort.Slice(usage, func(i, j int) bool { return usage[i].RoleARN < usage[j].RoleARN })
	if len(usage) > awsdiscovery.MaximumInventoryRoleUsage {
		usage = usage[:awsdiscovery.MaximumInventoryRoleUsage]
	}
	return usage
}

// discoveryAWSAccessChecks returns the checks the access comparison raises:
// an agent whose role holds unused model permissions, and a data service an
// agent role may reach in full.
func discoveryAWSAccessChecks(source awsdiscovery.AgentInventorySource) []awsdiscovery.AgentInventoryCheck {
	unused := map[string]bool{}
	for _, usage := range source.RoleUsage {
		unused[usage.RoleARN] = len(usage.Unused) > 0
	}
	var checks []awsdiscovery.AgentInventoryCheck
	for agent, role := range discoveryAWSAgentRoles(source) {
		if role != "" && unused[role] {
			checks = append(checks, awsdiscovery.AgentInventoryCheck{ARN: agent, Check: awsdiscovery.AgentCheckRoleUnusedAI})
		}
	}
	wide := map[string]bool{}
	for _, access := range source.DataAccess {
		if access.Scope == "service" && !wide[access.ARN] {
			wide[access.ARN] = true
			checks = append(checks, awsdiscovery.AgentInventoryCheck{ARN: access.ARN, Check: awsdiscovery.AgentCheckDataServiceWide})
		}
	}
	return checks
}

// Egress attribution. A source address of the network logs belongs to a
// network interface, and the interface says what runs behind it.
const (
	discoveryAWSEgressInstance = "ec2_instance"
	discoveryAWSEgressService  = "ecs_service"
	discoveryAWSEgressFunction = "lambda_function"
	discoveryAWSEgressPod      = "eks_pod"
)

// discoveryAWSEgressWorkload is what one or more source addresses were
// attributed to. id is an instance id, "<cluster>/<service>" of an ECS
// service, an EKS cluster name, or for a Lambda interface the interface's
// "<subnet>|<sorted security groups>" key (several functions may share it).
type discoveryAWSEgressWorkload struct {
	kind, id string
	signals  []string
	// hosts are the remote MCP server hosts the workload reached.
	hosts []string
}

var (
	discoveryAWSECSNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	discoveryAWSEKSNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)
)

// The interface tags that name the owner. An ECS task's interface carries
// its cluster and service names, and the VPC CNI tags the interfaces it
// manages with the cluster name. Both are from AWS documentation as
// remembered: UNVERIFIED against a real account.
const (
	discoveryAWSECSClusterTag = "aws:ecs:clusterName"
	discoveryAWSECSServiceTag = "aws:ecs:serviceName"
	discoveryAWSEKSClusterTag = "cluster.k8s.amazonaws.com/name"
)

// discoveryAWSInterfaceOwners asks which network interface holds each source
// address and returns what runs behind it. An address whose interface cannot
// be read, or says nothing, is absent from the result.
func discoveryAWSInterfaceOwners(ctx context.Context, api discoveryAWSNetworkInterfaceAPI, sources []netip.Addr) map[netip.Addr]discoveryAWSEgressWorkload {
	owners := map[netip.Addr]discoveryAWSEgressWorkload{}
	if len(sources) == 0 {
		return owners
	}
	wanted := make(map[netip.Addr]bool, len(sources))
	values := make([]string, 0, len(sources))
	for _, source := range sources {
		wanted[source] = true
		values = append(values, source.String())
	}
	sort.Strings(values)
	var token *string
	for page := 0; page < 4; page++ {
		output, err := api.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters: []ec2types.Filter{{Name: aws.String("addresses.private-ip-address"), Values: values}}, MaxResults: aws.Int32(200), NextToken: token,
		}, func(options *ec2.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil || output == nil {
			return owners
		}
		for _, networkInterface := range output.NetworkInterfaces {
			tags := map[string]string{}
			for _, tag := range networkInterface.TagSet {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			instance := ""
			if networkInterface.Attachment != nil {
				instance = aws.ToString(networkInterface.Attachment.InstanceId)
			}
			groups := make([]string, 0, len(networkInterface.Groups))
			for _, group := range networkInterface.Groups {
				groups = append(groups, aws.ToString(group.GroupId))
			}
			sort.Strings(groups)
			for _, address := range networkInterface.PrivateIpAddresses {
				source, err := netip.ParseAddr(aws.ToString(address.PrivateIpAddress))
				if err != nil || !wanted[source] {
					continue
				}
				cluster, service, eks := tags[discoveryAWSECSClusterTag], tags[discoveryAWSECSServiceTag], tags[discoveryAWSEKSClusterTag]
				switch {
				case discoveryAWSECSNamePattern.MatchString(cluster) && discoveryAWSECSNamePattern.MatchString(service):
					owners[source] = discoveryAWSEgressWorkload{kind: discoveryAWSEgressService, id: cluster + "/" + service}
				case networkInterface.InterfaceType == ec2types.NetworkInterfaceTypeLambda:
					owners[source] = discoveryAWSEgressWorkload{kind: discoveryAWSEgressFunction, id: aws.ToString(networkInterface.SubnetId) + "|" + strings.Join(groups, ",")}
				// A pod address is a secondary address of an interface the
				// VPC CNI manages; the primary address is the node's own.
				case discoveryAWSEKSNamePattern.MatchString(eks) && !aws.ToBool(address.Primary):
					owners[source] = discoveryAWSEgressWorkload{kind: discoveryAWSEgressPod, id: eks}
				case discoveryAWSInstancePattern.MatchString(instance):
					owners[source] = discoveryAWSEgressWorkload{kind: discoveryAWSEgressInstance, id: instance}
				}
			}
		}
		if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
			break
		}
		token = output.NextToken
	}
	return owners
}

// discoveryAWSVPCFunction is a Lambda function attached to a VPC: the
// interface key its traffic leaves from, and what the list said of it.
type discoveryAWSVPCFunction struct {
	arn, name, role, state string
	// keys are "<subnet>|<sorted security groups>" for each of its subnets.
	keys []string
}

// discoveryAWSFunctionForInterface returns the one VPC function whose
// subnets and security groups match a Lambda interface key. Functions that
// share subnets and security groups share interfaces; when more than one
// matches, the logs do not say which one called and none is named.
func discoveryAWSFunctionForInterface(functions []discoveryAWSVPCFunction, key string) (discoveryAWSVPCFunction, bool) {
	var match discoveryAWSVPCFunction
	count := 0
	for _, function := range functions {
		for _, candidate := range function.keys {
			if candidate == key {
				match = function
				count++
				break
			}
		}
	}
	return match, count == 1
}
