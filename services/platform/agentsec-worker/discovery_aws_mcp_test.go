package main

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

// mcpGatewayStub is the region stub with a gateway that can be described:
// an authorizer, a URL and targets. Descriptions and input schemas carry the
// sentinel and must not be kept.
type mcpGatewayStub struct {
	*discoveryAgentRegionStub
	authorizer agentcoretypes.AuthorizerType
	targets    map[string]agentcoretypes.TargetConfiguration
}

func (stub *mcpGatewayStub) GetGateway(_ context.Context, input *bedrockagentcorecontrol.GetGatewayInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error) {
	id := aws.ToString(input.GatewayIdentifier)
	return &bedrockagentcorecontrol.GetGatewayOutput{GatewayId: aws.String(id), AuthorizerType: stub.authorizer, Description: aws.String(discoveryAgentSentinel),
		GatewayUrl: aws.String("https://" + id + ".gateway.bedrock-agentcore." + stub.region + ".amazonaws.com/mcp?k=" + discoveryAgentSentinel)}, nil
}

func (stub *mcpGatewayStub) ListGatewayTargets(context.Context, *bedrockagentcorecontrol.ListGatewayTargetsInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error) {
	output := &bedrockagentcorecontrol.ListGatewayTargetsOutput{}
	for id := range stub.targets {
		output.Items = append(output.Items, agentcoretypes.TargetSummary{TargetId: aws.String(id), Name: aws.String("target-" + id), Description: aws.String(discoveryAgentSentinel)})
	}
	return output, nil
}

func (stub *mcpGatewayStub) GetGatewayTarget(_ context.Context, input *bedrockagentcorecontrol.GetGatewayTargetInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayTargetOutput, error) {
	return &bedrockagentcorecontrol.GetGatewayTargetOutput{TargetId: input.TargetId, Description: aws.String(discoveryAgentSentinel), TargetConfiguration: stub.targets[aws.ToString(input.TargetId)]}, nil
}

func mcpLambdaTarget(tools ...string) agentcoretypes.TargetConfiguration {
	definitions := make([]agentcoretypes.ToolDefinition, 0, len(tools))
	for _, tool := range tools {
		definitions = append(definitions, agentcoretypes.ToolDefinition{Name: aws.String(tool), Description: aws.String("does things " + discoveryAgentSentinel), InputSchema: &agentcoretypes.SchemaDefinition{Description: aws.String(discoveryAgentSentinel)}})
	}
	return &agentcoretypes.TargetConfigurationMemberMcp{Value: &agentcoretypes.McpTargetConfigurationMemberLambda{Value: agentcoretypes.McpLambdaTargetConfiguration{
		LambdaArn: aws.String("arn:aws:lambda:us-west-2:123456789012:function:tools"), ToolSchema: &agentcoretypes.ToolSchemaMemberInlinePayload{Value: definitions}}}}
}

// mcpIAMStub gives the reader role a policy that may invoke the gateway and
// two models, read one bucket and write to every DynamoDB table.
type mcpIAMStub struct{ discoveryInventoryIAMStub }

func (*mcpIAMStub) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	document := url.QueryEscape(`{"Statement":[` +
		`{"Action":["bedrock:InvokeModel*","bedrock:InvokeAgent"],"Effect":"Allow","Resource":"*"},` +
		`{"Action":"bedrock-agentcore:InvokeGateway","Effect":"Allow","Resource":"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/tools-*"},` +
		`{"Action":["s3:GetObject","s3:ListBucket"],"Effect":"Allow","Resource":["arn:aws:s3:::reports","arn:aws:s3:::reports/*"]},` +
		`{"Action":"dynamodb:PutItem","Effect":"Allow","Resource":"arn:aws:dynamodb:*:*:table/*"},` +
		`{"Action":"s3:DeleteObject","Effect":"Deny","Resource":"*"}],"Version":"2012-10-17"}`)
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: &document, VersionId: aws.String("v1")}}, nil
}

// mcpNetworkStub is the network log stub whose flow log reader can also name
// the owner of a source address.
type mcpNetworkStub struct {
	*networkLogStub
	interfaces []ec2types.NetworkInterface
	asked      []string
}

func (stub *mcpNetworkStub) DescribeNetworkInterfaces(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	for _, filter := range input.Filters {
		stub.asked = append(stub.asked, filter.Values...)
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: stub.interfaces}, nil
}

func mcpInterface(kind ec2types.NetworkInterfaceType, subnet, group, instance string, tags map[string]string, addresses ...string) ec2types.NetworkInterface {
	result := ec2types.NetworkInterface{InterfaceType: kind, SubnetId: aws.String(subnet), Groups: []ec2types.GroupIdentifier{{GroupId: aws.String(group)}}}
	if instance != "" {
		result.Attachment = &ec2types.NetworkInterfaceAttachment{InstanceId: aws.String(instance)}
	}
	for key, value := range tags {
		result.TagSet = append(result.TagSet, ec2types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	for index, address := range addresses {
		result.PrivateIpAddresses = append(result.PrivateIpAddresses, ec2types.NetworkInterfacePrivateIpAddress{PrivateIpAddress: aws.String(address), Primary: aws.Bool(index == 0)})
	}
	return result
}

// The whole AWS collection of an account with a gateway, remote MCP hosts
// in its network logs and an agent role with model and data grants: the MCP
// servers, their tools, who uses them, used against granted, the data
// stores, and the egress of a task, a function and a pod attributed to what
// runs them.
func TestAWSInventoryReadsMCPServersToolsUsesAndAccess(t *testing.T) {
	discoveryAWSLogPollInterval = time.Millisecond
	regions := discoveryAgentMixedAccount()
	// A function in a VPC with nothing AI-related in its configuration.
	regions["us-east-1"].functions = append(regions["us-east-1"].functions, discoveryAgentFunction{name: "quiet", role: discoveryAgentPlainRole})
	regions["us-east-1"].vpc = map[string]*lambdatypes.VpcConfigResponse{"quiet": {SubnetIds: []string{"subnet-1"}, SecurityGroupIds: []string{"sg-lambda"}}}
	factory := discoveryAgentFactory(regions)
	factory.IAM = func(string, aws.Credentials) (discoveryAWSIAMAPI, error) { return &mcpIAMStub{}, nil }
	gateway := &mcpGatewayStub{discoveryAgentRegionStub: regions["us-west-2"], authorizer: agentcoretypes.AuthorizerTypeNone, targets: map[string]agentcoretypes.TargetConfiguration{
		"T1LAMBDA00": mcpLambdaTarget("run_query", "list_tables", "bad name "+discoveryAgentSentinel),
		"T2REMOTE00": &agentcoretypes.TargetConfigurationMemberMcp{Value: &agentcoretypes.McpTargetConfigurationMemberMcpServer{Value: agentcoretypes.McpServerTargetConfiguration{Endpoint: aws.String("https://mcp.vendor.example/v1/" + discoveryAgentSentinel)}}},
	}}
	base := factory.AgentCore
	factory.AgentCore = func(region string, credentials aws.Credentials) (discoveryAWSAgentCoreAPI, error) {
		if region == "us-west-2" {
			gateway.region = region
			return gateway, nil
		}
		return base(region, credentials)
	}
	// The reader role used InvokeModel and never the streaming call.
	trail := &cloudTrailStub{events: map[string][]cloudtrailtypes.Event{"Converse": {cloudTrailEvent("AssumedRole", "Role", discoveryAgentReaderRole)}}}
	factory.CloudTrail = func(string, aws.Credentials) (discoveryAWSCloudTrailAPI, error) { return trail, nil }
	network := &mcpNetworkStub{networkLogStub: &networkLogStub{
		queryDestinations: []string{"arn:aws:logs:us-east-1:123456789012:log-group:/vpc/resolver:*"},
		flowLogs:          []ec2types.FlowLog{{LogDestinationType: ec2types.LogDestinationTypeCloudWatchLogs, LogGroupName: aws.String("/vpc/flow")}},
		resolverRows: [][]logstypes.ResultField{
			// An instance reached a remote MCP server.
			logRow("srcaddr", "10.0.1.15", "query_name", "mcp.linear.example.", "srcids.instance", "i-0aaaaaaaaaaaaaaa1", "answers.0.Rdata", "198.51.100.7"),
			// A Fargate task, a function and a pod: the log names no instance
			// for the first two and the node for the pod.
			logRow("srcaddr", "10.0.2.20", "query_name", "api.anthropic.com.", "answers.0.Rdata", "160.79.104.10"),
			logRow("srcaddr", "10.0.3.30", "query_name", "api.openai.com.", "answers.0.Rdata", "104.18.6.192"),
			logRow("srcaddr", "10.0.4.41", "query_name", "api.openai.com.", "srcids.instance", "i-0ccccccccccccccc3", "answers.0.Rdata", "104.18.6.192"),
			// An address no interface owns: dropped.
			logRow("srcaddr", "10.0.9.99", "query_name", "api.openai.com.", "answers.0.Rdata", "104.18.6.192"),
		},
		flowRows: [][]logstypes.ResultField{
			logRow("srcAddr", "10.0.1.15", "dstAddr", "198.51.100.7", "flows", "4"),
			logRow("srcAddr", "10.0.2.20", "dstAddr", "160.79.104.10", "flows", "9"),
			logRow("srcAddr", "10.0.3.30", "dstAddr", "104.18.6.192", "flows", "2"),
			logRow("srcAddr", "10.0.4.41", "dstAddr", "104.18.6.192", "flows", "2"),
			logRow("srcAddr", "10.0.9.99", "dstAddr", "104.18.6.192", "flows", "2"),
		},
	}, interfaces: []ec2types.NetworkInterface{
		mcpInterface(ec2types.NetworkInterfaceTypeInterface, "subnet-0", "sg-0", "i-0aaaaaaaaaaaaaaa1", nil, "10.0.1.15"),
		mcpInterface(ec2types.NetworkInterfaceTypeInterface, "subnet-2", "sg-2", "", map[string]string{"aws:ecs:clusterName": "prod", "aws:ecs:serviceName": "summariser"}, "10.0.2.20"),
		mcpInterface(ec2types.NetworkInterfaceTypeLambda, "subnet-1", "sg-lambda", "", nil, "10.0.3.30"),
		mcpInterface(ec2types.NetworkInterfaceTypeInterface, "subnet-4", "sg-4", "i-0ccccccccccccccc3", map[string]string{"cluster.k8s.amazonaws.com/name": "payments"}, "10.0.4.40", "10.0.4.41"),
	}}
	empty := &networkLogStub{}
	factory.Resolver = func(region string, _ aws.Credentials) (discoveryAWSResolverAPI, error) {
		if region == "us-east-1" {
			return network, nil
		}
		return empty, nil
	}
	factory.FlowLogs = func(region string, _ aws.Credentials) (discoveryAWSFlowLogAPI, error) {
		if region == "us-east-1" {
			return network, nil
		}
		return empty, nil
	}
	factory.Logs = func(region string, _ aws.Credentials) (discoveryAWSLogsAPI, error) {
		if region == "us-east-1" {
			return network, nil
		}
		return empty, nil
	}
	factory.Clock = discoveryAgentTestClock
	caller, err := newDiscoveryAWSCollectionInventoryCaller(factory, discoveryAgentTestClock)
	if err != nil {
		t.Fatal(err)
	}
	credential := mustDiscoveryAWSCredentialEnvelope(t, discoveryAgentTestClock().Add(15*time.Minute))
	inventory, err := caller.GetCollectionInventory(context.Background(), credential)
	clear(credential)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	var source awsdiscovery.AgentInventorySource
	if err := json.Unmarshal(inventory.AgentSource, &source); err != nil {
		t.Fatal(err)
	}
	const gatewayARN = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/tools-abcdefghij"
	wantGateway := awsdiscovery.AgentInventoryGateway{ARN: gatewayARN, Authorizer: "NONE", EndpointHost: "tools-abcdefghij.gateway.bedrock-agentcore.us-west-2.amazonaws.com", GatewayID: "tools-abcdefghij", Name: "tools", Region: "us-west-2", Status: "READY",
		Targets: []awsdiscovery.AgentInventoryGatewayTarget{{Name: "target-T1LAMBDA00", TargetID: "T1LAMBDA00", Tools: []string{"list_tables", "run_query"}}, {Name: "target-T2REMOTE00", RemoteHost: "mcp.vendor.example", TargetID: "T2REMOTE00"}}}
	if len(source.Gateways) != 1 || !reflect.DeepEqual(source.Gateways[0], wantGateway) {
		t.Fatalf("gateway = %+v", source.Gateways)
	}
	if want := []awsdiscovery.AgentInventoryMCPServer{{Host: "mcp.linear.example", Region: "us-east-1", Source: "egress"}, {Host: "mcp.vendor.example", Region: "us-west-2", Source: "gateway_target"}}; !reflect.DeepEqual(source.MCPServers, want) {
		t.Fatalf("mcp servers = %+v", source.MCPServers)
	}
	// Every agent that runs as the reader role may invoke the gateway; the
	// instance uses the remote server it reached.
	uses := map[string][]string{}
	for _, use := range source.Uses {
		uses[use.Server] = append(uses[use.Server], use.Agent[strings.LastIndexAny(use.Agent, ":/")+1:])
	}
	if !reflect.DeepEqual(uses, map[string][]string{gatewayARN: {"researcher-AbCdEfGhIj", "AGENT12345", "invoker"}, "us-east-1/mcp.linear.example": {"i-0aaaaaaaaaaaaaaa1"}}) {
		t.Fatalf("uses = %v", uses)
	}
	// Used against granted: InvokeModel was used, the streaming call was not;
	// InvokeAgent is granted but the audit log cannot show it, so it is not
	// called unused.
	if want := []awsdiscovery.AgentInventoryRoleUsage{{Granted: []string{"bedrock-agentcore:InvokeGateway", "bedrock:InvokeAgent", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}, RoleARN: discoveryAgentReaderRole, Unused: []string{"bedrock:InvokeModelWithResponseStream"}, Used: []string{"bedrock:InvokeModel"}}}; !reflect.DeepEqual(source.RoleUsage, want) {
		t.Fatalf("role usage = %+v", source.RoleUsage)
	}
	if want := []awsdiscovery.AgentInventoryDataAccess{
		{Access: "write", ARN: "arn:aws:dynamodb:::*", RoleARN: discoveryAgentReaderRole, Scope: "service", Service: "dynamodb"},
		{Access: "read", ARN: "arn:aws:s3:::reports", RoleARN: discoveryAgentReaderRole, Scope: "resource", Service: "s3"},
	}; !reflect.DeepEqual(source.DataAccess, want) {
		t.Fatalf("data access = %+v", source.DataAccess)
	}
	// Attribution: the task's service, the one function behind the Lambda
	// interface, the pod's cluster (not its node), and the instance.
	workloads := map[string]string{}
	for _, workload := range source.InferredWorkloads {
		workloads[workload.ARN] = workload.ResourceType + " " + strings.Join(workload.Signals, ",")
	}
	if !reflect.DeepEqual(workloads, map[string]string{
		"arn:aws:ec2:us-east-1:123456789012:instance/i-0aaaaaaaaaaaaaaa1": "ec2_instance egress:mcp_remote",
		"arn:aws:ecs:us-east-1:123456789012:service/prod/summariser":      "ecs_service egress:anthropic",
		"arn:aws:eks:us-east-1:123456789012:cluster/payments":             "eks_pod egress:openai",
	}) {
		t.Fatalf("inferred workloads = %v", workloads)
	}
	quiet := ""
	for _, function := range source.LambdaFunctions {
		if function.Name == "quiet" {
			quiet = strings.Join(function.Signals, ",")
		}
	}
	if quiet != "egress:openai" {
		t.Fatalf("the VPC function was not attributed: %+v", source.LambdaFunctions)
	}
	sort.Strings(network.asked)
	if strings.Join(network.asked, ",") != "10.0.1.15,10.0.2.20,10.0.3.30,10.0.4.41,10.0.9.99" {
		t.Fatalf("interface lookup asked for %v", network.asked)
	}
	checks := map[string]bool{}
	for _, check := range source.Checks {
		checks[check.ARN[strings.LastIndexAny(check.ARN, ":/")+1:]+" "+check.Check] = true
	}
	for _, want := range []string{"AGENT12345 agent_role_unused_ai_permissions", "invoker agent_role_unused_ai_permissions", "researcher-AbCdEfGhIj agent_role_unused_ai_permissions", "* agent_data_service_wide_access"} {
		if !checks[want] {
			t.Errorf("missing check %q in %+v", want, source.Checks)
		}
	}
	for _, leaked := range []string{discoveryAgentSentinel, "sentinel", "198.51", "10.0.", "does things", "/v1", "?k="} {
		if strings.Contains(string(inventory.AgentSource), leaked) {
			t.Fatalf("the agent source carries %q", leaked)
		}
	}

	// The pages: typed entities and the relationships attack paths walk.
	pages := runDiscoveryAgentPages(t, caller)
	entities := discoveryAgentPageEntities(t, pages[3])
	attributes := func(native string) string {
		encoded, _ := json.Marshal(entities[native]["attributes"])
		return string(encoded)
	}
	if got := attributes(gatewayARN); got != `{"auth":"none","endpoint_host":"tools-abcdefghij.gateway.bedrock-agentcore.us-west-2.amazonaws.com","source":"agentcore_gateway","status":"READY","transport":"http"}` {
		t.Fatalf("gateway attributes = %s", got)
	}
	if got := attributes(gatewayARN + "/target/T1LAMBDA00/tool/run_query"); entities[gatewayARN+"/target/T1LAMBDA00/tool/run_query"]["kind"] != "aws_mcp_tool" || got != `{"risk":"execute"}` {
		t.Fatalf("tool = %v %s", entities[gatewayARN+"/target/T1LAMBDA00/tool/run_query"], got)
	}
	if got := attributes(gatewayARN + "/target/T1LAMBDA00/tool/list_tables"); got != `{"risk":"read"}` {
		t.Fatalf("tool attributes = %s", got)
	}
	if got := attributes("aws:mcp_server:us-east-1:mcp.linear.example"); entities["aws:mcp_server:us-east-1:mcp.linear.example"]["kind"] != "aws_mcp_server" || got != `{"endpoint_host":"mcp.linear.example","source":"egress","transport":"http"}` {
		t.Fatalf("remote server = %s", got)
	}
	if got := attributes("arn:aws:dynamodb:::*"); entities["arn:aws:dynamodb:::*"]["kind"] != "aws_data_store" || entities["arn:aws:dynamodb:::*"]["display_name"] != "All DynamoDB tables" || got != `{"access":"write","scope":"service"}` {
		t.Fatalf("data store = %v %s", entities["arn:aws:dynamodb:::*"], got)
	}
	agent := attributes("arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345")
	if !strings.Contains(agent, `"ai_actions_granted":"bedrock-agentcore:InvokeGateway,bedrock:InvokeAgent,bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream"`) || !strings.Contains(agent, `"ai_actions_used":"bedrock:InvokeModel"`) || !strings.Contains(agent, `"ai_actions_unused":"bedrock:InvokeModelWithResponseStream"`) {
		t.Fatalf("agent usage attributes = %s", agent)
	}
	edges := map[string]bool{}
	for _, raw := range pages[3].Relationships {
		var relationship struct {
			Kind           string `json:"kind"`
			SourceNativeID string `json:"source_native_id"`
		}
		if err := json.Unmarshal(raw, &relationship); err != nil {
			t.Fatal(err)
		}
		edges[relationship.SourceNativeID] = true
	}
	for _, want := range []string{
		"arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345|depends_on|" + gatewayARN,
		gatewayARN + "|contains|" + gatewayARN + "/target/T1LAMBDA00/tool/run_query",
		gatewayARN + "|depends_on|aws:mcp_server:us-west-2:mcp.vendor.example",
		"arn:aws:ec2:us-east-1:123456789012:instance/i-0aaaaaaaaaaaaaaa1|depends_on|us-east-1/mcp.linear.example",
		discoveryAgentReaderRole + "|depends_on|arn:aws:dynamodb:::*",
		discoveryAgentReaderRole + "|depends_on|arn:aws:s3:::reports",
	} {
		if !edges[want] {
			t.Errorf("missing relationship %q", want)
		}
	}
	// The checks are findings on the entities the agents page emitted.
	findings := map[string]bool{}
	for _, raw := range pages[4].Findings {
		var finding struct {
			EntityID string `json:"entity_id"`
			CheckID  string `json:"check_id"`
		}
		if err := json.Unmarshal(raw, &finding); err != nil {
			t.Fatal(err)
		}
		findings[finding.CheckID+" "+finding.EntityID] = true
	}
	if !findings["agent_data_service_wide_access "+entities["arn:aws:dynamodb:::*"]["id"].(string)] || !findings["agent_role_unused_ai_permissions "+entities["arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"]["id"].(string)] {
		t.Fatalf("findings = %v", findings)
	}
}

func TestAWSDataResourceNamesTheStoreOrTheWholeService(t *testing.T) {
	for _, test := range []struct{ service, resource, arn, scope string }{
		{"s3", "*", "arn:aws:s3:::*", "service"},
		{"s3", "arn:aws:s3:::*", "arn:aws:s3:::*", "service"},
		{"s3", "arn:aws:s3:::reports/2026/*", "arn:aws:s3:::reports", "resource"},
		{"dynamodb", "arn:aws:dynamodb:us-east-1:123456789012:table/orders/index/*", "arn:aws:dynamodb:us-east-1:123456789012:table/orders", "resource"},
		{"dynamodb", "arn:aws:dynamodb:*:*:table/*", "arn:aws:dynamodb:::*", "service"},
		{"secretsmanager", "arn:aws:secretsmanager:us-east-1:123456789012:secret:*", "arn:aws:secretsmanager:::*", "service"},
		{"secretsmanager", "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-AbCdEf", "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-AbCdEf", "resource"},
		{"rds-data", "arn:aws:rds:us-east-1:123456789012:cluster:orders", "arn:aws:rds:us-east-1:123456789012:cluster:orders", "resource"},
		{"s3", "arn:aws:dynamodb:us-east-1:123456789012:table/orders", "", ""},
		{"s3", "arn:aws:s3:::bad bucket", "", ""},
	} {
		arn, scope, ok := discoveryAWSDataResource(test.service, test.resource)
		if arn != test.arn || scope != test.scope || ok != (test.arn != "") {
			t.Errorf("%s %s = %q %q %v", test.service, test.resource, arn, scope, ok)
		}
	}
}

// A lookup that stopped at the page limit proves no absence: nothing is
// called unused.
func TestAWSRoleUsageNeedsACompleteAuditRead(t *testing.T) {
	source := awsdiscovery.AgentInventorySource{BedrockAgents: []awsdiscovery.AgentInventoryBedrockAgent{{ARN: "arn:aws:bedrock:us-east-1:123456789012:agent/A", RoleARN: discoveryAgentReaderRole}}}
	actions := map[string][]string{discoveryAgentReaderRole: {"bedrock:*"}}
	sampled := discoveryAWSRoleUsage(source, actions, nil, false)
	complete := discoveryAWSRoleUsage(source, actions, nil, true)
	if len(sampled) != 1 || len(sampled[0].Unused) != 0 || len(sampled[0].Granted) != 6 {
		t.Fatalf("sampled = %+v", sampled)
	}
	if len(complete) != 1 || !reflect.DeepEqual(complete[0].Unused, []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}) {
		t.Fatalf("complete = %+v", complete)
	}
}
