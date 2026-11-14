package awsdiscovery

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// awsMCPSourceValue is the fixture source with a described gateway, a remote
// MCP server, uses, the role's data grants and its used-against-granted
// comparison.
func awsMCPSourceValue() AgentInventorySource {
	source := awsAgentSourceValue()
	const gateway, agent = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1", "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
	source.Gateways[0].Authorizer, source.Gateways[0].EndpointHost = "NONE", "gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com"
	source.Gateways[0].Targets = []AgentInventoryGatewayTarget{{Name: "sql", TargetID: "T1", Tools: []string{"list_tables", "run_query"}}, {Name: "vendor", RemoteHost: "mcp.vendor.example", TargetID: "T2"}}
	source.MCPServers = []AgentInventoryMCPServer{{Host: "mcp.linear.example", Region: "us-east-1", Source: "egress"}, {Host: "mcp.vendor.example", Region: "us-west-2", Source: "gateway_target"}}
	source.Uses = []AgentInventoryUse{{Agent: agent, Server: gateway}, {Agent: "arn:aws:lambda:us-east-1:123456789012:function:bot", Server: "us-east-1/mcp.linear.example"}}
	source.DataAccess = []AgentInventoryDataAccess{
		{Access: "write", ARN: "arn:aws:dynamodb:::*", RoleARN: awsAgentTestRole, Scope: "service", Service: "dynamodb"},
		{Access: "read", ARN: "arn:aws:s3:::reports", RoleARN: awsAgentTestRole, Scope: "resource", Service: "s3"},
	}
	source.RoleUsage = []AgentInventoryRoleUsage{{Granted: []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}, RoleARN: awsAgentTestRole, Unused: []string{"bedrock:InvokeModelWithResponseStream"}, Used: []string{"bedrock:InvokeModel"}}}
	source.Checks = []AgentInventoryCheck{{ARN: agent, Check: AgentCheckRoleUnusedAI}, {ARN: "arn:aws:dynamodb:::*", Check: AgentCheckDataServiceWide}}
	return source
}

// The MCP servers, their tools, the data stores and the relationships an
// attack path walks end in a typed snapshot through the collection client.
func TestCollectionClientCompletesATypedSnapshotWithMCPServersToolsAndDataStores(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}
	request := typedSnapshotRequest(t, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/connection/customer-0001", subject)
	authority := CollectionInventoryAuthority{Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt, ObservedAt: request.ObservationTime}
	inventory := awsAgentInventory(t, awsMCPSourceValue())
	inventory.CredentialExpiresAt = request.ObservationTime.Add(20 * time.Minute)
	api, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: inventory}, &recordingSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, artifacts := newTypedSnapshotArtifacts(t)
	client, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential-value"))
	byKind, relationships := requireTypedSnapshot(t, request, outcome, err, map[string]typedSnapshotEnvelope{
		"aws_account": {"asset", 9000}, "aws_role": {"identity", 9000}, "aws_policy": {"asset", 9000}, "aws_resource": {"asset", 9000}, "aws_service": {"asset", 9000},
		"aws_bedrock_agent": {"agent", 9500}, "aws_agentcore_runtime": {"agent", 9500}, "aws_agentcore_gateway": {"tool", 9000}, "aws_inferred_agent": {"agent", 6000},
		"aws_mcp_server": {"tool", 9000}, "aws_mcp_tool": {"tool", 9000}, "aws_data_store": {"asset", 9000},
	})
	id := func(kind, native string) string {
		return deterministicAWSInventoryID(request.Scope, subject, kind, native)
	}
	const gatewayARN, agentARN = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1", "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
	gateway := byKind["aws_agentcore_gateway"][0]
	if string(gateway.Attributes) != `{"auth":"none","endpoint_host":"gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com","source":"agentcore_gateway","status":"READY","transport":"http"}` {
		t.Fatalf("gateway attributes = %s", gateway.Attributes)
	}
	tools := map[string]string{}
	for _, tool := range byKind["aws_mcp_tool"] {
		tools[tool.DisplayName] = string(tool.StableFields) + string(tool.Attributes)
		if !typedSnapshotEdge(relationships, "contains", gateway.ID, tool.ID) {
			t.Fatalf("tool %s is not held by its gateway", tool.DisplayName)
		}
	}
	if len(tools) != 2 || tools["run_query"] != `{"account_id":"123456789012","arn":"`+gatewayARN+`","name":"run_query","region":"us-west-2","server":"gw-1","target":"T1"}{"risk":"execute"}` || !bytes.HasSuffix([]byte(tools["list_tables"]), []byte(`{"risk":"read"}`)) {
		t.Fatalf("tools = %v", tools)
	}
	servers := map[string]string{}
	for _, server := range byKind["aws_mcp_server"] {
		servers[server.DisplayName] = string(server.Attributes)
	}
	if len(servers) != 2 || servers["mcp.linear.example"] != `{"endpoint_host":"mcp.linear.example","source":"egress","transport":"http"}` || servers["mcp.vendor.example"] != `{"endpoint_host":"mcp.vendor.example","source":"gateway_target","transport":"http"}` {
		t.Fatalf("servers = %v", servers)
	}
	stores := map[string]string{}
	for _, store := range byKind["aws_data_store"] {
		stores[store.SourceNativeID] = store.DisplayName + " " + string(store.Attributes)
	}
	if len(stores) != 2 || stores["arn:aws:dynamodb:::*"] != `All DynamoDB tables {"access":"write","scope":"service"}` || stores["arn:aws:s3:::reports"] != `reports {"access":"read","scope":"resource"}` {
		t.Fatalf("data stores = %v", stores)
	}
	role := id("aws_role", awsAgentTestRole)
	for name, edge := range map[string][3]string{
		"agent uses the gateway":              {"depends_on", id("aws_bedrock_agent", agentARN), gateway.ID},
		"function uses the remote server":     {"depends_on", id("aws_inferred_agent", "arn:aws:lambda:us-east-1:123456789012:function:bot"), id("aws_mcp_server", "aws:mcp_server:us-east-1:mcp.linear.example")},
		"gateway fronts the vendor server":    {"depends_on", gateway.ID, id("aws_mcp_server", "aws:mcp_server:us-west-2:mcp.vendor.example")},
		"role reaches every DynamoDB table":   {"depends_on", role, id("aws_data_store", "arn:aws:dynamodb:::*")},
		"role reaches the reports bucket":     {"depends_on", role, id("aws_data_store", "arn:aws:s3:::reports")},
		"agent runs as the role (agent→role)": {"uses_identity", id("aws_bedrock_agent", agentARN), role},
	} {
		if !typedSnapshotEdge(relationships, edge[0], edge[1], edge[2]) {
			t.Errorf("%s: relationship missing", name)
		}
	}
	agent := byKind["aws_bedrock_agent"][0]
	if !bytes.Contains(agent.Attributes, []byte(`"ai_actions_granted":"bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream","ai_actions_unused":"bedrock:InvokeModelWithResponseStream","ai_actions_used":"bedrock:InvokeModel"`)) {
		t.Fatalf("agent attributes = %s", agent.Attributes)
	}
	// One Prowler finding of the fixture and the two checks.
	if snapshot := outcome.(collection.CompleteResult).Snapshot(); snapshot.EvidenceCount() != snapshot.EntityCount()+3 {
		t.Fatalf("evidence = %d for %d entities", snapshot.EvidenceCount(), snapshot.EntityCount())
	}
}

func TestAgentSourceRefusesMalformedMCPAndAccessParts(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*AgentInventorySource){
		"unknown authorizer": func(source *AgentInventorySource) { source.Gateways[0].Authorizer = "SOMETHING" },
		"host with a path":   func(source *AgentInventorySource) { source.Gateways[0].EndpointHost = "example.com/path" },
		"unsorted tools":     func(source *AgentInventorySource) { source.Gateways[0].Targets[0].Tools = []string{"b", "a"} },
		"tool with a space":  func(source *AgentInventorySource) { source.Gateways[0].Targets[0].Tools = []string{"a b"} },
		"server not a host":  func(source *AgentInventorySource) { source.MCPServers[0].Host = "10.0.0.1:8080" },
		"use of an unknown agent": func(source *AgentInventorySource) {
			source.Uses[0].Agent = "arn:aws:bedrock:us-east-1:123456789012:agent/OTHER"
		},
		"use of an unknown server": func(source *AgentInventorySource) { source.Uses[0].Server = "us-east-1/mcp.unknown.example" },
		"access by another role": func(source *AgentInventorySource) {
			source.DataAccess[0].RoleARN = "arn:aws:iam::123456789012:role/other"
		},
		"service scope on a store": func(source *AgentInventorySource) { source.DataAccess[1].Scope = "service" },
		"unused not granted":       func(source *AgentInventorySource) { source.RoleUsage[0].Unused = []string{"bedrock:InvokeAgent"} },
		"action with a wildcard":   func(source *AgentInventorySource) { source.RoleUsage[0].Granted = []string{"bedrock:*"} },
		"data check on a resource": func(source *AgentInventorySource) { source.Checks[1].ARN = "arn:aws:s3:::reports" },
	} {
		source := awsMCPSourceValue()
		mutate(&source)
		if _, ok := EncodeAgentInventorySource(source); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, ok := EncodeAgentInventorySource(awsMCPSourceValue()); !ok {
		t.Fatal("the fixture is refused")
	}
}
