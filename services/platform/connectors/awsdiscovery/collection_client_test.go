package awsdiscovery

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// The whole collection of an account, driven by the shared collection client
// exactly as the worker drives it, ends in a typed snapshot in which the
// agents phase's kinds carry their identity rules and their relationships.
func TestCollectionClientCompletesATypedSnapshotWithTheAgentsPhase(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}
	request := typedSnapshotRequest(t, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/connection/customer-0001", subject)
	authority := CollectionInventoryAuthority{Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt, ObservedAt: request.ObservationTime}
	inventory := awsInventoryFixture()
	inventory.CredentialExpiresAt = request.ObservationTime.Add(20 * time.Minute)
	caller, analyzer := &recordingAWSInventoryCaller{snapshot: inventory}, &recordingSecurityAnalyzer{}
	api, err := NewInventoryCollectionAPI(caller, analyzer, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driver, artifacts := newTypedSnapshotArtifacts(t)
	client, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("temporary-aws-credential-value")
	outcome, err := client.CollectWithCredential(context.Background(), request, bytes.Clone(credential))
	byKind, relationships := requireTypedSnapshot(t, request, outcome, err, map[string]typedSnapshotEnvelope{
		"aws_account":           {"asset", 9000},
		"aws_role":              {"identity", 9000},
		"aws_policy":            {"asset", 9000},
		"aws_resource":          {"asset", 9000},
		"aws_service":           {"asset", 9000},
		"aws_bedrock_agent":     {"agent", 9500},
		"aws_agentcore_runtime": {"agent", 9500},
		"aws_agentcore_gateway": {"tool", 9000},
		"aws_inferred_agent":    {"agent", 6000},
	})
	if caller.calls != 5 || len(analyzer.calls) != 2 || len(driver.objects) != 6 {
		t.Fatalf("inventory calls = %d, analyzer calls = %v, artifacts = %d", caller.calls, analyzer.calls, len(driver.objects))
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, credential) {
			t.Fatalf("artifact %s stores the credential", key)
		}
	}
	// Three AI services of the agents phase and the EC2 service of the
	// resources phase.
	services := map[string]bool{}
	for _, service := range byKind["aws_service"] {
		services[service.SourceNativeID] = true
	}
	if len(services) != 4 || !services["aws:bedrock-agent"] || !services["aws:bedrock-agentcore"] || !services["aws:lambda"] || len(byKind["aws_bedrock_agent"]) != 1 || len(byKind["aws_agentcore_runtime"]) != 1 || len(byKind["aws_agentcore_gateway"]) != 1 || len(byKind["aws_inferred_agent"]) != 2 {
		t.Fatalf("agents phase kinds: services=%d bedrock=%d runtimes=%d gateways=%d inferred=%d", len(byKind["aws_service"]), len(byKind["aws_bedrock_agent"]), len(byKind["aws_agentcore_runtime"]), len(byKind["aws_agentcore_gateway"]), len(byKind["aws_inferred_agent"]))
	}
	account := deterministicAWSInventoryID(request.Scope, subject, "aws_account", awsAgentTestAccount)
	role := deterministicAWSInventoryID(request.Scope, subject, "aws_role", awsAgentTestRole)
	for _, kind := range []string{"aws_service", "aws_bedrock_agent", "aws_agentcore_runtime", "aws_agentcore_gateway", "aws_inferred_agent"} {
		for _, entity := range byKind[kind] {
			if !typedSnapshotEdge(relationships, "contains", account, entity.ID) {
				t.Fatalf("%s %s is not contained in the account", kind, entity.SourceNativeID)
			}
			// The runtime's role is not a role of this inventory.
			if usesRole := kind == "aws_bedrock_agent" || kind == "aws_inferred_agent"; typedSnapshotEdge(relationships, "uses_identity", entity.ID, role) != usesRole {
				t.Fatalf("%s %s uses_identity edge to the role: want %t", kind, entity.SourceNativeID, usesRole)
			}
		}
	}
	agent := byKind["aws_bedrock_agent"][0]
	if string(agent.StableFields) != `{"account_id":"123456789012","agent_id":"AGENT12345","arn":"arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345","name":"support","region":"us-east-1"}` ||
		!bytes.HasPrefix(agent.Attributes, []byte(`{"discovery":{"method":"provider_api","platform":"bedrock_agent","signals":[]},"model":"anthropic.claude-sonnet","posture":{"cicd_write":false,"credential_active":true,`)) || !bytes.HasSuffix(agent.Attributes, []byte(`},"status":"PREPARED"}`)) {
		t.Fatalf("Bedrock agent stable %s\nattributes %s", agent.StableFields, agent.Attributes)
	}
	if snapshot := outcome.(collection.CompleteResult).Snapshot(); snapshot.EvidenceCount() != snapshot.EntityCount()+1 {
		t.Fatalf("evidence = %d for %d entities and one finding", snapshot.EvidenceCount(), snapshot.EntityCount())
	}
}

// The agentless signals travel the same road: a role and an instance
// inferred from the account's logs, the log sources' statuses and the failed
// agent posture checks all end in a typed snapshot, the checks as findings.
func TestCollectionClientCompletesATypedSnapshotWithInferredWorkloadsAndChecks(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "aws_account", ID: awsAgentTestAccount}
	request := typedSnapshotRequest(t, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/connection/customer-0001", subject)
	authority := CollectionInventoryAuthority{Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt, ObservedAt: request.ObservationTime}
	source := awsAgentSourceValue()
	const instanceARN, invokerARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaaaaaaaaaaaaaa1", "arn:aws:iam::123456789012:role/app/batch-summariser"
	source.InferredWorkloads = []AgentInventoryWorkload{
		{ARN: instanceARN, Name: "i-0aaaaaaaaaaaaaaa1", Region: "us-east-1", ResourceType: "ec2_instance", Signals: []string{"egress:anthropic"}},
		{ARN: invokerARN, Name: "batch-summariser", Region: "us-east-1", ResourceType: "iam_role", RoleARN: invokerARN, Signals: []string{"invoke:bedrock_model"}},
	}
	source.Checks = []AgentInventoryCheck{
		{ARN: "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345", Check: AgentCheckGuardrailMissing},
		{ARN: invokerARN, Check: AgentCheckRoleAdministrator},
		{ARN: invokerARN, Check: AgentCheckRoleUnused},
	}
	source.Services = append(source.Services, AgentInventoryService{Service: AgentServiceCloudTrail, Status: AgentServiceCollected}, AgentInventoryService{Service: AgentServiceResolverLogs, Status: AgentServiceUnavailable}, AgentInventoryService{Service: AgentServiceFlowLogs, Status: AgentServiceAccessDenied})
	inventory := awsAgentInventory(t, source)
	inventory.CredentialExpiresAt = request.ObservationTime.Add(20 * time.Minute)
	caller, analyzer := &recordingAWSInventoryCaller{snapshot: inventory}, &recordingSecurityAnalyzer{}
	api, err := NewInventoryCollectionAPI(caller, analyzer, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, artifacts := newTypedSnapshotArtifacts(t)
	client, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential-value"))
	byKind, _ := requireTypedSnapshot(t, request, outcome, err, map[string]typedSnapshotEnvelope{
		"aws_account": {"asset", 9000}, "aws_role": {"identity", 9000}, "aws_policy": {"asset", 9000}, "aws_resource": {"asset", 9000}, "aws_service": {"asset", 9000},
		"aws_bedrock_agent": {"agent", 9500}, "aws_agentcore_runtime": {"agent", 9500}, "aws_agentcore_gateway": {"tool", 9000}, "aws_inferred_agent": {"agent", 6000},
	})
	inferred := map[string]typedSnapshotEntity{}
	for _, entity := range byKind["aws_inferred_agent"] {
		inferred[entity.SourceNativeID] = entity
	}
	if len(inferred) != 4 ||
		!bytes.Contains(inferred[instanceARN].StableFields, []byte(`"resource_type":"ec2_instance"`)) || !bytes.Contains(inferred[instanceARN].Attributes, []byte(`"discovery":{"method":"inferred","platform":"ec2_instance","signals":["egress:anthropic"]}`)) ||
		!bytes.Contains(inferred[invokerARN].StableFields, []byte(`"resource_type":"iam_role"`)) || !bytes.Contains(inferred[invokerARN].Attributes, []byte(`"signals":["invoke:bedrock_model"]`)) {
		t.Fatalf("inferred agents = %+v", inferred)
	}
	statuses := map[string]string{}
	for _, service := range byKind["aws_service"] {
		statuses[service.SourceNativeID] = string(service.Attributes)
	}
	if statuses["aws:cloudtrail"] != `{"status":"collected"}` || statuses["aws:resolver-query-logs"] != `{"status":"unavailable"}` || statuses["aws:vpc-flow-logs"] != `{"status":"access_denied"}` {
		t.Fatalf("log source statuses = %v", statuses)
	}
	// Each failed check is one more piece of evidence than there are entities.
	snapshot := outcome.(collection.CompleteResult).Snapshot()
	if snapshot.EvidenceCount() != snapshot.EntityCount()+1+len(source.Checks) {
		t.Fatalf("evidence = %d for %d entities and %d checks", snapshot.EvidenceCount(), snapshot.EntityCount(), len(source.Checks))
	}
}

func TestAgentSourceRefusesUnknownChecksWorkloadsAndLogServices(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*AgentInventorySource){
		"check on an unlisted agent": func(source *AgentInventorySource) {
			source.Checks = []AgentInventoryCheck{{ARN: "arn:aws:bedrock:us-east-1:123456789012:agent/OTHER", Check: AgentCheckGuardrailMissing}}
		},
		"unknown check": func(source *AgentInventorySource) {
			source.Checks = []AgentInventoryCheck{{ARN: source.BedrockAgents[0].ARN, Check: "made_up"}}
		},
		"duplicate check": func(source *AgentInventorySource) {
			check := AgentInventoryCheck{ARN: source.BedrockAgents[0].ARN, Check: AgentCheckGuardrailMissing}
			source.Checks = []AgentInventoryCheck{check, check}
		},
		"workload of another account": func(source *AgentInventorySource) {
			source.InferredWorkloads = []AgentInventoryWorkload{{ARN: "arn:aws:iam::999999999999:role/x", Name: "x", Region: "us-east-1", ResourceType: "iam_role", RoleARN: "arn:aws:iam::999999999999:role/x", Signals: []string{"invoke:bedrock_model"}}}
		},
		"workload without a signal": func(source *AgentInventorySource) {
			source.InferredWorkloads = []AgentInventoryWorkload{{ARN: "arn:aws:iam::123456789012:role/x", Name: "x", Region: "us-east-1", ResourceType: "iam_role", RoleARN: "arn:aws:iam::123456789012:role/x"}}
		},
		"unknown workload type": func(source *AgentInventorySource) {
			source.InferredWorkloads = []AgentInventoryWorkload{{ARN: "arn:aws:iam::123456789012:role/x", Name: "x", Region: "us-east-1", ResourceType: "container", RoleARN: "arn:aws:iam::123456789012:role/x", Signals: []string{"invoke:bedrock_model"}}}
		},
		"log services out of order": func(source *AgentInventorySource) {
			source.Services = append(source.Services, AgentInventoryService{Service: AgentServiceFlowLogs, Status: AgentServiceCollected}, AgentInventoryService{Service: AgentServiceCloudTrail, Status: AgentServiceCollected})
		},
		"unknown log service": func(source *AgentInventorySource) {
			source.Services = append(source.Services, AgentInventoryService{Service: "s3", Status: AgentServiceCollected})
		},
	} {
		source := awsAgentSourceValue()
		change(&source)
		if _, ok := EncodeAgentInventorySource(source); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
