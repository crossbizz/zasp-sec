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
