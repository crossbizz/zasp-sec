package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
)

// mcpSnapshotArtifacts is an in-memory artifact driver for the collection
// the test drives through the shared collection client.
type mcpSnapshotArtifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *mcpSnapshotArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *mcpSnapshotArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *mcpSnapshotArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*mcpSnapshotArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://typed-snapshot-evidence/" + locator.Key, nil
}

// mcpInventoryCaller answers the AWS inventory with a fixed account.
type mcpInventoryCaller struct {
	inventory awsdiscovery.CollectionInventory
}

func (caller *mcpInventoryCaller) GetCollectionInventory(context.Context, []byte) (awsdiscovery.CollectionInventory, error) {
	return caller.inventory, nil
}
func (*mcpInventoryCaller) CheckCollectionReadiness(context.Context) error { return nil }

// mcpSecurityAnalyzer answers the IAM phase with the account's one role and
// the posture phase with no Prowler finding.
type mcpSecurityAnalyzer struct{}

func (*mcpSecurityAnalyzer) CheckCollectionReadiness(context.Context) error { return nil }
func (*mcpSecurityAnalyzer) Collect(_ context.Context, request awsdiscovery.CollectionSecurityRequest, _ []byte) (awsdiscovery.CollectionSecurityResult, error) {
	result := json.RawMessage(`{"findings":[],"version":"5.39.1"}`)
	if request.Mode == awsdiscovery.SecurityModeCartographyAWS {
		result = json.RawMessage(`{"policies":[],"roles":[{"arn":"arn:aws:iam::123456789012:role/read","name":"read","trusted_role_arns":[]}],"version":"0.139.1"}`)
	}
	return awsdiscovery.CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: result}, nil
}

const (
	mcpTestRole    = "arn:aws:iam::123456789012:role/read"
	mcpTestGateway = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1"
	mcpTestAgent   = "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
	mcpTestBot     = "arn:aws:lambda:us-east-1:123456789012:function:bot"
)

// mcpAgentSource is an account with a Bedrock agent and a function that run
// as one role, a gateway with no authorizer that serves an execute tool, a
// remote MCP server the function reached, and the role's data grants.
func mcpAgentSource() awsdiscovery.AgentInventorySource {
	return awsdiscovery.AgentInventorySource{
		AccountID:     "123456789012",
		BedrockAgents: []awsdiscovery.AgentInventoryBedrockAgent{{AgentID: "AGENT12345", ARN: mcpTestAgent, Model: "anthropic.claude-sonnet", Name: "support", Region: "us-east-1", RoleARN: mcpTestRole, Status: "PREPARED"}},
		Checks:        []awsdiscovery.AgentInventoryCheck{{ARN: mcpTestAgent, Check: awsdiscovery.AgentCheckRoleUnusedAI}, {ARN: "arn:aws:dynamodb:::*", Check: awsdiscovery.AgentCheckDataServiceWide}},
		DataAccess: []awsdiscovery.AgentInventoryDataAccess{
			{Access: "write", ARN: "arn:aws:dynamodb:::*", RoleARN: mcpTestRole, Scope: "service", Service: "dynamodb"},
			{Access: "read", ARN: "arn:aws:s3:::reports", RoleARN: mcpTestRole, Scope: "resource", Service: "s3"},
		},
		Gateways: []awsdiscovery.AgentInventoryGateway{{ARN: mcpTestGateway, Authorizer: "NONE", EndpointHost: "gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com", GatewayID: "gw-1", Name: "tools", Region: "us-west-2", Status: "READY",
			Targets: []awsdiscovery.AgentInventoryGatewayTarget{{Name: "sql", TargetID: "T1", Tools: []string{"list_tables", "run_query"}}}}},
		LambdaFunctions: []awsdiscovery.AgentInventoryLambdaFunction{{ARN: mcpTestBot, Name: "bot", Region: "us-east-1", RoleARN: mcpTestRole, Signals: []string{"env:openai"}, State: "Active"}},
		MCPServers:      []awsdiscovery.AgentInventoryMCPServer{{Host: "mcp.linear.example", Region: "us-east-1", Source: "egress"}},
		RoleUsage:       []awsdiscovery.AgentInventoryRoleUsage{{Granted: []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}, RoleARN: mcpTestRole, Unused: []string{"bedrock:InvokeModelWithResponseStream"}, Used: []string{"bedrock:InvokeModel"}}},
		Runtimes:        []awsdiscovery.AgentInventoryRuntime{},
		Services:        []awsdiscovery.AgentInventoryService{{Service: awsdiscovery.AgentServiceBedrockAgents, Status: awsdiscovery.AgentServiceCollected}, {Service: awsdiscovery.AgentServiceAgentCore, Status: awsdiscovery.AgentServiceCollected}, {Service: awsdiscovery.AgentServiceLambda, Status: awsdiscovery.AgentServiceCollected}},
		Uses:            []awsdiscovery.AgentInventoryUse{{Agent: mcpTestAgent, Server: mcpTestGateway}, {Agent: mcpTestBot, Server: "us-east-1/mcp.linear.example"}},
	}
}

// collectMCPAccount runs the whole AWS collection of the account through the
// collection client and returns its typed snapshot.
func collectMCPAccount(t *testing.T, ctx context.Context, identity RequestIdentity, integrationID string) collection.CompleteResult {
	t.Helper()
	parse := func(value string) domain.ProductID {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	subject := collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}
	request := collection.Request{Scope: identity.Scope, IntegrationID: parse(integrationID), ConnectionID: parse("pid_7b000005-0000-4000-8000-000000000005"), JobID: parse("pid_7b000006-0000-4000-8000-000000000006"), Attempt: 1,
		Provider: collection.ProviderAWS, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialAWSAssumeRole, CredentialReference: "ref:aws/connection/customer-0001", ExpectedSubject: subject,
		ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 5 * time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	cartography := json.RawMessage(`{"account_id":"123456789012","managed_policies":{"arn:aws:iam::123456789012:role/read":{"arn:aws:iam::123456789012:policy/read":[]}},"roles":[{"Arn":"arn:aws:iam::123456789012:role/read","AssumeRolePolicyDocument":{},"CreateDate":"2026-08-20T00:00:00Z","Path":"/","RoleId":"AROAABCDEFGHIJKLMNOP","RoleName":"read"}]}`)
	prowler := json.RawMessage(`{"account_id":"123456789012","instances":[],"roles":[{"Arn":"arn:aws:iam::123456789012:role/read","AssumeRolePolicyDocument":{},"AttachedPolicies":[{"PolicyName":"read"}],"IsServiceRole":false,"RoleId":"AROAABCDEFGHIJKLMNOP","RoleName":"read"}]}`)
	agents, ok := awsdiscovery.EncodeAgentInventorySource(mcpAgentSource())
	if !ok {
		t.Fatal("the agent source is refused")
	}
	inventory := awsdiscovery.CollectionInventory{Identity: awsdiscovery.Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/discovery/session"}, CredentialExpiresAt: request.ObservationTime.Add(20 * time.Minute),
		CartographySource: cartography, CartographyDigest: sha256.Sum256(cartography), ProwlerSource: prowler, ProwlerDigest: sha256.Sum256(prowler), AgentSource: agents, AgentDigest: sha256.Sum256(agents)}
	authority := awsdiscovery.CollectionInventoryAuthority{Scope: request.Scope, IntegrationID: request.IntegrationID, ConnectionID: request.ConnectionID, JobID: request.JobID, Attempt: request.Attempt, ObservedAt: request.ObservationTime}
	api, err := awsdiscovery.NewInventoryCollectionAPI(&mcpInventoryCaller{inventory: inventory}, &mcpSecurityAnalyzer{}, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := artifactstore.New(&mcpSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(ctx, request, []byte("temporary-aws-credential-value"))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	return complete
}

// Sections WS5a to WS5c of completion.sql against the released baseline: the
// sections apply and a second run changes nothing; the rule catalog equals
// the compiled one; the typed snapshot the AWS collector produces for an
// account with a gateway, a remote MCP server and data grants is applied to
// the inventory; the MCP servers are listed with their tools, users and
// approval; registry decisions change the posture findings; and attack paths
// run agent, server, tool and agent, role, data store.
func TestMCPSectionsOnTheInstalledBaselinePostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	connection := installedBaselineConnection(t, ctx)
	definitions := func() string {
		t.Helper()
		var functions, constraints string
		if err := connection.QueryRow(ctx, `SELECT
 (SELECT md5(string_agg(pg_get_functiondef(p.oid),'' ORDER BY p.oid::regprocedure::text)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind='f' AND (n.nspname LIKE 'zasp%' OR n.nspname='public')),
 (SELECT md5(string_agg(c.conrelid::regclass::text||c.conname||pg_get_constraintdef(c.oid),'' ORDER BY c.conrelid::regclass::text,c.conname)) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname LIKE 'zasp%' OR n.nspname='public')`).Scan(&functions, &constraints); err != nil {
			t.Fatal(err)
		}
		return functions + constraints
	}
	// Everything the WS5 sections build on, then the sections, then all of
	// it again: the tail of the file runs twice without a change.
	sections := []string{"saas_providers", "rule_catalog_digest", "inventory_posture_dismissal", "saas_generic_provider", "saas_rule_catalog", "ai_framework_data", "ws5_rule_catalog", "ws5_mcp_registry", "ws5_mcp_posture", "ws5_agent_access"}
	for _, tag := range sections {
		applyCompletionBlock(t, ctx, connection, tag)
	}
	applied := definitions()
	for _, tag := range sections {
		applyCompletionBlock(t, ctx, connection, tag)
	}
	if definitions() != applied {
		t.Fatal("a second run of the sections changed a function or a constraint")
	}
	var rules int
	var digest string
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_inventory_identity_rules),(SELECT value FROM zasp_schema_metadata WHERE key='typed_inventory_rule_catalog_digest')`).Scan(&rules, &digest); err != nil {
		t.Fatal(err)
	}
	if compiled := inventoryprojection.RuleCatalogDigest(); rules != len(inventoryprojection.RuleCatalog()) || rules != 56 || digest != hexDigest(compiled) {
		t.Fatalf("rule catalog: rows=%d digest=%s, compiled rows=%d digest=%s", rules, digest, len(inventoryprojection.RuleCatalog()), hexDigest(compiled))
	}
	// Every rule row equals the compiled rule.
	rows, err := connection.Query(ctx, `SELECT provider,source_kind,identity_namespace,product_kind,rule_version,priority,confidence_basis_points,freshness_seconds FROM zasp_inventory_identity_rules ORDER BY provider,source_kind`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var provider, sourceKind, namespace, productKind string
		var version, priority, confidence int
		var freshness int64
		if err := rows.Scan(&provider, &sourceKind, &namespace, &productKind, &version, &priority, &confidence, &freshness); err != nil {
			t.Fatal(err)
		}
		rule, found := inventoryprojection.LookupRule(provider, sourceKind)
		if !found || rule.Namespace != namespace || string(rule.ProductKind) != productKind || rule.Version != version || rule.Priority != priority || rule.ConfidenceBasisPoints != confidence || int64(rule.Freshness/time.Second) != freshness {
			t.Fatalf("rule row %s/%s differs from the compiled rule %+v", provider, sourceKind, rule)
		}
	}
	rows.Close()

	// The AWS collection, applied by the function the worker calls.
	identity := fixtureRequestIdentity(t)
	organizationID, workspaceID, environmentID := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	scope := []any{organizationID, workspaceID, environmentID}
	const integrationID, syncID, snapshotID = "pid_7b000001-0000-4000-8000-000000000001", "pid_7b000002-0000-4000-8000-000000000002", "pid_7b000003-0000-4000-8000-000000000003"
	if _, err := connection.Exec(ctx, postgresDiscoveryCreateIntegrationSQL, organizationID, workspaceID, environmentID, integrationID, "aws", "1.0.0", "AWS", `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`, ""); err != nil {
		t.Fatalf("create the integration: %v", err)
	}
	if _, err := connection.Exec(ctx, postgresDiscoveryTransitionIntegrationSQL, organizationID, workspaceID, environmentID, integrationID, int64(1), "active"); err != nil {
		t.Fatal(err)
	}
	collected := collectMCPAccount(t, ctx, identity, integrationID)
	candidate := collected.Snapshot()
	manifest := collected.Manifest().Descriptor()
	checksum := manifest.Checksum()
	requestDigest := sha256.Sum256([]byte("mcp-typed-sync"))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'mcp-typed-sync-0001',$6,'manual',$7,'parser_v1','tool_v1')`,
		organizationID, workspaceID, environmentID, syncID, integrationID, requestDigest[:], identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	var snapshotEntities []struct {
		ID             string `json:"id"`
		Kind           string `json:"kind"`
		SourceNativeID string `json:"source_native_id"`
		ObservedAt     string `json:"observed_at"`
	}
	if err := json.Unmarshal(candidate.Entities(), &snapshotEntities); err != nil || len(snapshotEntities) == 0 {
		t.Fatalf("snapshot entities: %v", err)
	}
	entityID := map[string]string{}
	for _, entity := range snapshotEntities {
		entityID[entity.SourceNativeID] = entity.ID
	}
	observed, err := time.Parse(time.RFC3339, snapshotEntities[0].ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, postgresDiscoveryApplySnapshotSQL, organizationID, workspaceID, environmentID, integrationID, syncID, snapshotID, int64(1), "aws", manifest.ObjectReference(), checksum[:],
		observed, "aws", collected.NextCursor().Value, string(candidate.Entities()), string(candidate.Relationships()), string(candidate.Evidence())); err != nil {
		t.Fatalf("apply the typed snapshot: %v", err)
	}

	// The discovery findings of the snapshot (the two checks), applied the
	// way the risk projection applies them, and the posture refresh.
	var evidence []struct {
		ID        string `json:"id"`
		EntityID  string `json:"entity_id"`
		FindingID string `json:"finding_id"`
		CheckID   string `json:"check_id"`
	}
	if err := json.Unmarshal(candidate.Evidence(), &evidence); err != nil {
		t.Fatal(err)
	}
	var findingItems []map[string]string
	for _, item := range evidence {
		if item.FindingID != "" {
			findingItems = append(findingItems, map[string]string{"finding_id": item.FindingID, "entity_id": item.EntityID, "check_id": item.CheckID, "evidence_id": item.ID, "source": "aws"})
		}
	}
	if len(findingItems) != 2 {
		t.Fatalf("discovery findings in the snapshot = %d: %s", len(findingItems), candidate.Evidence())
	}
	encodedFindings, _ := json.Marshal(findingItems)
	if _, err := connection.Exec(ctx, `SELECT zasp_inventory_apply_findings($1,$2,$3,$4::jsonb)`, organizationID, workspaceID, environmentID, string(encodedFindings)); err != nil {
		t.Fatalf("apply the discovery findings: %v", err)
	}
	refresh := func() {
		t.Helper()
		if _, err := connection.Exec(ctx, `SELECT zasp_inventory_refresh_posture_findings($1,$2,$3)`, scope...); err != nil {
			t.Fatalf("refresh the posture findings: %v", err)
		}
	}
	refresh()

	// A stdio server a repository declares, used by the function: the rows
	// the GitHub collector's typed snapshot leaves (its own collection test
	// proves their shape), copied from the remote server's rows.
	remoteID, gatewayID := entityID["aws:mcp_server:us-east-1:mcp.linear.example"], entityID[mcpTestGateway]
	agentID, botID, roleID := entityID[mcpTestAgent], entityID[mcpTestBot], entityID[mcpTestRole]
	toolID, storeID := entityID[mcpTestGateway+"/target/T1/tool/run_query"], entityID["arn:aws:dynamodb:::*"]
	for name, id := range map[string]string{"remote server": remoteID, "gateway": gatewayID, "agent": agentID, "function": botID, "role": roleID, "tool": toolID, "data store": storeID} {
		if id == "" {
			t.Fatalf("the snapshot has no %s", name)
		}
	}
	const stdioID, stdioEdgeID = "pid_7b0000a1-0000-4000-8000-0000000000a1", "pid_7b0000a2-0000-4000-8000-0000000000a2"
	stdioAttributes := `{"auth":"not_applicable","command":"npx","config_path":".mcp.json","package":"@acme/tracker-mcp","package_pinned":false,"source":"repository_config","transport":"stdio"}`
	for _, statement := range []string{
		`INSERT INTO zasp_inventory_entities SELECT (jsonb_populate_record(entity,jsonb_build_object('id',$5::text,'display_name','tracker','stable_fields',jsonb_build_object('installation_id',9001,'name','tracker','owner','acme','repository','alpha'),'winning_attributes',$6::jsonb,'winning_source_native_id','github:repository:101:mcp_server:tracker'))).* FROM zasp_inventory_entities entity WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`,
		`INSERT INTO zasp_inventory_source_observations SELECT (jsonb_populate_record(observation,jsonb_build_object('entity_id',$5::text,'source_native_id','github:repository:101:mcp_server:tracker','source_kind','github_mcp_server','identity_namespace','github_mcp_server','display_name','tracker','attributes',$6::jsonb))).* FROM zasp_inventory_source_observations observation WHERE (organization_id,workspace_id,environment_id,entity_id)=($1,$2,$3,$4)`,
	} {
		if _, err := connection.Exec(ctx, statement, organizationID, workspaceID, environmentID, remoteID, stdioID, stdioAttributes); err != nil {
			t.Fatalf("%s: %v", statement[:60], err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_relationships SELECT (jsonb_populate_record(relationship,jsonb_build_object('id',$6::text,'to_entity_id',$7::text,'source_native_id','bot|depends_on|tracker'))).* FROM zasp_inventory_relationships relationship WHERE (organization_id,workspace_id,environment_id,from_entity_id,to_entity_id,kind)=($1,$2,$3,$4,$5,'depends_on')`,
		organizationID, workspaceID, environmentID, botID, remoteID, stdioEdgeID, stdioID); err != nil {
		t.Fatal(err)
	}

	// A skill of the function's repository, as the GitHub collector leaves it.
	const skillID, skillEdgeID = "pid_7b0000a3-0000-4000-8000-0000000000a3", "pid_7b0000a4-0000-4000-8000-0000000000a4"
	for _, statement := range []string{
		`INSERT INTO zasp_inventory_entities SELECT (jsonb_populate_record(entity,jsonb_build_object('id',$5::text,'kind','asset','product_kind','asset','display_name','.claude/skills/release','stable_fields',jsonb_build_object('installation_id',9001,'name','.claude/skills/release','owner','acme','repository','alpha'),'winning_attributes',jsonb_build_object('skill_kind','skill'),'winning_source_native_id','github:repository:101:agent_skill:.claude/skills/release'))).* FROM zasp_inventory_entities entity WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`,
		`INSERT INTO zasp_inventory_source_observations SELECT (jsonb_populate_record(observation,jsonb_build_object('entity_id',$5::text,'source_native_id','github:repository:101:agent_skill:.claude/skills/release','source_kind','github_agent_skill','identity_namespace','github_agent_skill','product_kind','asset','display_name','.claude/skills/release','attributes',jsonb_build_object('skill_kind','skill')))).* FROM zasp_inventory_source_observations observation WHERE (organization_id,workspace_id,environment_id,entity_id)=($1,$2,$3,$4)`,
	} {
		if _, err := connection.Exec(ctx, statement, organizationID, workspaceID, environmentID, remoteID, skillID); err != nil {
			t.Fatalf("%s: %v", statement[:60], err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_relationships SELECT (jsonb_populate_record(relationship,jsonb_build_object('id',$6::text,'from_entity_id',$7::text,'to_entity_id',$8::text,'source_native_id','bot|contains|skill'))).* FROM zasp_inventory_relationships relationship WHERE (organization_id,workspace_id,environment_id,from_entity_id,to_entity_id,kind)=($1,$2,$3,$4,$5,'contains')`,
		organizationID, workspaceID, environmentID, gatewayID, toolID, skillEdgeID, botID, skillID); err != nil {
		t.Fatal(err)
	}

	// What an agent may use: used against granted, its MCP servers, the data
	// stores its role reaches, and the skills of its repository.
	access := func(id string) string {
		t.Helper()
		var payload []byte
		if err := connection.QueryRow(ctx, `SELECT zasp_mcp_agent_access_json($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, id).Scan(&payload); err != nil || payload == nil {
			t.Fatalf("access of %s: %v", id, err)
		}
		var decoded AgentAccess
		if err := decodeStrictInventory(payload, &decoded); err != nil || !validAgentAccess(decoded, id) {
			t.Fatalf("access of %s is not the API's shape: %s (%v)", id, payload, err)
		}
		canonical, _ := json.Marshal(decoded)
		return string(canonical)
	}
	if got, want := access(agentID), `{"agent_id":"`+agentID+`","ai_actions":{"window_days":7,"granted":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"],"used":["bedrock:InvokeModel"],"unused":["bedrock:InvokeModelWithResponseStream"]},`+
		`"mcp_servers":[{"id":"`+gatewayID+`","name":"tools","identity":"host:gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com","approval":"unapproved"}],`+
		`"data_stores":[{"id":"`+storeID+`","name":"All DynamoDB tables","service":"dynamodb","access":"write","scope":"service"},{"id":"`+entityID["arn:aws:s3:::reports"]+`","name":"reports","service":"s3","access":"read","scope":"resource"}],"skills":[]}`; got != want {
		t.Fatalf("agent access\n got %s\nwant %s", got, want)
	}
	if got := access(botID); !strings.Contains(got, `"skills":[{"id":"`+skillID+`","path":".claude/skills/release","kind":"skill"}]`) || !strings.Contains(got, `"name":"mcp.linear.example"`) || !strings.Contains(got, `"name":"tracker"`) {
		t.Fatalf("function access = %s", got)
	}
	var missing []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_mcp_agent_access_json($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, roleID).Scan(&missing); err != nil || missing != nil {
		t.Fatalf("access of something that is not an agent = %s, %v", missing, err)
	}

	// The MCP servers as the API lists them.
	server := func(id string) map[string]any {
		t.Helper()
		var payload []byte
		if err := connection.QueryRow(ctx, `SELECT zasp_mcp_server_json($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, id).Scan(&payload); err != nil || payload == nil {
			t.Fatalf("server %s: %v", id, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	var listed int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_mcp_servers($1,$2,$3)`, scope...).Scan(&listed); err != nil || listed != 3 {
		t.Fatalf("MCP servers = %d, %v", listed, err)
	}
	gateway := server(gatewayID)
	if gateway["identity"] != "host:gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com" || gateway["approval"] != "unapproved" || gateway["auth"] != "none" || gateway["source"] != "agentcore_gateway" || gateway["transport"] != "http" || gateway["source_kind"] != "aws_agentcore_gateway" ||
		gateway["tool_count"] != float64(2) || gateway["agent_count"] != float64(1) || gateway["package"] != nil || gateway["package_pinned"] != nil {
		t.Fatalf("gateway = %v", gateway)
	}
	// The execute tool is listed first.
	if tools := gateway["tools"].([]any); len(tools) != 2 || tools[0].(map[string]any)["name"] != "run_query" || tools[0].(map[string]any)["risk"] != "execute" || tools[1].(map[string]any)["risk"] != "read" {
		t.Fatalf("gateway tools = %v", gateway["tools"])
	}
	if agents := gateway["agents"].([]any); len(agents) != 1 || agents[0].(map[string]any)["id"] != agentID || agents[0].(map[string]any)["name"] != "support" {
		t.Fatalf("gateway agents = %v", gateway["agents"])
	}
	if stdio := server(stdioID); stdio["identity"] != "package:@acme/tracker-mcp" || stdio["transport"] != "stdio" || stdio["command"] != "npx" || stdio["package_pinned"] != false || stdio["auth"] != "not_applicable" || stdio["agent_count"] != float64(1) || stdio["endpoint_host"] != nil {
		t.Fatalf("stdio server = %v", stdio)
	}
	if remote := server(remoteID); remote["identity"] != "host:mcp.linear.example" || remote["source"] != "egress" || remote["auth"] != "unknown" || remote["agent_count"] != float64(1) {
		t.Fatalf("remote server = %v", remote)
	}

	// Posture findings: who uses what, before any decision.
	findings := func() map[string]string {
		t.Helper()
		rows, err := connection.Query(ctx, `SELECT finding.rule,agent.display_name,finding.status FROM zasp_risk_findings finding JOIN zasp_inventory_entities agent ON (agent.organization_id,agent.workspace_id,agent.environment_id,agent.id)=(finding.organization_id,finding.workspace_id,finding.environment_id,finding.agent_id)
 WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.source)=($1,$2,$3,'posture') AND finding.rule LIKE 'mcp\_%' ORDER BY finding.rule,agent.display_name`, scope...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		result := map[string]string{}
		for rows.Next() {
			var rule, agent, status string
			if err := rows.Scan(&rule, &agent, &status); err != nil {
				t.Fatal(err)
			}
			result[rule+" "+agent] = status
		}
		return result
	}
	refresh()
	// The agent's role may write to every DynamoDB table: production access.
	want := map[string]string{
		"mcp_server_unapproved support": "open", "mcp_server_unapproved bot": "open",
		"mcp_server_no_auth support":          "open",
		"mcp_execute_tool_production support": "open",
		"mcp_server_unpinned_package bot":     "open",
	}
	if got := findings(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("posture findings\n got %v\nwant %v", got, want)
	}

	// An agent whose platform reports the lowest content moderation level (a
	// Copilot Studio agent's attribute) has a finding, and loses it when the
	// level is raised.
	moderation := func(level string) string {
		t.Helper()
		if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=winning_attributes||jsonb_build_object('content_moderation',$5::text) WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, agentID, level); err != nil {
			t.Fatal(err)
		}
		refresh()
		var status string
		if err := connection.QueryRow(ctx, `SELECT COALESCE((SELECT status FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,source,rule,agent_id)=($1,$2,$3,'posture','agent_content_moderation_low',$4)),'none')`, organizationID, workspaceID, environmentID, agentID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if low, high := moderation("low"), moderation("high"); low != "open" || high != "resolved" {
		t.Fatalf("content moderation finding: low=%s high=%s", low, high)
	}

	// Skills, decided from what the collector recorded of the tree and of
	// CODEOWNERS: a skill that ships scripts in an agent with production
	// access, and a skill no code owner is named for. Nothing is said while
	// the collector could not establish either.
	skillFindings := func(attributes string) string {
		t.Helper()
		if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=$5::jsonb WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, skillID, attributes); err != nil {
			t.Fatal(err)
		}
		refresh()
		var listed string
		if err := connection.QueryRow(ctx, `SELECT COALESCE(string_agg(finding.rule||'='||finding.status,' ' ORDER BY finding.rule),'') FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.source,finding.agent_id)=($1,$2,$3,'posture',$4) AND finding.rule LIKE 'skill\_%'`, organizationID, workspaceID, environmentID, botID).Scan(&listed); err != nil {
			t.Fatal(err)
		}
		return listed
	}
	if got := skillFindings(`{"skill_kind":"skill"}`); got != "" {
		t.Fatalf("skill findings with nothing established = %q", got)
	}
	if got := skillFindings(`{"skill_kind":"skill","scripts":true,"ownership":"uncovered"}`); got != "skill_scripts_production=open skill_unowned=open" {
		t.Fatalf("skill findings = %q", got)
	}
	if got := skillFindings(`{"skill_kind":"skill","scripts":true,"ownership":"no_codeowners"}`); got != "skill_scripts_production=open skill_unowned=open" {
		t.Fatalf("skill findings without a CODEOWNERS file = %q", got)
	}
	if got := skillFindings(`{"skill_kind":"skill","scripts":false,"ownership":"covered"}`); got != "skill_scripts_production=resolved skill_unowned=resolved" {
		t.Fatalf("skill findings after the fix = %q", got)
	}
	// Both rules are evidence for framework controls, in SQL as in Go.
	var mappedSkillRules int
	if err := connection.QueryRow(ctx, `SELECT count(DISTINCT rule) FROM zasp_compliance_ai_rule_controls() WHERE rule IN('skill_scripts_production','skill_unowned','mcp_execute_tool_production','agent_content_moderation_low')`).Scan(&mappedSkillRules); err != nil || mappedSkillRules != 4 {
		t.Fatalf("WS5 rules in the SQL rule to control mapping = %d, %v", mappedSkillRules, err)
	}

	// Registry decisions, under the version the caller read.
	put := func(identityValue, status string, expected int64, sequence int) (map[string]any, error) {
		var payload []byte
		err := connection.QueryRow(ctx, `SELECT zasp_mcp_registry_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, organizationID, workspaceID, environmentID, identity.PrincipalID.String(), identityValue, status, "reviewed", expected,
			fmt.Sprintf("pid_7b0000b%d-0000-4000-8000-0000000000b%d", sequence, sequence), fmt.Sprintf("pid_7b0000c%d-0000-4000-8000-0000000000c%d", sequence, sequence)).Scan(&payload)
		var decoded map[string]any
		if err == nil {
			err = json.Unmarshal(payload, &decoded)
		}
		return decoded, err
	}
	approved, err := put("host:gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com", "approved", 0, 1)
	if err != nil || approved["status"] != "approved" || approved["version"] != float64(1) || approved["server_count"] != float64(1) {
		t.Fatalf("approve the gateway: %v %v", approved, err)
	}
	if _, err := put("host:gw-1.gateway.bedrock-agentcore.us-west-2.amazonaws.com", "blocked", 0, 2); err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("a stale version was accepted: %v", err)
	}
	if _, err := put("package:@acme/tracker-mcp", "blocked", 0, 3); err != nil {
		t.Fatalf("block the package: %v", err)
	}
	for _, refused := range []string{"gw-1", "host:", "host:a\nb", "unknown:x"} {
		if _, err := put(refused, "approved", 0, 4); err == nil {
			t.Fatalf("identity %q was accepted", refused)
		}
	}
	if _, err := put("host:mcp.linear.example", "allowed", 0, 4); err == nil {
		t.Fatal("an unknown status was accepted")
	}
	// The decision refreshed the findings in its own transaction: the
	// gateway is approved, the package is blocked, the remote host is still
	// unapproved for the function.
	want = map[string]string{
		"mcp_server_unapproved support": "resolved", "mcp_server_unapproved bot": "open",
		"mcp_server_blocked bot":              "open",
		"mcp_server_no_auth support":          "open",
		"mcp_execute_tool_production support": "open",
		"mcp_server_unpinned_package bot":     "open",
	}
	if got := findings(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("posture findings after the decisions\n got %v\nwant %v", got, want)
	}
	if got := server(gatewayID)["approval"]; got != "approved" {
		t.Fatalf("gateway approval = %v", got)
	}
	if got := server(stdioID)["approval"]; got != "blocked" {
		t.Fatalf("stdio approval = %v", got)
	}
	var registry []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_mcp_registry_json($1,$2,$3)`, scope...).Scan(&registry); err != nil || !strings.Contains(string(registry), `"identity": "package:@acme/tracker-mcp"`) || strings.Count(string(registry), `"identity"`) != 2 {
		t.Fatalf("registry = %s, %v", registry, err)
	}
	var audited int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_workflow_audit WHERE (organization_id,workspace_id,environment_id,operation,resource_kind,resource_id)=($1,$2,$3,'putMCPRegistryEntry','environment',$3)`, scope...).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("audited decisions = %d, %v", audited, err)
	}
	// Removing a decision returns the server to unapproved.
	if removed, err := put("package:@acme/tracker-mcp", "unapproved", 1, 5); err != nil || removed["status"] != "unapproved" || removed["version"] != float64(0) {
		t.Fatalf("remove the decision: %v %v", removed, err)
	}
	if got := findings(); got["mcp_server_blocked bot"] != "resolved" || got["mcp_server_unapproved bot"] != "open" {
		t.Fatalf("posture findings after removing the decision = %v", got)
	}

	// Attack paths. Through MCP: agent, gateway, execute tool, with the
	// ranked fixes. Through the role: agent, role, data store, walked by the
	// chain's own computation from the discovery finding on the store.
	paths := func() map[string]string {
		t.Helper()
		rows, err := connection.Query(ctx, `SELECT path.id,path.state,zasp_risk_attack_path_valid(path),(SELECT string_agg(node.node_id,'>' ORDER BY node.position) FROM zasp_risk_attack_path_nodes node WHERE (node.organization_id,node.workspace_id,node.environment_id,node.path_id)=(path.organization_id,path.workspace_id,path.environment_id,path.id))
 FROM zasp_risk_attack_paths path WHERE (path.organization_id,path.workspace_id,path.environment_id)=($1,$2,$3)`, scope...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		result := map[string]string{}
		for rows.Next() {
			var id, state, nodes string
			var valid bool
			if err := rows.Scan(&id, &state, &valid, &nodes); err != nil {
				t.Fatal(err)
			}
			if !valid || state != "observed" {
				t.Fatalf("path %s (%s) is not a valid observed path", nodes, state)
			}
			result[nodes] = id
		}
		return result
	}
	found := paths()
	toolPath, dataPath := found[agentID+">"+gatewayID+">"+toolID], found[agentID+">"+roleID+">"+storeID]
	if toolPath == "" {
		t.Fatalf("no path agent > MCP server > tool in %v", found)
	}
	if dataPath == "" {
		// The function runs as the same role; the walk keeps one path per
		// finding, the longest and then the first by node ids.
		dataPath = found[botID+">"+roleID+">"+storeID]
	}
	if dataPath == "" {
		t.Fatalf("no path agent > role > data store in %v", found)
	}
	for _, expected := range []string{agentID + ">" + gatewayID, botID + ">" + remoteID, botID + ">" + stdioID} {
		if found[expected] == "" {
			t.Fatalf("no path %s in %v", expected, found)
		}
	}
	var options string
	if err := connection.QueryRow(ctx, `SELECT string_agg(option_value.rank||':'||option_value.kind||':'||option_value.target_id,' ' ORDER BY option_value.rank) FROM zasp_risk_break_options option_value WHERE (option_value.organization_id,option_value.workspace_id,option_value.environment_id,option_value.path_id)=($1,$2,$3,$4)`,
		organizationID, workspaceID, environmentID, toolPath).Scan(&options); err != nil || options != "1:remove_node:"+gatewayID+" 2:enforce_policy:"+agentID+" 3:enforce_policy:"+toolID {
		t.Fatalf("break options of the tool path = %s, %v", options, err)
	}
	// Every open MCP finding names its path, and the path starts at the
	// finding's agent; the execute finding names the tool path.
	var linked, unlinked int
	var executePath string
	if err := connection.QueryRow(ctx, `SELECT
 count(*) FILTER(WHERE finding.path_id IS NOT NULL AND EXISTS(SELECT 1 FROM zasp_mcp_attack_paths owned JOIN zasp_risk_attack_path_nodes node ON (node.organization_id,node.workspace_id,node.environment_id,node.path_id)=(owned.organization_id,owned.workspace_id,owned.environment_id,owned.path_id)
   WHERE (owned.organization_id,owned.workspace_id,owned.environment_id,owned.path_id,owned.finding_id)=(finding.organization_id,finding.workspace_id,finding.environment_id,finding.path_id,finding.id) AND (node.position,node.node_id)=(1,finding.agent_id))),
 count(*) FILTER(WHERE finding.path_id IS NULL),
 COALESCE(max(finding.path_id) FILTER(WHERE finding.rule='mcp_execute_tool_production'),'')
 FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.source)=($1,$2,$3,'posture') AND finding.rule LIKE 'mcp\_%' AND finding.status IN('open','under_review','accepted')`, scope...).Scan(&linked, &unlinked, &executePath); err != nil || linked != 4 || unlinked != 0 || executePath != toolPath {
		t.Fatalf("findings linked to their path = %d, without = %d, execute path = %s (want %s), %v", linked, unlinked, executePath, toolPath, err)
	}
	// A resolved finding names none, and no other posture finding names one.
	var stray int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.source)=($1,$2,$3,'posture') AND finding.path_id IS NOT NULL AND (finding.status='resolved' OR finding.rule NOT LIKE 'mcp\_%')`, scope...).Scan(&stray); err != nil || stray != 0 {
		t.Fatalf("posture findings that should name no path = %d, %v", stray, err)
	}
	// A refresh that changes nothing keeps every path and finding, and their
	// versions.
	versions := func() string {
		var value string
		if err := connection.QueryRow(ctx, `SELECT (SELECT string_agg(id||':'||version,',' ORDER BY id) FROM zasp_risk_attack_paths WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3))||'|'||
 (SELECT string_agg(id||':'||version||':'||COALESCE(path_id,'-'),',' ORDER BY id) FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,source)=($1,$2,$3,'posture'))`, scope...).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := versions()
	refresh()
	if versions() != before {
		t.Fatal("an unchanged refresh changed an attack path")
	}
	// Blocking the gateway resolves nothing about the tool path (the agent
	// still uses it), but dismissing the agent removes its findings and paths.
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value,team_value,tags) VALUES($1,$2,$3,$4,'','','["not-an-agent"]'::jsonb)`, organizationID, workspaceID, environmentID, botID); err != nil {
		t.Fatal(err)
	}
	refresh()
	after := paths()
	if after[botID+">"+remoteID] != "" || after[botID+">"+stdioID] != "" || after[agentID+">"+gatewayID+">"+toolID] == "" {
		t.Fatalf("paths after dismissing the function = %v", after)
	}
	if got := findings(); got["mcp_server_unapproved bot"] != "resolved" || got["mcp_server_unpinned_package bot"] != "resolved" || got["mcp_execute_tool_production support"] != "open" {
		t.Fatalf("posture findings after dismissing the function = %v", got)
	}
	// The resolved findings no longer name a path, and no finding names a
	// path that is gone.
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.source)=($1,$2,$3,'posture') AND finding.path_id IS NOT NULL
 AND (finding.status='resolved' OR NOT EXISTS(SELECT 1 FROM zasp_risk_attack_paths path WHERE (path.organization_id,path.workspace_id,path.environment_id,path.id)=(finding.organization_id,finding.workspace_id,finding.environment_id,finding.path_id)))`, scope...).Scan(&stray); err != nil || stray != 0 {
		t.Fatalf("findings naming a missing path after the dismissal = %d, %v", stray, err)
	}

	// The API statements exist, are the API role's only way in, and refuse a
	// session without a current authorization proof.
	for statement, arguments := range map[string][]any{
		postgresMCPServerPageSQL:   {organizationID, workspaceID, environmentID, "", 50},
		postgresMCPRegistryPageSQL: {organizationID, workspaceID, environmentID},
		postgresAgentAccessSQL:     {organizationID, workspaceID, environmentID, agentID},
		postgresMCPRegistryPutSQL:  {organizationID, workspaceID, environmentID, identity.PrincipalID.String(), "host:mcp.linear.example", "approved", "", int64(0), "pid_7b0000d1-0000-4000-8000-0000000000d1", "pid_7b0000d2-0000-4000-8000-0000000000d2"},
	} {
		if _, err := connection.Exec(ctx, statement, arguments...); err == nil || !strings.Contains(err.Error(), "42501") && !strings.Contains(err.Error(), "authorization") && !strings.Contains(err.Error(), "read purpose") {
			t.Fatalf("%s without a proof: %v", statement, err)
		}
	}
	var grants int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_authorization80' AND p.proname IN('mcp_server_page','mcp_registry_page','mcp_registry_put','agent_access') AND p.prosecdef
 AND pg_get_userbyid(p.proowner)='zasp_discovery_authority' AND has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE') AND NOT has_function_privilege('public',p.oid,'EXECUTE')`).Scan(&grants); err != nil || grants != 4 {
		t.Fatalf("authorized MCP statements = %d, %v", grants, err)
	}
	var direct int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp\_mcp\_%' AND (has_function_privilege('zasp_discovery_api',p.oid,'EXECUTE') OR has_function_privilege('public',p.oid,'EXECUTE'))`).Scan(&direct); err != nil || direct != 0 {
		t.Fatalf("MCP functions the API role may call directly = %d, %v", direct, err)
	}
}

var _ = pgx.ErrNoRows
