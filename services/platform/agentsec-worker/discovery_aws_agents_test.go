package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// discoveryAgentSentinel is the value of every environment variable the
// stubs return. It must never leave the provider's answer.
const discoveryAgentSentinel = "sk-sentinel-DO-NOT-LEAK-7f3a9c"

// discoveryAgentRegionStub answers the three AI services for one region.
type discoveryAgentRegionStub struct {
	region string

	agents        []bedrockagenttypes.Agent
	listAgentsErr error
	getAgentErr   map[string]error

	runtimes        []bedrockagentcorecontrol.GetAgentRuntimeOutput
	listRuntimesErr error
	getRuntimeErr   map[string]error
	gateways        []agentcoretypes.GatewaySummary
	listGatewaysErr error

	// functions are name, role ARN and environment variable names.
	functions        []discoveryAgentFunction
	listFunctionsErr error
	pageSize         int
	// vpc is the VPC configuration of a function, by name.
	vpc map[string]*lambdatypes.VpcConfigResponse
}

type discoveryAgentFunction struct {
	name, role string
	env        []string
}

func (stub *discoveryAgentRegionStub) ListAgents(_ context.Context, input *bedrockagent.ListAgentsInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error) {
	if stub.listAgentsErr != nil {
		return nil, stub.listAgentsErr
	}
	start, end, next := discoveryAgentStubPage(input.NextToken, len(stub.agents), stub.pageSize)
	output := &bedrockagent.ListAgentsOutput{NextToken: next}
	for _, agent := range stub.agents[start:end] {
		output.AgentSummaries = append(output.AgentSummaries, bedrockagenttypes.AgentSummary{AgentId: agent.AgentId, AgentName: agent.AgentName, AgentStatus: agent.AgentStatus, Description: aws.String("summary " + discoveryAgentSentinel)})
	}
	return output, nil
}

func (stub *discoveryAgentRegionStub) GetAgent(_ context.Context, input *bedrockagent.GetAgentInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error) {
	if err := stub.getAgentErr[aws.ToString(input.AgentId)]; err != nil {
		return nil, err
	}
	for _, agent := range stub.agents {
		if aws.ToString(agent.AgentId) == aws.ToString(input.AgentId) {
			copied := agent
			copied.Instruction = aws.String("You are an agent. " + discoveryAgentSentinel)
			return &bedrockagent.GetAgentOutput{Agent: &copied}, nil
		}
	}
	return nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "no such agent"}
}

func (stub *discoveryAgentRegionStub) ListAgentRuntimes(_ context.Context, input *bedrockagentcorecontrol.ListAgentRuntimesInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error) {
	if stub.listRuntimesErr != nil {
		return nil, stub.listRuntimesErr
	}
	start, end, next := discoveryAgentStubPage(input.NextToken, len(stub.runtimes), stub.pageSize)
	output := &bedrockagentcorecontrol.ListAgentRuntimesOutput{NextToken: next}
	for _, runtime := range stub.runtimes[start:end] {
		output.AgentRuntimes = append(output.AgentRuntimes, agentcoretypes.AgentRuntime{AgentRuntimeArn: runtime.AgentRuntimeArn, AgentRuntimeId: runtime.AgentRuntimeId, AgentRuntimeName: runtime.AgentRuntimeName, Status: runtime.Status})
	}
	return output, nil
}

func (stub *discoveryAgentRegionStub) GetAgentRuntime(_ context.Context, input *bedrockagentcorecontrol.GetAgentRuntimeInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	if err := stub.getRuntimeErr[aws.ToString(input.AgentRuntimeId)]; err != nil {
		return nil, err
	}
	for _, runtime := range stub.runtimes {
		if aws.ToString(runtime.AgentRuntimeId) == aws.ToString(input.AgentRuntimeId) {
			copied := runtime
			copied.EnvironmentVariables = map[string]string{"OPENAI_API_KEY": discoveryAgentSentinel}
			return &copied, nil
		}
	}
	return nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "no such runtime"}
}

func (stub *discoveryAgentRegionStub) ListGateways(_ context.Context, input *bedrockagentcorecontrol.ListGatewaysInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error) {
	if stub.listGatewaysErr != nil {
		return nil, stub.listGatewaysErr
	}
	start, end, next := discoveryAgentStubPage(input.NextToken, len(stub.gateways), stub.pageSize)
	return &bedrockagentcorecontrol.ListGatewaysOutput{Items: append([]agentcoretypes.GatewaySummary(nil), stub.gateways[start:end]...), NextToken: next}, nil
}

func (stub *discoveryAgentRegionStub) ListFunctions(_ context.Context, input *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if stub.listFunctionsErr != nil {
		return nil, stub.listFunctionsErr
	}
	start, end, next := discoveryAgentStubPage(input.Marker, len(stub.functions), stub.pageSize)
	output := &lambda.ListFunctionsOutput{NextMarker: next}
	for _, function := range stub.functions[start:end] {
		configuration := lambdatypes.FunctionConfiguration{FunctionArn: aws.String("arn:aws:lambda:" + stub.region + ":123456789012:function:" + function.name), FunctionName: aws.String(function.name), Role: aws.String(function.role), State: lambdatypes.StateActive, Description: aws.String("described " + discoveryAgentSentinel)}
		if len(function.env) > 0 {
			configuration.Environment = &lambdatypes.EnvironmentResponse{Variables: map[string]string{}}
			for _, name := range function.env {
				configuration.Environment.Variables[name] = discoveryAgentSentinel
			}
		}
		configuration.VpcConfig = stub.vpc[function.name]
		output.Functions = append(output.Functions, configuration)
	}
	return output, nil
}

func discoveryAgentStubPage(token *string, total, size int) (int, int, *string) {
	if size < 1 {
		size = 50
	}
	start, _ := strconv.Atoi(aws.ToString(token))
	end := min(start+size, total)
	if end < total {
		return start, end, aws.String(strconv.Itoa(end))
	}
	return start, end, nil
}

// An account with no AI service content, for tests that are not about agents.
func emptyDiscoveryBedrockAgents(region string, _ aws.Credentials) (discoveryAWSBedrockAgentAPI, error) {
	return &discoveryAgentRegionStub{region: region}, nil
}

func emptyDiscoveryAgentCore(region string, _ aws.Credentials) (discoveryAWSAgentCoreAPI, error) {
	return &discoveryAgentRegionStub{region: region}, nil
}

func emptyDiscoveryLambda(region string, _ aws.Credentials) (discoveryAWSLambdaAPI, error) {
	return &discoveryAgentRegionStub{region: region}, nil
}

// discoveryAgentIAMStub is the inventory IAM stub with one role, "reader",
// whose managed policy allows calling a Bedrock model.
type discoveryAgentIAMStub struct{ discoveryInventoryIAMStub }

func (*discoveryAgentIAMStub) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	document := url.QueryEscape(`{"Statement":[{"Action":["s3:GetObject","bedrock:InvokeModel"],"Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}`)
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: &document, VersionId: aws.String("v1")}}, nil
}

const (
	discoveryAgentReaderRole = "arn:aws:iam::123456789012:role/reader"
	discoveryAgentPlainRole  = "arn:aws:iam::123456789012:role/plain"
)

func discoveryAgentFactory(regions map[string]*discoveryAgentRegionStub) discoveryAWSInventoryFactory {
	stub := func(region string) *discoveryAgentRegionStub {
		if found := regions[region]; found != nil {
			found.region = region
			return found
		}
		return &discoveryAgentRegionStub{region: region}
	}
	return discoveryAWSInventoryFactory{
		Identity: func(string, aws.Credentials) (discoveryCallerIdentityAPI, error) {
			return &discoveryCallerIdentityStub{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp/session")}}, nil
		},
		IAM: func(string, aws.Credentials) (discoveryAWSIAMAPI, error) { return &discoveryAgentIAMStub{}, nil },
		EC2: func(region string, _ aws.Credentials) (discoveryAWSEC2API, error) {
			return &discoveryInventoryEC2Stub{region: region}, nil
		},
		BedrockAgent: func(region string, _ aws.Credentials) (discoveryAWSBedrockAgentAPI, error) { return stub(region), nil },
		AgentCore:    func(region string, _ aws.Credentials) (discoveryAWSAgentCoreAPI, error) { return stub(region), nil },
		Lambda:       func(region string, _ aws.Credentials) (discoveryAWSLambdaAPI, error) { return stub(region), nil },
	}
}

func discoveryAgentStubAgent(region, id, name, role string) bedrockagenttypes.Agent {
	return bedrockagenttypes.Agent{AgentArn: aws.String("arn:aws:bedrock:" + region + ":123456789012:agent/" + id), AgentId: aws.String(id), AgentName: aws.String(name), AgentResourceRoleArn: aws.String(role), AgentStatus: bedrockagenttypes.AgentStatusPrepared, FoundationModel: aws.String("anthropic.claude-sonnet")}
}

func discoveryAgentStubRuntime(region, id, name, role string) bedrockagentcorecontrol.GetAgentRuntimeOutput {
	return bedrockagentcorecontrol.GetAgentRuntimeOutput{AgentRuntimeArn: aws.String("arn:aws:bedrock-agentcore:" + region + ":123456789012:runtime/" + id), AgentRuntimeId: aws.String(id), AgentRuntimeName: aws.String(name), RoleArn: aws.String(role), Status: agentcoretypes.AgentRuntimeStatusReady}
}

// The mixed account the tests share: us-east-1 has a Bedrock agent with a
// role and three functions; us-west-2 has an AgentCore runtime and gateway.
func discoveryAgentMixedAccount() map[string]*discoveryAgentRegionStub {
	return map[string]*discoveryAgentRegionStub{
		"us-east-1": {
			agents: []bedrockagenttypes.Agent{discoveryAgentStubAgent("us-east-1", "AGENT12345", "support", discoveryAgentReaderRole)},
			functions: []discoveryAgentFunction{
				{name: "bot", role: discoveryAgentPlainRole, env: []string{"OPENAI_API_KEY", "DATABASE_URL"}},
				{name: "invoker", role: discoveryAgentReaderRole},
				{name: "plain", role: discoveryAgentPlainRole, env: []string{"DATABASE_URL", "LOG_LEVEL"}},
			},
		},
		"us-west-2": {
			runtimes: []bedrockagentcorecontrol.GetAgentRuntimeOutput{discoveryAgentStubRuntime("us-west-2", "researcher-AbCdEfGhIj", "researcher", discoveryAgentReaderRole)},
			gateways: []agentcoretypes.GatewaySummary{{GatewayId: aws.String("tools-abcdefghij"), Name: aws.String("tools"), Status: agentcoretypes.GatewayStatusReady, Description: aws.String("gateway " + discoveryAgentSentinel)}},
		},
	}
}

const discoveryAgentMixedSource = `{"account_id":"123456789012",` +
	`"bedrock_agents":[{"agent_id":"AGENT12345","arn":"arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345","model":"anthropic.claude-sonnet","name":"support","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/reader","status":"PREPARED"}],` +
	// The reader role's policy allows s3:GetObject on every resource: the
	// role reaches every bucket, which is a data store with a check on it.
	`"checks":[{"arn":"arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345","check":"agent_guardrail_missing"},{"arn":"arn:aws:s3:::*","check":"agent_data_service_wide_access"}],` +
	`"data_access":[{"access":"read","arn":"arn:aws:s3:::*","role_arn":"arn:aws:iam::123456789012:role/reader","scope":"service","service":"s3"}],` +
	`"gateways":[{"arn":"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/tools-abcdefghij","gateway_id":"tools-abcdefghij","name":"tools","region":"us-west-2","status":"READY"}],` +
	`"lambda_functions":[{"arn":"arn:aws:lambda:us-east-1:123456789012:function:bot","name":"bot","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/plain","signals":["env:openai"],"state":"Active"},` +
	`{"arn":"arn:aws:lambda:us-east-1:123456789012:function:invoker","name":"invoker","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/reader","signals":["iam:bedrock_invoke_model"],"state":"Active"}],` +
	`"runtimes":[{"arn":"arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/researcher-AbCdEfGhIj","name":"researcher","region":"us-west-2","role_arn":"arn:aws:iam::123456789012:role/reader","runtime_id":"researcher-AbCdEfGhIj","status":"READY"}],` +
	`"services":[{"service":"bedrock-agent","status":"collected"},{"service":"bedrock-agentcore","status":"collected"},{"service":"lambda","status":"collected"}]}`

var discoveryAgentTestClock = func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }

func readDiscoveryAgentInventory(t *testing.T, regions map[string]*discoveryAgentRegionStub) (*discoveryAWSCollectionInventoryCaller, awsdiscovery.CollectionInventory, error) {
	t.Helper()
	caller, err := newDiscoveryAWSCollectionInventoryCaller(discoveryAgentFactory(regions), discoveryAgentTestClock)
	if err != nil {
		t.Fatal(err)
	}
	credential := mustDiscoveryAWSCredentialEnvelope(t, discoveryAgentTestClock().Add(15*time.Minute))
	inventory, err := caller.GetCollectionInventory(context.Background(), credential)
	clear(credential)
	return caller, inventory, err
}

// discoveryAgentAnalyzerStub answers the IAM phase with the one role of the
// inventory IAM stub and the posture phase with no finding.
type discoveryAgentAnalyzerStub struct{}

func (*discoveryAgentAnalyzerStub) CheckCollectionReadiness(context.Context) error { return nil }

func (*discoveryAgentAnalyzerStub) Collect(_ context.Context, request awsdiscovery.CollectionSecurityRequest, _ []byte) (awsdiscovery.CollectionSecurityResult, error) {
	result := json.RawMessage(`{"findings":[],"version":"5.39.1"}`)
	if request.Mode == awsdiscovery.SecurityModeCartographyAWS {
		result = json.RawMessage(`{"policies":[],"roles":[{"arn":"arn:aws:iam::123456789012:role/reader","name":"reader","trusted_role_arns":[]}],"version":"0.139.1"}`)
	}
	return awsdiscovery.CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: result}, nil
}

// runDiscoveryAgentPages runs the five pages of one collection against the
// worker's inventory caller.
func runDiscoveryAgentPages(t *testing.T, caller awsdiscovery.CollectionInventoryCaller) []awsdiscovery.CollectionPage {
	t.Helper()
	binding := discoveryAWSInventoryTestBinding(t, "pid_61000006-0000-4000-8000-000000000006")
	api, err := awsdiscovery.NewInventoryCollectionAPI(caller, &discoveryAgentAnalyzerStub{}, awsdiscovery.CollectionInventoryAuthority{Scope: binding.Scope, IntegrationID: binding.IntegrationID, ConnectionID: binding.ConnectionID, JobID: binding.JobID, Attempt: 1, ObservedAt: discoveryAgentTestClock()}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := awsdiscovery.CollectionPageRequest{Provider: collection.ProviderAWS, Subject: binding.Subject, Page: 1, RemainingItems: 10_000, RemainingRelationships: 20_000, RemainingFindings: 100, RemainingBytes: 16 << 20}
	pages := make([]awsdiscovery.CollectionPage, 0, 5)
	for page := 1; page <= 5; page++ {
		request.Page = page
		credential := mustDiscoveryAWSCredentialEnvelope(t, discoveryAgentTestClock().Add(15*time.Minute))
		result, err := api.FetchCollectionPage(context.Background(), credential, request)
		clear(credential)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if result.Complete != (page == 5) {
			t.Fatalf("page %d complete = %v", page, result.Complete)
		}
		pages = append(pages, result)
		request.Cursor = result.Cursor
	}
	return pages
}

func discoveryAgentPageEntities(t *testing.T, page awsdiscovery.CollectionPage) map[string]map[string]any {
	t.Helper()
	entities := map[string]map[string]any{}
	for _, raw := range page.Entities {
		var entity map[string]any
		if err := json.Unmarshal(raw, &entity); err != nil {
			t.Fatal(err)
		}
		entities[entity["source_native_id"].(string)] = entity
	}
	return entities
}

func TestAWSInventoryReadsAgentsOfAMixedAccount(t *testing.T) {
	t.Parallel()
	caller, inventory, err := readDiscoveryAgentInventory(t, discoveryAgentMixedAccount())
	if err != nil {
		t.Fatal(err)
	}
	// The plain function is not in the source; the two inferred ones are.
	if string(inventory.AgentSource) != discoveryAgentMixedSource {
		t.Fatalf("agent source =\n%s\nwant\n%s", inventory.AgentSource, discoveryAgentMixedSource)
	}
	pages := runDiscoveryAgentPages(t, caller)
	entities := discoveryAgentPageEntities(t, pages[3])
	kinds := map[string]string{}
	for native, entity := range entities {
		kinds[native] = entity["kind"].(string)
	}
	wantKinds := map[string]string{
		"aws:bedrock-agent": "aws_service", "aws:bedrock-agentcore": "aws_service", "aws:lambda": "aws_service",
		"arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345":                        "aws_bedrock_agent",
		"arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/researcher-AbCdEfGhIj": "aws_agentcore_runtime",
		"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/tools-abcdefghij":      "aws_agentcore_gateway",
		"arn:aws:lambda:us-east-1:123456789012:function:bot":                             "aws_inferred_agent",
		"arn:aws:lambda:us-east-1:123456789012:function:invoker":                         "aws_inferred_agent",
		"arn:aws:s3:::*": "aws_data_store",
	}
	if !reflect.DeepEqual(kinds, wantKinds) {
		t.Fatalf("agent page kinds = %v", kinds)
	}
	// Identity edges: the agent, the runtime and the invoker use the role the
	// IAM phase emitted. The bot's role is not in the inventory.
	var identities []string
	for _, raw := range pages[3].Relationships {
		var relationship struct {
			Kind           string `json:"kind"`
			SourceNativeID string `json:"source_native_id"`
		}
		if err := json.Unmarshal(raw, &relationship); err != nil {
			t.Fatal(err)
		}
		if relationship.Kind == "uses_identity" {
			identities = append(identities, relationship.SourceNativeID)
		}
	}
	if len(pages[3].Relationships) != 13 || len(identities) != 3 || strings.Contains(strings.Join(identities, " "), "function:bot") || strings.Contains(strings.Join(identities, " "), "role/plain") {
		t.Fatalf("relationships = %d, identity edges = %v", len(pages[3].Relationships), identities)
	}
	// The run reads the account once: the later pages resume what the first
	// page read, the agent source included.
	held, found := caller.retained.find(func() awsdiscovery.InventoryBinding {
		binding := discoveryAWSInventoryTestBinding(t, "pid_61000006-0000-4000-8000-000000000006")
		for key := range caller.retained.entries {
			binding.Digest = key.Digest
		}
		return binding
	}())
	if !found || !bytes.Equal(held.agents, inventory.AgentSource) {
		t.Fatalf("held agent source = %s (found %v)", held.agents, found)
	}
}

// The provider answers carry environment variable values, an agent
// instruction and descriptions. None of them reaches the source or a page,
// and no environment variable name does either.
func TestAWSInventoryNeverKeepsEnvironmentValuesOrInstructions(t *testing.T) {
	t.Parallel()
	caller, inventory, err := readDiscoveryAgentInventory(t, discoveryAgentMixedAccount())
	if err != nil {
		t.Fatal(err)
	}
	everything := [][]byte{inventory.AgentSource, inventory.CartographySource, inventory.ProwlerSource}
	for _, page := range runDiscoveryAgentPages(t, caller) {
		everything = append(everything, page.Raw)
		everything = append(everything, []byte(page.Cursor.Value))
		for _, list := range [][]json.RawMessage{page.Entities, page.Relationships, page.Findings} {
			for _, raw := range list {
				everything = append(everything, raw)
			}
		}
	}
	for _, held := range caller.retained.entries {
		everything = append(everything, held.agents, held.cartography, held.prowler)
	}
	for _, forbidden := range []string{discoveryAgentSentinel, "sentinel", "OPENAI_API_KEY", "DATABASE_URL", "LOG_LEVEL", "You are an agent", "described", "summary"} {
		for _, document := range everything {
			if bytes.Contains(document, []byte(forbidden)) {
				t.Fatalf("%q leaked into %s", forbidden, document)
			}
		}
	}
	if len(everything) < 20 || !bytes.Contains(inventory.AgentSource, []byte(`"signals":["env:openai"]`)) {
		t.Fatalf("nothing was checked: %d documents", len(everything))
	}
}

func discoveryAgentAPIError(status int, code, message string) error {
	return &smithy.OperationError{ServiceID: "Bedrock Agent", OperationName: "ListAgents", Err: &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}}, Err: &smithy.GenericAPIError{Code: code, Message: message}}}
}

func TestClassifyAWSAgentFailure(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"access denied exception":   {discoveryAgentAPIError(403, "AccessDeniedException", "User: arn:aws:sts::123456789012:assumed-role/zasp/session is not authorized to perform: bedrock:ListAgents"), awsdiscovery.AgentServiceAccessDenied},
		"access denied":             {discoveryAgentAPIError(403, "AccessDenied", "denied"), awsdiscovery.AgentServiceAccessDenied},
		"unauthorized operation":    {discoveryAgentAPIError(403, "UnauthorizedOperation", "denied"), awsdiscovery.AgentServiceAccessDenied},
		"unknown operation":         {discoveryAgentAPIError(400, "UnknownOperationException", "unknown"), awsdiscovery.AgentServiceUnavailable},
		"not implemented status":    {discoveryAgentAPIError(501, "InternalFailure", "whatever"), awsdiscovery.AgentServiceUnavailable},
		"route not found":           {discoveryAgentAPIError(404, "UnknownError", ""), awsdiscovery.AgentServiceUnavailable},
		"emulator pro feature":      {discoveryAgentAPIError(500, "InternalFailure", "API for service 'bedrock-agent' not yet implemented or pro feature - please check the docs"), awsdiscovery.AgentServiceUnavailable},
		"emulator not emulated":     {discoveryAgentAPIError(500, "InternalFailure", "The API for service 'bedrock-agentcore-control' is either not included in your current license plan or has not yet been emulated by LocalStack."), awsdiscovery.AgentServiceUnavailable},
		"emulator operation":        {discoveryAgentAPIError(500, "NotImplementedError", "The ListGateways action has not been implemented"), awsdiscovery.AgentServiceUnavailable},
		"no endpoint for region":    {&smithy.OperationError{ServiceID: "Bedrock AgentCore Control", OperationName: "ListAgentRuntimes", Err: fmt.Errorf("failed to resolve service endpoint, %w", errors.New("endpoint rule error, Invalid Configuration: Missing Region"))}, awsdiscovery.AgentServiceUnavailable},
		"endpoint not found":        {&aws.EndpointNotFoundError{Err: errors.New("no endpoint")}, awsdiscovery.AgentServiceUnavailable},
		"no such host":              {&smithy.OperationError{ServiceID: "Bedrock AgentCore Control", OperationName: "ListAgentRuntimes", Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "bedrock-agentcore-control.eu-south-2.amazonaws.com", IsNotFound: true}}}, awsdiscovery.AgentServiceUnavailable},
		"throttling":                {discoveryAgentAPIError(429, "ThrottlingException", "Rate exceeded"), ""},
		"server error":              {discoveryAgentAPIError(500, "InternalServerException", "internal error"), ""},
		"service unavailable":       {discoveryAgentAPIError(503, "ServiceUnavailableException", "try again"), ""},
		"expired token":             {discoveryAgentAPIError(403, "ExpiredTokenException", "expired"), ""},
		"unrecognized client":       {discoveryAgentAPIError(403, "UnrecognizedClientException", "invalid token"), ""},
		"validation":                {discoveryAgentAPIError(400, "ValidationException", "bad"), ""},
		"temporary name resolution": {&net.DNSError{Err: "server misbehaving", IsTemporary: true}, ""},
		"timeout":                   {context.DeadlineExceeded, ""},
		"connection reset":          {errors.New("read: connection reset by peer"), ""},
	} {
		got, err := classifyDiscoveryAWSAgentFailure(context.Background(), test.err)
		if got != test.want || (test.want == "") != errors.Is(err, awsdiscovery.ErrDenied) {
			t.Errorf("%s: classified %q, %v; want %q", name, got, err, test.want)
		}
	}
	// A cancelled read is never an answer about the service.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := classifyDiscoveryAWSAgentFailure(cancelled, discoveryAgentAPIError(403, "AccessDeniedException", "denied")); got != "" || !errors.Is(err, awsdiscovery.ErrDenied) {
		t.Fatalf("cancelled: %q, %v", got, err)
	}
}

func TestAWSInventoryReportsDeniedAndUnavailableAIServicesAndStillCompletes(t *testing.T) {
	t.Parallel()
	denied := discoveryAgentAPIError(403, "AccessDeniedException", "User is not authorized to perform this action "+discoveryAgentSentinel)
	unavailable := discoveryAgentAPIError(501, "InternalFailure", "API for service not yet implemented or pro feature "+discoveryAgentSentinel)
	type statuses struct{ bedrock, agentCore, lambda string }
	const collected, refused, absent = awsdiscovery.AgentServiceCollected, awsdiscovery.AgentServiceAccessDenied, awsdiscovery.AgentServiceUnavailable
	for name, test := range map[string]struct {
		change func(map[string]*discoveryAgentRegionStub)
		want   statuses
		// native ids the agents page must and must not carry
		present, missing []string
	}{
		"an old read role: every AI service refused": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				for _, region := range regions {
					region.listAgentsErr, region.listRuntimesErr, region.listGatewaysErr, region.listFunctionsErr = denied, denied, denied, denied
				}
			},
			want:    statuses{refused, refused, refused},
			missing: []string{"agent/AGENT12345", "runtime/researcher-AbCdEfGhIj", "gateway/tools-abcdefghij", "function:bot"},
		},
		"an emulator: Bedrock and AgentCore not served, Lambda read": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				for _, region := range regions {
					region.listAgentsErr, region.listRuntimesErr, region.listGatewaysErr = unavailable, unavailable, unavailable
				}
			},
			want:    statuses{absent, absent, collected},
			present: []string{"function:bot", "function:invoker"},
			missing: []string{"agent/AGENT12345", "runtime/researcher-AbCdEfGhIj", "gateway/tools-abcdefghij"},
		},
		"refused in one region, collected in the other": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				regions["us-west-2"].listAgentsErr, regions["us-west-2"].listFunctionsErr = denied, denied
			},
			want:    statuses{refused, collected, refused},
			present: []string{"agent/AGENT12345", "runtime/researcher-AbCdEfGhIj", "gateway/tools-abcdefghij", "function:bot", "function:invoker"},
		},
		"AgentCore not in one region, refused in the other: refused wins": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				regions["us-east-1"].listRuntimesErr = unavailable
				regions["us-west-2"].listRuntimesErr, regions["us-west-2"].listGatewaysErr = denied, denied
			},
			want:    statuses{collected, refused, collected},
			present: []string{"agent/AGENT12345"},
			missing: []string{"runtime/researcher-AbCdEfGhIj", "gateway/tools-abcdefghij"},
		},
		"AgentCore not in one region, collected in the other: the account has it": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				regions["us-east-1"].listRuntimesErr = unavailable
			},
			want:    statuses{collected, collected, collected},
			present: []string{"runtime/researcher-AbCdEfGhIj", "gateway/tools-abcdefghij"},
		},
		"runtimes listed, gateways refused": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				regions["us-west-2"].listGatewaysErr = denied
			},
			want:    statuses{collected, refused, collected},
			present: []string{"runtime/researcher-AbCdEfGhIj"},
			missing: []string{"gateway/tools-abcdefghij"},
		},
		"agents listed, their description refused: kept without a role": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				regions["us-east-1"].getAgentErr = map[string]error{"AGENT12345": denied}
				regions["us-west-2"].getRuntimeErr = map[string]error{"researcher-AbCdEfGhIj": denied}
			},
			want:    statuses{refused, refused, collected},
			present: []string{"agent/AGENT12345", "runtime/researcher-AbCdEfGhIj", "gateway/tools-abcdefghij"},
		},
		"an agent deleted between the list and its description": {
			change: func(regions map[string]*discoveryAgentRegionStub) {
				regions["us-east-1"].getAgentErr = map[string]error{"AGENT12345": discoveryAgentAPIError(404, "ResourceNotFoundException", "gone")}
			},
			want:    statuses{collected, collected, collected},
			present: []string{"runtime/researcher-AbCdEfGhIj"},
			missing: []string{"agent/AGENT12345"},
		},
	} {
		regions := discoveryAgentMixedAccount()
		test.change(regions)
		caller, inventory, err := readDiscoveryAgentInventory(t, regions)
		if err != nil {
			t.Fatalf("%s: the inventory read failed: %v", name, err)
		}
		// Nothing of the provider's error text is kept.
		if bytes.Contains(inventory.AgentSource, []byte("sentinel")) || bytes.Contains(inventory.AgentSource, []byte("authorized")) || bytes.Contains(inventory.AgentSource, []byte("implemented")) {
			t.Fatalf("%s: error text in the source: %s", name, inventory.AgentSource)
		}
		pages := runDiscoveryAgentPages(t, caller)
		entities := discoveryAgentPageEntities(t, pages[3])
		got := statuses{}
		for native, status := range map[string]*string{"aws:bedrock-agent": &got.bedrock, "aws:bedrock-agentcore": &got.agentCore, "aws:lambda": &got.lambda} {
			entity := entities[native]
			if entity == nil || entity["kind"] != "aws_service" {
				t.Fatalf("%s: no service entity %s", name, native)
			}
			*status, _ = entity["attributes"].(map[string]any)["status"].(string)
		}
		if got != test.want {
			t.Fatalf("%s: statuses = %+v, want %+v", name, got, test.want)
		}
		natives := make([]string, 0, len(entities))
		for native := range entities {
			natives = append(natives, native)
		}
		joined := strings.Join(natives, " ")
		for _, fragment := range test.present {
			if !strings.Contains(joined, fragment) {
				t.Fatalf("%s: %s was not emitted: %s", name, fragment, joined)
			}
		}
		for _, fragment := range test.missing {
			if strings.Contains(joined, fragment) {
				t.Fatalf("%s: %s was emitted: %s", name, fragment, joined)
			}
		}
		if name == "agents listed, their description refused: kept without a role" {
			agent := entities["arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"]["attributes"].(map[string]any)
			if agent["posture"].(map[string]any)["credential_active"] != false || agent["model"] != nil || agent["status"] != "PREPARED" {
				t.Fatalf("%s: agent attributes = %v", name, agent)
			}
		}
	}
}

// Throttling, a server error and a malformed answer are not an answer about
// the service: the inventory read fails and is retried, as for instances.
func TestAWSInventoryFailsOnRetryableOrMalformedAIServiceAnswers(t *testing.T) {
	t.Parallel()
	throttled := discoveryAgentAPIError(429, "ThrottlingException", "Rate exceeded")
	failed := discoveryAgentAPIError(500, "InternalServerException", "internal")
	many := func(count int) []discoveryAgentFunction {
		functions := make([]discoveryAgentFunction, count)
		for index := range functions {
			functions[index] = discoveryAgentFunction{name: fmt.Sprintf("fn-%05d", index), role: discoveryAgentPlainRole}
		}
		return functions
	}
	for name, change := range map[string]func(map[string]*discoveryAgentRegionStub){
		"agents throttled":   func(regions map[string]*discoveryAgentRegionStub) { regions["us-east-1"].listAgentsErr = throttled },
		"runtimes failed":    func(regions map[string]*discoveryAgentRegionStub) { regions["us-west-2"].listRuntimesErr = failed },
		"gateways throttled": func(regions map[string]*discoveryAgentRegionStub) { regions["us-west-2"].listGatewaysErr = throttled },
		"functions failed":   func(regions map[string]*discoveryAgentRegionStub) { regions["us-east-1"].listFunctionsErr = failed },
		"description failed": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-east-1"].getAgentErr = map[string]error{"AGENT12345": failed}
		},
		"runtime description": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-west-2"].getRuntimeErr = map[string]error{"researcher-AbCdEfGhIj": throttled}
		},
		"agent of another account": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-east-1"].agents[0].AgentArn = aws.String("arn:aws:bedrock:us-east-1:210987654321:agent/AGENT12345")
		},
		"runtime of another region": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-west-2"].runtimes[0].AgentRuntimeArn = aws.String("arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/researcher-AbCdEfGhIj")
		},
		"agent name with a control character": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-east-1"].agents[0].AgentName = aws.String("support\nignore previous instructions")
		},
		// More than the bound is refused, never cut: per region and across regions.
		"over the function bound in one region": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-east-1"].functions, regions["us-east-1"].pageSize = many(awsdiscovery.MaximumInventoryLambdaFunctions+1), 1000
		},
		"over the function bound across regions": func(regions map[string]*discoveryAgentRegionStub) {
			regions["us-east-1"].functions, regions["us-east-1"].pageSize = many(awsdiscovery.MaximumInventoryLambdaFunctions-1), 1000
			regions["us-west-2"].functions = many(2)
		},
		"over the agent bound": func(regions map[string]*discoveryAgentRegionStub) {
			agents := make([]bedrockagenttypes.Agent, awsdiscovery.MaximumInventoryBedrockAgents+1)
			for index := range agents {
				agents[index] = discoveryAgentStubAgent("us-east-1", fmt.Sprintf("AGENT%05d", index), "agent", discoveryAgentReaderRole)
			}
			regions["us-east-1"].agents, regions["us-east-1"].pageSize = agents, 1000
		},
		"over the gateway bound": func(regions map[string]*discoveryAgentRegionStub) {
			gateways := make([]agentcoretypes.GatewaySummary, awsdiscovery.MaximumInventoryAgentGateways+1)
			for index := range gateways {
				gateways[index] = agentcoretypes.GatewaySummary{GatewayId: aws.String(fmt.Sprintf("gw-%05d", index)), Name: aws.String("gw")}
			}
			regions["us-west-2"].gateways, regions["us-west-2"].pageSize = gateways, 1000
		},
	} {
		regions := discoveryAgentMixedAccount()
		change(regions)
		if _, inventory, err := readDiscoveryAgentInventory(t, regions); !errors.Is(err, awsdiscovery.ErrDenied) || len(inventory.AgentSource) != 0 || len(inventory.CartographySource) != 0 {
			t.Fatalf("%s: err = %v, source = %s", name, err, inventory.AgentSource)
		}
	}
	// The bound itself is read, over many provider pages.
	regions := discoveryAgentMixedAccount()
	regions["us-east-1"].functions = append(many(awsdiscovery.MaximumInventoryLambdaFunctions-1), discoveryAgentFunction{name: "bot", role: discoveryAgentPlainRole, env: []string{"ANTHROPIC_API_KEY"}})
	_, inventory, err := readDiscoveryAgentInventory(t, regions)
	if err != nil || !bytes.Contains(inventory.AgentSource, []byte(`"lambda_functions":[{"arn":"arn:aws:lambda:us-east-1:123456789012:function:bot","name":"bot","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/plain","signals":["env:anthropic"],"state":"Active"}],`)) {
		t.Fatalf("at the bound: err = %v, source = %.400s", err, inventory.AgentSource)
	}
}

func TestAWSRoleModelActionsReadOnlyAllowedNamedActions(t *testing.T) {
	t.Parallel()
	statement := func(text string) any {
		var decoded any
		if err := json.Unmarshal([]byte(text), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	role := func(name string, statements ...string) discoveryAWSNativeRole {
		list := make([]any, 0, len(statements))
		for _, text := range statements {
			list = append(list, statement(text))
		}
		return discoveryAWSNativeRole{ARN: "arn:aws:iam::123456789012:role/" + name, ManagedPolicies: map[string][]any{"arn:aws:iam::123456789012:policy/" + name: list}}
	}
	got := discoveryAWSRoleModelActions([]discoveryAWSNativeRole{
		role("string-action", `{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"*"}`),
		role("array-action", `{"Effect":"Allow","Action":["s3:GetObject","bedrock:InvokeAgent","bedrock-agentcore:Invoke*"]}`),
		role("service-wildcard", `{"Effect":"Allow","Action":"bedrock:*"}`),
		role("sagemaker", `{"Effect":"Allow","Action":["sagemaker:InvokeEndpoint"]}`),
		role("denied", `{"Effect":"Deny","Action":"bedrock:InvokeModel"}`),
		role("not-action", `{"Effect":"Allow","NotAction":"bedrock:InvokeModel"}`),
		role("administrator", `{"Effect":"Allow","Action":"*"}`, `{"Effect":"Allow","Action":["*:*","*:Invoke*"]}`),
		role("unrelated", `{"Effect":"Allow","Action":["ec2:DescribeInstances","bedrock:ListAgents"]}`),
		role("malformed", `"Allow"`, `{"Effect":"Allow","Action":7}`, `{"Effect":"Allow","Action":[7,null,{"a":"bedrock:InvokeModel"}]}`, `{"Action":"bedrock:InvokeModel"}`),
	})
	want := map[string][]string{
		"arn:aws:iam::123456789012:role/string-action":    {"bedrock:InvokeModel"},
		"arn:aws:iam::123456789012:role/array-action":     {"bedrock-agentcore:Invoke*", "bedrock:InvokeAgent"},
		"arn:aws:iam::123456789012:role/service-wildcard": {"bedrock:*"},
		"arn:aws:iam::123456789012:role/sagemaker":        {"sagemaker:InvokeEndpoint"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("role actions = %v", got)
	}
}

// One weak sign is not an agent; a weak sign in the environment and a weak
// grant on the role together are.
func TestAWSLambdaInferenceNeedsEnoughEvidence(t *testing.T) {
	t.Parallel()
	actions := map[string][]string{discoveryAgentReaderRole: {"sagemaker:InvokeEndpoint"}}
	stub := &discoveryAgentRegionStub{region: "us-east-1", pageSize: 2, functions: []discoveryAgentFunction{
		{name: "weak-env", role: discoveryAgentPlainRole, env: []string{"OPENAI_BASE_URL"}},
		{name: "weak-role", role: discoveryAgentReaderRole},
		{name: "weak-both", role: discoveryAgentReaderRole, env: []string{"OPENAI_BASE_URL"}},
		{name: "strong-prefix", role: discoveryAgentPlainRole, env: []string{"MCP_SERVER_URL"}},
		{name: "no-environment", role: discoveryAgentPlainRole},
	}}
	functions, scanned, status, err := collectDiscoveryAWSLambdaAgents(context.Background(), stub, "123456789012", "us-east-1", actions, nil, nil)
	if err != nil || scanned != 5 || status != awsdiscovery.AgentServiceCollected || len(functions) != 2 {
		t.Fatalf("functions = %#v, scanned %d, %s, %v", functions, scanned, status, err)
	}
	if functions[0].Name != "strong-prefix" || !reflect.DeepEqual(functions[0].Signals, []string{"env:mcp"}) || functions[1].Name != "weak-both" || !reflect.DeepEqual(functions[1].Signals, []string{"env:openai", "iam:sagemaker_invoke"}) {
		t.Fatalf("functions = %#v", functions)
	}
}
