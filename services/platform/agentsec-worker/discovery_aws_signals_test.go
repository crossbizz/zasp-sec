package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	resolvertypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

const (
	signalWorkerRole = "arn:aws:iam::123456789012:role/app/batch-summariser"
	signalAdminRole  = "arn:aws:iam::123456789012:role/reader"
)

func cloudTrailEvent(identityType, issuerType, arn string) cloudtrailtypes.Event {
	body, _ := json.Marshal(map[string]any{"userIdentity": map[string]any{"type": identityType, "sessionContext": map[string]any{"sessionIssuer": map[string]any{"type": issuerType, "arn": arn}}}, "requestParameters": map[string]any{"modelId": "secret-model-name"}})
	return cloudtrailtypes.Event{CloudTrailEvent: aws.String(string(body))}
}

type cloudTrailStub struct {
	events map[string][]cloudtrailtypes.Event
	err    error
	calls  []string
}

func (stub *cloudTrailStub) LookupEvents(_ context.Context, input *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	name := aws.ToString(input.LookupAttributes[0].AttributeValue)
	stub.calls = append(stub.calls, name)
	if stub.err != nil {
		return nil, stub.err
	}
	return &cloudtrail.LookupEventsOutput{Events: stub.events[name]}, nil
}

func TestCloudTrailInvokersAreWorkloadRolesOnly(t *testing.T) {
	now := discoveryAgentTestClock()
	stub := &cloudTrailStub{events: map[string][]cloudtrailtypes.Event{
		"InvokeModel": {
			cloudTrailEvent("AssumedRole", "Role", signalWorkerRole),
			cloudTrailEvent("AssumedRole", "Role", "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"),
			cloudTrailEvent("AssumedRole", "Role", "arn:aws:iam::123456789012:role/aws-service-role/bedrock.amazonaws.com/AWSServiceRoleForBedrock"),
			cloudTrailEvent("AssumedRole", "Role", "arn:aws:iam::999999999999:role/other-account"),
			cloudTrailEvent("IAMUser", "", ""),
			{CloudTrailEvent: aws.String("not json")},
		},
		"Converse": {cloudTrailEvent("AssumedRole", "Role", signalWorkerRole)},
	}}
	invokers, _, status, err := collectDiscoveryAWSInvokers(context.Background(), stub, "123456789012", now)
	if err != nil || status != awsdiscovery.AgentServiceCollected || len(invokers) != 1 || len(invokers[signalWorkerRole]) != 1 || invokers[signalWorkerRole][0] != "invoke:bedrock_model" {
		t.Fatalf("invokers = %v, status %q, err %v", invokers, status, err)
	}
	if len(stub.calls) != len(discoveryAWSInvocationEvents) {
		t.Fatalf("asked for %v", stub.calls)
	}
	for name, test := range map[string]struct {
		err  error
		want string
	}{
		"denied":    {discoveryAgentAPIError(403, "AccessDeniedException", "denied"), awsdiscovery.AgentServiceAccessDenied},
		"throttled": {discoveryAgentAPIError(400, "ThrottlingException", "slow down"), awsdiscovery.AgentServiceUnavailable},
		"transport": {errors.New("connection reset"), awsdiscovery.AgentServiceUnavailable},
	} {
		invokers, _, status, err := collectDiscoveryAWSInvokers(context.Background(), &cloudTrailStub{err: test.err}, "123456789012", now)
		if err != nil || status != test.want || invokers != nil {
			t.Errorf("%s: status %q, err %v", name, status, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := collectDiscoveryAWSInvokers(cancelled, &cloudTrailStub{err: context.Canceled}, "123456789012", now); err == nil {
		t.Fatal("a cancelled read did not fail")
	}
}

type networkLogStub struct {
	queryDestinations []string
	flowLogs          []ec2types.FlowLog
	resolverErr       error
	// rows answers a query by a fragment of its text.
	resolverRows, flowRows [][]logstypes.ResultField
	queries                []string
	running                int
}

func (stub *networkLogStub) ListResolverQueryLogConfigs(context.Context, *route53resolver.ListResolverQueryLogConfigsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigsOutput, error) {
	if stub.resolverErr != nil {
		return nil, stub.resolverErr
	}
	output := &route53resolver.ListResolverQueryLogConfigsOutput{}
	for _, destination := range stub.queryDestinations {
		output.ResolverQueryLogConfigs = append(output.ResolverQueryLogConfigs, resolvertypes.ResolverQueryLogConfig{DestinationArn: aws.String(destination)})
	}
	return output, nil
}

func (stub *networkLogStub) DescribeFlowLogs(context.Context, *ec2.DescribeFlowLogsInput, ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	return &ec2.DescribeFlowLogsOutput{FlowLogs: stub.flowLogs}, nil
}

func (stub *networkLogStub) StartQuery(_ context.Context, input *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	stub.queries = append(stub.queries, aws.ToString(input.QueryString))
	if input.EndTime == nil || input.StartTime == nil || *input.EndTime-*input.StartTime != int64(discoveryAWSLogWindow/time.Second) || aws.ToInt32(input.Limit) != maximumAWSLogRows {
		return nil, errors.New("unbounded query")
	}
	if strings.Contains(aws.ToString(input.QueryString), "query_name") {
		return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("resolver")}, nil
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("flow")}, nil
}

func (stub *networkLogStub) GetQueryResults(_ context.Context, input *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	if stub.running > 0 {
		stub.running--
		return &cloudwatchlogs.GetQueryResultsOutput{Status: logstypes.QueryStatusRunning}, nil
	}
	if aws.ToString(input.QueryId) == "resolver" {
		return &cloudwatchlogs.GetQueryResultsOutput{Status: logstypes.QueryStatusComplete, Results: stub.resolverRows}, nil
	}
	return &cloudwatchlogs.GetQueryResultsOutput{Status: logstypes.QueryStatusComplete, Results: stub.flowRows}, nil
}

func logRow(pairs ...string) []logstypes.ResultField {
	row := make([]logstypes.ResultField, 0, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		row = append(row, logstypes.ResultField{Field: aws.String(pairs[index]), Value: aws.String(pairs[index+1])})
	}
	return row
}

func signalNetworkStub() *networkLogStub {
	return &networkLogStub{
		queryDestinations: []string{"arn:aws:logs:us-east-1:123456789012:log-group:/vpc/resolver:*", "arn:aws:s3:::resolver-archive"},
		flowLogs:          []ec2types.FlowLog{{LogDestinationType: ec2types.LogDestinationTypeCloudWatchLogs, LogGroupName: aws.String("/vpc/flow")}, {LogDestinationType: ec2types.LogDestinationTypeS3}},
		resolverRows: [][]logstypes.ResultField{
			// Resolved a model API (through a CNAME) and connected: recorded.
			logRow("srcaddr", "10.0.1.15", "query_name", "api.anthropic.com.", "srcids.instance", "i-0aaaaaaaaaaaaaaa1", "answers.0.Rdata", "edge.example.net.", "answers.1.Rdata", "160.79.104.10"),
			// Resolved a model API and never connected: not recorded.
			logRow("srcaddr", "10.0.1.16", "query_name", "api.openai.com.", "srcids.instance", "i-0bbbbbbbbbbbbbbb2", "answers.0.Rdata", "104.18.6.192"),
			// The prefilter matched but the catalog does not: dropped.
			logRow("srcaddr", "10.0.1.17", "query_name", "together.example.com.", "srcids.instance", "i-0ccccccccccccccc3", "answers.0.Rdata", "93.184.216.34"),
			// Only an agent tooling host, a weak signal: not an agent.
			logRow("srcaddr", "10.0.1.18", "query_name", "api.tavily.com.", "srcids.instance", "i-0ddddddddddddddd4", "answers.0.Rdata", "203.0.113.9"),
			// No instance (a Lambda or Fargate address): not attributed.
			logRow("srcaddr", "10.0.1.19", "query_name", "api.openai.com.", "answers.0.Rdata", "104.18.6.193"),
		},
		flowRows: [][]logstypes.ResultField{
			logRow("srcAddr", "10.0.1.15", "dstAddr", "160.79.104.10", "flows", "12"),
			logRow("srcAddr", "10.0.1.17", "dstAddr", "93.184.216.34", "flows", "3"),
			logRow("srcAddr", "10.0.1.18", "dstAddr", "203.0.113.9", "flows", "1"),
			// A connection to the address by an instance that never asked for the name.
			logRow("srcAddr", "10.0.1.16", "dstAddr", "160.79.104.10", "flows", "1"),
		},
	}
}

func TestNetworkLogJoinFindsInstancesThatResolvedAndConnected(t *testing.T) {
	discoveryAWSLogPollInterval = time.Millisecond
	stub := signalNetworkStub()
	stub.running = 2
	result, err := collectDiscoveryAWSEgress(context.Background(), stub, stub, stub, discoveryAgentTestClock())
	if err != nil || result.resolver != awsdiscovery.AgentServiceCollected || result.flow != awsdiscovery.AgentServiceCollected {
		t.Fatalf("result = %+v, err %v", result, err)
	}
	if len(result.instances) != 1 || len(result.instances["i-0aaaaaaaaaaaaaaa1"]) != 1 || result.instances["i-0aaaaaaaaaaaaaaa1"][0] != "egress:anthropic" {
		t.Fatalf("instances = %v", result.instances)
	}
	if len(stub.queries) != 2 || !strings.Contains(stub.queries[1], `"10.0.1.15"`) || !strings.Contains(stub.queries[1], `"160.79.104.10"`) || strings.Contains(stub.queries[1], "10.0.1.19") || strings.Contains(stub.queries[1], "93.184.216.34") {
		t.Fatalf("queries = %q", stub.queries)
	}
	for name, change := range map[string]func(*networkLogStub){
		"no flow logs in CloudWatch":     func(stub *networkLogStub) { stub.flowLogs = stub.flowLogs[1:] },
		"no resolver logs in CloudWatch": func(stub *networkLogStub) { stub.queryDestinations = stub.queryDestinations[1:] },
		"resolver refused": func(stub *networkLogStub) {
			stub.resolverErr = discoveryAgentAPIError(403, "AccessDeniedException", "denied")
		},
	} {
		stub := signalNetworkStub()
		change(stub)
		result, err := collectDiscoveryAWSEgress(context.Background(), stub, stub, stub, discoveryAgentTestClock())
		if err != nil || len(result.instances) != 0 || len(stub.queries) != 0 || result.resolver == awsdiscovery.AgentServiceCollected && result.flow == awsdiscovery.AgentServiceCollected {
			t.Errorf("%s: result %+v, queries %d, err %v", name, result, len(stub.queries), err)
		}
		if name == "resolver refused" && result.resolver != awsdiscovery.AgentServiceAccessDenied {
			t.Errorf("refusal reported as %q", result.resolver)
		}
	}
}

type roleUsageStub struct{ lastUsed map[string]*time.Time }

func (stub *roleUsageStub) GetRole(_ context.Context, input *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	name := aws.ToString(input.RoleName)
	last, known := stub.lastUsed[name]
	if !known {
		return nil, discoveryAgentAPIError(404, "NoSuchEntity", "gone")
	}
	arn := "arn:aws:iam::123456789012:role/" + name
	if name == "batch-summariser" {
		arn = signalWorkerRole
	}
	created := discoveryAgentTestClock().Add(-400 * 24 * time.Hour)
	role := &iamtypes.Role{Arn: aws.String(arn), RoleName: aws.String(name), CreateDate: &created}
	if last != nil {
		role.RoleLastUsed = &iamtypes.RoleLastUsed{LastUsedDate: last}
	}
	return &iam.GetRoleOutput{Role: role}, nil
}

// The whole agents read with every agentless signal: a role CloudTrail shows
// invoking a model and an instance the network logs show reaching a model
// API are listed as inferred agents, a function gains the invoke signal of
// its role, and the three posture checks are raised on the right agents.
func TestAWSInventoryReadsAgentlessRuntimeSignalsAndChecks(t *testing.T) {
	discoveryAWSLogPollInterval = time.Millisecond
	regions := discoveryAgentMixedAccount()
	guarded := discoveryAgentStubAgent("us-east-1", "GUARDED123", "guarded", discoveryAgentPlainRole)
	guarded.GuardrailConfiguration = &bedrockagenttypes.GuardrailConfiguration{GuardrailIdentifier: aws.String("gr-1"), GuardrailVersion: aws.String("1")}
	regions["us-east-1"].agents = append(regions["us-east-1"].agents, guarded)
	factory := discoveryAgentFactory(regions)
	trail := &cloudTrailStub{events: map[string][]cloudtrailtypes.Event{"InvokeModel": {cloudTrailEvent("AssumedRole", "Role", signalWorkerRole), cloudTrailEvent("AssumedRole", "Role", discoveryAgentPlainRole)}}}
	// CloudTrail records when the worker role's call happened; the other
	// role's event carries no time.
	invokedAt := discoveryAgentTestClock().Add(-5*time.Hour - 30*time.Minute)
	trail.events["InvokeModel"][0].EventTime = aws.Time(invokedAt)
	factory.CloudTrail = func(region string, _ aws.Credentials) (discoveryAWSCloudTrailAPI, error) {
		if region == "us-east-1" {
			return trail, nil
		}
		return &cloudTrailStub{}, nil
	}
	network := signalNetworkStub()
	empty := &networkLogStub{}
	pick := func(region string) *networkLogStub {
		if region == "us-east-1" {
			return network
		}
		return empty
	}
	factory.Resolver = func(region string, _ aws.Credentials) (discoveryAWSResolverAPI, error) { return pick(region), nil }
	factory.FlowLogs = func(region string, _ aws.Credentials) (discoveryAWSFlowLogAPI, error) { return pick(region), nil }
	factory.Logs = func(region string, _ aws.Credentials) (discoveryAWSLogsAPI, error) { return pick(region), nil }
	recent, old := discoveryAgentTestClock().Add(-24*time.Hour), discoveryAgentTestClock().Add(-200*24*time.Hour)
	factory.RoleUsage = func(string, aws.Credentials) (discoveryAWSRoleUsageAPI, error) {
		return &roleUsageStub{lastUsed: map[string]*time.Time{"reader": &recent, "plain": &old, "batch-summariser": nil}}, nil
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
	if want := invokedAt.UTC().Truncate(time.Hour).Format(time.RFC3339); len(source.Invocations) != 1 || source.Invocations[0] != (awsdiscovery.AgentInventoryInvocation{LastInvokedAt: want, RoleARN: signalWorkerRole}) {
		t.Fatalf("invocations = %+v, want the worker role at %s", source.Invocations, want)
	}
	workloads := map[string]awsdiscovery.AgentInventoryWorkload{}
	for _, workload := range source.InferredWorkloads {
		workloads[workload.ARN] = workload
	}
	instance := workloads["arn:aws:ec2:us-east-1:123456789012:instance/i-0aaaaaaaaaaaaaaa1"]
	role := workloads[signalWorkerRole]
	if len(workloads) != 2 || instance.ResourceType != "ec2_instance" || len(instance.Signals) != 1 || instance.Signals[0] != "egress:anthropic" || role.ResourceType != "iam_role" || role.Name != "batch-summariser" || role.Region != "us-east-1" || len(role.Signals) != 1 || role.Signals[0] != "invoke:bedrock_model" {
		t.Fatalf("inferred workloads = %+v", source.InferredWorkloads)
	}
	// The plain role invoked a model too, but it is the role of listed
	// agents, so it is not listed on its own; its function gains the signal.
	for _, function := range source.LambdaFunctions {
		if function.Name == "bot" && strings.Join(function.Signals, ",") != "env:openai,invoke:bedrock_model" {
			t.Fatalf("bot signals = %v", function.Signals)
		}
		// A function with no AI in its configuration is found by its role's calls.
		if function.Name == "plain" && strings.Join(function.Signals, ",") != "invoke:bedrock_model" {
			t.Fatalf("plain signals = %v", function.Signals)
		}
	}
	if len(source.LambdaFunctions) != 3 {
		t.Fatalf("functions = %+v", source.LambdaFunctions)
	}
	services := map[string]string{}
	for _, service := range source.Services {
		services[service.Service] = service.Status
	}
	if len(source.Services) != 6 || services[awsdiscovery.AgentServiceCloudTrail] != "collected" || services[awsdiscovery.AgentServiceResolverLogs] != "collected" || services[awsdiscovery.AgentServiceFlowLogs] != "collected" {
		t.Fatalf("services = %+v", source.Services)
	}
	checks := map[string]bool{}
	for _, check := range source.Checks {
		checks[check.ARN[strings.LastIndexAny(check.ARN, ":/")+1:]+" "+check.Check] = true
	}
	for _, want := range []string{
		"AGENT12345 agent_guardrail_missing",         // no guardrail attached
		"GUARDED123 agent_role_unused_90_days",       // plain role last used 200 days ago
		"bot agent_role_unused_90_days",              // same role
		"batch-summariser agent_role_unused_90_days", // never used, created 400 days ago
	} {
		if !checks[want] {
			t.Errorf("missing check %q in %+v", want, source.Checks)
		}
	}
	for _, unwanted := range []string{"GUARDED123 agent_guardrail_missing", "AGENT12345 agent_role_unused_90_days"} {
		if checks[unwanted] {
			t.Errorf("unexpected check %q", unwanted)
		}
	}
	for _, leaked := range []string{"anthropic.com", "160.79", "10.0.1", "secret-model-name", "edge.example"} {
		if strings.Contains(string(inventory.AgentSource), leaked) {
			t.Fatalf("the agent source carries %q", leaked)
		}
	}
}

func TestAdministratorRolesNeedAllowEverythingOnEverything(t *testing.T) {
	statement := func(effect string, action, resource any) map[string]any {
		return map[string]any{"Effect": effect, "Action": action, "Resource": resource}
	}
	roles := []discoveryAWSNativeRole{
		{ARN: "admin", ManagedPolicies: map[string][]any{"p": {statement("Allow", "*", "*")}}},
		{ARN: "admin-list", ManagedPolicies: map[string][]any{"p": {statement("Allow", []any{"s3:Get*", "*"}, []any{"*"})}}},
		{ARN: "scoped", ManagedPolicies: map[string][]any{"p": {statement("Allow", "*", "arn:aws:s3:::bucket/*")}}},
		{ARN: "denied", ManagedPolicies: map[string][]any{"p": {statement("Deny", "*", "*")}}},
		{ARN: "service", ManagedPolicies: map[string][]any{"p": {statement("Allow", "bedrock:*", "*")}}},
	}
	got := discoveryAWSAdministratorRoles(roles)
	if len(got) != 2 || !got["admin"] || !got["admin-list"] {
		t.Fatalf("administrators = %v", got)
	}
}

// The newest event time CloudTrail records for a role, inside the lookup
// window, is when the role last invoked a model.
func TestCloudTrailInvokersCarryTheNewestEventTime(t *testing.T) {
	now := discoveryAgentTestClock()
	at := func(age time.Duration) cloudtrailtypes.Event {
		event := cloudTrailEvent("AssumedRole", "Role", signalWorkerRole)
		event.EventTime = aws.Time(now.Add(-age))
		return event
	}
	otherRole := "arn:aws:iam::123456789012:role/untimed-worker"
	stub := &cloudTrailStub{events: map[string][]cloudtrailtypes.Event{
		"InvokeModel": {at(50 * time.Hour), at(3 * time.Hour), cloudTrailEvent("AssumedRole", "Role", otherRole)},
		// A time after the read or before the window is not an invocation time.
		"Converse": {at(26 * time.Hour), at(-time.Hour), at(discoveryAWSInvocationWindow + time.Hour)},
	}}
	invokers, invoked, status, err := collectDiscoveryAWSInvokers(context.Background(), stub, "123456789012", now)
	if err != nil || status != awsdiscovery.AgentServiceCollected || len(invokers) != 2 {
		t.Fatalf("invokers = %v, status %q, err %v", invokers, status, err)
	}
	if got, ok := invoked[signalWorkerRole]; !ok || !got.Equal(now.Add(-3*time.Hour)) {
		t.Fatalf("last invocation = %v, want %v", got, now.Add(-3*time.Hour))
	}
	// A role whose events carry no time keeps its signal and has no time.
	if _, timed := invoked[otherRole]; timed || len(invokers[otherRole]) != 1 {
		t.Fatalf("untimed role: invoked=%v signals=%v", invoked[otherRole], invokers[otherRole])
	}
}
