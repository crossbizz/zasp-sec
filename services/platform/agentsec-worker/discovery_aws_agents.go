package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

// The AI services of an account are optional reads. A read role granted
// before they existed has no permission for them, an emulator does not serve
// them, and AgentCore is not in every region. None of that fails the
// inventory: each service is reported as collected, access_denied or
// unavailable, and what was collected is kept.

type discoveryAWSBedrockAgentAPI interface {
	ListAgents(context.Context, *bedrockagent.ListAgentsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error)
	GetAgent(context.Context, *bedrockagent.GetAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error)
}

type discoveryAWSAgentCoreAPI interface {
	ListAgentRuntimes(context.Context, *bedrockagentcorecontrol.ListAgentRuntimesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error)
	GetAgentRuntime(context.Context, *bedrockagentcorecontrol.GetAgentRuntimeInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error)
	ListGateways(context.Context, *bedrockagentcorecontrol.ListGatewaysInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error)
}

type discoveryAWSLambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

// One list is read in at most this many provider pages.
const maximumAWSAgentListPages = 256

// discoveryAWSAgentStatusRank orders what a service answered inside one
// region: the worst answer of any of its operations is the region's status.
var discoveryAWSAgentStatusRank = map[string]int{awsdiscovery.AgentServiceCollected: 0, awsdiscovery.AgentServiceUnavailable: 1, awsdiscovery.AgentServiceAccessDenied: 2}

func worseDiscoveryAWSAgentStatus(left, right string) string {
	if discoveryAWSAgentStatusRank[right] > discoveryAWSAgentStatusRank[left] {
		return right
	}
	return left
}

// accountDiscoveryAWSAgentStatus folds one region's answer into the
// account's. A refusal in any region is access_denied: a permission is
// missing. A service that some regions do not offer is still collected when
// another region served it (AgentCore is not in every region); it is
// unavailable only when no region did.
func accountDiscoveryAWSAgentStatus(account, region string) string {
	switch {
	case account == "":
		return region
	case account == awsdiscovery.AgentServiceAccessDenied || region == awsdiscovery.AgentServiceAccessDenied:
		return awsdiscovery.AgentServiceAccessDenied
	case account == awsdiscovery.AgentServiceCollected || region == awsdiscovery.AgentServiceCollected:
		return awsdiscovery.AgentServiceCollected
	default:
		return awsdiscovery.AgentServiceUnavailable
	}
}

var (
	discoveryAWSAccessDeniedCodes = map[string]bool{"AccessDenied": true, "AccessDeniedException": true, "UnauthorizedOperation": true, "AuthorizationError": true}
	discoveryAWSNotServedCodes    = map[string]bool{"UnknownOperationException": true, "UnknownOperation": true, "InvalidAction": true, "NotImplemented": true, "NotImplementedException": true, "UnsupportedOperation": true, "UnsupportedOperationException": true}
	// What an emulator answers for a service or an operation it does not serve.
	discoveryAWSNotServedMessages = []string{"not implemented", "not yet implemented", "not been implemented", "pro feature", "not yet been emulated", "not included in your current license plan"}
)

// classifyDiscoveryAWSAgentFailure says what a failed AI service request
// means. A refusal for lack of permission is access_denied. A service that is
// not there (no endpoint for the region, no such host, an unknown operation,
// HTTP 501 or 404, an emulator that does not serve it) is unavailable.
// Everything else, such as throttling, a timeout or a server error, fails the
// inventory read like any other provider request. The error is only
// inspected: nothing of it is kept.
func classifyDiscoveryAWSAgentFailure(ctx context.Context, err error) (string, error) {
	if err == nil || ctx == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", awsdiscovery.ErrDenied
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code := apiError.ErrorCode()
		if discoveryAWSAccessDeniedCodes[code] {
			return awsdiscovery.AgentServiceAccessDenied, nil
		}
		if discoveryAWSNotServedCodes[code] {
			return awsdiscovery.AgentServiceUnavailable, nil
		}
		message := strings.ToLower(apiError.ErrorMessage())
		for _, fragment := range discoveryAWSNotServedMessages {
			if strings.Contains(message, fragment) {
				return awsdiscovery.AgentServiceUnavailable, nil
			}
		}
	}
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) && (response.HTTPStatusCode() == 501 || response.HTTPStatusCode() == 404) {
		return awsdiscovery.AgentServiceUnavailable, nil
	}
	var endpoint *aws.EndpointNotFoundError
	var dns *net.DNSError
	if errors.As(err, &endpoint) || errors.As(err, &dns) && dns.IsNotFound || strings.Contains(err.Error(), "failed to resolve service endpoint") {
		return awsdiscovery.AgentServiceUnavailable, nil
	}
	return "", awsdiscovery.ErrDenied
}

func discoveryAWSAgentGone(err error) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == "ResourceNotFoundException"
}

type discoveryAWSRegionAgents struct {
	bedrock, agentCore, lambda string
	agents                     []awsdiscovery.AgentInventoryBedrockAgent
	runtimes                   []awsdiscovery.AgentInventoryRuntime
	gateways                   []awsdiscovery.AgentInventoryGateway
	functions                  []awsdiscovery.AgentInventoryLambdaFunction
	scannedFunctions           int
}

// collectDiscoveryAWSAgentSource reads the AI services of every enabled
// region and returns the canonical agent source of the account.
func collectDiscoveryAWSAgentSource(ctx context.Context, factory discoveryAWSInventoryFactory, credentials aws.Credentials, accountID string, regions []string, roles []discoveryAWSNativeRole) (json.RawMessage, error) {
	if ctx == nil || factory.BedrockAgent == nil || factory.AgentCore == nil || factory.Lambda == nil || len(regions) < 1 {
		return nil, awsdiscovery.ErrDenied
	}
	roleActions := discoveryAWSRoleModelActions(roles)
	regional := make([]discoveryAWSRegionAgents, len(regions))
	if err := discoveryAWSEach(ctx, len(regions), func(bounded context.Context, index int) error {
		found, err := collectDiscoveryAWSRegionAgents(bounded, factory, credentials, accountID, regions[index], roleActions)
		regional[index] = found
		return err
	}); err != nil {
		return nil, err
	}
	source := awsdiscovery.AgentInventorySource{AccountID: accountID, BedrockAgents: []awsdiscovery.AgentInventoryBedrockAgent{}, Gateways: []awsdiscovery.AgentInventoryGateway{}, LambdaFunctions: []awsdiscovery.AgentInventoryLambdaFunction{}, Runtimes: []awsdiscovery.AgentInventoryRuntime{}}
	bedrock, agentCore, functions, scanned := "", "", "", 0
	for _, found := range regional {
		bedrock, agentCore, functions = accountDiscoveryAWSAgentStatus(bedrock, found.bedrock), accountDiscoveryAWSAgentStatus(agentCore, found.agentCore), accountDiscoveryAWSAgentStatus(functions, found.lambda)
		scanned += found.scannedFunctions
		source.BedrockAgents = append(source.BedrockAgents, found.agents...)
		source.Runtimes = append(source.Runtimes, found.runtimes...)
		source.Gateways = append(source.Gateways, found.gateways...)
		source.LambdaFunctions = append(source.LambdaFunctions, found.functions...)
		// More than the account bound is refused, as it is for instances.
		if len(source.BedrockAgents) > awsdiscovery.MaximumInventoryBedrockAgents || len(source.Runtimes) > awsdiscovery.MaximumInventoryAgentRuntimes || len(source.Gateways) > awsdiscovery.MaximumInventoryAgentGateways || scanned > awsdiscovery.MaximumInventoryLambdaFunctions {
			return nil, awsdiscovery.ErrDenied
		}
	}
	sort.Slice(source.BedrockAgents, func(i, j int) bool { return source.BedrockAgents[i].ARN < source.BedrockAgents[j].ARN })
	sort.Slice(source.Runtimes, func(i, j int) bool { return source.Runtimes[i].ARN < source.Runtimes[j].ARN })
	sort.Slice(source.Gateways, func(i, j int) bool { return source.Gateways[i].ARN < source.Gateways[j].ARN })
	sort.Slice(source.LambdaFunctions, func(i, j int) bool { return source.LambdaFunctions[i].ARN < source.LambdaFunctions[j].ARN })
	source.Services = []awsdiscovery.AgentInventoryService{{Service: awsdiscovery.AgentServiceBedrockAgents, Status: bedrock}, {Service: awsdiscovery.AgentServiceAgentCore, Status: agentCore}, {Service: awsdiscovery.AgentServiceLambda, Status: functions}}
	encoded, ok := awsdiscovery.EncodeAgentInventorySource(source)
	if !ok || len(encoded) > 16<<20 {
		return nil, awsdiscovery.ErrDenied
	}
	return encoded, nil
}

func collectDiscoveryAWSRegionAgents(ctx context.Context, factory discoveryAWSInventoryFactory, credentials aws.Credentials, accountID, region string, roleActions map[string][]string) (discoveryAWSRegionAgents, error) {
	var found discoveryAWSRegionAgents
	bedrockAPI, err := factory.BedrockAgent(region, credentials)
	if err != nil || nilDiscoveryClientDependency(bedrockAPI) {
		return found, awsdiscovery.ErrDenied
	}
	if found.agents, found.bedrock, err = collectDiscoveryAWSBedrockAgents(ctx, bedrockAPI, accountID, region); err != nil {
		return found, err
	}
	agentCoreAPI, err := factory.AgentCore(region, credentials)
	if err != nil || nilDiscoveryClientDependency(agentCoreAPI) {
		return found, awsdiscovery.ErrDenied
	}
	if found.runtimes, found.agentCore, err = collectDiscoveryAWSAgentRuntimes(ctx, agentCoreAPI, accountID, region); err != nil {
		return found, err
	}
	// A region without AgentCore has no gateways to ask for.
	if found.agentCore != awsdiscovery.AgentServiceUnavailable {
		gateways, status, err := collectDiscoveryAWSAgentGateways(ctx, agentCoreAPI, accountID, region)
		if err != nil {
			return found, err
		}
		found.gateways, found.agentCore = gateways, worseDiscoveryAWSAgentStatus(found.agentCore, status)
	}
	lambdaAPI, err := factory.Lambda(region, credentials)
	if err != nil || nilDiscoveryClientDependency(lambdaAPI) {
		return found, awsdiscovery.ErrDenied
	}
	found.functions, found.scannedFunctions, found.lambda, err = collectDiscoveryAWSLambdaAgents(ctx, lambdaAPI, accountID, region, roleActions)
	return found, err
}

// nextDiscoveryAWSAgentToken accepts the token of a further provider page.
func nextDiscoveryAWSAgentToken(previous, next *string) bool {
	return next != previous && strings.TrimSpace(aws.ToString(next)) != "" && aws.ToString(next) != aws.ToString(previous)
}

func collectDiscoveryAWSBedrockAgents(ctx context.Context, api discoveryAWSBedrockAgentAPI, accountID, region string) ([]awsdiscovery.AgentInventoryBedrockAgent, string, error) {
	status := awsdiscovery.AgentServiceCollected
	listed := make(map[string]awsdiscovery.AgentInventoryBedrockAgent)
	var token *string
	for page := 0; ; page++ {
		if page >= maximumAWSAgentListPages {
			return nil, "", awsdiscovery.ErrDenied
		}
		output, err := api.ListAgents(ctx, &bedrockagent.ListAgentsInput{NextToken: token, MaxResults: aws.Int32(1000)}, func(options *bedrockagent.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			classified, failure := classifyDiscoveryAWSAgentFailure(ctx, err)
			if failure != nil {
				return nil, "", failure
			}
			status = worseDiscoveryAWSAgentStatus(status, classified)
			break
		}
		if output == nil || ctx.Err() != nil {
			return nil, "", awsdiscovery.ErrDenied
		}
		for _, summary := range output.AgentSummaries {
			id, name := aws.ToString(summary.AgentId), aws.ToString(summary.AgentName)
			if id == "" || name == "" {
				return nil, "", awsdiscovery.ErrDenied
			}
			listed[id] = awsdiscovery.AgentInventoryBedrockAgent{AgentID: id, ARN: "arn:aws:bedrock:" + region + ":" + accountID + ":agent/" + id, Name: name, Region: region, Status: discoveryAWSAgentState(string(summary.AgentStatus))}
			if len(listed) > awsdiscovery.MaximumInventoryBedrockAgents {
				return nil, "", awsdiscovery.ErrDenied
			}
		}
		if output.NextToken == nil {
			break
		}
		if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
			return nil, "", awsdiscovery.ErrDenied
		}
		token = output.NextToken
	}
	agents := make([]awsdiscovery.AgentInventoryBedrockAgent, 0, len(listed))
	for _, agent := range listed {
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ARN < agents[j].ARN })
	// The list names the agent; its role and model are in its description.
	// An agent whose description may not be read is still an agent.
	described, detailStatus, err := describeDiscoveryAWSAgents(ctx, len(agents), func(bounded context.Context, index int) (bool, error) {
		output, err := api.GetAgent(bounded, &bedrockagent.GetAgentInput{AgentId: aws.String(agents[index].AgentID)}, func(options *bedrockagent.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			return false, err
		}
		if output == nil || output.Agent == nil || aws.ToString(output.Agent.AgentId) != agents[index].AgentID || aws.ToString(output.Agent.AgentArn) != agents[index].ARN {
			return false, awsdiscovery.ErrDenied
		}
		// Only these members are read. The agent's instruction is not.
		agents[index].RoleARN = discoveryAWSAgentRole(aws.ToString(output.Agent.AgentResourceRoleArn))
		agents[index].Model = discoveryAWSAgentText(aws.ToString(output.Agent.FoundationModel))
		if state := discoveryAWSAgentState(string(output.Agent.AgentStatus)); state != "" {
			agents[index].Status = state
		}
		return true, nil
	})
	if err != nil {
		return nil, "", err
	}
	kept := agents[:0]
	for index, agent := range agents {
		if described[index] {
			kept = append(kept, agent)
		}
	}
	return kept, worseDiscoveryAWSAgentStatus(status, detailStatus), nil
}

func collectDiscoveryAWSAgentRuntimes(ctx context.Context, api discoveryAWSAgentCoreAPI, accountID, region string) ([]awsdiscovery.AgentInventoryRuntime, string, error) {
	status := awsdiscovery.AgentServiceCollected
	listed := make(map[string]awsdiscovery.AgentInventoryRuntime)
	var token *string
	for page := 0; ; page++ {
		if page >= maximumAWSAgentListPages {
			return nil, "", awsdiscovery.ErrDenied
		}
		output, err := api.ListAgentRuntimes(ctx, &bedrockagentcorecontrol.ListAgentRuntimesInput{NextToken: token, MaxResults: aws.Int32(100)}, func(options *bedrockagentcorecontrol.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			classified, failure := classifyDiscoveryAWSAgentFailure(ctx, err)
			if failure != nil {
				return nil, "", failure
			}
			status = worseDiscoveryAWSAgentStatus(status, classified)
			break
		}
		if output == nil || ctx.Err() != nil {
			return nil, "", awsdiscovery.ErrDenied
		}
		for _, summary := range output.AgentRuntimes {
			id, name, arn := aws.ToString(summary.AgentRuntimeId), aws.ToString(summary.AgentRuntimeName), aws.ToString(summary.AgentRuntimeArn)
			if id == "" || name == "" || arn != "arn:aws:bedrock-agentcore:"+region+":"+accountID+":runtime/"+id {
				return nil, "", awsdiscovery.ErrDenied
			}
			listed[id] = awsdiscovery.AgentInventoryRuntime{ARN: arn, Name: name, Region: region, RuntimeID: id, Status: discoveryAWSAgentState(string(summary.Status))}
			if len(listed) > awsdiscovery.MaximumInventoryAgentRuntimes {
				return nil, "", awsdiscovery.ErrDenied
			}
		}
		if output.NextToken == nil {
			break
		}
		if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
			return nil, "", awsdiscovery.ErrDenied
		}
		token = output.NextToken
	}
	runtimes := make([]awsdiscovery.AgentInventoryRuntime, 0, len(listed))
	for _, runtime := range listed {
		runtimes = append(runtimes, runtime)
	}
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i].ARN < runtimes[j].ARN })
	described, detailStatus, err := describeDiscoveryAWSAgents(ctx, len(runtimes), func(bounded context.Context, index int) (bool, error) {
		output, err := api.GetAgentRuntime(bounded, &bedrockagentcorecontrol.GetAgentRuntimeInput{AgentRuntimeId: aws.String(runtimes[index].RuntimeID)}, func(options *bedrockagentcorecontrol.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			return false, err
		}
		if output == nil {
			return false, awsdiscovery.ErrDenied
		}
		// The description carries the runtime's environment variables. They
		// are dropped unread: only the role and the status are taken.
		clear(output.EnvironmentVariables)
		output.EnvironmentVariables = nil
		if aws.ToString(output.AgentRuntimeId) != runtimes[index].RuntimeID || aws.ToString(output.AgentRuntimeArn) != runtimes[index].ARN {
			return false, awsdiscovery.ErrDenied
		}
		runtimes[index].RoleARN = discoveryAWSAgentRole(aws.ToString(output.RoleArn))
		if state := discoveryAWSAgentState(string(output.Status)); state != "" {
			runtimes[index].Status = state
		}
		return true, nil
	})
	if err != nil {
		return nil, "", err
	}
	kept := runtimes[:0]
	for index, runtime := range runtimes {
		if described[index] {
			kept = append(kept, runtime)
		}
	}
	return kept, worseDiscoveryAWSAgentStatus(status, detailStatus), nil
}

func collectDiscoveryAWSAgentGateways(ctx context.Context, api discoveryAWSAgentCoreAPI, accountID, region string) ([]awsdiscovery.AgentInventoryGateway, string, error) {
	status := awsdiscovery.AgentServiceCollected
	listed := make(map[string]awsdiscovery.AgentInventoryGateway)
	var token *string
	for page := 0; ; page++ {
		if page >= maximumAWSAgentListPages {
			return nil, "", awsdiscovery.ErrDenied
		}
		output, err := api.ListGateways(ctx, &bedrockagentcorecontrol.ListGatewaysInput{NextToken: token, MaxResults: aws.Int32(1000)}, func(options *bedrockagentcorecontrol.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			classified, failure := classifyDiscoveryAWSAgentFailure(ctx, err)
			if failure != nil {
				return nil, "", failure
			}
			status = worseDiscoveryAWSAgentStatus(status, classified)
			break
		}
		if output == nil || ctx.Err() != nil {
			return nil, "", awsdiscovery.ErrDenied
		}
		for _, summary := range output.Items {
			id, name := aws.ToString(summary.GatewayId), aws.ToString(summary.Name)
			if id == "" || name == "" {
				return nil, "", awsdiscovery.ErrDenied
			}
			// The list does not carry the ARN; it is the gateway's id in the
			// region and account that were asked.
			listed[id] = awsdiscovery.AgentInventoryGateway{ARN: "arn:aws:bedrock-agentcore:" + region + ":" + accountID + ":gateway/" + id, GatewayID: id, Name: name, Region: region, Status: discoveryAWSAgentState(string(summary.Status))}
			if len(listed) > awsdiscovery.MaximumInventoryAgentGateways {
				return nil, "", awsdiscovery.ErrDenied
			}
		}
		if output.NextToken == nil {
			break
		}
		if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
			return nil, "", awsdiscovery.ErrDenied
		}
		token = output.NextToken
	}
	gateways := make([]awsdiscovery.AgentInventoryGateway, 0, len(listed))
	for _, gateway := range listed {
		gateways = append(gateways, gateway)
	}
	sort.Slice(gateways, func(i, j int) bool { return gateways[i].ARN < gateways[j].ARN })
	return gateways, status, nil
}

// collectDiscoveryAWSLambdaAgents lists the region's functions and keeps the
// ones the evidence says are agents. The evidence is the names of a
// function's environment variables and the model and agent invocations its
// execution role's managed policies allow. An environment variable value is
// never copied out of the provider's answer.
func collectDiscoveryAWSLambdaAgents(ctx context.Context, api discoveryAWSLambdaAPI, accountID, region string, roleActions map[string][]string) ([]awsdiscovery.AgentInventoryLambdaFunction, int, string, error) {
	status := awsdiscovery.AgentServiceCollected
	inferred := make(map[string]awsdiscovery.AgentInventoryLambdaFunction)
	seen := make(map[string]bool)
	var marker *string
	for page := 0; ; page++ {
		if page >= maximumAWSAgentListPages {
			return nil, 0, "", awsdiscovery.ErrDenied
		}
		output, err := api.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker, MaxItems: aws.Int32(50)}, func(options *lambda.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			classified, failure := classifyDiscoveryAWSAgentFailure(ctx, err)
			if failure != nil {
				return nil, 0, "", failure
			}
			status = worseDiscoveryAWSAgentStatus(status, classified)
			break
		}
		if output == nil || ctx.Err() != nil {
			return nil, 0, "", awsdiscovery.ErrDenied
		}
		for index := range output.Functions {
			function := &output.Functions[index]
			var evidence agentsignals.Evidence
			if function.Environment != nil {
				for name := range function.Environment.Variables {
					evidence.EnvironmentNames(name)
				}
				clear(function.Environment.Variables)
				function.Environment = nil
			}
			name, arn := aws.ToString(function.FunctionName), aws.ToString(function.FunctionArn)
			if name == "" || arn != "arn:aws:lambda:"+region+":"+accountID+":function:"+name {
				return nil, 0, "", awsdiscovery.ErrDenied
			}
			seen[arn] = true
			if len(seen) > awsdiscovery.MaximumInventoryLambdaFunctions {
				return nil, 0, "", awsdiscovery.ErrDenied
			}
			role := discoveryAWSAgentRole(aws.ToString(function.Role))
			evidence.IAMActions(roleActions[role]...)
			if !evidence.IsAgent() {
				continue
			}
			inferred[arn] = awsdiscovery.AgentInventoryLambdaFunction{ARN: arn, Name: name, Region: region, RoleARN: role, Signals: evidence.Signals(), State: discoveryAWSAgentState(string(function.State))}
		}
		if output.NextMarker == nil || aws.ToString(output.NextMarker) == "" {
			break
		}
		if !nextDiscoveryAWSAgentToken(marker, output.NextMarker) {
			return nil, 0, "", awsdiscovery.ErrDenied
		}
		marker = output.NextMarker
	}
	functions := make([]awsdiscovery.AgentInventoryLambdaFunction, 0, len(inferred))
	for _, function := range inferred {
		functions = append(functions, function)
	}
	sort.Slice(functions, func(i, j int) bool { return functions[i].ARN < functions[j].ARN })
	return functions, len(seen), status, nil
}

// describeDiscoveryAWSAgents reads the description of each listed item, a few
// at a time. It reports which items still exist (one deleted since the list
// is dropped) and what the description read answered. Once a description is
// refused or not served, the remaining items are kept as the list gave them
// and no further description is asked for.
func describeDiscoveryAWSAgents(ctx context.Context, count int, describe func(context.Context, int) (bool, error)) ([]bool, string, error) {
	var mu sync.Mutex
	status, stopped := awsdiscovery.AgentServiceCollected, false
	exists := make([]bool, count)
	err := discoveryAWSEach(ctx, count, func(bounded context.Context, index int) error {
		mu.Lock()
		skip := stopped
		mu.Unlock()
		if skip {
			exists[index] = true
			return nil
		}
		described, err := describe(bounded, index)
		if err == nil {
			exists[index] = described
			return nil
		}
		if errors.Is(err, awsdiscovery.ErrDenied) {
			return err
		}
		if discoveryAWSAgentGone(err) {
			return nil
		}
		classified, failure := classifyDiscoveryAWSAgentFailure(bounded, err)
		if failure != nil {
			return failure
		}
		exists[index] = true
		mu.Lock()
		status, stopped = worseDiscoveryAWSAgentStatus(status, classified), true
		mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return exists, status, nil
}

// discoveryAWSRoleModelActions returns, for each role, the Action entries of
// its managed policies' allowing statements that grant a model or agent
// invocation. NotAction is not read. An entry that names no service ("*",
// "*:Invoke*") is an administrative grant, not a sign of a model caller, and
// is left out.
func discoveryAWSRoleModelActions(roles []discoveryAWSNativeRole) map[string][]string {
	relevant := make(map[string]bool)
	grants := func(action string) bool {
		if known, found := relevant[action]; found {
			return known
		}
		service, _, named := strings.Cut(action, ":")
		var evidence agentsignals.Evidence
		if named && service != "" && !strings.ContainsAny(service, "*?[\\") {
			evidence.IAMActions(action)
		}
		relevant[action] = len(evidence.Signals()) > 0
		return relevant[action]
	}
	actions := make(map[string][]string, len(roles))
	for _, role := range roles {
		found := make(map[string]bool)
		for _, statements := range role.ManagedPolicies {
			for _, raw := range statements {
				statement, ok := raw.(map[string]any)
				if effect, _ := statement["Effect"].(string); !ok || effect != "Allow" {
					continue
				}
				switch action := statement["Action"].(type) {
				case string:
					if grants(action) {
						found[action] = true
					}
				case []any:
					for _, entry := range action {
						if text, ok := entry.(string); ok && grants(text) {
							found[text] = true
						}
					}
				}
			}
		}
		if len(found) == 0 {
			continue
		}
		list := make([]string, 0, len(found))
		for action := range found {
			list = append(list, action)
		}
		sort.Strings(list)
		actions[role.ARN] = list
	}
	return actions
}

// A state, role or model the provider words in an unexpected way is left out
// rather than copied.
func discoveryAWSAgentState(value string) string {
	if len(value) < 1 || len(value) > 64 {
		return ""
	}
	for index, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character == '_' && index > 0) {
			return ""
		}
	}
	return value
}

var discoveryAWSAgentRolePattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)

func discoveryAWSAgentRole(arn string) string {
	if !discoveryAWSAgentRolePattern.MatchString(arn) {
		return ""
	}
	return arn
}

func discoveryAWSAgentText(value string) string {
	if len(value) < 1 || len(value) > 2048 || strings.TrimSpace(value) != value || strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f || character == '�' }) != -1 {
		return ""
	}
	return value
}
