package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"github.com/aws/smithy-go"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

// Agentless runtime signals. Nothing runs in the customer's account: the
// read role reads the account's own logs.
//
//   - CloudTrail says which roles invoked a model (management events).
//   - Route 53 Resolver query logs say which instance was given which address
//     for a catalog name, and VPC Flow Logs say whether it then connected to
//     that address: the same join the node sensor makes.
//
// Every one of these is optional evidence. A missing permission, a log that
// is not enabled, throttling or a failed query is reported as a service
// status and never fails the inventory. Only catalog tokens are kept: no
// query name, address, event or log line leaves this file.

type discoveryAWSCloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

type discoveryAWSRoleUsageAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

type discoveryAWSFlowLogAPI interface {
	DescribeFlowLogs(context.Context, *ec2.DescribeFlowLogsInput, ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
}

type discoveryAWSResolverAPI interface {
	ListResolverQueryLogConfigs(context.Context, *route53resolver.ListResolverQueryLogConfigsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigsOutput, error)
}

type discoveryAWSLogsAPI interface {
	StartQuery(context.Context, *cloudwatchlogs.StartQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
}

const (
	// CloudTrail keeps 90 days; a week is enough to see a running agent and
	// keeps the read small.
	discoveryAWSInvocationWindow = 7 * 24 * time.Hour
	// At most this many CloudTrail pages (50 events each) per event name
	// and region. A busy account is sampled from its newest events.
	maximumAWSInvocationPages = 4
	discoveryAWSLogWindow     = 24 * time.Hour
	maximumAWSLogRows         = 1000
	maximumAWSLogSources      = 100
	maximumAWSLogDestinations = 300
	maximumAWSLogQueryPolls   = 30
	discoveryAWSRoleUnusedFor = 90 * 24 * time.Hour
	maximumAWSRoleUsageReads  = 200
)

// Only the Bedrock runtime calls are management events CloudTrail returns
// from LookupEvents; agent invocations are data events and are not asked for.
var discoveryAWSInvocationEvents = []string{"Converse", "ConverseStream", "InvokeModel", "InvokeModelWithResponseStream"}

// classifyDiscoveryAWSSignalFailure never fails the inventory: a refusal is
// access_denied and everything else, throttling included, is unavailable.
// Only a cancelled read is an error.
func classifyDiscoveryAWSSignalFailure(ctx context.Context, err error) (string, error) {
	if ctx == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", awsdiscovery.ErrDenied
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) && discoveryAWSAccessDeniedCodes[apiError.ErrorCode()] {
		return awsdiscovery.AgentServiceAccessDenied, nil
	}
	return awsdiscovery.AgentServiceUnavailable, nil
}

// collectDiscoveryAWSInvokers returns, per role ARN of the account, the
// invoke signals CloudTrail shows for it in one region.
func collectDiscoveryAWSInvokers(ctx context.Context, api discoveryAWSCloudTrailAPI, accountID string, now time.Time) (map[string][]string, string, error) {
	status := awsdiscovery.AgentServiceCollected
	start := now.Add(-discoveryAWSInvocationWindow)
	evidence := map[string]*agentsignals.Evidence{}
	for _, name := range discoveryAWSInvocationEvents {
		var token *string
		for page := 0; page < maximumAWSInvocationPages; page++ {
			output, err := api.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				LookupAttributes: []cloudtrailtypes.LookupAttribute{{AttributeKey: cloudtrailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String(name)}},
				StartTime:        aws.Time(start), EndTime: aws.Time(now), MaxResults: aws.Int32(50), NextToken: token,
			}, func(options *cloudtrail.Options) { options.Retryer = aws.NopRetryer{} })
			if err != nil {
				classified, failure := classifyDiscoveryAWSSignalFailure(ctx, err)
				if failure != nil {
					return nil, "", failure
				}
				return nil, classified, nil
			}
			if output == nil {
				return nil, awsdiscovery.AgentServiceUnavailable, nil
			}
			for _, event := range output.Events {
				role := discoveryAWSInvokerRole(aws.ToString(event.CloudTrailEvent), accountID)
				if role == "" {
					continue
				}
				if evidence[role] == nil {
					evidence[role] = &agentsignals.Evidence{}
				}
				evidence[role].Invoked(name)
			}
			if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
				break
			}
			token = output.NextToken
		}
	}
	invokers := make(map[string][]string, len(evidence))
	for role, found := range evidence {
		invokers[role] = found.Signals()
	}
	return invokers, status, nil
}

// discoveryAWSInvokerRole reads the role that made a recorded call. Only the
// session issuer's ARN is read. People signed in through IAM Identity Center
// and AWS's own service-linked roles are not workloads and are skipped.
func discoveryAWSInvokerRole(event, accountID string) string {
	if len(event) == 0 || len(event) > 256<<10 {
		return ""
	}
	var record struct {
		UserIdentity struct {
			Type           string `json:"type"`
			SessionContext struct {
				SessionIssuer struct {
					Type string `json:"type"`
					ARN  string `json:"arn"`
				} `json:"sessionIssuer"`
			} `json:"sessionContext"`
		} `json:"userIdentity"`
	}
	if json.Unmarshal([]byte(event), &record) != nil || record.UserIdentity.Type != "AssumedRole" || record.UserIdentity.SessionContext.SessionIssuer.Type != "Role" {
		return ""
	}
	role := discoveryAWSAgentRole(record.UserIdentity.SessionContext.SessionIssuer.ARN)
	if role == "" || !strings.HasPrefix(role, "arn:aws:iam::"+accountID+":role/") || strings.Contains(role, ":role/aws-reserved/") || strings.Contains(role, ":role/aws-service-role/") {
		return ""
	}
	return role
}

// discoveryAWSAdministratorRoles returns the roles a managed policy lets do
// everything: an Allow statement with action * on resource *.
func discoveryAWSAdministratorRoles(roles []discoveryAWSNativeRole) map[string]bool {
	everything := func(value any) bool {
		switch typed := value.(type) {
		case string:
			return typed == "*"
		case []any:
			for _, entry := range typed {
				if text, ok := entry.(string); ok && text == "*" {
					return true
				}
			}
		}
		return false
	}
	administrators := map[string]bool{}
	for _, role := range roles {
		for _, statements := range role.ManagedPolicies {
			for _, raw := range statements {
				statement, ok := raw.(map[string]any)
				if effect, _ := statement["Effect"].(string); ok && effect == "Allow" && everything(statement["Action"]) && everything(statement["Resource"]) {
					administrators[role.ARN] = true
				}
			}
		}
	}
	return administrators
}

// discoveryAWSUnusedRoles asks IAM when each given role was last used and
// returns the ones not used in 90 days (and created before that). A role
// whose usage cannot be read is not reported.
func discoveryAWSUnusedRoles(ctx context.Context, api discoveryAWSRoleUsageAPI, roleARNs []string, now time.Time) map[string]bool {
	unused := map[string]bool{}
	for index, arn := range roleARNs {
		if index >= maximumAWSRoleUsageReads || ctx.Err() != nil {
			break
		}
		name := arn[strings.LastIndex(arn, "/")+1:]
		output, err := api.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(name)}, func(options *iam.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil || output == nil || output.Role == nil || aws.ToString(output.Role.Arn) != arn || output.Role.CreateDate == nil {
			continue
		}
		last := *output.Role.CreateDate
		if output.Role.RoleLastUsed != nil && output.Role.RoleLastUsed.LastUsedDate != nil {
			last = *output.Role.RoleLastUsed.LastUsedDate
		}
		if now.Sub(last) > discoveryAWSRoleUnusedFor {
			unused[arn] = true
		}
	}
	return unused
}

var (
	discoveryAWSLogGroupARNPattern = regexp.MustCompile(`^arn:aws[a-z-]*:logs:[a-z0-9-]+:[0-9]{12}:log-group:([A-Za-z0-9_./#-]{1,512})(?::\*)?$`)
	discoveryAWSLogGroupPattern    = regexp.MustCompile(`^[A-Za-z0-9_./#-]{1,512}$`)
	discoveryAWSInstancePattern    = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
)

// discoveryAWSEgressResult is one region's answer for the network-log join.
type discoveryAWSEgressResult struct {
	resolver, flow string
	// instances maps an instance ID to its sorted egress signals.
	instances map[string][]string
}

// collectDiscoveryAWSEgress joins the region's resolver query logs to its
// flow logs. Both must be delivered to CloudWatch Logs; a log delivered only
// to S3 or Firehose, or not enabled, is unavailable.
func collectDiscoveryAWSEgress(ctx context.Context, resolver discoveryAWSResolverAPI, flows discoveryAWSFlowLogAPI, logs discoveryAWSLogsAPI, now time.Time) (discoveryAWSEgressResult, error) {
	result := discoveryAWSEgressResult{resolver: awsdiscovery.AgentServiceCollected, flow: awsdiscovery.AgentServiceCollected}
	fail := func(status *string, err error) (bool, error) {
		classified, failure := classifyDiscoveryAWSSignalFailure(ctx, err)
		if failure != nil {
			return true, failure
		}
		*status = classified
		return false, nil
	}
	// Where the two logs are.
	var queryGroups, flowGroups []string
	configs, err := resolver.ListResolverQueryLogConfigs(ctx, &route53resolver.ListResolverQueryLogConfigsInput{MaxResults: aws.Int32(100)}, func(options *route53resolver.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil {
		if stop, failure := fail(&result.resolver, err); stop {
			return result, failure
		}
	} else if configs != nil {
		for _, config := range configs.ResolverQueryLogConfigs {
			if match := discoveryAWSLogGroupARNPattern.FindStringSubmatch(aws.ToString(config.DestinationArn)); len(match) == 2 {
				queryGroups = append(queryGroups, match[1])
			}
		}
	}
	described, err := flows.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{MaxResults: aws.Int32(1000)}, func(options *ec2.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil {
		if stop, failure := fail(&result.flow, err); stop {
			return result, failure
		}
	} else if described != nil {
		for _, flow := range described.FlowLogs {
			if group := aws.ToString(flow.LogGroupName); string(flow.LogDestinationType) == "cloud-watch-logs" && discoveryAWSLogGroupPattern.MatchString(group) {
				flowGroups = append(flowGroups, group)
			}
		}
	}
	if result.resolver == awsdiscovery.AgentServiceCollected && len(queryGroups) == 0 {
		result.resolver = awsdiscovery.AgentServiceUnavailable
	}
	if result.flow == awsdiscovery.AgentServiceCollected && len(flowGroups) == 0 {
		result.flow = awsdiscovery.AgentServiceUnavailable
	}
	if result.resolver != awsdiscovery.AgentServiceCollected || result.flow != awsdiscovery.AgentServiceCollected {
		return result, nil
	}
	queryGroups, flowGroups = discoveryAWSLogGroups(queryGroups), discoveryAWSLogGroups(flowGroups)

	// Which instance was given which address for a catalog name. The name
	// filter runs in the log service; rows are classified again here and a
	// name outside the catalog is dropped.
	rows, status, err := runDiscoveryAWSLogQuery(ctx, logs, queryGroups, now,
		`fields srcaddr, query_name, srcids.instance, answers.0.Rdata, answers.1.Rdata, answers.2.Rdata, answers.3.Rdata, answers.4.Rdata, answers.5.Rdata | filter rcode = "NOERROR" and query_name like /`+agentsignals.EgressHostPrefilter+`/ | dedup srcaddr, query_name`)
	if err != nil {
		return result, err
	}
	if status != awsdiscovery.AgentServiceCollected {
		result.resolver = status
		return result, nil
	}
	type pair struct{ source, destination netip.Addr }
	type resolution struct{ instance, token string }
	resolved := map[pair]resolution{}
	sources, destinations := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	for _, row := range rows {
		token, ok := agentsignals.EgressHost(row["query_name"])
		source, sourceErr := netip.ParseAddr(row["srcaddr"])
		instance := row["srcids.instance"]
		if !ok || sourceErr != nil || !discoveryAWSInstancePattern.MatchString(instance) {
			continue
		}
		for field, value := range row {
			if !strings.HasPrefix(field, "answers.") {
				continue
			}
			destination, err := netip.ParseAddr(value)
			if err != nil || len(sources) >= maximumAWSLogSources && !sources[source] || len(destinations) >= maximumAWSLogDestinations && !destinations[destination] {
				continue
			}
			sources[source], destinations[destination] = true, true
			resolved[pair{source, destination}] = resolution{instance, token}
		}
	}
	if len(resolved) == 0 {
		return result, nil
	}
	quote := func(values map[netip.Addr]bool) string {
		list := make([]string, 0, len(values))
		for value := range values {
			list = append(list, `"`+value.String()+`"`)
		}
		sort.Strings(list)
		return strings.Join(list, ",")
	}
	// Whether it then connected to that address.
	rows, status, err = runDiscoveryAWSLogQuery(ctx, logs, flowGroups, now,
		`filter action = "ACCEPT" and srcAddr in [`+quote(sources)+`] and dstAddr in [`+quote(destinations)+`] | stats count(*) as flows by srcAddr, dstAddr`)
	if err != nil {
		return result, err
	}
	if status != awsdiscovery.AgentServiceCollected {
		result.flow = status
		return result, nil
	}
	evidence := map[string]*agentsignals.Evidence{}
	for _, row := range rows {
		source, sourceErr := netip.ParseAddr(row["srcAddr"])
		destination, destinationErr := netip.ParseAddr(row["dstAddr"])
		if sourceErr != nil || destinationErr != nil {
			continue
		}
		if found, ok := resolved[pair{source, destination}]; ok {
			if evidence[found.instance] == nil {
				evidence[found.instance] = &agentsignals.Evidence{}
			}
			evidence[found.instance].Egress(found.token)
		}
	}
	result.instances = make(map[string][]string, len(evidence))
	for instance, found := range evidence {
		// A weak tooling host alone does not make an agent.
		if found.IsAgent() {
			result.instances[instance] = found.Signals()
		}
	}
	return result, nil
}

func discoveryAWSLogGroups(groups []string) []string {
	sort.Strings(groups)
	unique := groups[:0]
	for index, group := range groups {
		if index == 0 || group != groups[index-1] {
			unique = append(unique, group)
		}
	}
	// One Logs Insights query reads at most 50 log groups.
	if len(unique) > 50 {
		unique = unique[:50]
	}
	return unique
}

// runDiscoveryAWSLogQuery runs one bounded Logs Insights query over the last
// day and returns its rows as field maps.
func runDiscoveryAWSLogQuery(ctx context.Context, api discoveryAWSLogsAPI, groups []string, now time.Time, query string) ([]map[string]string, string, error) {
	classify := func(err error) ([]map[string]string, string, error) {
		classified, failure := classifyDiscoveryAWSSignalFailure(ctx, err)
		return nil, classified, failure
	}
	if len(query) > 10_000 {
		return nil, awsdiscovery.AgentServiceUnavailable, nil
	}
	started, err := api.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupNames: groups, QueryString: aws.String(query), Limit: aws.Int32(maximumAWSLogRows),
		StartTime: aws.Int64(now.Add(-discoveryAWSLogWindow).Unix()), EndTime: aws.Int64(now.Unix()),
	}, func(options *cloudwatchlogs.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil {
		return classify(err)
	}
	if started == nil || aws.ToString(started.QueryId) == "" {
		return nil, awsdiscovery.AgentServiceUnavailable, nil
	}
	for poll := 0; poll < maximumAWSLogQueryPolls; poll++ {
		output, err := api.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: started.QueryId}, func(options *cloudwatchlogs.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil {
			return classify(err)
		}
		if output == nil {
			return nil, awsdiscovery.AgentServiceUnavailable, nil
		}
		switch output.Status {
		case logstypes.QueryStatusComplete:
			rows := make([]map[string]string, 0, len(output.Results))
			for _, fields := range output.Results {
				row := make(map[string]string, len(fields))
				for _, field := range fields {
					row[aws.ToString(field.Field)] = aws.ToString(field.Value)
				}
				rows = append(rows, row)
			}
			return rows, awsdiscovery.AgentServiceCollected, nil
		case logstypes.QueryStatusRunning, logstypes.QueryStatusScheduled:
			timer := time.NewTimer(discoveryAWSLogPollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, "", awsdiscovery.ErrDenied
			case <-timer.C:
			}
		default:
			return nil, awsdiscovery.AgentServiceUnavailable, nil
		}
	}
	return nil, awsdiscovery.AgentServiceUnavailable, nil
}

// A variable so tests do not wait.
var discoveryAWSLogPollInterval = time.Second
