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
// invoke signals CloudTrail shows for it in one region, and the time of the
// newest invocation it shows for that role. The time is the event time
// CloudTrail records, inside the lookup window; an event without one, or with
// one outside the window, gives the role its signal and no time.
func collectDiscoveryAWSInvokers(ctx context.Context, api discoveryAWSCloudTrailAPI, accountID string, now time.Time) (map[string][]string, map[string]time.Time, string, error) {
	invocations, status, err := collectDiscoveryAWSInvocations(ctx, api, accountID, now)
	return invocations.signals, invocations.latest, status, err
}

// discoveryAWSInvocations is what one region's audit log showed: per role,
// its invoke signals, the time of its newest invocation and the IAM actions
// it used. complete is false when a lookup stopped at the page limit with
// more events to read; an absence in a sampled log proves nothing.
type discoveryAWSInvocations struct {
	signals  map[string][]string
	latest   map[string]time.Time
	actions  map[string]map[string]bool
	complete bool
}

func collectDiscoveryAWSInvocations(ctx context.Context, api discoveryAWSCloudTrailAPI, accountID string, now time.Time) (discoveryAWSInvocations, string, error) {
	status := awsdiscovery.AgentServiceCollected
	start := now.Add(-discoveryAWSInvocationWindow)
	evidence := map[string]*agentsignals.Evidence{}
	latest := map[string]time.Time{}
	found := discoveryAWSInvocations{actions: map[string]map[string]bool{}, latest: latest, complete: true}
	for _, name := range discoveryAWSInvocationEvents {
		var token *string
		for page := 0; ; page++ {
			if page >= maximumAWSInvocationPages {
				found.complete = false
				break
			}
			output, err := api.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				LookupAttributes: []cloudtrailtypes.LookupAttribute{{AttributeKey: cloudtrailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String(name)}},
				StartTime:        aws.Time(start), EndTime: aws.Time(now), MaxResults: aws.Int32(50), NextToken: token,
			}, func(options *cloudtrail.Options) { options.Retryer = aws.NopRetryer{} })
			if err != nil {
				classified, failure := classifyDiscoveryAWSSignalFailure(ctx, err)
				if failure != nil {
					return discoveryAWSInvocations{}, "", failure
				}
				return discoveryAWSInvocations{}, classified, nil
			}
			if output == nil {
				return discoveryAWSInvocations{}, awsdiscovery.AgentServiceUnavailable, nil
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
				if event.EventTime != nil && !event.EventTime.Before(start) && !event.EventTime.After(now) && event.EventTime.After(latest[role]) {
					latest[role] = event.EventTime.UTC()
				}
				if action, known := agentsignals.InvocationAction(name); known {
					if found.actions[role] == nil {
						found.actions[role] = map[string]bool{}
					}
					found.actions[role][action] = true
				}
			}
			if !nextDiscoveryAWSAgentToken(token, output.NextToken) {
				break
			}
			token = output.NextToken
		}
	}
	found.signals = make(map[string][]string, len(evidence))
	for role, recorded := range evidence {
		found.signals[role] = recorded.Signals()
	}
	return found, status, nil
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
	// workloads are everything the sources were attributed to, instances
	// included, sorted by kind and id, with the remote MCP hosts each reached.
	workloads []discoveryAWSEgressWorkload
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
	// host is the name itself only for a remote MCP server (a catalog rule);
	// for every other name only the token is kept.
	type resolution struct{ instance, token, host string }
	resolved := map[pair]resolution{}
	sources, destinations := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	// A source the log names no instance for (a task, a function, a pod) can
	// be attributed only by its network interface.
	interfaces, attributable := flows.(discoveryAWSNetworkInterfaceAPI)
	attributable = attributable && !nilDiscoveryClientDependency(interfaces)
	for _, row := range rows {
		token, ok := agentsignals.EgressHost(row["query_name"])
		source, sourceErr := netip.ParseAddr(row["srcaddr"])
		instance := row["srcids.instance"]
		if !discoveryAWSInstancePattern.MatchString(instance) {
			instance = ""
		}
		if !ok || sourceErr != nil || instance == "" && !attributable {
			continue
		}
		host, _ := agentsignals.IsRemoteMCPHost(row["query_name"])
		for field, value := range row {
			if !strings.HasPrefix(field, "answers.") {
				continue
			}
			destination, err := netip.ParseAddr(value)
			if err != nil || len(sources) >= maximumAWSLogSources && !sources[source] || len(destinations) >= maximumAWSLogDestinations && !destinations[destination] {
				continue
			}
			sources[source], destinations[destination] = true, true
			resolved[pair{source, destination}] = resolution{instance, token, host}
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
	// What each source address resolved and then reached.
	type reached struct {
		instance string
		evidence agentsignals.Evidence
		hosts    map[string]bool
	}
	bySource := map[netip.Addr]*reached{}
	for _, row := range rows {
		source, sourceErr := netip.ParseAddr(row["srcAddr"])
		destination, destinationErr := netip.ParseAddr(row["dstAddr"])
		if sourceErr != nil || destinationErr != nil {
			continue
		}
		if found, ok := resolved[pair{source, destination}]; ok {
			if bySource[source] == nil {
				bySource[source] = &reached{instance: found.instance, hosts: map[string]bool{}}
			}
			bySource[source].evidence.Egress(found.token)
			if found.host != "" {
				bySource[source].hosts[found.host] = true
			}
		}
	}
	owners := map[netip.Addr]discoveryAWSEgressWorkload{}
	if attributable {
		confirmed := make([]netip.Addr, 0, len(bySource))
		for source := range bySource {
			confirmed = append(confirmed, source)
		}
		owners = discoveryAWSInterfaceOwners(ctx, interfaces, confirmed)
		if ctx.Err() != nil {
			return result, awsdiscovery.ErrDenied
		}
	}
	// Several addresses may be one workload (the tasks of a service).
	type attributed struct {
		evidence agentsignals.Evidence
		hosts    map[string]bool
	}
	byWorkload := map[[2]string]*attributed{}
	for source, found := range bySource {
		owner, known := owners[source]
		if !known {
			if found.instance == "" {
				continue
			}
			owner = discoveryAWSEgressWorkload{kind: discoveryAWSEgressInstance, id: found.instance}
		}
		key := [2]string{owner.kind, owner.id}
		if byWorkload[key] == nil {
			byWorkload[key] = &attributed{hosts: map[string]bool{}}
		}
		byWorkload[key].evidence.AddSignals(found.evidence.Signals()...)
		for host := range found.hosts {
			byWorkload[key].hosts[host] = true
		}
	}
	result.instances = map[string][]string{}
	for key, found := range byWorkload {
		// A weak tooling host alone does not make an agent.
		if !found.evidence.IsAgent() {
			continue
		}
		workload := discoveryAWSEgressWorkload{kind: key[0], id: key[1], signals: found.evidence.Signals()}
		for host := range found.hosts {
			workload.hosts = append(workload.hosts, host)
		}
		sort.Strings(workload.hosts)
		result.workloads = append(result.workloads, workload)
		if workload.kind == discoveryAWSEgressInstance {
			result.instances[workload.id] = workload.signals
		}
	}
	sort.Slice(result.workloads, func(i, j int) bool {
		if result.workloads[i].kind != result.workloads[j].kind {
			return result.workloads[i].kind < result.workloads[j].kind
		}
		return result.workloads[i].id < result.workloads[j].id
	})
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
