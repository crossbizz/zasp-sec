package demodata

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// AWSSource is one AWS account as the worker's AWS reader hands it to the
// collector: the IAM roles, what the two analyzers found on them, and the
// typed agent inventory (Bedrock agents, AgentCore runtimes and gateways,
// inferred agents, MCP servers, data access and role usage).
//
// The demo enters the AWS pipeline here, after the AWS SDK reads: the
// collector's normalization (entities, relationships, findings) is the real
// code; the SDK calls that fill this source in a deployment are not run.
// The lists may be in any order; they are sorted the way the collector
// requires before they are handed over.
type AWSSource struct {
	Roles []AWSRole `json:"roles"`
	// Activity is when a role last invoked a model, in hours before the
	// collection. It becomes the source's invocations, so that the demo's
	// "last invoked" stays recent whenever it is seeded.
	Activity []AWSActivity                     `json:"activity,omitempty"`
	Agents   awsdiscovery.AgentInventorySource `json:"agents"`
}

// AWSActivity is the last model invocation of a role.
type AWSActivity struct {
	Role     string `json:"role"`
	HoursAgo int    `json:"hours_ago"`
}

// AWSRole is one IAM role of the account.
type AWSRole struct {
	// Name is the role name; Path its IAM path ("/" when empty).
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	// AdministratorAccess: the AdministratorAccess policy is attached.
	AdministratorAccess bool `json:"administrator_access,omitempty"`
	// ConfusedDeputy: a service may assume the role without a source
	// condition.
	ConfusedDeputy bool `json:"confused_deputy,omitempty"`
}

func (role AWSRole) arn(account string) string {
	path := role.Path
	if path == "" {
		path = "/"
	}
	return "arn:aws:iam::" + account + ":role" + path + role.Name
}

// roleID is a role ID of the documented form (AROA and sixteen characters),
// derived from the name. It identifies nothing.
func (role AWSRole) roleID() string {
	digest := sha256.Sum256([]byte("demo-role\x1f" + role.Name))
	return "AROA" + base32.StdEncoding.EncodeToString(digest[:])[:16]
}

type awsCaller struct {
	inventory awsdiscovery.CollectionInventory
}

func (caller *awsCaller) GetCollectionInventory(context.Context, []byte) (awsdiscovery.CollectionInventory, error) {
	return caller.inventory, nil
}
func (*awsCaller) CheckCollectionReadiness(context.Context) error { return nil }

// awsAnalyzer answers the two analyzer phases from the fixture's roles, in
// the result documents the analyzers produce.
type awsAnalyzer struct{ cartography, prowler json.RawMessage }

func (*awsAnalyzer) CheckCollectionReadiness(context.Context) error { return nil }
func (analyzer *awsAnalyzer) Collect(_ context.Context, request awsdiscovery.CollectionSecurityRequest, _ []byte) (awsdiscovery.CollectionSecurityResult, error) {
	result := analyzer.prowler
	if request.Mode == awsdiscovery.SecurityModeCartographyAWS {
		result = analyzer.cartography
	}
	return awsdiscovery.CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: result}, nil
}

// canonical sorts the lists of the agent source the way the collector
// requires them, so that the fixture can be edited in any order.
func canonicalAgentSource(source awsdiscovery.AgentInventorySource) awsdiscovery.AgentInventorySource {
	sort.Slice(source.BedrockAgents, func(l, r int) bool { return source.BedrockAgents[l].ARN < source.BedrockAgents[r].ARN })
	sort.Slice(source.Gateways, func(l, r int) bool { return source.Gateways[l].ARN < source.Gateways[r].ARN })
	sort.Slice(source.LambdaFunctions, func(l, r int) bool { return source.LambdaFunctions[l].ARN < source.LambdaFunctions[r].ARN })
	sort.Slice(source.Runtimes, func(l, r int) bool { return source.Runtimes[l].ARN < source.Runtimes[r].ARN })
	sort.Slice(source.InferredWorkloads, func(l, r int) bool { return source.InferredWorkloads[l].ARN < source.InferredWorkloads[r].ARN })
	sort.Slice(source.Invocations, func(l, r int) bool { return source.Invocations[l].RoleARN < source.Invocations[r].RoleARN })
	sort.Slice(source.Checks, func(l, r int) bool {
		return source.Checks[l].ARN+"\x1f"+source.Checks[l].Check < source.Checks[r].ARN+"\x1f"+source.Checks[r].Check
	})
	sort.Slice(source.DataAccess, func(l, r int) bool {
		return source.DataAccess[l].RoleARN+"\x1f"+source.DataAccess[l].ARN < source.DataAccess[r].RoleARN+"\x1f"+source.DataAccess[r].ARN
	})
	sort.Slice(source.MCPServers, func(l, r int) bool {
		return source.MCPServers[l].Region+"/"+source.MCPServers[l].Host < source.MCPServers[r].Region+"/"+source.MCPServers[r].Host
	})
	sort.Slice(source.RoleUsage, func(l, r int) bool { return source.RoleUsage[l].RoleARN < source.RoleUsage[r].RoleARN })
	sort.Slice(source.Uses, func(l, r int) bool {
		return source.Uses[l].Agent+"\x1f"+source.Uses[l].Server < source.Uses[r].Agent+"\x1f"+source.Uses[r].Server
	})
	for index := range source.Gateways {
		targets := source.Gateways[index].Targets
		sort.Slice(targets, func(l, r int) bool { return targets[l].TargetID < targets[r].TargetID })
		for _, target := range targets {
			sort.Strings(target.Tools)
		}
	}
	for index := range source.LambdaFunctions {
		sort.Strings(source.LambdaFunctions[index].Signals)
	}
	for index := range source.InferredWorkloads {
		sort.Strings(source.InferredWorkloads[index].Signals)
	}
	for index := range source.RoleUsage {
		sort.Strings(source.RoleUsage[index].Granted)
		sort.Strings(source.RoleUsage[index].Used)
		sort.Strings(source.RoleUsage[index].Unused)
	}
	return source
}

func init() { collectors["aws"] = collectAWS }

func collectAWS(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	account := integration.Subject
	source := integration.AWS.Agents
	if len(source.Invocations) != 0 {
		return Snapshot{}, fmt.Errorf("%w: %s: write activity, not invocations", ErrCollection, integration.Key)
	}
	for _, activity := range integration.AWS.Activity {
		invoked := target.ObservedAt.Add(-time.Duration(activity.HoursAgo) * time.Hour).Truncate(time.Hour)
		source.Invocations = append(source.Invocations, awsdiscovery.AgentInventoryInvocation{LastInvokedAt: invoked.Format("2006-01-02T15:00:00Z"), RoleARN: "arn:aws:iam::" + account + ":role/" + activity.Role})
	}
	source = canonicalAgentSource(source)
	if source.AccountID != account {
		return Snapshot{}, fmt.Errorf("%w: %s: the agent source is for another account", ErrCollection, integration.Key)
	}
	agents, valid := awsdiscovery.EncodeAgentInventorySource(source)
	if !valid {
		return Snapshot{}, fmt.Errorf("%w: %s: the collector refuses the agent source", ErrCollection, integration.Key)
	}
	roles := append([]AWSRole(nil), integration.AWS.Roles...)
	sort.Slice(roles, func(l, r int) bool { return roles[l].arn(account) < roles[r].arn(account) })

	// The two analyzer inputs (what the AWS reader lists of IAM) and the two
	// analyzer results, each in the analyzer's own document.
	type sourceRole struct {
		ARN        string         `json:"Arn"`
		Trust      map[string]any `json:"AssumeRolePolicyDocument"`
		CreateDate string         `json:"CreateDate"`
		Path       string         `json:"Path"`
		RoleID     string         `json:"RoleId"`
		RoleName   string         `json:"RoleName"`
	}
	type prowlerRole struct {
		ARN      string              `json:"Arn"`
		Trust    map[string]any      `json:"AssumeRolePolicyDocument"`
		Attached []map[string]string `json:"AttachedPolicies"`
		Service  bool                `json:"IsServiceRole"`
		RoleID   string              `json:"RoleId"`
		RoleName string              `json:"RoleName"`
	}
	type resultRole struct {
		ARN     string   `json:"arn"`
		Name    string   `json:"name"`
		Trusted []string `json:"trusted_role_arns"`
	}
	type finding struct {
		CheckID     string `json:"check_id"`
		Region      string `json:"region"`
		ResourceARN string `json:"resource_arn"`
		ResourceID  string `json:"resource_id"`
		Severity    string `json:"severity"`
		Status      string `json:"status"`
	}
	managed := map[string]map[string][]any{}
	cartographyRoles, prowlerRoles, resultRoles, findings := []sourceRole{}, []prowlerRole{}, []resultRole{}, []finding{}
	status := func(failed bool) string {
		if failed {
			return "FAIL"
		}
		return "PASS"
	}
	for _, role := range roles {
		arn, path := role.arn(account), role.Path
		if path == "" {
			path = "/"
		}
		policy := "ReadOnlyAccess"
		if role.AdministratorAccess {
			policy = "AdministratorAccess"
		}
		managed[arn] = map[string][]any{"arn:aws:iam::aws:policy/" + policy: {}}
		cartographyRoles = append(cartographyRoles, sourceRole{ARN: arn, Trust: map[string]any{}, CreateDate: "2026-03-02T09:00:00Z", Path: path, RoleID: role.roleID(), RoleName: role.Name})
		prowlerRoles = append(prowlerRoles, prowlerRole{ARN: arn, Trust: map[string]any{}, Attached: []map[string]string{{"PolicyName": policy}}, RoleID: role.roleID(), RoleName: role.Name})
		resultRoles = append(resultRoles, resultRole{ARN: arn, Name: role.Name, Trusted: []string{}})
		findings = append(findings,
			finding{"iam_role_administratoraccess_policy", "global", arn, role.Name, "high", status(role.AdministratorAccess)},
			finding{"iam_role_cross_service_confused_deputy_prevention", "global", arn, role.Name, "high", status(role.ConfusedDeputy)})
	}
	sort.Slice(findings, func(l, r int) bool {
		return findings[l].CheckID+"\x00"+findings[l].ResourceARN < findings[r].CheckID+"\x00"+findings[r].ResourceARN
	})
	encode := func(value any) json.RawMessage {
		encoded, err := json.Marshal(value)
		if err != nil {
			panic("demodata: " + err.Error())
		}
		return encoded
	}
	cartographySource := encode(map[string]any{"account_id": account, "managed_policies": managed, "roles": cartographyRoles})
	prowlerSource := encode(map[string]any{"account_id": account, "instances": []any{}, "roles": prowlerRoles})
	analyzer := &awsAnalyzer{
		cartography: encode(map[string]any{"policies": []any{}, "roles": resultRoles, "version": "0.139.1"}),
		prowler:     encode(map[string]any{"findings": findings, "version": "5.39.1"}),
	}

	built, err := request(integration, target, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/connection/demo-"+strings.ToLower(account), "aws_account")
	if err != nil {
		return Snapshot{}, err
	}
	inventory := awsdiscovery.CollectionInventory{
		Identity:            awsdiscovery.Identity{AccountID: account, PrincipalARN: "arn:aws:sts::" + account + ":assumed-role/zasp-discovery/demo"},
		CredentialExpiresAt: built.ObservationTime.Add(30 * time.Minute),
		CartographySource:   cartographySource, CartographyDigest: sha256.Sum256(cartographySource),
		ProwlerSource: prowlerSource, ProwlerDigest: sha256.Sum256(prowlerSource),
		AgentSource: agents, AgentDigest: sha256.Sum256(agents),
	}
	authority := awsdiscovery.CollectionInventoryAuthority{Scope: built.Scope, IntegrationID: built.IntegrationID, ConnectionID: built.ConnectionID, JobID: built.JobID, Attempt: built.Attempt, ObservedAt: built.ObservationTime}
	api, err := awsdiscovery.NewInventoryCollectionAPI(&awsCaller{inventory: inventory}, analyzer, authority, 10*time.Second)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %s: %v", ErrCollection, integration.Key, err)
	}
	artifacts, err := newArtifacts()
	if err != nil {
		return Snapshot{}, err
	}
	client, err := awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: CollectorVersion, ParserVersion: ParserVersion, ToolVersion: ToolVersion, Clock: clock})
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %s: %v", ErrCollection, integration.Key, err)
	}
	// The collector requires a credential of plausible length and never
	// stores it. This one opens nothing.
	outcome, err := client.CollectWithCredential(ctx, built, []byte("demo-collection-no-credential"))
	return finish(integration, outcome, err, nil)
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
