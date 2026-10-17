package preflight

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func equalClosedStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range expected {
		if v == "" || seen[v] {
			return false
		}
		seen[v] = true
	}
	for _, v := range actual {
		if !seen[v] {
			return false
		}
		delete(seen, v)
	}
	return len(seen) == 0
}
func (r *Runner) observeAttackLabProfile(ctx context.Context, sdk aws.Config, authority *AWSAuthorityConfig, target *AWSAttackLabTarget, enabled bool) *attackLabEvidence {
	evidence := &attackLabEvidence{}
	if !enabled || ctx == nil || ctx.Err() != nil || authority == nil || target == nil {
		return evidence
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	api := eks.NewFromConfig(sdk)
	call, stop := context.WithTimeout(bounded, 10*time.Second)
	operation := "eks:DescribeFargateProfile"
	failureTarget := target.ProfileARN
	var failureErr error
	defer func() {
		if evidence.profileAttempted && !evidence.profile {
			evidence.failures = attackLabFailures(operation, []string{failureTarget}, failureErr)
		}
	}()
	evidence.profileAttempted = true
	result, e := api.DescribeFargateProfile(call, &eks.DescribeFargateProfileInput{ClusterName: aws.String(authority.Cluster.Name), FargateProfileName: aws.String("attack-lab")})
	failureErr = probeError(call, e)
	matched := e == nil && call.Err() == nil && result != nil && result.FargateProfile != nil
	if matched {
		p := result.FargateProfile
		executionRole := ""
		for _, role := range authority.Roles {
			if role.Purpose == "aws_iam_role.attack_lab_pod" {
				executionRole = role.RoleARN
			}
		}
		matched = executionRole != "" && aws.ToString(p.ClusterName) == authority.Cluster.Name && aws.ToString(p.FargateProfileName) == "attack-lab" && aws.ToString(p.FargateProfileArn) == target.ProfileARN && aws.ToString(p.PodExecutionRoleArn) == executionRole && string(p.Status) == "ACTIVE" && equalClosedStrings(p.Subnets, target.SubnetIDs) && len(p.Selectors) == 1 && aws.ToString(p.Selectors[0].Namespace) == "zasp-attack-lab" && reflect.DeepEqual(p.Selectors[0].Labels, map[string]string{"zasp.io/execution": "attack-lab"}) && (p.Health == nil || len(p.Health.Issues) == 0)
	}
	stop()
	if !matched {
		return evidence
	}
	call, stop = context.WithTimeout(bounded, 10*time.Second)
	defer stop()
	operation = "eks:DescribeAddon"
	failureTarget = authority.Cluster.ARN + "/addons/vpc-cni"
	addon, e := api.DescribeAddon(call, &eks.DescribeAddonInput{ClusterName: aws.String(authority.Cluster.Name), AddonName: aws.String("vpc-cni")})
	failureErr = probeError(call, e)
	if e != nil || call.Err() != nil || addon == nil || addon.Addon == nil {
		return evidence
	}
	a := addon.Addon
	prefix := "arn:" + r.config.Deployment.Partition + ":eks:" + r.config.Deployment.Region + ":" + r.config.Deployment.AccountID + ":addon/" + authority.Cluster.Name + "/vpc-cni/"
	if aws.ToString(a.ClusterName) != authority.Cluster.Name || aws.ToString(a.AddonName) != "vpc-cni" || !strings.HasPrefix(aws.ToString(a.AddonArn), prefix) || len(strings.TrimPrefix(aws.ToString(a.AddonArn), prefix)) != 36 || aws.ToString(a.AddonVersion) != target.ExpectedCNIAddonVersion || string(a.Status) != "ACTIVE" || a.Health != nil && len(a.Health.Issues) != 0 {
		return evidence
	}
	raw := []byte(aws.ToString(a.ConfigurationValues))
	if len(raw) > 32768 || !uniqueProviderJSON(raw) {
		return evidence
	}
	top, ok := exactObjectKeys(raw, "env")
	if !ok || len(top) != 1 {
		return evidence
	}
	env, ok := exactObjectKeys(top["env"], "ENABLE_POD_ENI", "POD_SECURITY_GROUP_ENFORCING_MODE")
	evidence.profile = ok && len(env) == 2 && scalarPolicyString(env["ENABLE_POD_ENI"], "true") && scalarPolicyString(env["POD_SECURITY_GROUP_ENFORCING_MODE"], "strict")
	return evidence
}
func exactRunnerDenyAllPolicy(raw string) bool {
	if len(raw) == 0 || len(raw) > 65536 {
		return false
	}
	document := raw
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		var e error
		document, e = url.QueryUnescape(raw)
		if e != nil {
			return false
		}
	}
	if len(document) > 32768 || !uniqueProviderJSON([]byte(document)) {
		return false
	}
	top, ok := exactObjectKeys([]byte(document), "Version", "Statement", "Id")
	if !ok || !scalarPolicyString(top["Version"], "2012-10-17") {
		return false
	}
	var statements []json.RawMessage
	if json.Unmarshal(top["Statement"], &statements) != nil || len(statements) != 1 {
		return false
	}
	row, ok := exactObjectKeys(statements[0], "Sid", "Effect", "Action", "Resource")
	return ok && scalarPolicyString(row["Effect"], "Deny") && exactPolicyString(row["Action"], "*") && exactPolicyString(row["Resource"], "*")
}
