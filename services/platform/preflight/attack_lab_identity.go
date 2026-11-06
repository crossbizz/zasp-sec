package preflight

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func exactAttackLabExecutionTrust(raw string, c Config, cluster string) bool {
	if len(raw) == 0 || len(raw) > 65536 {
		return false
	}
	doc := raw
	if !strings.HasPrefix(strings.TrimSpace(doc), "{") {
		var e error
		doc, e = url.QueryUnescape(raw)
		if e != nil {
			return false
		}
	}
	if len(doc) > 32768 || !uniqueProviderJSON([]byte(doc)) {
		return false
	}
	top, ok := exactObjectKeys([]byte(doc), "Version", "Statement", "Id")
	if !ok || !scalarPolicyString(top["Version"], "2012-10-17") {
		return false
	}
	var statements []json.RawMessage
	if json.Unmarshal(top["Statement"], &statements) != nil || len(statements) != 1 {
		return false
	}
	row, ok := exactObjectKeys(statements[0], "Sid", "Effect", "Action", "Principal", "Condition")
	if !ok || !scalarPolicyString(row["Effect"], "Allow") || !exactPolicyString(row["Action"], "sts:AssumeRole") {
		return false
	}
	principal, ok := exactObjectKeys(row["Principal"], "Service")
	if !ok || len(principal) != 1 || !exactPolicyString(principal["Service"], "eks-fargate-pods.amazonaws.com") {
		return false
	}
	conditions, ok := exactObjectKeys(row["Condition"], "ArnLike", "StringEquals")
	if !ok || len(conditions) != 2 {
		return false
	}
	account, ok := exactObjectKeys(conditions["StringEquals"], "aws:SourceAccount")
	if !ok || len(account) != 1 || !exactPolicyString(account["aws:SourceAccount"], c.Deployment.AccountID) {
		return false
	}
	source, ok := exactObjectKeys(conditions["ArnLike"], "aws:SourceArn")
	expected := "arn:" + c.Deployment.Partition + ":eks:" + c.Deployment.Region + ":" + c.Deployment.AccountID + ":fargateprofile/" + cluster + "/*"
	return ok && len(source) == 1 && exactPolicyString(source["aws:SourceArn"], expected)
}
func (r *Runner) observeAttackLabIsolationIdentity(ctx context.Context, sdk aws.Config, authority *AWSAuthorityConfig, target *AWSAttackLabTarget, enabled bool) *attackLabEvidence {
	evidence := &attackLabEvidence{}
	if !enabled || ctx == nil || ctx.Err() != nil || authority == nil || target == nil || target.RunnerBoundaryPolicyARN == "" {
		return evidence
	}
	roles, ok := authorityRoles(authority, requiredAWSRoleInventory(true), r.config.Deployment)
	if !ok {
		return evidence
	}
	runnerARN, podARN := roles["aws_iam_role.attack_lab_runner_test"], roles["aws_iam_role.attack_lab_pod"]
	if runnerARN == "" || podARN == "" || runnerARN == podARN {
		return evidence
	}
	runnerName := runnerARN[strings.LastIndex(runnerARN, "/")+1:]
	podName := podARN[strings.LastIndex(podARN, "/")+1:]
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	api := iam.NewFromConfig(sdk)
	call, stop := context.WithTimeout(bounded, 10*time.Second)
	operation := "iam:GetRole"
	failureTarget := runnerARN
	var failureErr error
	defer func() {
		if evidence.runnerAttempted && !evidence.runner {
			evidence.failures = attackLabFailures(operation, []string{failureTarget}, failureErr)
		}
	}()
	evidence.runnerAttempted = true
	runner, e := api.GetRole(call, &iam.GetRoleInput{RoleName: aws.String(runnerName)})
	failureErr = probeError(call, e)
	matched := e == nil && call.Err() == nil && runner != nil && runner.Role != nil
	if matched {
		role := runner.Role
		matched = aws.ToString(role.Arn) == runnerARN && aws.ToString(role.RoleName) == runnerName && aws.ToString(role.RoleId) != "" && role.PermissionsBoundary != nil && aws.ToString(role.PermissionsBoundary.PermissionsBoundaryArn) == target.RunnerBoundaryPolicyARN && string(role.PermissionsBoundary.PermissionsBoundaryType) == "PermissionsBoundaryPolicy"
	}
	stop()
	if !matched {
		return evidence
	}
	call, stop = context.WithTimeout(bounded, 10*time.Second)
	operation = "iam:GetPolicy"
	failureTarget = target.RunnerBoundaryPolicyARN
	policy, e := api.GetPolicy(call, &iam.GetPolicyInput{PolicyArn: aws.String(target.RunnerBoundaryPolicyARN)})
	failureErr = probeError(call, e)
	matched = e == nil && call.Err() == nil && policy != nil && policy.Policy != nil && aws.ToString(policy.Policy.Arn) == target.RunnerBoundaryPolicyARN && aws.ToString(policy.Policy.DefaultVersionId) != ""
	stop()
	if !matched {
		return evidence
	}
	version := aws.ToString(policy.Policy.DefaultVersionId)
	call, stop = context.WithTimeout(bounded, 10*time.Second)
	operation = "iam:GetPolicyVersion"
	failureTarget = target.RunnerBoundaryPolicyARN
	document, e := api.GetPolicyVersion(call, &iam.GetPolicyVersionInput{PolicyArn: aws.String(target.RunnerBoundaryPolicyARN), VersionId: aws.String(version)})
	failureErr = probeError(call, e)
	matched = e == nil && call.Err() == nil && document != nil && document.PolicyVersion != nil && document.PolicyVersion.IsDefaultVersion && aws.ToString(document.PolicyVersion.VersionId) == version && exactRunnerDenyAllPolicy(aws.ToString(document.PolicyVersion.Document))
	stop()
	if !matched {
		return evidence
	}
	call, stop = context.WithTimeout(bounded, 10*time.Second)
	inlineName := runnerName + "-deny"
	operation = "iam:GetRolePolicy"
	failureTarget = runnerARN + "/inline/" + inlineName
	inline, e := api.GetRolePolicy(call, &iam.GetRolePolicyInput{RoleName: aws.String(runnerName), PolicyName: aws.String(inlineName)})
	failureErr = probeError(call, e)
	matched = e == nil && call.Err() == nil && inline != nil && aws.ToString(inline.RoleName) == runnerName && aws.ToString(inline.PolicyName) == inlineName && exactRunnerDenyAllPolicy(aws.ToString(inline.PolicyDocument))
	stop()
	if !matched {
		return evidence
	}
	call, stop = context.WithTimeout(bounded, 10*time.Second)
	operation = "iam:GetRole"
	failureTarget = podARN
	pod, e := api.GetRole(call, &iam.GetRoleInput{RoleName: aws.String(podName)})
	failureErr = probeError(call, e)
	matched = e == nil && call.Err() == nil && pod != nil && pod.Role != nil && aws.ToString(pod.Role.Arn) == podARN && aws.ToString(pod.Role.RoleName) == podName && aws.ToString(pod.Role.RoleId) != "" && exactAttackLabExecutionTrust(aws.ToString(pod.Role.AssumeRolePolicyDocument), r.config, authority.Cluster.Name)
	stop()
	if !matched {
		return evidence
	}
	// IAM may return fewer than MaxItems while still truncated. Follow the actual
	// cursor with a hard cap; never accept an empty/repeated/ignored continuation.
	marker := ""
	seen := map[string]bool{}
	count := 0
	expected := "arn:" + r.config.Deployment.Partition + ":iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
	for page := 0; page < 4; page++ {
		input := &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(podName), MaxItems: aws.Int32(100)}
		if marker != "" {
			input.Marker = aws.String(marker)
		}
		call, stop = context.WithTimeout(bounded, 10*time.Second)
		operation = "iam:ListAttachedRolePolicies"
		failureTarget = podARN
		attached, e := api.ListAttachedRolePolicies(call, input)
		failureErr = probeError(call, e)
		matched = e == nil && call.Err() == nil && attached != nil
		stop()
		if !matched {
			return evidence
		}
		if len(attached.AttachedPolicies) > 100 {
			return evidence
		}
		for _, p := range attached.AttachedPolicies {
			count++
			if count > 1 || aws.ToString(p.PolicyArn) != expected || aws.ToString(p.PolicyName) != "AmazonEKSFargatePodExecutionRolePolicy" {
				return evidence
			}
		}
		next := aws.ToString(attached.Marker)
		if !attached.IsTruncated {
			if next != "" {
				return evidence
			}
			evidence.runner = count == 1
			return evidence
		}
		if next == "" || len(next) > 1024 || seen[next] {
			return evidence
		}
		seen[next] = true
		marker = next
	}
	return evidence
}
