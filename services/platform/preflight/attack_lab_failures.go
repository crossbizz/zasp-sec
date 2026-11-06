package preflight

import "errors"

// Only closed operation labels, target digests and outcomes reach the report.
// Dependency errors remain private to this run; provider messages are not read.
func attackLabFailures(operation string, targets []string, err error) []Failure {
	hints := map[string]string{
		"eks:DescribeFargateProfile":                "inspect eks:DescribeFargateProfile on the exact profile and its configured bindings",
		"eks:DescribeAddon":                         "inspect eks:DescribeAddon on this cluster vpc-cni addon and exact build/strict settings",
		"iam:GetRole":                               "inspect iam:GetRole on this exact runner or execution role and its existing isolation boundary or trust",
		"iam:GetPolicy":                             "inspect iam:GetPolicy on this exact existing runner boundary",
		"iam:GetPolicyVersion":                      "inspect iam:GetPolicyVersion on the existing boundary default version and preserve DenyAll",
		"iam:GetRolePolicy":                         "inspect iam:GetRolePolicy on this runner inline deny policy; do not grant product access",
		"iam:ListAttachedRolePolicies":              "inspect iam:ListAttachedRolePolicies on the execution role and its exact AWS managed execution policy",
		"ec2:DescribeVpcs":                          "inspect ec2:DescribeVpcs for this selected VPC",
		"ec2:DescribeSubnets":                       "inspect ec2:DescribeSubnets for this exact configured subnet",
		"ec2:DescribeRouteTables":                   "inspect ec2:DescribeRouteTables in this selected VPC and exact isolated/main route bindings",
		"ec2:DescribePrefixLists":                   "inspect ec2:DescribePrefixLists for this selected regional S3 prefix list",
		"ec2:DescribeSecurityGroups":                "inspect ec2:DescribeSecurityGroups for this exact configured group",
		"ec2:DescribeVpcEndpoints":                  "inspect ec2:DescribeVpcEndpoints for this exact configured endpoint",
		"kubernetes:GetVersion":                     "verify GET on the fixed Kubernetes version endpoint and supported cluster version",
		"kubernetes:GetNamespace":                   "verify GET on the fixed attack-lab Namespace and exact isolation labels",
		"kubernetes:GetServiceAccount":              "verify GET on the fixed runner ServiceAccount and its existing isolated role annotation",
		"kubernetes:GetConfigMap":                   "verify GET on the fixed immutable proxy CA ConfigMap and intended CA digest",
		"kubernetes:GetSecurityGroupPolicy":         "verify GET on this fixed SecurityGroupPolicy and its exact selector and group",
		"configuration:ValidateAttackLabTopology":   "compare observed VPC, subnets, routes, endpoint bindings and security groups with the exact deployment configuration; metadata does not prove packet enforcement",
		"configuration:ValidateAttackLabKubernetes": "compare the observed fixed Kubernetes prerequisites, isolation policies and immutable CA with the exact deployment configuration",
	}
	hint, ok := hints[operation]
	if !ok {
		return nil
	}
	outcome := failureOutcome(err)
	var kube *awsKubernetesOutcomeError
	if errors.As(err, &kube) {
		outcome = kube.outcome
	}
	out := []Failure{}
	seen := map[string]bool{}
	for _, target := range targets {
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		if len(out) == 32 {
			break
		}
		out = append(out, Failure{Operation: operation, Hint: hint, TargetDigest: singleTargetDigest(target), Outcome: outcome})
	}
	return out
}
