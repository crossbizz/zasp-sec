package preflight

import (
	"net/netip"
	"regexp"
	"strings"
)

var attackLabSubnetID = regexp.MustCompile(`^subnet-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var attackLabGroupID = regexp.MustCompile(`^sg-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var attackLabRouteID = regexp.MustCompile(`^rtb-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var attackLabEndpointID = regexp.MustCompile(`^vpce-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var attackLabUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var attackLabCNI = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-eksbuild\.[0-9]+$`)
var attackLabSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validAttackLabCIDRs(values []string, private bool) bool {
	maximum, minBits := 16, 16
	if private {
		maximum, minBits = 8, 24
	}
	if len(values) < 1 || len(values) > maximum {
		return false
	}
	seen := map[string]bool{}
	for _, raw := range values {
		p, e := netip.ParsePrefix(raw)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < minBits || seen[raw] {
			return false
		}
		seen[raw] = true
		b := p.Addr().As4()
		isPrivate := b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168
		if private {
			if !isPrivate {
				return false
			}
		} else if isPrivate || b[0] == 0 || b[0] == 127 || b[0] == 169 && b[1] == 254 || b[0] >= 224 {
			return false
		}
	}
	return true
}
func validAWSAttackLabConfig(c Config) bool {
	if c.AWSAuthority == nil || c.AWSAuthority.Fargate == nil {
		return true
	}
	t := c.AWSAuthority.Fargate
	prefix := "arn:" + c.Deployment.Partition + ":eks:" + c.Deployment.Region + ":" + c.Deployment.AccountID + ":fargateprofile/" + c.AWSAuthority.Cluster.Name + "/attack-lab/"
	if !strings.HasPrefix(t.ProfileARN, prefix) || !attackLabUUID.MatchString(strings.TrimPrefix(t.ProfileARN, prefix)) || !attackLabCNI.MatchString(t.ExpectedCNIAddonVersion) || len(t.ExpectedCNIAddonVersion) > 64 || !attackLabSHA256.MatchString(t.ProxyCASHA256) || strings.Trim(t.ProxyCASHA256, "0") == "" || !attackLabRouteID.MatchString(t.IsolatedRouteTableID) {
		return false
	}
	if len(t.SubnetIDs) != 2 || len(t.ProductSubnetIDs) < 2 || len(t.ProductSubnetIDs) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range append(append([]string{}, t.SubnetIDs...), t.ProductSubnetIDs...) {
		if !attackLabSubnetID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, id := range []string{t.RunnerSecurityGroupID, t.ProxySecurityGroupID, t.ImagePullSecurityGroupID, t.EndpointSecurityGroupID} {
		if !attackLabGroupID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	purposes := []string{"ecr.api", "ecr.dkr", "kms", "logs", "secretsmanager", "sqs", "sts", "product-s3", "image-s3"}
	if len(t.EndpointIDs) != len(purposes) {
		return false
	}
	for _, purpose := range purposes {
		id := t.EndpointIDs[purpose]
		if !attackLabEndpointID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	if !arnIn(c, t.RunnerBoundaryPolicyARN, "iam", "") || !strings.HasPrefix(strings.SplitN(t.RunnerBoundaryPolicyARN, ":", 6)[5], "policy/") || !namePattern.MatchString(strings.TrimPrefix(strings.SplitN(t.RunnerBoundaryPolicyARN, ":", 6)[5], "policy/")) || !validAttackLabCIDRs(t.TargetCIDRs, false) || !validAttackLabCIDRs(t.DatabaseCIDRs, true) {
		return false
	}
	if c.Features.AttackLab == "enabled" {
		roles, ok := authorityRoles(c.AWSAuthority, requiredAWSRoleInventory(true), c.Deployment)
		if !ok || roles["aws_iam_role.attack_lab_pod"] == "" || !strings.HasSuffix(roles["aws_iam_role.attack_lab_runner_test"], "-attack-lab-runner-test") {
			return false
		}
	}
	return true
}
