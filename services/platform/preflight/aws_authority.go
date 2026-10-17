package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/cloudreadiness"
)

func authorityRoles(c *AWSAuthorityConfig, inventory []awsRoleRequirement, d Deployment) (map[string]string, bool) {
	out := map[string]string{}
	used := map[string]bool{}
	known := map[string]bool{}
	for _, r := range inventory {
		known[r.purpose] = true
	}
	if c == nil || len(c.Roles) > len(inventory) {
		return nil, false
	}
	prefix := "arn:" + d.Partition + ":iam::" + d.AccountID + ":role/"
	for _, r := range c.Roles {
		if !known[r.Purpose] || out[r.Purpose] != "" || used[r.RoleARN] || !strings.HasPrefix(r.RoleARN, prefix) {
			return nil, false
		}
		name := strings.TrimPrefix(r.RoleARN, prefix)
		if name == "" || len(name) > 512 || strings.ContainsAny(name, " *?\r\n\t") || strings.HasSuffix(name, "/") {
			return nil, false
		}
		out[r.Purpose] = r.RoleARN
		used[r.RoleARN] = true
	}
	return out, true
}
func validAWSAuthority(c *AWSAuthorityConfig, d Deployment, attackLab bool) bool {
	if c == nil {
		return true
	}
	if c.Inspection.Kind != "operator_environment" && c.Inspection.Kind != "operator_file" {
		return false
	}
	if !strings.HasPrefix(c.Inspection.ExpectedRoleARN, "arn:"+d.Partition+":iam::"+d.AccountID+":role/") || c.Inspection.TokenFile != "" || c.Inspection.Namespace != "" || c.Inspection.ServiceAccount != "" {
		return false
	}
	if c.Inspection.Kind == "operator_file" && (c.Inspection.File == "" || !strings.HasPrefix(c.Inspection.File, "/")) || c.Inspection.Kind == "operator_environment" && c.Inspection.File != "" {
		return false
	}
	t := c.Cluster
	if !namePattern.MatchString(t.Name) || strings.Contains(t.Name, "/") || t.ARN != "arn:"+d.Partition+":eks:"+d.Region+":"+d.AccountID+":cluster/"+t.Name || !strings.HasPrefix(t.VPCID, "vpc-") || len(t.CASHA256) != 64 || len(t.ClusterUID) != 36 {
		return false
	}
	if b, e := hex.DecodeString(t.CASHA256); e != nil || len(b) != 32 || strings.ToLower(t.CASHA256) != t.CASHA256 {
		return false
	}
	for _, raw := range []string{t.Endpoint, t.Issuer} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
			return false
		}
	}
	if !strings.HasPrefix(t.Issuer, "https://oidc.eks."+d.Region+".amazonaws.com/id/") {
		return false
	}
	roles, ok := authorityRoles(c, requiredAWSRoleInventory(attackLab), d)
	if !ok {
		return false
	}
	if c.Selected != nil && (roles[c.Selected.Purpose] == "" || !dnsPattern.MatchString(c.Selected.PodName) || len(c.Selected.PodUID) != 36) {
		return false
	}
	return true
}
func primarySARole(subject string, roles map[string]string, inventory []awsRoleRequirement) string {
	if subject == "system:serviceaccount:agentsec:agentsec-api" {
		return roles["aws_iam_role.api"]
	}
	for _, r := range inventory {
		if r.subject == subject {
			return roles[r.purpose]
		}
	}
	return ""
}
func serviceAccountObservation(ctx context.Context, k KubernetesIdentityReader, subject, role string) (bool, error) {
	parts := strings.Split(subject, ":")
	if len(parts) != 4 || k == nil || role == "" {
		return false, ErrRejected
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sa, e := k.ServiceAccount(child, parts[2], parts[3])
	return e == nil && child.Err() == nil && sa.Namespace == parts[2] && sa.Name == parts[3] && sa.UID != "" && !sa.Deleting && sa.RoleARN == role, probeError(child, e)
}
func (r *Runner) inspectAWSAuthority(ctx context.Context, report *Report, c *AWSAuthorityConfig, k KubernetesIdentityReader) *awsAuthorityEvidence {
	evidence := &awsAuthorityEvidence{}
	inventory := requiredAWSRoleInventory(r.config.Features.AttackLab == "enabled")
	evidence.requiredRoles = len(inventory)
	for _, v := range inventory {
		if v.trustClass == "irsa" {
			evidence.requiredTrust++
		}
	}
	if c == nil || ctx == nil || k == nil || !validAWSAuthority(c, r.config.Deployment, r.config.Features.AttackLab == "enabled") {
		return evidence
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	inspector := *r
	inspector.config = r.config
	inspector.config.Credentials = c.Inspection
	credentials, err := inspector.credentials(bounded)
	if err != nil {
		return evidence
	}
	sdk := aws.Config{Region: r.config.Deployment.Region, HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		if credentials.CanExpire && !credentials.Expires.After(time.Now().Add(time.Minute)) {
			return aws.Credentials{}, ErrRejected
		}
		return credentials, nil
	}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	child, stop := context.WithTimeout(bounded, 10*time.Second)
	evidence.inspectionAttempted = true
	caller, err := sts.NewFromConfig(sdk).GetCallerIdentity(child, &sts.GetCallerIdentityInput{})
	matched := err == nil && child.Err() == nil && cloudreadiness.Role(caller, r.config.Deployment.Partition, r.config.Deployment.AccountID, c.Inspection.ExpectedRoleARN)
	r.authorityFailure(report, "iam_role", "sts:GetCallerIdentity", c.Inspection.ExpectedRoleARN, probeError(child, err), matched)
	stop()
	if !matched {
		return evidence
	}
	child, stop = context.WithTimeout(bounded, 10*time.Second)
	cluster, err := eks.NewFromConfig(sdk).DescribeCluster(child, &eks.DescribeClusterInput{Name: aws.String(c.Cluster.Name)})
	matched = err == nil && child.Err() == nil && cluster != nil && cluster.Cluster != nil
	if matched {
		actual := cluster.Cluster
		t := c.Cluster
		matched = aws.ToString(actual.Name) == t.Name && aws.ToString(actual.Arn) == t.ARN && string(actual.Status) == "ACTIVE" && aws.ToString(actual.Version) == "1.34" && aws.ToString(actual.Endpoint) == t.Endpoint && actual.Identity != nil && actual.Identity.Oidc != nil && aws.ToString(actual.Identity.Oidc.Issuer) == t.Issuer && actual.ResourcesVpcConfig != nil && aws.ToString(actual.ResourcesVpcConfig.VpcId) == t.VPCID && actual.ResourcesVpcConfig.EndpointPrivateAccess && !actual.ResourcesVpcConfig.EndpointPublicAccess
		if matched && actual.CertificateAuthority != nil {
			b, e := base64.StdEncoding.DecodeString(aws.ToString(actual.CertificateAuthority.Data))
			digest := sha256.Sum256(b)
			matched = e == nil && len(b) > 0 && hex.EncodeToString(digest[:]) == t.CASHA256
		} else {
			matched = false
		}
	}
	r.authorityFailure(report, "eks_version_supported", "eks:DescribeCluster", c.Cluster.ARN, probeError(child, err), matched)
	stop()
	if !matched {
		r.record(report, "eks_version_supported", false, "cluster_binding_unavailable", "operator", c.Cluster.ARN, true)
		return evidence
	}
	child, stop = context.WithTimeout(bounded, 10*time.Second)
	uid, e := k.ClusterUID(child)
	matched = e == nil && child.Err() == nil && uid == c.Cluster.ClusterUID
	r.authorityFailure(report, "irsa_trust", "kubernetes:GetNamespace", "kube-system", probeError(child, e), matched)
	stop()
	if !matched {
		return evidence
	}
	evidence.clusterVerified = true
	r.record(report, "eks_version_supported", true, "", "operator", c.Cluster.ARN, true)
	roles, _ := authorityRoles(c, inventory, r.config.Deployment)
	providerARN := "arn:" + r.config.Deployment.Partition + ":iam::" + r.config.Deployment.AccountID + ":oidc-provider/" + strings.TrimPrefix(c.Cluster.Issuer, "https://")
	api := iam.NewFromConfig(sdk)
	child, stop = context.WithTimeout(bounded, 10*time.Second)
	oidc, err := api.GetOpenIDConnectProvider(child, &iam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: aws.String(providerARN)})
	oidcOK := err == nil && child.Err() == nil && oidc != nil && aws.ToString(oidc.Url) == strings.TrimPrefix(c.Cluster.Issuer, "https://")
	audience := false
	if oidc != nil {
		for _, a := range oidc.ClientIDList {
			audience = audience || a == "sts.amazonaws.com"
		}
	}
	oidcOK = oidcOK && audience
	r.authorityFailure(report, "irsa_trust", "iam:GetOpenIDConnectProvider", providerARN, probeError(child, err), oidcOK)
	stop()
	saCache := map[string]bool{}
	for _, required := range inventory {
		roleARN := roles[required.purpose]
		if roleARN == "" {
			continue
		}
		name := roleARN[strings.LastIndex(roleARN, "/")+1:]
		child, stop = context.WithTimeout(bounded, 10*time.Second)
		out, err := api.GetRole(child, &iam.GetRoleInput{RoleName: aws.String(name)})
		ok := err == nil && child.Err() == nil && out != nil && out.Role != nil && aws.ToString(out.Role.Arn) == roleARN && aws.ToString(out.Role.RoleName) == name && aws.ToString(out.Role.RoleId) != ""
		r.authorityFailure(report, "iam_role", "iam:GetRole", roleARN, probeError(child, err), ok)
		stop()
		if !ok {
			continue
		}
		evidence.observedRoles++
		if required.trustClass != "irsa" {
			continue
		}
		trust := oidcOK && exactIRSATrustPolicy(aws.ToString(out.Role.AssumeRolePolicyDocument), c.Cluster.Issuer, required.subject, providerARN)
		saOK, seen := saCache[required.subject]
		if !seen {
			var saErr error
			saOK, saErr = serviceAccountObservation(bounded, k, required.subject, primarySARole(required.subject, roles, inventory))
			parts := strings.Split(required.subject, ":")
			r.authorityFailure(report, "irsa_trust", "kubernetes:GetServiceAccount", parts[2]+"/"+parts[3], saErr, saOK)
			saCache[required.subject] = saOK
		}
		if trust && saOK {
			evidence.observedTrust++
		}
		r.authorityFailure(report, "irsa_trust", "iam:GetRole", roleARN, nil, trust)
	}
	r.record(report, "iam_role", evidence.observedRoles == evidence.requiredRoles, "required_role_inventory_incomplete", "operator", c.Roles, true)
	r.record(report, "irsa_trust", evidence.observedTrust == evidence.requiredTrust, "required_trust_inventory_incomplete", "operator", c.Cluster.ARN, true)
	return evidence
}
func (r *Runner) authorityFailure(report *Report, name, operation string, target any, err error, matched bool) {
	if matched {
		return
	}
	hints := map[string]string{"sts:GetCallerIdentity": "verify the explicit inspector identity and network; no identity-policy allow is required", "eks:DescribeCluster": "inspect eks:DescribeCluster on the exact selected cluster", "iam:GetRole": "inspect iam:GetRole on the exact original deployment role and its closed trust", "iam:GetOpenIDConnectProvider": "inspect iam:GetOpenIDConnectProvider on the exact selected cluster OIDC provider", "kubernetes:GetNamespace": "verify GET on the fixed kube-system Namespace and exact selected cluster UID", "kubernetes:GetServiceAccount": "verify GET on this fixed deployment ServiceAccount and its primary role annotation", "kubernetes:GetPod": "verify GET on the one selected Pod and its exact current UID, service account and projected audience"}
	hint, ok := hints[operation]
	if !ok {
		return
	}
	for i := range report.Checks {
		for j := range report.Checks[i].Observations {
			o := &report.Checks[i].Observations[j]
			if o.Name == name && len(o.Failures) < 48 {
				outcome := failureOutcome(err)
				var kubeError *awsKubernetesOutcomeError
				if errors.As(err, &kubeError) {
					outcome = kubeError.outcome
				}
				o.Failures = append(o.Failures, Failure{Operation: operation, Hint: hint, TargetDigest: singleTargetDigest(target), Outcome: outcome})
				return
			}
		}
	}
}
