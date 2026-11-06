package preflight

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/cloudreadiness"
)

// This private value is returned only by this process's successful STS exchange.
// It must never be accepted from configuration, a report, a token's unverified
// claims, an artifact or an earlier run. It proves no Pod UID or revocation fact.
type awsWebIdentityProof struct {
	subject, audience, provider, requestedRoleARN, assumedRoleARN string
	expires                                                       time.Time
}

func (r *Runner) exchangeAWSWebIdentity(ctx context.Context, roleARN string, token []byte) (aws.Credentials, *awsWebIdentityProof, error) {
	if ctx == nil || r == nil || r.http == nil || len(token) < 64 || len(token) > 16384 {
		return aws.Credentials{}, nil, ErrRejected
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	api := sts.NewFromConfig(aws.Config{Region: r.config.Deployment.Region, HTTPClient: r.http, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }})
	out, err := api.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String("zasp-preflight-inspector"), WebIdentityToken: aws.String(string(token)), DurationSeconds: aws.Int32(900)})
	now := time.Now().UTC()
	if err != nil || bounded.Err() != nil || out == nil || out.Credentials == nil || out.Credentials.Expiration == nil || !out.Credentials.Expiration.After(now.Add(time.Minute)) || out.Credentials.Expiration.After(now.Add(16*time.Minute)) {
		return aws.Credentials{}, nil, ErrRejected
	}
	sc := out.Credentials
	credentials := aws.Credentials{AccessKeyID: aws.ToString(sc.AccessKeyId), SecretAccessKey: aws.ToString(sc.SecretAccessKey), SessionToken: aws.ToString(sc.SessionToken), CanExpire: true, Expires: sc.Expiration.UTC(), Source: "zasp-preflight-web-identity"}
	if !validCredentialValue(credentials.AccessKeyID, 8, 128) || !validCredentialValue(credentials.SecretAccessKey, 8, 256) || !validCredentialValue(credentials.SessionToken, 8, 16384) {
		return aws.Credentials{}, nil, ErrRejected
	}
	// Preserve original usable-credential behavior if the provider omitted new
	// observation fields, but do not mint an identity proof from missing facts.
	if out.AssumedRoleUser == nil || aws.ToString(out.AssumedRoleUser.Arn) == "" || aws.ToString(out.SubjectFromWebIdentityToken) == "" || aws.ToString(out.Audience) == "" || aws.ToString(out.Provider) == "" {
		return credentials, nil, nil
	}
	proof := &awsWebIdentityProof{subject: aws.ToString(out.SubjectFromWebIdentityToken), audience: aws.ToString(out.Audience), provider: aws.ToString(out.Provider), requestedRoleARN: roleARN, assumedRoleARN: aws.ToString(out.AssumedRoleUser.Arn), expires: credentials.Expires}
	return credentials, proof, nil
}
func (r *Runner) observeSelectedAWSBinding(ctx context.Context, report *Report, c *AWSAuthorityConfig, e *awsAuthorityEvidence, p *awsWebIdentityProof, k KubernetesIdentityReader) {
	if c == nil || c.Selected == nil || e == nil || p == nil || k == nil || ctx == nil || ctx.Err() != nil || !e.clusterVerified || r.config.Credentials.Kind != "workload_web_identity" {
		return
	}
	inventory := requiredAWSRoleInventory(r.config.Features.AttackLab == "enabled")
	roles, ok := authorityRoles(c, inventory, r.config.Deployment)
	if !ok {
		return
	}
	subject := ""
	for _, v := range inventory {
		if v.purpose == c.Selected.Purpose && v.trustClass == "irsa" {
			subject = v.subject
		}
	}
	parts := strings.Split(subject, ":")
	if len(parts) != 4 {
		return
	}
	role := roles[c.Selected.Purpose]
	// cloudreadiness.Role validates the exact assumed-role form against the
	// intended IAM role, including partition/account. No JWT parsing is involved.
	assumed := &sts.GetCallerIdentityOutput{Account: aws.String(r.config.Deployment.AccountID), Arn: aws.String(p.assumedRoleARN)}
	e.selectedExchangeVerified = p.subject == subject && p.audience == "sts.amazonaws.com" && p.provider == c.Cluster.Issuer && p.requestedRoleARN == role && r.config.Credentials.ExpectedRoleARN == role && r.config.Credentials.Namespace == parts[2] && r.config.Credentials.ServiceAccount == parts[3] && p.expires.After(time.Now().Add(time.Minute)) && cloudreadiness.Role(assumed, r.config.Deployment.Partition, r.config.Deployment.AccountID, role)
	if !e.selectedExchangeVerified {
		return
	}
	saOK, saErr := serviceAccountObservation(ctx, k, subject, primarySARole(subject, roles, inventory))
	r.authorityFailure(report, "irsa_binding", "kubernetes:GetServiceAccount", parts[2]+"/"+parts[3], saErr, saOK)
	if !saOK {
		r.record(report, "irsa_binding", false, "selected_service_account_or_inventory_unavailable", "workload", c.Cluster.ARN, true)
		return
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pod, err := k.Pod(child, parts[2], c.Selected.PodName)
	e.selectedSpecVerified = err == nil && child.Err() == nil && !pod.Deleting && pod.Namespace == parts[2] && pod.Name == c.Selected.PodName && pod.UID == c.Selected.PodUID && pod.ServiceAccount == parts[3] && pod.Phase == "Running" && pod.ProjectedAudience == "sts.amazonaws.com"
	r.authorityFailure(report, "irsa_binding", "kubernetes:GetPod", parts[2]+"/"+c.Selected.PodName, probeError(child, err), e.selectedSpecVerified)
	complete := e.selectedExchangeVerified && e.selectedSpecVerified && e.observedRoles == e.requiredRoles && e.observedTrust == e.requiredTrust
	r.record(report, "irsa_binding", complete, "selected_service_account_or_inventory_unavailable", "workload", c.Cluster.ARN, true)
}
