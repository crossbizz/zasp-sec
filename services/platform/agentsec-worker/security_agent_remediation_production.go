package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// remediationCloudSession is the role session name of the action worker's
// own (Zasp-side) identity when it performs provider remediations.
const remediationCloudSession = "zasp-security-agent-remediation"

// validRemediationWorkerConfig reports whether the remediation settings of
// the action worker are absent (no remediation is performed) or complete.
func validRemediationWorkerConfig(config workerRuntimeConfig) bool {
	if config.RemediationRoleARN == "" && config.RemediationTokenFile == "" && config.RemediationSecretPrefix == "" {
		return true
	}
	return discoveryCloudRolePattern.MatchString(config.RemediationRoleARN) && config.RemediationTokenFile == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" &&
		validDiscoverySecretRoot(config.RemediationSecretPrefix) && discoveryRegionPattern.MatchString(config.AWSRegion)
}

// productionRemediationClientFactory builds provider clients for a claimed
// remediation. The worker's own identity reads the integration's external ID
// (the same secret discovery uses, by reference) and assumes the remediation
// role the claim names. The discovery role is not known here and is never
// assumed: PostgreSQL refuses a remediation role equal to the read role.
type productionRemediationClientFactory struct {
	cloud      *productionDiscoveryCloudAuthority
	secrets    discoverySecretReader
	assumeRole discoveryAssumeRoleAPI
	clock      func() time.Time
}

func newProductionRemediationClientFactory(config workerRuntimeConfig) (*productionRemediationClientFactory, error) {
	if !validRemediationWorkerConfig(config) || config.RemediationRoleARN == "" {
		return nil, errRuntimeUnavailable
	}
	timeout := minDuration(config.LeaseDuration/3, 20*time.Second)
	clock := func() time.Time { return time.Now().UTC() }
	cloud, err := newProductionDiscoveryCloudAuthority(productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.RemediationRoleARN, TokenFile: config.RemediationTokenFile, SecretRoot: config.RemediationSecretPrefix, Timeout: timeout, Clock: clock, Session: remediationCloudSession})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	secrets, err := newDiscoverySecretsManagerReader(cloud.secrets, config.RemediationSecretPrefix, timeout)
	if err != nil {
		_ = cloud.Close()
		return nil, errRuntimeUnavailable
	}
	return &productionRemediationClientFactory{cloud: cloud, secrets: secrets, assumeRole: cloud.assumeRole, clock: clock}, nil
}

func (factory *productionRemediationClientFactory) Close() error {
	if factory == nil || factory.cloud == nil {
		return nil
	}
	return factory.cloud.Close()
}

func (factory *productionRemediationClientFactory) RemediationClients(ctx context.Context, claim apiserver.ProviderRemediationClaim) (remediationProviderClients, error) {
	if factory == nil || factory.cloud == nil || factory.secrets == nil || factory.assumeRole == nil || ctx == nil || !apiserver.ValidProviderRemediationClaim(claim) {
		return remediationProviderClients{}, errWorkerExecution
	}
	externalID, err := factory.secrets.ResolveDiscoverySecret(ctx, claim.ExternalIDReference)
	if err != nil || !validDiscoveryOpaqueSecret(externalID, 16, 256) {
		clear(externalID)
		return remediationProviderClients{}, errWorkerExecution
	}
	digest := sha256.Sum256([]byte(claim.OrganizationID + "\x1f" + claim.WorkspaceID + "\x1f" + claim.EnvironmentID + "\x1f" + claim.RunID + "\x1f" + claim.StepID))
	duration := int32(900)
	externalIDText := string(externalID)
	output, assumeErr := factory.assumeRole.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: aws.String(claim.RemediationRoleARN), RoleSessionName: aws.String("zasp-remediation-" + hex.EncodeToString(digest[:12])), ExternalId: aws.String(externalIDText), DurationSeconds: &duration}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	externalIDText = ""
	clear(externalID)
	if assumeErr != nil || ctx.Err() != nil {
		var provider smithy.APIError
		if ctx.Err() == nil && errors.As(assumeErr, &provider) && provider.ErrorCode() == "AccessDenied" {
			return remediationProviderClients{}, errRemediationRoleDenied
		}
		return remediationProviderClients{}, errWorkerExecution
	}
	if output == nil || output.Credentials == nil || output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil || output.Credentials.Expiration == nil {
		return remediationProviderClients{}, errWorkerExecution
	}
	credentials := aws.Credentials{AccessKeyID: *output.Credentials.AccessKeyId, SecretAccessKey: *output.Credentials.SecretAccessKey, SessionToken: *output.Credentials.SessionToken, CanExpire: true, Expires: output.Credentials.Expiration.UTC(), Source: "zasp-remediation-role"}
	base, err := factory.cloud.customerAWSConfig(claim.Target.Region, credentials)
	if err != nil {
		clearAWSCredentials(&credentials)
		return remediationProviderClients{}, errWorkerExecution
	}
	return remediationProviderClients{Bedrock: bedrockagent.NewFromConfig(base), IAM: iam.NewFromConfig(base)}, nil
}
