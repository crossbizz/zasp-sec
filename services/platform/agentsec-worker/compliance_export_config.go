package main

import (
	"net/url"
	"regexp"
	"strings"
	"time"
)

type complianceExportConfiguration struct{ Bucket, Owner, KMSKey, RoleARN, TokenFile string }

func loadComplianceExportConfiguration(getenv func(string) string, mode workerMode) (*complianceExportConfiguration, error) {
	c := &complianceExportConfiguration{Bucket: getenv("ZASP_COMPLIANCE_EXPORT_BUCKET"), Owner: getenv("ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER"), KMSKey: getenv("ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"), RoleARN: getenv("ZASP_COMPLIANCE_EXPORT_ROLE_ARN"), TokenFile: getenv("ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE")}
	if mode != workerModeComplianceExport && mode != workerModeComplianceCleanup {
		if *c != (complianceExportConfiguration{}) {
			return nil, errWorkerConfiguration
		}
		return nil, nil
	}
	return c, nil
}

func validComplianceExportConfiguration(c workerRuntimeConfig) bool {
	if c.Mode != workerModeComplianceExport && c.Mode != workerModeComplianceCleanup {
		return c.ComplianceExports == nil
	}
	p := c.ComplianceExports
	if p == nil || c.AuditExports != nil || c.LeaseDuration != 60*time.Second || c.ProviderTimeout < time.Second || c.ProviderTimeout > 30*time.Second || c.BatchSize > 10 || !workerRegionPattern.MatchString(c.AWSRegion) || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(p.Bucket) || !workerAccountPattern.MatchString(p.Owner) || !workerKMSPattern.MatchString(p.KMSKey) || !workerProjectionRolePattern.MatchString(p.RoleARN) || p.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
		return false
	}
	kms := strings.Split(p.KMSKey, ":")
	role := strings.Split(p.RoleARN, ":")
	if len(kms) != 6 || len(role) != 6 || kms[3] != c.AWSRegion || kms[4] != p.Owner || role[4] != p.Owner {
		return false
	}
	u, err := url.Parse(c.PostgresDSN)
	if err != nil || u.User == nil || !regexp.MustCompile(`^[a-z][a-z0-9_]{2,62}$`).MatchString(u.User.Username()) || strings.HasPrefix(u.User.Username(), "zasp_") {
		return false
	}
	for _, s := range []string{c.DiscoveryQueueURL, c.RuntimeQueueURL, c.RedTeamQueueURL, c.AttackLabQueueURL, c.RecoveryQueueURL, c.RecoveryRoleARN, c.RecoveryTokenFile, c.RuntimeRoleARN, c.RuntimeTokenFile, c.RuntimeStageRoleARN, c.RuntimeStageTokenFile, c.DiscoveryRoleARN, c.DiscoveryTokenFile, c.ProjectionRoleARN, c.ProjectionTokenFile, c.OutboxRoleARN, c.OutboxTokenFile, c.RedTeamRoleARN, c.RedTeamTokenFile, c.AttackLabRoleARN, c.AttackLabTokenFile, c.EvidenceBucket, c.EvidenceOwner, c.EvidenceKMSKeyARN, c.GatewaySigningPrivateFile, c.SecurityAgentPlannerToken, c.RecoveryKubernetesToken, c.AttackLabKubernetesToken, c.TestReconcilerRoleARN, c.TestReconcilerTokenFile} {
		if s != "" {
			return false
		}
	}
	return true
}
