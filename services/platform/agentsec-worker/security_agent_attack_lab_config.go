package main

import (
	"reflect"
	"strings"
	"time"
)

func validAttackLabReconcilerAuthority(c workerRuntimeConfig) bool {
	role := discoveryAWSRolePattern.FindStringSubmatch(c.AttackLabReconcilerRoleARN)
	if len(role) != 2 || role[1] != c.EvidenceOwner || !workerRegionPattern.MatchString(c.AWSRegion) || !workerAccountPattern.MatchString(c.EvidenceOwner) || !workerBucketPattern.MatchString(c.EvidenceBucket) || !workerKMSPattern.MatchString(c.EvidenceKMSKeyARN) || !strings.HasPrefix(c.EvidenceKMSKeyARN, "arn:aws:kms:"+c.AWSRegion+":"+c.EvidenceOwner+":key/") || c.AttackLabReconcilerTokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || c.LeaseDuration != time.Minute || c.BatchSize != 1 {
		return false
	}
	allowed := workerRuntimeConfig{Mode: c.Mode, PostgresDSN: c.PostgresDSN, DatabaseAuthority: c.DatabaseAuthority, WorkerID: c.WorkerID, PollInterval: c.PollInterval, LeaseDuration: c.LeaseDuration, BatchSize: c.BatchSize, ShutdownTimeout: c.ShutdownTimeout, AWSRegion: c.AWSRegion, EvidenceBucket: c.EvidenceBucket, EvidenceOwner: c.EvidenceOwner, EvidenceKMSKeyARN: c.EvidenceKMSKeyARN, AttackLabReconcilerRoleARN: c.AttackLabReconcilerRoleARN, AttackLabReconcilerTokenFile: c.AttackLabReconcilerTokenFile}
	return reflect.DeepEqual(c, allowed)
}

func loadAttackLabReconcilerIdentity(getenv func(string) string, c *workerRuntimeConfig) error {
	c.AttackLabReconcilerRoleARN = getenv("ZASP_ATTACK_LAB_RECONCILER_ROLE_ARN")
	c.AttackLabReconcilerTokenFile = getenv("ZASP_ATTACK_LAB_RECONCILER_WEB_IDENTITY_TOKEN_FILE")
	if c.Mode != workerModeAttackLabReconciler {
		if c.AttackLabReconcilerRoleARN != "" || c.AttackLabReconcilerTokenFile != "" {
			return errWorkerConfiguration
		}
		return nil
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "ZASP_ATTACK_LAB_CONTROLLER_DSN", "ZASP_SECURITY_AGENT_WORKER_DSN", "ZASP_SECURITY_AGENT_ACTION_WORKER_DSN", "ZASP_TEST_RECONCILER_DSN"} {
		if getenv(key) != "" {
			return errWorkerConfiguration
		}
	}
	return nil
}
