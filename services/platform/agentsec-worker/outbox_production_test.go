package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestOutboxWebIdentityProviderUsesOnlyExplicitBoundAuthority(t *testing.T) {
	t.Parallel()
	tokenPath := filepath.Join(t.TempDir(), "token")
	token := "header.payload.signature-with-a-production-length-token-value-1234567890"
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(10 * time.Minute).UTC()
	api := &outboxAssumeRoleStub{output: &sts.AssumeRoleWithWebIdentityOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AKIAEXAMPLE00000000"), SecretAccessKey: aws.String("secret-value-not-real"), SessionToken: aws.String("session-value-not-real"), Expiration: &expires,
	}}}
	provider := &outboxWebIdentityProvider{client: api, roleARN: "arn:aws:iam::123456789012:role/zasp-production-outbox", tokenFile: tokenPath, timeout: time.Second}
	credentials, err := provider.Retrieve(context.Background())
	if err != nil || credentials.Source != "zasp-outbox-web-identity" {
		t.Fatalf("Retrieve() credentials=%#v err=%v", credentials, err)
	}
	if api.input == nil || aws.ToString(api.input.RoleArn) != provider.roleARN || aws.ToString(api.input.WebIdentityToken) != token || aws.ToString(api.input.RoleSessionName) != "zasp-outbox-worker" || aws.ToInt32(api.input.DurationSeconds) != 900 {
		t.Fatalf("AssumeRoleWithWebIdentity input = %#v", api.input)
	}
}

func TestAuditExportWebIdentityUsesOnlyExactWorkerSessions(t *testing.T) {
	for _, session := range []string{"zasp-audit-export-worker", "zasp-audit-export-outbox", "zasp-audit-export-reader", " zasp-audit-export-worker", "zasp-audit-export"} {
		t.Run(session, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			token := "header.payload.signature-with-owned-test-token-length-1234567890123456"
			if err := os.WriteFile(path, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			expiration := time.Now().Add(10 * time.Minute)
			api := &outboxAssumeRoleStub{output: &sts.AssumeRoleWithWebIdentityOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE00000000"), SecretAccessKey: aws.String("fixture-secret-not-real"), SessionToken: aws.String("fixture-session-not-real"), Expiration: &expiration}}}
			provider := &outboxWebIdentityProvider{client: api, roleARN: "arn:aws:iam::123456789012:role/zasp-owned-audit-worker", tokenFile: path, timeout: time.Second, session: session}
			credentials, err := provider.Retrieve(context.Background())
			valid := session == "zasp-audit-export-worker" || session == "zasp-audit-export-outbox"
			if valid && (err != nil || api.input == nil || aws.ToString(api.input.RoleSessionName) != session || aws.ToString(api.input.RoleArn) != provider.roleARN || credentials.AccessKeyID == "") {
				t.Fatal("explicit export role/session refused", err)
			}
			if !valid && (err == nil || api.input != nil) {
				t.Fatal("unreviewed session reached STS")
			}
		})
	}
}

type auditExportAssumeCallback func(context.Context, *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error)

func (f auditExportAssumeCallback) AssumeRoleWithWebIdentity(ctx context.Context, in *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return f(ctx, in)
}

func TestAuditExportWebIdentityRejectsLateOrEmptySuccessfulCredentials(t *testing.T) {
	for _, fault := range []string{"caller cancellation", "own deadline", "empty access", "empty secret", "empty session"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte("header.payload.signature-with-owned-test-token-length-1234567890123456"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api := auditExportAssumeCallback(func(bounded context.Context, _ *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
				if fault == "caller cancellation" {
					cancel()
				}
				if fault == "own deadline" {
					<-bounded.Done()
				}
				expiry := time.Now().Add(10 * time.Minute)
				credentials := &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE00000000"), SecretAccessKey: aws.String("fixture-secret-not-real"), SessionToken: aws.String("fixture-session-not-real"), Expiration: &expiry}
				switch fault {
				case "empty access":
					credentials.AccessKeyId = aws.String("")
				case "empty secret":
					credentials.SecretAccessKey = aws.String("")
				case "empty session":
					credentials.SessionToken = aws.String("")
				}
				return &sts.AssumeRoleWithWebIdentityOutput{Credentials: credentials}, nil
			})
			provider := &outboxWebIdentityProvider{client: api, roleARN: "arn:aws:iam::123456789012:role/zasp-owned-audit-worker", tokenFile: path, timeout: time.Second, session: "zasp-audit-export-worker"}
			credentials, err := provider.Retrieve(ctx)
			if err == nil || credentials.AccessKeyID != "" || credentials.SecretAccessKey != "" || credentials.SessionToken != "" {
				t.Fatal("expired/empty STS success released credentials")
			}
		})
	}
}

func TestWebIdentitySessionAuthorityIncludesEveryRuntimeStage(t *testing.T) {
	for _, value := range []string{"", "zasp-outbox-worker", "zasp-runtime-outbox-worker", "zasp-red-team-outbox-worker", "zasp-attack-lab-outbox-worker", "zasp-runtime-coordinator", "zasp-runtime-archive-worker", "zasp-runtime-index-worker", "zasp-runtime-correlation-worker", "zasp-runtime-projection-worker", "zasp-runtime-complete-worker"} {
		if !validOutboxSession(value) {
			t.Fatalf("session %q rejected", value)
		}
	}
	for _, value := range []string{"runtime-projection", "zasp-runtime-finalize-worker", " zasp-runtime-index-worker"} {
		if validOutboxSession(value) {
			t.Fatalf("session %q accepted", value)
		}
	}
}

func TestAttackLabOutboxQueueReadinessBindsExactARNAndDLQ(t *testing.T) {
	t.Parallel()
	config := validAttackLabOutboxRuntimeConfig()
	api := &outboxQueueReadinessStub{output: &sqs.GetQueueAttributesOutput{Attributes: map[string]string{
		string(sqstypes.QueueAttributeNameQueueArn):      "arn:aws:sqs:us-west-2:123456789012:agentsec-attack-lab-jobs",
		string(sqstypes.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:123456789012:agentsec-attack-lab-jobs-dlq","maxReceiveCount":"5"}`,
	}}}
	if err := outboxQueueReady(context.Background(), api, config); err != nil {
		t.Fatalf("attack lab outbox readiness=%v", err)
	}
	if api.input == nil || aws.ToString(api.input.QueueUrl) != config.AttackLabQueueURL {
		t.Fatalf("attack lab queue input=%#v", api.input)
	}
}

func TestRecoveryOutboxQueueReadinessBindsHundredAttemptRedrivePolicy(t *testing.T) {
	t.Parallel()
	config := validRecoveryOutboxRuntimeConfig()
	api := &outboxQueueReadinessStub{output: &sqs.GetQueueAttributesOutput{Attributes: map[string]string{
		string(sqstypes.QueueAttributeNameQueueArn):      "arn:aws:sqs:us-west-2:123456789012:agentsec-recovery-backup-jobs",
		string(sqstypes.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:123456789012:agentsec-recovery-backup-jobs-dlq","maxReceiveCount":"100"}`,
	}}}
	if err := outboxQueueReady(context.Background(), api, config); err != nil {
		t.Fatalf("recovery outbox readiness=%v", err)
	}
}

func TestOutboxQueueReadinessBindsExactARNAndRedrivePolicy(t *testing.T) {
	t.Parallel()
	config := validSchedulerRuntimeConfig()
	config.Mode, config.DatabaseAuthority = workerModeOutbox, "zasp_outbox_worker"
	config.DiscoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs"
	config.AWSRegion = "us-west-2"
	config.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-outbox"
	config.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	api := &outboxQueueReadinessStub{output: &sqs.GetQueueAttributesOutput{Attributes: map[string]string{
		string(sqstypes.QueueAttributeNameQueueArn):      "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs",
		string(sqstypes.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs-dlq","maxReceiveCount":"5"}`,
	}}}
	if err := outboxQueueReady(context.Background(), api, config); err != nil {
		t.Fatalf("outboxQueueReady() error = %v", err)
	}
	if api.input == nil || aws.ToString(api.input.QueueUrl) != config.DiscoveryQueueURL || len(api.input.AttributeNames) != 2 {
		t.Fatalf("GetQueueAttributes input = %#v", api.input)
	}
	api.output.Attributes[string(sqstypes.QueueAttributeNameQueueArn)] = "arn:aws:sqs:us-west-2:210987654321:agentsec-discovery-jobs"
	if err := outboxQueueReady(context.Background(), api, config); err == nil {
		t.Fatal("account-drifted queue readiness succeeded")
	}
}

func TestRuntimeOutboxQueueReadinessBindsExactRuntimeARN(t *testing.T) {
	t.Parallel()
	config := validSchedulerRuntimeConfig()
	config.Mode, config.DatabaseAuthority = workerModeRuntimeOutbox, "zasp_outbox_worker"
	config.RuntimeQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events"
	config.AWSRegion = "us-west-2"
	config.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox"
	config.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	api := &outboxQueueReadinessStub{output: &sqs.GetQueueAttributesOutput{Attributes: map[string]string{
		string(sqstypes.QueueAttributeNameQueueArn):      "arn:aws:sqs:us-west-2:123456789012:agentsec-runtime-events",
		string(sqstypes.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:123456789012:agentsec-runtime-events-dlq","maxReceiveCount":"5"}`,
	}}}
	if err := outboxQueueReady(context.Background(), api, config); err != nil {
		t.Fatalf("runtime outbox readiness=%v", err)
	}
	if api.input == nil || aws.ToString(api.input.QueueUrl) != config.RuntimeQueueURL {
		t.Fatalf("runtime queue input=%#v", api.input)
	}
}

func TestOutboxReadinessCachesSuccessfulLiveCheckAcrossEmptyPolls(t *testing.T) {
	calls := 0
	readiness, err := newCachedOutboxReadiness(func(context.Context) error {
		calls++
		return nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		if err := readiness.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 0 {
		t.Fatalf("cached readiness called dependency %d times", calls)
	}
	readiness.checkedAt = readiness.checkedAt.Add(-2 * time.Second)
	if err := readiness.Ready(context.Background()); err != nil || calls != 1 {
		t.Fatalf("stale readiness err=%v calls=%d", err, calls)
	}
	readiness.now = func() time.Time { return readiness.checkedAt.Add(-time.Second) }
	if err := readiness.Ready(context.Background()); err != nil || calls != 2 {
		t.Fatalf("wall-clock rollback readiness err=%v calls=%d", err, calls)
	}
}

type outboxQueueReadinessStub struct {
	input  *sqs.GetQueueAttributesInput
	output *sqs.GetQueueAttributesOutput
}

func (stub *outboxQueueReadinessStub) GetQueueAttributes(_ context.Context, input *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	stub.input = input
	return stub.output, nil
}

type outboxAssumeRoleStub struct {
	input  *sts.AssumeRoleWithWebIdentityInput
	output *sts.AssumeRoleWithWebIdentityOutput
}

func (stub *outboxAssumeRoleStub) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	stub.input = input
	return stub.output, nil
}
