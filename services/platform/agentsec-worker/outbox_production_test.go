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
