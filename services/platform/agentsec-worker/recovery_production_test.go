package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type recoverySigningReadinessStub struct {
	output *kms.DescribeKeyOutput
	err    error
	input  *kms.DescribeKeyInput
}

func (stub *recoverySigningReadinessStub) DescribeKey(_ context.Context, input *kms.DescribeKeyInput, options ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	stub.input = input
	configured := kms.Options{}
	for _, option := range options {
		option(&configured)
	}
	if configured.Retryer == nil {
		return nil, errors.New("retryer missing")
	}
	return stub.output, stub.err
}

func TestRecoverySigningReadinessRequiresExactAsymmetricKeyAuthority(t *testing.T) {
	keyARN := "arn:aws:kms:us-west-2:123456789012:key/22222222-2222-4222-8222-222222222222"
	metadata := &kmstypes.KeyMetadata{
		AWSAccountId: aws.String("123456789012"), Arn: aws.String(keyARN), KeyId: aws.String("22222222-2222-4222-8222-222222222222"), Enabled: true,
		KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, KeyUsage: kmstypes.KeyUsageTypeSignVerify, KeySpec: kmstypes.KeySpecEccNistP256, Origin: kmstypes.OriginTypeAwsKms,
	}
	stub := &recoverySigningReadinessStub{output: &kms.DescribeKeyOutput{KeyMetadata: metadata}}
	if err := readyProductionRecoverySigningKey(context.Background(), stub, keyARN, "123456789012"); err != nil {
		t.Fatal(err)
	}
	if stub.input == nil || aws.ToString(stub.input.KeyId) != keyARN {
		t.Fatalf("input=%#v", stub.input)
	}
	for name, mutate := range map[string]func(*kmstypes.KeyMetadata){
		"disabled":        func(value *kmstypes.KeyMetadata) { value.Enabled = false },
		"encrypt key":     func(value *kmstypes.KeyMetadata) { value.KeyUsage = kmstypes.KeyUsageTypeEncryptDecrypt },
		"wrong curve":     func(value *kmstypes.KeyMetadata) { value.KeySpec = kmstypes.KeySpecEccNistP384 },
		"foreign account": func(value *kmstypes.KeyMetadata) { value.AWSAccountId = aws.String("210987654321") },
	} {
		t.Run(name, func(t *testing.T) {
			copyValue := *metadata
			mutate(&copyValue)
			api := &recoverySigningReadinessStub{output: &kms.DescribeKeyOutput{KeyMetadata: &copyValue}}
			if err := readyProductionRecoverySigningKey(context.Background(), api, keyARN, "123456789012"); !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
