package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type recoveryKMSStub struct {
	input *kms.SignInput
}

func (stub *recoveryKMSStub) Sign(_ context.Context, input *kms.SignInput, options ...func(*kms.Options)) (*kms.SignOutput, error) {
	stub.input = input
	configured := kms.Options{}
	for _, option := range options {
		option(&configured)
	}
	if configured.Retryer == nil {
		return nil, errWorkerExecution
	}
	return &kms.SignOutput{KeyId: input.KeyId, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256, Signature: bytes.Repeat([]byte{0x27}, 64)}, nil
}

func TestRecoveryKMSSignerUsesOneExactAsymmetricAuthority(t *testing.T) {
	stub := &recoveryKMSStub{}
	keyARN := "arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-42d3-a456-426614174000"
	signer, err := newRecoveryKMSSigner(stub, keyARN, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"schema_version":"recovery_manifest_v1"}`)
	returnedKey, signature, err := signer.Sign(context.Background(), payload)
	if err != nil || returnedKey != keyARN || len(signature) != 64 {
		t.Fatalf("Sign()=(%q,%d,%v)", returnedKey, len(signature), err)
	}
	if stub.input == nil || aws.ToString(stub.input.KeyId) != keyARN || stub.input.MessageType != kmstypes.MessageTypeRaw || stub.input.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || !bytes.Equal(stub.input.Message, payload) {
		t.Fatalf("input=%#v", stub.input)
	}
}
