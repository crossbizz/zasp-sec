package main

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type recoveryKMSAPI interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

type recoveryKMSVerifyAPI interface {
	Verify(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

type recoveryKMSSigner struct {
	client  recoveryKMSAPI
	keyARN  string
	timeout time.Duration
}

type recoveryKMSVerifier struct {
	client  recoveryKMSVerifyAPI
	keyARN  string
	timeout time.Duration
}

func newRecoveryKMSSigner(client recoveryKMSAPI, keyARN string, timeout time.Duration) (*recoveryKMSSigner, error) {
	if nilDiscoveryCloudDependency(client) || !workerKMSPattern.MatchString(keyARN) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	return &recoveryKMSSigner{client: client, keyARN: keyARN, timeout: timeout}, nil
}

func newRecoveryKMSVerifier(client recoveryKMSVerifyAPI, keyARN string, timeout time.Duration) (*recoveryKMSVerifier, error) {
	if nilDiscoveryCloudDependency(client) || !workerKMSPattern.MatchString(keyARN) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	return &recoveryKMSVerifier{client: client, keyARN: keyARN, timeout: timeout}, nil
}

func (signer *recoveryKMSSigner) Sign(ctx context.Context, payload []byte) (keyARN string, signature []byte, resultErr error) {
	if signer == nil || nilDiscoveryCloudDependency(signer.client) || ctx == nil || ctx.Err() != nil || len(payload) == 0 || len(payload) > 56<<10 {
		return "", nil, errRuntimeUnavailable
	}
	defer func() {
		if recover() != nil {
			keyARN, signature, resultErr = "", nil, errRuntimeUnavailable
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, signer.timeout)
	defer cancel()
	output, err := signer.client.Sign(bounded, &kms.SignInput{
		KeyId: aws.String(signer.keyARN), Message: append([]byte(nil), payload...), MessageType: kmstypes.MessageTypeRaw, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}, func(options *kms.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || bounded.Err() != nil || output == nil || aws.ToString(output.KeyId) != signer.keyARN || output.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || len(output.Signature) < 32 || len(output.Signature) > 512 {
		return "", nil, errRuntimeUnavailable
	}
	return signer.keyARN, append([]byte(nil), output.Signature...), nil
}

func (verifier *recoveryKMSVerifier) Verify(ctx context.Context, keyARN string, payload, signature []byte) (resultErr error) {
	if verifier == nil || nilDiscoveryCloudDependency(verifier.client) || ctx == nil || ctx.Err() != nil || keyARN != verifier.keyARN || len(payload) == 0 || len(payload) > 56<<10 || len(signature) < 32 || len(signature) > 512 {
		return errRuntimeUnavailable
	}
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, verifier.timeout)
	defer cancel()
	output, err := verifier.client.Verify(bounded, &kms.VerifyInput{KeyId: aws.String(verifier.keyARN), Message: append([]byte(nil), payload...), MessageType: kmstypes.MessageTypeRaw, Signature: append([]byte(nil), signature...), SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256}, func(options *kms.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || bounded.Err() != nil || output == nil || aws.ToString(output.KeyId) != verifier.keyARN || output.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || !output.SignatureValid {
		return errRuntimeUnavailable
	}
	return nil
}
