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

type recoveryKMSSigner struct {
	client  recoveryKMSAPI
	keyARN  string
	timeout time.Duration
}

func newRecoveryKMSSigner(client recoveryKMSAPI, keyARN string, timeout time.Duration) (*recoveryKMSSigner, error) {
	if nilDiscoveryCloudDependency(client) || !workerKMSPattern.MatchString(keyARN) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	return &recoveryKMSSigner{client: client, keyARN: keyARN, timeout: timeout}, nil
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
