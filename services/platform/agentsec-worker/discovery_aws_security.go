package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type discoveryAWSSecurityRunner struct {
	runner discoveryAWSCollectionSecurityRunner
	clock  func() time.Time
}

type discoveryAWSCollectionSecurityRunner interface {
	Collect(context.Context, awsdiscovery.CollectionSecurityRequest, []byte) (awsdiscovery.CollectionSecurityResult, error)
	CheckCollectionReadiness(context.Context) error
}

func newDiscoveryAWSSecurityRunner(runner discoveryAWSCollectionSecurityRunner, clock func() time.Time) (*discoveryAWSSecurityRunner, error) {
	if nilWorkerDependency(runner) || clock == nil {
		return nil, errRuntimeUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errRuntimeUnavailable
	}
	return &discoveryAWSSecurityRunner{runner: runner, clock: clock}, nil
}

func (analyzer *discoveryAWSSecurityRunner) Collect(ctx context.Context, request awsdiscovery.CollectionSecurityRequest, credential []byte) (awsdiscovery.CollectionSecurityResult, error) {
	if analyzer == nil || nilWorkerDependency(analyzer.runner) || analyzer.clock == nil || ctx == nil || ctx.Err() != nil {
		return awsdiscovery.CollectionSecurityResult{}, discoveryCredentialFailure(ctx, collection.FailureCancelled)
	}
	envelope, err := decodeDiscoveryCredentialEnvelope(credential)
	if err != nil || envelope.Provider != collection.ProviderAWS || envelope.SubjectKind != request.Subject.Kind || envelope.SubjectID != request.Subject.ID || envelope.ExpiresAt != request.CredentialExpiresAt || !envelope.ExpiresAt.After(analyzer.clock()) {
		envelope.Destroy()
		return awsdiscovery.CollectionSecurityResult{}, discoveryCredentialFailure(ctx, collection.FailureRetryable)
	}
	defer envelope.Destroy()
	var inner []byte
	if request.Mode == awsdiscovery.SecurityModeProwlerAWS {
		inner, err = json.Marshal(struct {
			AccessKeyID     string `json:"access_key_id"`
			ExpiresAt       string `json:"expires_at"`
			SecretAccessKey string `json:"secret_access_key"`
			SessionToken    string `json:"session_token"`
		}{AccessKeyID: string(envelope.AccessKeyID), ExpiresAt: envelope.ExpiresAt.Format(time.RFC3339), SecretAccessKey: string(envelope.SecretAccessKey), SessionToken: string(envelope.SessionToken)})
		if err != nil {
			clear(inner)
			return awsdiscovery.CollectionSecurityResult{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
		}
	} else if request.Mode != awsdiscovery.SecurityModeCartographyAWS {
		return awsdiscovery.CollectionSecurityResult{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	defer clear(inner)
	return analyzer.runner.Collect(ctx, request, inner)
}

func (analyzer *discoveryAWSSecurityRunner) CheckCollectionReadiness(ctx context.Context) error {
	if analyzer == nil || nilWorkerDependency(analyzer.runner) || analyzer.clock == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return analyzer.runner.CheckCollectionReadiness(ctx)
}

var _ awsdiscovery.CollectionSecurityAnalyzer = (*discoveryAWSSecurityRunner)(nil)
