package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type productionRuntimeStageDependencies struct {
	Stage     runtimeevent.RuntimeStage
	Executor  runtimeStageExecutor
	ready     func(context.Context) error
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

func newProductionRuntimeArchive(ctx context.Context, config workerRuntimeConfig) (*productionRuntimeStageDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeArchiveAWSAuthority(config) {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: minDuration(config.LeaseDuration/3, 30*time.Second), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RuntimeStageRoleARN, tokenFile: config.RuntimeStageTokenFile, timeout: minDuration(config.LeaseDuration/3, 30*time.Second), session: "zasp-runtime-archive-worker"}
	credentials := aws.NewCredentialsCache(provider)
	if _, err := credentials.Retrieve(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	base.Credentials = credentials
	s3API := s3.NewFromConfig(base)
	kmsAPI := kms.NewFromConfig(base)
	identityAPI := sts.NewFromConfig(base)
	executor, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: s3API, Bucket: config.EvidenceBucket, ExpectedOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, MaximumBytes: 64 << 20})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	cloud := productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.RuntimeStageRoleARN, TokenFile: config.RuntimeStageTokenFile, SecretRoot: "runtime/archive", Timeout: minDuration(config.LeaseDuration/3, 30*time.Second), Clock: func() time.Time { return time.Now().UTC() }}
	artifacts := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaximumBytes: 64 << 20}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if _, err := credentials.Retrieve(readyCtx); err != nil || readyProductionDiscoveryRole(readyCtx, identityAPI, cloud, artifacts) != nil || readyProductionDiscoveryArtifactAuthority(readyCtx, s3API, kmsAPI, cloud, artifacts) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := ready(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	return &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageArchive, Executor: executor, ready: ready, close: func() error { transport.CloseIdleConnections(); return nil }}, nil
}

func (dependencies *productionRuntimeStageDependencies) Ready(ctx context.Context) error {
	if dependencies == nil || dependencies.ready == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return dependencies.ready(ctx)
}

func (dependencies *productionRuntimeStageDependencies) Close() error {
	if dependencies == nil {
		return nil
	}
	dependencies.closeOnce.Do(func() {
		if dependencies.close != nil {
			dependencies.closeErr = dependencies.close()
		}
	})
	return dependencies.closeErr
}
