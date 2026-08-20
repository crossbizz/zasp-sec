package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	runtimeopensearch "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

func newProductionRuntimeIndex(ctx context.Context, config workerRuntimeConfig) (*productionRuntimeStageDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeIndexAWSAuthority(config) {
		return nil, errRuntimeUnavailable
	}
	requestTimeout := minDuration(config.LeaseDuration/3, 30*time.Second)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: requestTimeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RuntimeStageRoleARN, tokenFile: config.RuntimeStageTokenFile, timeout: requestTimeout, session: "zasp-runtime-index-worker"}
	credentials := aws.NewCredentialsCache(provider)
	if _, err := credentials.Retrieve(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	base.Credentials = credentials
	s3API := s3.NewFromConfig(base)
	kmsAPI := kms.NewFromConfig(base)
	identityAPI := sts.NewFromConfig(base)
	reader, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: s3API, Bucket: config.EvidenceBucket, ExpectedOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, MaximumBytes: 64 << 20})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	receipts, err := newProductionDiscoveryArtifactAuthority(s3API, productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 64 << 20})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	driver, err := runtimeopensearch.New(runtimeopensearch.Config{Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: requestTimeout, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20}, credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	index, err := runtimeindex.New(driver, runtimeindex.Config{MaximumBatchBytes: 64 << 20, MaximumDocuments: 1000})
	if err != nil {
		driver.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	executor, err := newRuntimeIndexExecutor(runtimeIndexExecutorConfig{Reader: reader, Index: index, Receipts: receipts, ImplementationVersion: config.RuntimeStageVersion})
	if err != nil {
		driver.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	cloud := productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.RuntimeStageRoleARN, TokenFile: config.RuntimeStageTokenFile, SecretRoot: "runtime/index", Timeout: requestTimeout, Clock: func() time.Time { return time.Now().UTC() }}
	artifacts := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 64 << 20}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if _, err := credentials.Retrieve(readyCtx); err != nil || readyProductionDiscoveryRole(readyCtx, identityAPI, cloud, artifacts) != nil || readyProductionDiscoveryArtifactAuthority(readyCtx, s3API, kmsAPI, cloud, artifacts) != nil || driver.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := ready(ctx); err != nil {
		driver.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	return &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageIndex, Executor: executor, ready: ready, close: func() error { driver.Close(); transport.CloseIdleConnections(); return nil }}, nil
}
