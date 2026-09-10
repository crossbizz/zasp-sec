package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore/neo4jstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func newProductionRuntimeCorrelation(ctx context.Context, config workerRuntimeConfig, database runtimeevent.ProductionIngestDatabase) (*productionRuntimeStageDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeCorrelationAWSAuthority(config) || nilWorkerDependency(database) {
		return nil, errRuntimeUnavailable
	}
	requestTimeout := minDuration(config.LeaseDuration/3, 30*time.Second)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: requestTimeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RuntimeStageRoleARN, tokenFile: config.RuntimeStageTokenFile, timeout: requestTimeout, session: "zasp-runtime-correlation-worker"}
	credentials := aws.NewCredentialsCache(provider)
	if _, err := credentials.Retrieve(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	base.Credentials = credentials
	s3API := s3.NewFromConfig(base)
	kmsAPI := kms.NewFromConfig(base)
	identityAPI := sts.NewFromConfig(base)
	resolver := &projectionNeo4jAuthenticationResolver{client: secretsmanager.NewFromConfig(base), prefix: config.ProjectionSecretPrefix}
	adapter, err := neo4jstore.NewProduction(ctx, neo4jstore.ProductionConfig{
		Endpoint: config.Neo4jURI, AuthenticationReference: config.Neo4jCredential, ReadinessTimeout: requestTimeout,
		ExpectedPrincipal: config.Neo4jExpectedPrincipal, ExpectedRole: config.Neo4jExpectedRole,
	}, resolver)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	closeGraph := func() error {
		closeCtx, cancel := context.WithTimeout(context.Background(), minDuration(config.ShutdownTimeout, config.LeaseDuration/3))
		defer cancel()
		return adapter.Close(closeCtx)
	}
	graph, err := graphstore.New(adapter, graphstore.Config{OperationTimeout: minDuration(config.LeaseDuration/2, 30*time.Second), MaximumNodes: 3_000, MaximumEdges: 2_000, MaximumDepth: 8})
	if err != nil {
		_ = closeGraph()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	reader, err := newRuntimeArchiveExecutor(runtimeArchiveExecutorConfig{API: s3API, Bucket: config.EvidenceBucket, ExpectedOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, MaximumBytes: 64 << 20})
	if err != nil {
		_ = closeGraph()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	receipts, err := newProductionDiscoveryArtifactAuthority(s3API, productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 64 << 20})
	if err != nil {
		_ = closeGraph()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	executor, err := newRuntimeCorrelationExecutorWithDatabase(runtimeCorrelationExecutorConfig{Reader: reader, Receipts: receipts, Graph: graph, ImplementationVersion: config.RuntimeStageVersion}, database)
	if err != nil {
		_ = closeGraph()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	cloud := productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.RuntimeStageRoleARN, TokenFile: config.RuntimeStageTokenFile, SecretRoot: "runtime/correlation", Timeout: requestTimeout, Clock: func() time.Time { return time.Now().UTC() }}
	artifacts := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 64 << 20}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if _, err := credentials.Retrieve(readyCtx); err != nil || readyProductionDiscoveryRole(readyCtx, identityAPI, cloud, artifacts) != nil || readyProductionDiscoveryArtifactAuthority(readyCtx, s3API, kmsAPI, cloud, artifacts) != nil || adapter.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := ready(ctx); err != nil {
		_ = closeGraph()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	return &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageCorrelate, Executor: executor, ready: ready, close: func() error { closeErr := closeGraph(); transport.CloseIdleConnections(); return closeErr }}, nil
}

func newRuntimeCorrelationExecutorWithDatabase(config runtimeCorrelationExecutorConfig, database runtimeevent.ProductionIngestDatabase) (*runtimeCorrelationExecutor, error) {
	if !nilWorkerDependency(config.Candidates) {
		return nil, errRuntimeUnavailable
	}
	if config.ImplementationVersion == "runtime-correlation-v2" {
		var err error
		config.Candidates, err = runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
		if err != nil {
			return nil, errRuntimeUnavailable
		}
	}
	return newRuntimeCorrelationExecutor(config)
}
