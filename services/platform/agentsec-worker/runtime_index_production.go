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

func newProductionRuntimeIndex(ctx context.Context, config workerRuntimeConfig, database recoveryJSONDatabase) (*productionRuntimeStageDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeIndexAWSAuthority(config) || config.RetentionProfileChecksum != "" && !workerUsesRetentionRuntimeProfile(config) {
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
	var retentionGate *retentionJournalIndexVisibility
	if workerUsesRetentionRuntimeProfile(config) {
		retentionGate, err = newRetentionJournalIndexVisibility(database, config.RetentionProfileChecksum, config.RetentionJournalProfileChecksum, receipts)
		if err == nil {
			index, err = runtimeindex.NewRetained(driver, runtimeindex.Config{MaximumBatchBytes: 64 << 20, MaximumDocuments: 1000}, retentionGate)
		}
	}
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
	sessionIndex, err := runtimeopensearch.NewConfiguredSessionIndex(config.RuntimeSessionIndex, runtimeopensearch.Config{Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: requestTimeout, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20}, credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		driver.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	if retentionGate != nil {
		sessionIndex.Close()
		sessionIndex, err = runtimeopensearch.NewRetainedSessionWriteIndex(config.RuntimeSessionIndex, runtimeopensearch.Config{Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: requestTimeout, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20}, credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() }, retentionGate)
		if err != nil {
			driver.Close()
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
	}
	sessions, err := newRuntimeSessionSearchExecutor(reader, receipts, sessionIndex)
	if config.RuntimeStageVersion == "runtime-index-v2" {
		sessions, err = newRuntimePreciseSessionSearchExecutor(reader, receipts, sessionIndex)
	}
	if err != nil {
		sessionIndex.Close()
		driver.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	var cleanup *retentionCleanup
	var cleanupOther *runtimeopensearch.SessionIndex
	if retentionGate != nil {
		v1, v2 := sessionIndex, sessionIndex
		name := "zasp-runtime-sessions-v2"
		if config.RuntimeSessionIndex == "zasp-runtime-sessions-v2" {
			name = "zasp-runtime-sessions-v1"
		}
		cleanupOther, err = runtimeopensearch.NewConfiguredSessionIndex(name, runtimeopensearch.Config{Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: requestTimeout, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20}, credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
		if err == nil {
			if name == "zasp-runtime-sessions-v1" {
				v1 = cleanupOther
			} else {
				v2 = cleanupOther
			}
			cleanup, err = newRetentionCleanup(database, config.RetentionProfileChecksum, config.WorkerID, driver, v1, v2, requestTimeout, config.ShutdownTimeout)
		}
		if err != nil {
			if cleanupOther != nil {
				cleanupOther.Close()
			}
			sessionIndex.Close()
			driver.Close()
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
	}
	artifacts := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: requestTimeout, MaximumBytes: 64 << 20}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if retentionGate != nil && retentionGate.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}

		if _, err := credentials.Retrieve(readyCtx); err != nil || readyProductionDiscoveryRole(readyCtx, identityAPI, cloud, artifacts) != nil || readyProductionDiscoveryArtifactAuthority(readyCtx, s3API, kmsAPI, cloud, artifacts) != nil || driver.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := func() error {
		if cleanup != nil && cleanup.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return ready(ctx)
	}(); err != nil {
		if cleanup != nil {
			_ = cleanup.Close()
		}
		if cleanupOther != nil {
			cleanupOther.Close()
		}
		sessionIndex.Close()
		driver.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	var cleanupRuntime retentionIndexCleanupRuntime
	if cleanup != nil {
		cleanupRuntime = cleanup
	}
	return &productionRuntimeStageDependencies{retentionCleanup: cleanupRuntime, Stage: runtimeevent.RuntimeStageIndex, Executor: executor, Sessions: sessions, SessionReady: sessionIndex.Ready, ready: ready, close: func() error {
		if cleanupOther != nil {
			cleanupOther.Close()
		}
		sessionIndex.Close()
		driver.Close()
		transport.CloseIdleConnections()
		return nil
	}}, nil
}
