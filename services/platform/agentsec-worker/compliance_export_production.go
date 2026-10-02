package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
)

type complianceExportProductionClients struct {
	credentials aws.CredentialsProvider
	identity    runtimeIdentityAPI
	writer      s3driver.API
	reader      s3driver.ExportReadAPI
	cleanup     s3driver.ExportCleanupAPI
	transport   *http.Transport
}

func newComplianceExportProductionClients(config workerRuntimeConfig) (*complianceExportProductionClients, error) {
	if !validWorkerRuntimeConfig(config) || config.ComplianceExports == nil {
		return nil, errRuntimeUnavailable
	}
	p := config.ComplianceExports
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: config.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	credentials := newAuditExportCredentialCache(&outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: p.RoleARN, tokenFile: p.TokenFile, timeout: config.ProviderTimeout, session: "zasp-" + string(config.Mode)})
	base.Credentials = credentials
	result := &complianceExportProductionClients{credentials: credentials, identity: sts.NewFromConfig(base), transport: transport}
	provider := s3.NewFromConfig(base)
	if config.Mode == workerModeComplianceExport {
		result.writer = provider
	} else {
		result.reader = provider
		result.cleanup = provider
	}
	return result, nil
}

func composeComplianceExportWorkerRuntime(ctx context.Context, config workerRuntimeConfig, database recoveryJSONDatabase, clients *complianceExportProductionClients) (workerRuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validWorkerRuntimeConfig(config) || config.ComplianceExports == nil || nilWorkerDependency(database) || clients == nil || clients.transport == nil || nilWorkerDependency(clients.credentials) || nilWorkerDependency(clients.identity) {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	pins := *config.ComplianceExports
	p := &complianceExportProcessor{authority: newPostgresComplianceExportAuthority(database), worker: config.WorkerID, batch: config.BatchSize, timeout: config.ProviderTimeout, heartbeat: 20 * time.Second, cleanupMode: config.Mode == workerModeComplianceCleanup}
	storage := s3driver.Config{Bucket: pins.Bucket, ExpectedBucketOwner: pins.Owner, KMSKeyARN: pins.KMSKey, MaximumBytes: 8 << 20}
	var err error
	lane := "execute"
	if p.cleanupMode {
		if !nilWorkerDependency(clients.writer) || nilWorkerDependency(clients.reader) || nilWorkerDependency(clients.cleanup) {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		p.verifier, err = s3driver.NewExportVerifier(clients.reader, storage)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		p.cleanup, err = s3driver.NewExportCleanup(clients.cleanup, storage)
		lane = "cleanup"
	} else {
		if nilWorkerDependency(clients.writer) || !nilWorkerDependency(clients.reader) || !nilWorkerDependency(clients.cleanup) {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		var driver *s3driver.Driver
		driver, err = s3driver.NewExport(clients.writer, storage)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		p.store, err = artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: config.ProviderTimeout, MaximumBytes: 8 << 20})
	}
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	credentials, identity := clients.credentials, clients.identity
	ready, err := newBoundedCachedWorkerReadiness(func(parent context.Context) error {
		bounded, end := context.WithTimeout(parent, config.ProviderTimeout)
		defer end()
		if p.authority.Ready(bounded, lane) != nil {
			return errRuntimeUnavailable
		}
		creds, err := credentials.Retrieve(bounded)
		if err != nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" || !creds.CanExpire || !creds.Expires.After(time.Now()) {
			return errRuntimeUnavailable
		}
		caller, err := identity.GetCallerIdentity(bounded, &sts.GetCallerIdentityInput{}, func(o *sts.Options) { o.Retryer = aws.NopRetryer{} })
		roleName := pins.RoleARN[strings.LastIndex(pins.RoleARN, "/")+1:]
		if err != nil || caller == nil || bounded.Err() != nil || aws.ToString(caller.Account) != pins.Owner || aws.ToString(caller.Arn) != "arn:aws:sts::"+pins.Owner+":assumed-role/"+roleName+"/zasp-"+string(config.Mode) {
			return errRuntimeUnavailable
		}
		return nil
	}, minDuration(config.ProviderTimeout, 5*time.Second), 30*time.Second)
	if err != nil || ready(ctx) != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	runtime := &complianceExportRuntime{borrowers: map[uint64]context.CancelFunc{}, processor: p, ready: ready, closeTransport: clients.transport.CloseIdleConnections, shutdown: config.ShutdownTimeout}
	return workerRuntimeDependencies{Processor: runtime, Ready: runtime.Ready, Close: runtime.Close}, nil
}
