package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type productionRecoveryDependencies struct {
	Publisher      recoveryBackupPublisher
	Loader         recoveryManifestLoader
	Infrastructure recoveryRestoreInfrastructure
	ready          func(context.Context) error
	close          func() error
	closeOnce      sync.Once
	closeErr       error
}

func newProductionRecoveryDependencies(ctx context.Context, config workerRuntimeConfig, postgresLSN func(context.Context, domain.Scope) (string, error)) (*productionRecoveryDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validWorkerRuntimeConfig(config) || config.Mode != workerModeRecovery || postgresLSN == nil {
		return nil, errRuntimeUnavailable
	}
	timeout := minDuration(config.LeaseDuration/3, 30*time.Second)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 1 << 20}
	httpClient := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: httpClient, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &outboxWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RecoveryRoleARN, tokenFile: config.RecoveryTokenFile, timeout: timeout, session: "zasp-recovery-worker"}
	credentials := aws.NewCredentialsCache(provider)
	base.Credentials = credentials
	s3Client := s3.NewFromConfig(base)
	kmsClient := kms.NewFromConfig(base)
	artifacts := productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: timeout, MaximumBytes: recoveryMaximumCapturedBytes}
	store, err := newProductionDiscoveryArtifactAuthority(s3Client, artifacts)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	dependencies := &productionRecoveryDependencies{}
	var kubernetesTransport *recoveryKubernetesHTTPTransport
	if config.RecoveryOperationKind == "backup" {
		signer, signerErr := newRecoveryKMSSigner(kmsClient, config.RecoverySigningKMSKeyARN, timeout)
		if signerErr != nil {
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
		publisher, publisherErr := newRecoveryArtifactPublisher(recoveryArtifactPublisherConfig{Store: store, Signer: signer, NeonProjectID: config.RecoveryNeonProjectID, NeonBranchID: config.RecoveryNeonBranchID, PostgresLSN: postgresLSN, Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) }})
		if publisherErr != nil {
			transport.CloseIdleConnections()
			return nil, errRuntimeUnavailable
		}
		dependencies.Publisher = publisher
	} else {
		verifier, verifierErr := newRecoveryKMSVerifier(kmsClient, config.RecoverySigningKMSKeyARN, timeout)
		secretsReader, secretsErr := newDiscoverySecretsManagerReader(secretsmanager.NewFromConfig(base), "zasp-recovery", timeout)
		neon, neonErr := newRotatingRecoveryNeonClient(secretsReader, config.RecoveryNeonSecretReference, config.RecoveryNeonProjectID, config.RecoveryNeonBranchID, timeout)
		kubernetesTransport, err = newProductionRecoveryKubernetesHTTPTransport(config.RecoveryKubernetesURL, config.RecoveryKubernetesToken, config.RecoveryKubernetesCA, timeout)
		if verifierErr != nil || secretsErr != nil || neonErr != nil || err != nil {
			transport.CloseIdleConnections()
			if kubernetesTransport != nil {
				_ = kubernetesTransport.Close()
			}
			return nil, errRuntimeUnavailable
		}
		kubernetes, kubernetesErr := newRecoveryKubernetesAPI(recoveryKubernetesAPIConfig{Transport: kubernetesTransport, Store: store, RunnerImage: config.RecoveryRunnerImage, ServiceAccount: config.RecoveryRunnerServiceAccount, SourcePostgresDSN: config.PostgresDSN, NeonCIDRs: config.RecoveryNeonEgressCIDRs, PollInterval: 250 * time.Millisecond, Resolve: func(resolveCtx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
		}})
		loader, loaderErr := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: store, Verifier: verifier, Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) }})
		infrastructure, infrastructureErr := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: config.RecoveryNeonProjectID, ParentBranchID: config.RecoveryNeonBranchID})
		if kubernetesErr != nil || loaderErr != nil || infrastructureErr != nil {
			transport.CloseIdleConnections()
			_ = kubernetesTransport.Close()
			return nil, errRuntimeUnavailable
		}
		dependencies.Loader = loader
		dependencies.Infrastructure = infrastructure
	}
	cloud := productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.RecoveryRoleARN, TokenFile: config.RecoveryTokenFile, SecretRoot: "zasp-recovery", Timeout: timeout, Clock: func() time.Time { return time.Now().UTC() }, Session: "zasp-recovery-worker"}
	roleAPI := sts.NewFromConfig(base)
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		bounded, cancel := context.WithTimeout(readyCtx, timeout)
		defer cancel()
		credential, credentialErr := credentials.Retrieve(bounded)
		clearAWSCredentials(&credential)
		if credentialErr != nil || readyProductionDiscoveryRole(bounded, roleAPI, cloud, artifacts) != nil || readyProductionDiscoveryArtifactAuthority(bounded, s3Client, kmsClient, cloud, artifacts) != nil || readyProductionRecoverySigningKey(bounded, kmsClient, config.RecoverySigningKMSKeyARN, config.EvidenceOwner) != nil || config.RecoveryOperationKind == "restore" && dependencies.Infrastructure.Ready(bounded) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	dependencies.ready = ready
	dependencies.close = func() error {
		transport.CloseIdleConnections()
		if kubernetesTransport != nil {
			return kubernetesTransport.Close()
		}
		return nil
	}
	return dependencies, nil
}

func readyProductionRecoverySigningKey(ctx context.Context, api discoveryKMSReadinessAPI, keyARN, account string) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(api) || !workerKMSPattern.MatchString(keyARN) || !workerAccountPattern.MatchString(account) {
		return errRuntimeUnavailable
	}
	output, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyARN)}, func(options *kms.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || output == nil || output.KeyMetadata == nil {
		return errRuntimeUnavailable
	}
	metadata := output.KeyMetadata
	wantKeyID := strings.TrimPrefix(strings.Split(keyARN, ":")[5], "key/")
	if aws.ToString(metadata.Arn) != keyARN || aws.ToString(metadata.KeyId) != wantKeyID || aws.ToString(metadata.AWSAccountId) != account || !metadata.Enabled || metadata.KeyManager != kmstypes.KeyManagerTypeCustomer || metadata.KeyState != kmstypes.KeyStateEnabled || metadata.KeyUsage != kmstypes.KeyUsageTypeSignVerify || metadata.KeySpec != kmstypes.KeySpecEccNistP256 || metadata.Origin != kmstypes.OriginTypeAwsKms {
		return errRuntimeUnavailable
	}
	return nil
}

func (dependencies *productionRecoveryDependencies) Ready(ctx context.Context) error {
	if dependencies == nil || dependencies.ready == nil {
		return errRuntimeUnavailable
	}
	return dependencies.ready(ctx)
}

func (dependencies *productionRecoveryDependencies) Close() error {
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
