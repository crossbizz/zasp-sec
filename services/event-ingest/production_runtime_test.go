package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestProductionDatabaseQueryErrorPreservesOnlyStableRateLimit(t *testing.T) {
	rateError := productionDatabaseQueryError(&pgconn.PgError{Code: "53300", Message: "runtime batch rate limited", Detail: "tenant-secret"})
	if !errors.Is(rateError, runtimeevent.ErrProductionIngestRateLimited) || strings.Contains(rateError.Error(), "tenant-secret") {
		t.Fatalf("rate error=%v", rateError)
	}
	for _, input := range []error{
		&pgconn.PgError{Code: "53300", Message: "different", Detail: "tenant-secret"},
		&pgconn.PgError{Code: "23505", Message: "runtime batch rate limited", Detail: "tenant-secret"},
		errors.New("tenant-secret"),
	} {
		classified := productionDatabaseQueryError(input)
		if errors.Is(classified, runtimeevent.ErrProductionIngestRateLimited) || strings.Contains(classified.Error(), "tenant-secret") {
			t.Fatalf("database error=%v classified=%v", input, classified)
		}
	}
}

func TestProductionIngestCloudReadinessBindsRoleBucketVersioningEncryptionAndKMS(t *testing.T) {
	config, err := loadProductionIngestConfig(func(key string) string { return validProductionIngestEnvironment()[key] })
	if err != nil {
		t.Fatal(err)
	}
	stub := validProductionCloudReadinessStub(config)
	cloud := &productionIngestCloud{
		credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret", SessionToken: "token"}, nil
		}),
		role: stub, bucket: stub, kms: stub,
	}
	if err := readyProductionIngestCloud(context.Background(), cloud, config); err != nil {
		t.Fatalf("readyProductionIngestCloud() error = %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*productionCloudReadinessStub)
	}{
		{name: "foreign account", mutate: func(value *productionCloudReadinessStub) { value.identity.Account = aws.String("999999999999") }},
		{name: "wrong role", mutate: func(value *productionCloudReadinessStub) {
			value.identity.Arn = aws.String("arn:aws:sts::123456789012:assumed-role/foreign/session")
		}},
		{name: "suspended versioning", mutate: func(value *productionCloudReadinessStub) {
			value.versioning.Status = s3types.BucketVersioningStatusSuspended
		}},
		{name: "wrong encryption key", mutate: func(value *productionCloudReadinessStub) {
			value.encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID = aws.String("foreign")
		}},
		{name: "disabled kms", mutate: func(value *productionCloudReadinessStub) { value.key.KeyMetadata.Enabled = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validProductionCloudReadinessStub(config)
			test.mutate(candidate)
			cloud := &productionIngestCloud{credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "a", SecretAccessKey: "b"}, nil
			}), role: candidate, bucket: candidate, kms: candidate}
			if err := readyProductionIngestCloud(context.Background(), cloud, config); !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProductionReadinessCacheCachesOnlySuccessAndRechecksRollback(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	calls := 0
	checkErr := error(nil)
	cache, err := newProductionReadinessCache(func(context.Context) error { calls++; return checkErr }, time.Second, 30*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if err := cache.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	now = now.Add(31 * time.Second)
	checkErr = errors.New("sensitive drift")
	if err := cache.Ready(context.Background()); !errors.Is(err, errRuntimeUnavailable) || calls != 2 {
		t.Fatalf("expired error=%v calls=%d", err, calls)
	}
	checkErr = nil
	if err := cache.Ready(context.Background()); err != nil || calls != 3 {
		t.Fatalf("recovery error=%v calls=%d", err, calls)
	}
	now = now.Add(-time.Minute)
	checkErr = errors.New("rollback drift")
	if err := cache.Ready(context.Background()); !errors.Is(err, errRuntimeUnavailable) || calls != 4 {
		t.Fatalf("rollback error=%v calls=%d", err, calls)
	}
}

func TestServeProductionIngestRunsPrivateAndHealthListenersAndDrains(t *testing.T) {
	config, err := loadProductionIngestConfig(func(key string) string { return validProductionIngestEnvironment()[key] })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan struct {
		address  string
		listener net.Listener
	}, 2)
	listen := func(network, address string) (net.Listener, error) {
		listener, listenErr := net.Listen(network, "127.0.0.1:0")
		opened <- struct {
			address  string
			listener net.Listener
		}{address: address, listener: listener}
		return listener, listenErr
	}
	closes := 0
	dependencies := productionIngestDependencies{
		Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
		Ready:   func(context.Context) error { return nil },
		Close:   func() error { closes++; return nil },
	}
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() { result <- serveProductionIngest(ctx, &output, "1.2.3", config, dependencies, listen) }()
	listeners := map[string]net.Listener{}
	for len(listeners) < 2 {
		select {
		case value := <-opened:
			listeners[value.address] = value.listener
		case <-time.After(2 * time.Second):
			t.Fatal("listeners did not open")
		}
	}
	waitForHealthStatus(t, "http://"+listeners[healthListenAddress].Addr().String()+"/readyz", http.StatusOK)
	response, err := healthTestClient.Post("http://"+listeners[productionIngestListenAddress].Addr().String()+"/anything", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("private status=%d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil || closes != 1 || output.String() != "event-ingest build 1.2.3\n" {
			t.Fatalf("result=%v closes=%d output=%q", err, closes, output.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("production server did not drain")
	}
}

type productionCloudReadinessStub struct {
	identity   *sts.GetCallerIdentityOutput
	head       *s3.HeadBucketOutput
	versioning *s3.GetBucketVersioningOutput
	encryption *s3.GetBucketEncryptionOutput
	key        *kms.DescribeKeyOutput
}

func validProductionCloudReadinessStub(config productionIngestConfig) *productionCloudReadinessStub {
	keyID := stringsAfterLast(config.KMSKeyARN, "/")
	return &productionCloudReadinessStub{
		identity:   &sts.GetCallerIdentityOutput{Account: aws.String(config.ExpectedBucketOwner), Arn: aws.String("arn:aws:sts::" + config.ExpectedBucketOwner + ":assumed-role/zasp-event-ingest/session")},
		head:       &s3.HeadBucketOutput{BucketRegion: aws.String(config.Region)},
		versioning: &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled},
		encryption: &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String(config.KMSKeyARN)}, BucketKeyEnabled: aws.Bool(true)}}}},
		key:        &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{AWSAccountId: aws.String(config.ExpectedBucketOwner), Arn: aws.String(config.KMSKeyARN), KeyId: aws.String(keyID), Enabled: true, KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeySpec: kmstypes.KeySpecSymmetricDefault, Origin: kmstypes.OriginTypeAwsKms}},
	}
}

func (stub *productionCloudReadinessStub) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return stub.identity, nil
}
func (stub *productionCloudReadinessStub) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return stub.head, nil
}
func (stub *productionCloudReadinessStub) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return stub.versioning, nil
}
func (stub *productionCloudReadinessStub) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return stub.encryption, nil
}
func (stub *productionCloudReadinessStub) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return stub.key, nil
}

func stringsAfterLast(value, separator string) string {
	for index := len(value) - len(separator); index >= 0; index-- {
		if value[index:index+len(separator)] == separator {
			return value[index+len(separator):]
		}
	}
	return value
}
