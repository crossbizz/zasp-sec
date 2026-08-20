package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent/s3rawstore"
)

const productionIngestReadinessTTL = 30 * time.Second

var productionWebTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type productionAssumeRoleAPI interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type productionRoleReadinessAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type productionBucketReadinessAPI interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
}

type productionKMSReadinessAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

type productionWebIdentityProvider struct {
	client    productionAssumeRoleAPI
	roleARN   string
	tokenFile string
	timeout   time.Duration
	clock     func() time.Time
}

func (provider *productionWebIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider == nil || nilProductionDependency(provider.client) || ctx == nil || ctx.Err() != nil || !productionRolePattern.MatchString(provider.roleARN) || provider.tokenFile != projectedServiceAccountTokenPath || provider.timeout < time.Second || provider.timeout > 30*time.Second || provider.clock == nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	file, err := os.Open(provider.tokenFile)
	if err != nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 16_385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(token) < 64 || len(token) > 16_384 || !productionWebTokenPattern.Match(token) || strings.TrimSpace(string(token)) != string(token) {
		clear(token)
		return aws.Credentials{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	duration := int32(900)
	output, assumeErr := provider.client.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn: aws.String(provider.roleARN), RoleSessionName: aws.String("zasp-event-ingest"), WebIdentityToken: aws.String(string(token)), DurationSeconds: &duration,
	}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	clear(token)
	now := provider.clock()
	if assumeErr != nil || bounded.Err() != nil || now.IsZero() || now.Location() != time.UTC || output == nil || output.Credentials == nil || output.Credentials.AccessKeyId == nil || output.Credentials.SecretAccessKey == nil || output.Credentials.SessionToken == nil || output.Credentials.Expiration == nil || !output.Credentials.Expiration.After(now.Add(time.Minute)) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	return aws.Credentials{AccessKeyID: *output.Credentials.AccessKeyId, SecretAccessKey: *output.Credentials.SecretAccessKey, SessionToken: *output.Credentials.SessionToken, CanExpire: true, Expires: output.Credentials.Expiration.UTC(), Source: "zasp-event-ingest-web-identity"}, nil
}

type productionIngestCloud struct {
	credentials aws.CredentialsProvider
	role        productionRoleReadinessAPI
	bucket      productionBucketReadinessAPI
	kms         productionKMSReadinessAPI
	s3          *s3.Client
	transport   *http.Transport
	closeOnce   sync.Once
}

func newProductionIngestCloud(config productionIngestConfig, clock func() time.Time) (*productionIngestCloud, error) {
	if !validProductionIngestConfig(config) || clock == nil {
		return nil, errRuntimeUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: config.OperationTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.OperationTimeout,
		ResponseHeaderTimeout: config.OperationTimeout, MaxResponseHeaderBytes: 1 << 20,
	}
	client := &http.Client{Transport: transport, Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.Region, HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &productionWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.RoleARN, tokenFile: config.TokenFile, timeout: config.OperationTimeout, clock: clock}
	credentials := aws.NewCredentialsCache(provider)
	base.Credentials = credentials
	return &productionIngestCloud{credentials: credentials, role: sts.NewFromConfig(base), bucket: s3.NewFromConfig(base), kms: kms.NewFromConfig(base), s3: s3.NewFromConfig(base), transport: transport}, nil
}

func (cloud *productionIngestCloud) Close() error {
	if cloud == nil {
		return nil
	}
	cloud.closeOnce.Do(func() {
		if cloud.transport != nil {
			cloud.transport.CloseIdleConnections()
		}
	})
	return nil
}

func readyProductionIngestCloud(ctx context.Context, cloud *productionIngestCloud, config productionIngestConfig) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || cloud == nil || nilProductionDependency(cloud.credentials) || nilProductionDependency(cloud.role) || nilProductionDependency(cloud.bucket) || nilProductionDependency(cloud.kms) {
		return errRuntimeUnavailable
	}
	if _, err := cloud.credentials.Retrieve(ctx); err != nil {
		return errRuntimeUnavailable
	}
	identity, err := cloud.role.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	roleName := config.RoleARN[strings.LastIndex(config.RoleARN, "/")+1:]
	if err != nil || ctx.Err() != nil || identity == nil || aws.ToString(identity.Account) != config.ExpectedBucketOwner || !strings.HasPrefix(aws.ToString(identity.Arn), "arn:aws:sts::"+config.ExpectedBucketOwner+":assumed-role/"+roleName+"/") {
		return errRuntimeUnavailable
	}
	head, err := cloud.bucket.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(config.Bucket), ExpectedBucketOwner: aws.String(config.ExpectedBucketOwner)}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || head == nil || aws.ToString(head.BucketRegion) != config.Region {
		return errRuntimeUnavailable
	}
	versioning, err := cloud.bucket.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(config.Bucket), ExpectedBucketOwner: aws.String(config.ExpectedBucketOwner)}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || versioning == nil || versioning.Status != s3types.BucketVersioningStatusEnabled {
		return errRuntimeUnavailable
	}
	encryption, err := cloud.bucket.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(config.Bucket), ExpectedBucketOwner: aws.String(config.ExpectedBucketOwner)}, func(options *s3.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || encryption == nil || encryption.ServerSideEncryptionConfiguration == nil || len(encryption.ServerSideEncryptionConfiguration.Rules) != 1 {
		return errRuntimeUnavailable
	}
	rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil || rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != s3types.ServerSideEncryptionAwsKms || aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) != config.KMSKeyARN || !aws.ToBool(rule.BucketKeyEnabled) {
		return errRuntimeUnavailable
	}
	key, err := cloud.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(config.KMSKeyARN)}, func(options *kms.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || key == nil || key.KeyMetadata == nil {
		return errRuntimeUnavailable
	}
	metadata := key.KeyMetadata
	wantKeyID := strings.TrimPrefix(strings.Split(config.KMSKeyARN, ":")[5], "key/")
	if aws.ToString(metadata.Arn) != config.KMSKeyARN || aws.ToString(metadata.KeyId) != wantKeyID || aws.ToString(metadata.AWSAccountId) != config.ExpectedBucketOwner || !metadata.Enabled || metadata.KeyManager != kmstypes.KeyManagerTypeCustomer || metadata.KeyState != kmstypes.KeyStateEnabled || metadata.KeyUsage != kmstypes.KeyUsageTypeEncryptDecrypt || metadata.KeySpec != kmstypes.KeySpecSymmetricDefault || metadata.Origin != kmstypes.OriginTypeAwsKms {
		return errRuntimeUnavailable
	}
	return nil
}

type productionReadinessCache struct {
	mu        sync.Mutex
	check     func(context.Context) error
	timeout   time.Duration
	ttl       time.Duration
	checkedAt time.Time
	ready     bool
	clock     func() time.Time
}

func newProductionReadinessCache(check func(context.Context) error, timeout, ttl time.Duration, clock func() time.Time) (*productionReadinessCache, error) {
	if check == nil || timeout < time.Second || timeout > 30*time.Second || ttl < time.Second || ttl > time.Minute || clock == nil {
		return nil, errRuntimeUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errRuntimeUnavailable
	}
	return &productionReadinessCache{check: check, timeout: timeout, ttl: ttl, clock: clock}, nil
}

func (readiness *productionReadinessCache) Ready(ctx context.Context) error {
	if readiness == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	now := readiness.clock()
	elapsed := now.Sub(readiness.checkedAt)
	if readiness.ready && elapsed >= 0 && elapsed < readiness.ttl {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, readiness.timeout)
	defer cancel()
	if readiness.check(bounded) != nil || bounded.Err() != nil {
		readiness.ready = false
		return errRuntimeUnavailable
	}
	readiness.ready = true
	readiness.checkedAt = now
	return nil
}

type productionIngestDependencies struct {
	Handler http.Handler
	Ready   func(context.Context) error
	Close   func() error
}

type cachedProductionIngestRepository struct {
	productionIngestRepository
	ready func(context.Context) error
}

func (repository cachedProductionIngestRepository) Ready(ctx context.Context) error {
	if repository.ready == nil {
		return errRuntimeUnavailable
	}
	return repository.ready(ctx)
}

func buildProductionIngestDependencies(ctx context.Context, config productionIngestConfig) (productionIngestDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validProductionIngestConfig(config) {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	connectCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	poolConfig.MaxConns, poolConfig.MinConns = 20, 2
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	failPool := func() (productionIngestDependencies, error) {
		pool.Close()
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	if pool.Ping(connectCtx) != nil {
		return failPool()
	}
	database := &productionJSONDatabase{pool: pool}
	failDatabase := func() (productionIngestDependencies, error) {
		database.Close()
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	repository, err := runtimeevent.NewPostgresProductionIngestRepository(database)
	if err != nil {
		return failDatabase()
	}
	clock := func() time.Time { return time.Now().UTC() }
	cloud, err := newProductionIngestCloud(config, clock)
	if err != nil {
		return failDatabase()
	}
	failCloud := func() (productionIngestDependencies, error) {
		_ = cloud.Close()
		database.Close()
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	artifacts, err := s3rawstore.New(cloud.s3, s3rawstore.Config{Bucket: config.Bucket, ExpectedBucketOwner: config.ExpectedBucketOwner, KMSKeyARN: config.KMSKeyARN, MaximumBytes: config.MaximumBytes, OperationTimeout: config.OperationTimeout})
	if err != nil {
		return failCloud()
	}
	check := func(readyCtx context.Context) error {
		if repository.Ready(readyCtx) != nil || readyProductionIngestCloud(readyCtx, cloud, config) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	readiness, err := newProductionReadinessCache(check, config.OperationTimeout, productionIngestReadinessTTL, clock)
	if err != nil || readiness.Ready(connectCtx) != nil {
		return failCloud()
	}
	cachedRepository := cachedProductionIngestRepository{productionIngestRepository: repository, ready: readiness.Ready}
	router, err := newProductionIngestRouter(cachedRepository, artifacts, config.MaximumBytes, clock)
	if err != nil {
		return failCloud()
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			cloudErr := cloud.Close()
			database.Close()
			if cloudErr != nil {
				closeErr = errRuntimeUnavailable
			}
		})
		return closeErr
	}
	return productionIngestDependencies{Handler: readinessGatedIngestHandler{ready: readiness.Ready, next: router}, Ready: readiness.Ready, Close: closeDependencies}, nil
}

type productionJSONDatabase struct {
	mu     sync.RWMutex
	pool   *pgxpool.Pool
	closed bool
}

func (database *productionJSONDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	if database == nil || ctx == nil || ctx.Err() != nil || statement == "" {
		return nil, errors.New("database unavailable")
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || database.pool == nil {
		return nil, errors.New("database unavailable")
	}
	var payload []byte
	if err := database.pool.QueryRow(ctx, statement, arguments...).Scan(&payload); err != nil || len(payload) == 0 || !json.Valid(payload) {
		return nil, errors.New("database unavailable")
	}
	return append(json.RawMessage(nil), payload...), nil
}

func (database *productionJSONDatabase) Close() {
	if database == nil {
		return
	}
	database.mu.Lock()
	defer database.mu.Unlock()
	if !database.closed && database.pool != nil {
		database.pool.Close()
	}
	database.closed = true
}

func nilProductionDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ aws.CredentialsProvider = (*productionWebIdentityProvider)(nil)
