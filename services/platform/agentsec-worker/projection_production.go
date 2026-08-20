package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j"
	"github.com/neo4j/neo4j-go-driver/v6/neo4j/auth"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore/neo4jstore"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch/opensearchdriver"
)

var (
	projectionWebTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

type projectionAssumeRoleAPI interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type projectionSecretsAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type projectionCallerIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type projectionAWSAuthority struct {
	credentials aws.CredentialsProvider
	secrets     *secretsmanager.Client
	identity    projectionCallerIdentityAPI
	transport   *http.Transport
}

type projectionWebIdentityProvider struct {
	client    projectionAssumeRoleAPI
	roleARN   string
	tokenFile string
	timeout   time.Duration
}

func (provider *projectionWebIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil || !workerProjectionRolePattern.MatchString(provider.roleARN) || provider.tokenFile == "" || provider.timeout < time.Second || provider.timeout > 30*time.Second {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	file, err := os.Open(provider.tokenFile)
	if err != nil {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	token, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(token) < 64 || len(token) > 16384 || !projectionWebTokenPattern.Match(token) || strings.TrimSpace(string(token)) != string(token) {
		clear(token)
		return aws.Credentials{}, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, provider.timeout)
	defer cancel()
	duration := int32(900)
	result, assumeErr := provider.client.AssumeRoleWithWebIdentity(bounded, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn: aws.String(provider.roleARN), RoleSessionName: aws.String("zasp-projection-worker"), WebIdentityToken: aws.String(string(token)), DurationSeconds: &duration,
	})
	clear(token)
	if assumeErr != nil || result == nil || result.Credentials == nil || result.Credentials.AccessKeyId == nil || result.Credentials.SecretAccessKey == nil || result.Credentials.SessionToken == nil || result.Credentials.Expiration == nil || !result.Credentials.Expiration.After(time.Now().Add(time.Minute)) {
		return aws.Credentials{}, errRuntimeUnavailable
	}
	return aws.Credentials{
		AccessKeyID: *result.Credentials.AccessKeyId, SecretAccessKey: *result.Credentials.SecretAccessKey, SessionToken: *result.Credentials.SessionToken,
		CanExpire: true, Expires: result.Credentials.Expiration.UTC(), Source: "zasp-projection-web-identity",
	}, nil
}

type projectionNeo4jAuthenticationResolver struct {
	client projectionSecretsAPI
	prefix string
}

func (resolver *projectionNeo4jAuthenticationResolver) ResolveNeo4jAuthentication(ctx context.Context, reference string) (auth.TokenManager, error) {
	const referencePrefix = "ref:neo4j/auth/"
	if resolver == nil || resolver.client == nil || ctx == nil || ctx.Err() != nil || !workerSecretPrefixPattern.MatchString(resolver.prefix) || !strings.HasPrefix(reference, referencePrefix) {
		return nil, errRuntimeUnavailable
	}
	identifier := strings.TrimPrefix(reference, referencePrefix)
	if !projectionNeo4jIDPattern.MatchString(identifier) {
		return nil, errRuntimeUnavailable
	}
	initial, err := resolver.readBasicToken(ctx, identifier)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	var lock sync.Mutex
	first := true
	manager := auth.BasicTokenManager(func(readCtx context.Context) (neo4j.AuthToken, error) {
		lock.Lock()
		defer lock.Unlock()
		if first {
			first = false
			return initial, nil
		}
		return resolver.readBasicToken(readCtx, identifier)
	})
	return manager, nil
}

func (resolver *projectionNeo4jAuthenticationResolver) readBasicToken(ctx context.Context, identifier string) (neo4j.AuthToken, error) {
	stage := "AWSCURRENT"
	output, err := resolver.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(resolver.prefix + "/neo4j/auth/" + identifier), VersionStage: &stage})
	if err != nil || output == nil || output.SecretString != nil == (len(output.SecretBinary) > 0) {
		return neo4j.AuthToken{}, errRuntimeUnavailable
	}
	var raw []byte
	if output.SecretString != nil {
		raw = []byte(*output.SecretString)
	} else {
		raw = append([]byte(nil), output.SecretBinary...)
	}
	defer clear(raw)
	if len(raw) < 1 || len(raw) > 16384 {
		return neo4j.AuthToken{}, errRuntimeUnavailable
	}
	var value struct {
		Scheme      string `json:"scheme"`
		Principal   string `json:"principal"`
		Credentials string `json:"credentials"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Scheme != "basic" || len(value.Principal) < 1 || len(value.Principal) > 512 || len(value.Credentials) < 16 || len(value.Credentials) > 8192 || strings.TrimSpace(value.Principal) != value.Principal || strings.ContainsAny(value.Principal+value.Credentials, "\x00\r\n") {
		return neo4j.AuthToken{}, errRuntimeUnavailable
	}
	return neo4j.BasicAuth(value.Principal, value.Credentials, ""), nil
}

type productionProjectionProjector struct {
	projectionProjector
	ready func(context.Context) error
	close func() error
}

func newProductionSearchProjection(ctx context.Context, config workerRuntimeConfig) (productionProjectionProjector, error) {
	authority, err := newProjectionAWSAuthority(config)
	if err != nil {
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	requestTimeout := minDuration(time.Duration(config.LeaseDuration)/3, 30*time.Second)
	driver, err := opensearchdriver.New(opensearchdriver.Config{
		Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: requestTimeout, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20,
	}, authority.credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	store, err := inventorysearch.New(driver, inventorysearch.Config{MaximumDocuments: 10_000, MaximumDocumentBytes: 65_536, MaximumBatchBytes: 8 << 20, MaximumResults: 100})
	if err != nil {
		driver.Close()
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	projector, err := newSearchProjectionProjector(store)
	if err != nil {
		driver.Close()
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil {
			return errRuntimeUnavailable
		}
		if verifyProjectionCallerIdentity(readyCtx, authority.identity, config.ProjectionRoleARN) != nil || driver.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := ready(ctx); err != nil {
		driver.Close()
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	return productionProjectionProjector{projectionProjector: projector, ready: ready, close: func() error { driver.Close(); authority.transport.CloseIdleConnections(); return nil }}, nil
}

func newProductionGraphProjection(ctx context.Context, config workerRuntimeConfig) (productionProjectionProjector, error) {
	authority, err := newProjectionAWSAuthority(config)
	if err != nil {
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	resolver := &projectionNeo4jAuthenticationResolver{client: authority.secrets, prefix: config.ProjectionSecretPrefix}
	adapter, err := neo4jstore.NewProduction(ctx, neo4jstore.ProductionConfig{
		Endpoint: config.Neo4jURI, AuthenticationReference: config.Neo4jCredential, ReadinessTimeout: minDuration(config.LeaseDuration/3, 30*time.Second),
		ExpectedPrincipal: config.Neo4jExpectedPrincipal, ExpectedRole: config.Neo4jExpectedRole,
	}, resolver)
	if err != nil {
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	store, err := graphstore.New(adapter, graphstore.Config{OperationTimeout: minDuration(config.LeaseDuration/2, 30*time.Second), MaximumNodes: 1_000, MaximumEdges: 2_000, MaximumDepth: 8})
	if err != nil {
		closeCtx, cancel := context.WithTimeout(ctx, time.Second)
		_ = adapter.Close(closeCtx)
		cancel()
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	projector, err := newGraphProjectionProjector(store)
	if err != nil {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = adapter.Close(closeCtx)
		cancel()
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	ready := func(readyCtx context.Context) error {
		if readyCtx == nil || readyCtx.Err() != nil || verifyProjectionCallerIdentity(readyCtx, authority.identity, config.ProjectionRoleARN) != nil || adapter.Ready(readyCtx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	if err := ready(ctx); err != nil {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		_ = adapter.Close(closeCtx)
		cancel()
		authority.transport.CloseIdleConnections()
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	return productionProjectionProjector{
		projectionProjector: projector,
		ready:               ready,
		close: func() error {
			closeCtx, cancel := context.WithTimeout(context.Background(), minDuration(config.ShutdownTimeout, config.LeaseDuration/3))
			defer cancel()
			closeErr := adapter.Close(closeCtx)
			authority.transport.CloseIdleConnections()
			return closeErr
		},
	}, nil
}

func newProjectionAWSAuthority(config workerRuntimeConfig) (projectionAWSAuthority, error) {
	if !validProjectionAWSAuthority(config) {
		return projectionAWSAuthority{}, errRuntimeUnavailable
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaxResponseHeaderBytes: 1 << 20,
	}
	client := &http.Client{Transport: transport, Timeout: minDuration(config.LeaseDuration/3, 30*time.Second), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.AWSRegion, HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	provider := &projectionWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.ProjectionRoleARN, tokenFile: config.ProjectionTokenFile, timeout: minDuration(config.LeaseDuration/3, 30*time.Second)}
	credentials := aws.NewCredentialsCache(provider)
	base.Credentials = credentials
	return projectionAWSAuthority{credentials: credentials, secrets: secretsmanager.NewFromConfig(base), identity: sts.NewFromConfig(base), transport: transport}, nil
}

func verifyProjectionCallerIdentity(ctx context.Context, api projectionCallerIdentityAPI, roleARN string) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	match := regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/(?:[A-Za-z0-9+=,.@_-]+/)*([A-Za-z0-9+=,.@_-]{1,64})$`).FindStringSubmatch(roleARN)
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(api) || len(match) != 3 {
		return errRuntimeUnavailable
	}
	output, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || output == nil || aws.ToString(output.Account) != match[1] ||
		aws.ToString(output.Arn) != "arn:aws:sts::"+match[1]+":assumed-role/"+match[2]+"/zasp-projection-worker" ||
		len(aws.ToString(output.UserId)) < 3 || len(aws.ToString(output.UserId)) > 256 || !strings.HasSuffix(aws.ToString(output.UserId), ":zasp-projection-worker") {
		return errRuntimeUnavailable
	}
	return nil
}

var (
	_ aws.CredentialsProvider           = (*projectionWebIdentityProvider)(nil)
	_ neo4jstore.AuthenticationResolver = (*projectionNeo4jAuthenticationResolver)(nil)
	_ projectionProjector               = (*searchProjectionProjector)(nil)
	_ projectionProjector               = (*graphProjectionProjector)(nil)
)
