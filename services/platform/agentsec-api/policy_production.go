package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/policy/opensearchhistory"
	runtimeopensearch "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

type productionPolicyHistory struct {
	history       *opensearchhistory.Driver
	schema        *runtimeopensearch.Driver
	sessionSearch *runtimeopensearch.SessionIndex
	transport     *http.Transport
	credentials   aws.CredentialsProvider
}

func newProductionPolicyHistory(config RuntimeConfig) (*productionPolicyHistory, error) {
	if !validRuntimeConfig(config) {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: config.ProviderTimeout, MaxResponseHeaderBytes: 1 << 20,
	}
	client := &http.Client{Transport: transport, Timeout: config.ProviderTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := aws.Config{Region: config.ConnectorAWSRegion, HTTPClient: client, Credentials: aws.AnonymousCredentials{}, Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
	var credentials aws.CredentialsProvider
	if config.Environment == "test" {
		credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test-policy-history", SecretAccessKey: "test-policy-history-secret", SessionToken: "test-policy-history-token", Source: "test-policy-history"}, nil
		})
	} else {
		credentials = aws.NewCredentialsCache(&connectorWebIdentityProvider{client: sts.NewFromConfig(base), roleARN: config.ConnectorRoleARN, tokenFile: config.ConnectorTokenFile, timeout: config.ProviderTimeout})
	}
	clock := func() time.Time { return time.Now().UTC() }
	allowTestLoopback := config.Environment == "test"
	schema, err := runtimeopensearch.New(runtimeopensearch.Config{Endpoint: config.PolicyHistoryEndpoint, Region: config.ConnectorAWSRegion, RequestTimeout: config.ProviderTimeout, MaximumRequestBytes: 1, MaximumResponseBytes: 8 << 20, AllowTestLoopback: allowTestLoopback}, credentials, v4.NewSigner(), clock)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	history, err := opensearchhistory.New(opensearchhistory.Config{Endpoint: config.PolicyHistoryEndpoint, Region: config.ConnectorAWSRegion, RequestTimeout: config.ProviderTimeout, MaximumResponseBytes: 8 << 20, AllowTestLoopback: allowTestLoopback}, credentials, v4.NewSigner(), schema, clock)
	if err != nil {
		schema.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	sessionSearch, err := runtimeopensearch.NewSessionIndex(runtimeopensearch.Config{Endpoint: config.PolicyHistoryEndpoint, Region: config.ConnectorAWSRegion, RequestTimeout: config.ProviderTimeout, MaximumRequestBytes: 64 << 10, MaximumResponseBytes: 8 << 20, AllowTestLoopback: allowTestLoopback}, credentials, v4.NewSigner(), clock)
	if err != nil {
		_ = history.Close()
		schema.Close()
		transport.CloseIdleConnections()
		return nil, errRuntimeUnavailable
	}
	return &productionPolicyHistory{history: history, schema: schema, sessionSearch: sessionSearch, transport: transport, credentials: credentials}, nil
}

func (history *productionPolicyHistory) SearchPolicyActions(ctx context.Context, scope domain.Scope, trigger string, limit int) ([]platformpolicy.ActionContext, error) {
	if history == nil || history.history == nil {
		return nil, errRuntimeUnavailable
	}
	return history.history.SearchPolicyActions(ctx, scope, trigger, limit)
}

func (history *productionPolicyHistory) Ready(ctx context.Context) error {
	if history == nil || history.history == nil || history.credentials == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	if _, err := history.credentials.Retrieve(ctx); err != nil || history.history.Ready(ctx) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (history *productionPolicyHistory) Close() error {
	if history == nil {
		return nil
	}
	var result error
	if history.history != nil {
		result = history.history.Close()
	}
	if history.schema != nil {
		history.schema.Close()
	}
	if history.sessionSearch != nil {
		history.sessionSearch.Close()
	}
	if history.transport != nil {
		history.transport.CloseIdleConnections()
	}
	return result
}
