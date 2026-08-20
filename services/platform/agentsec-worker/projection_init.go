package main

import (
	"context"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore/neo4jstore"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch/opensearchdriver"
)

func runProductionProjectionInit(ctx context.Context, config workerRuntimeConfig) error {
	if ctx == nil || ctx.Err() != nil || !validProjectionInitConfig(config) {
		return errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, config.LeaseDuration)
	defer cancel()
	authority, err := newProjectionAWSAuthority(config)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer authority.transport.CloseIdleConnections()
	if verifyProjectionCallerIdentity(bounded, authority.identity, config.ProjectionRoleARN) != nil {
		return errRuntimeUnavailable
	}
	if config.Mode == workerModeProjectionSearchInit {
		driver, createErr := opensearchdriver.New(opensearchdriver.Config{
			Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: minDuration(config.LeaseDuration/3, 10*time.Second), MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20,
		}, authority.credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
		if createErr != nil {
			return errRuntimeUnavailable
		}
		defer driver.Close()
		if driver.InitializeSchema(bounded) != nil || driver.Ready(bounded) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	resolver := &projectionNeo4jAuthenticationResolver{client: authority.secrets, prefix: config.ProjectionSecretPrefix}
	adapter, err := neo4jstore.NewProduction(bounded, neo4jstore.ProductionConfig{
		Endpoint: config.Neo4jURI, AuthenticationReference: config.Neo4jCredential, ReadinessTimeout: minDuration(config.LeaseDuration/3, 10*time.Second),
	}, resolver)
	if err != nil {
		return errRuntimeUnavailable
	}
	operationErr := adapter.EnsureSchema(bounded)
	if operationErr == nil {
		operationErr = adapter.Ready(bounded)
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), minDuration(config.LeaseDuration/3, 5*time.Second))
	closeErr := adapter.Close(closeCtx)
	closeCancel()
	if operationErr != nil || closeErr != nil {
		return errRuntimeUnavailable
	}
	return nil
}
