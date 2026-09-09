package main

import (
	"context"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore/neo4jstore"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch/opensearchdriver"
	runtimeopensearch "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
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
		runtimeConfig := runtimeopensearch.Config{Endpoint: config.OpenSearchURL, Region: config.AWSRegion, RequestTimeout: minDuration(config.LeaseDuration/3, 10*time.Second), MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20}
		raw, err := runtimeopensearch.New(runtimeConfig, authority.credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
		if err != nil {
			return errRuntimeUnavailable
		}
		defer raw.Close()
		sessions, err := runtimeopensearch.NewSessionIndex(runtimeConfig, authority.credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
		if err != nil {
			return errRuntimeUnavailable
		}
		defer sessions.Close()
		return initializeProductionSearchSchemas(bounded, driver, raw, sessions)
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

type productionSearchSchema interface {
	InitializeSchema(context.Context) error
	Ready(context.Context) error
}

// The one-shot schema identity owns exactly these three fixed indexes. Runtime
// workers never create mappings, rewrite drifted markers, or gain schema rights.
func initializeProductionSearchSchemas(ctx context.Context, inventory, raw, sessions productionSearchSchema) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(inventory) || nilWorkerDependency(raw) || nilWorkerDependency(sessions) {
		return errRuntimeUnavailable
	}
	for _, index := range []productionSearchSchema{inventory, raw, sessions} {
		if index.InitializeSchema(ctx) != nil || index.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
	}
	return nil
}
