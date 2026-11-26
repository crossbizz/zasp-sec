package main

import (
	"context"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaokv"
)

type discoveryKVReader struct {
	store *openbaokv.Store
	root  string
}

func newDiscoveryConnectorSecrets(aws discoverySecretsManagerAPI, c productionDiscoveryDependencyConfig) (discoverySecretReader, func(), error) {
	if !c.ConnectorSecrets.Valid() {
		return nil, nil, errRuntimeUnavailable
	}
	if c.ConnectorSecrets.Provider != openbaokv.Provider {
		r, err := newDiscoverySecretsManagerReader(aws, c.Cloud.SecretRoot, c.Cloud.Timeout)
		return r, nil, err
	}
	store, err := openbaokv.New(c.ConnectorSecrets, c.Cloud.SecretRoot, c.Cloud.Timeout)
	if err != nil {
		return nil, nil, err
	}
	if err = store.Ready(context.Background()); err != nil {
		store.CloseIdleConnections()
		return nil, nil, err
	}
	return &discoveryKVReader{store, c.Cloud.SecretRoot}, store.CloseIdleConnections, nil
}

func (r *discoveryKVReader) ResolveDiscoverySecret(ctx context.Context, ref string) ([]byte, error) {
	if r == nil || !validDiscoveryCredentialReference(ref, "ref:") {
		return nil, errDiscoveryCredentialUnavailable
	}
	value, err := r.store.Read(ctx, r.root+"/"+strings.TrimPrefix(ref, "ref:"))
	if err != nil {
		return nil, errDiscoveryCredentialUnavailable
	}
	return value, nil
}
