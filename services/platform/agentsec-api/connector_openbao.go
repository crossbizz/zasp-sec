package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
	"github.com/zasp-ai/zasp-sec/services/platform/openbaokv"
)

type runtimeConnectorSecrets interface {
	apiserver.OAuthSecretDriver
	valid() bool
	oauthStore(RuntimeConfig) (apiserver.ConnectorOAuthSecretStore, error)
}

func (d *connectorSecretsDriver) valid() bool { return d != nil && d.client != nil }
func (d *connectorSecretsDriver) oauthStore(config RuntimeConfig) (apiserver.ConnectorOAuthSecretStore, error) {
	return apiserver.NewDurableOAuthSecretStore(d, config.ConnectorSecretPrefix, config.ConnectorKMSKeyARN, config.ProviderTimeout, utcNowForConnector)
}

func utcNowForConnector() time.Time { return time.Now().UTC() }

type baoConnectorDriver struct{ store *openbaokv.Store }

func (d *baoConnectorDriver) valid() bool { return d != nil && d.store != nil }
func (d *baoConnectorDriver) oauthStore(config RuntimeConfig) (apiserver.ConnectorOAuthSecretStore, error) {
	return apiserver.NewKVStoreForOAuth(d, config.ConnectorSecretPrefix, config.ProviderTimeout, utcNowForConnector)
}

func validConnectorSecretAuthority(config RuntimeConfig) bool {
	if !config.ConnectorSecrets.Valid() {
		return false
	}
	if config.ConnectorSecrets.Provider == openbaokv.Provider {
		return config.ConnectorKMSKeyARN == "" && strings.HasSuffix(config.ConnectorSecretPrefix, "/oauth") && openbaoclient.ValidPath(strings.TrimSuffix(config.ConnectorSecretPrefix, "/oauth"))
	}
	return connectorKMSPattern.MatchString(config.ConnectorKMSKeyARN)
}

func newRuntimeConnectorSecrets(ctx context.Context, config RuntimeConfig) (runtimeConnectorSecrets, idleConnectionCloser, error) {
	if !validConnectorSecretAuthority(config) {
		return nil, nil, errRuntimeUnavailable
	}
	if config.ConnectorSecrets.Provider != openbaokv.Provider {
		client, tr, err := newConnectorSecretsClient(config)
		if err != nil {
			return nil, nil, err
		}
		return &connectorSecretsDriver{client: client}, tr, nil
	}
	store, err := openbaokv.New(config.ConnectorSecrets, strings.TrimSuffix(config.ConnectorSecretPrefix, "/oauth"), config.ProviderTimeout)
	if err != nil {
		return nil, nil, err
	}
	if err = store.Ready(ctx); err != nil {
		store.CloseIdleConnections()
		return nil, nil, err
	}
	return &baoConnectorDriver{store: store}, store, nil
}

func (d *baoConnectorDriver) Create(ctx context.Context, name, kms string, value []byte) error {
	if kms != "" || len(value) < 1 || len(value) > 16384 {
		return errRuntimeUnavailable
	}
	err := d.store.Create(ctx, name, value)
	if err != nil && !errors.Is(err, openbaoclient.ErrVersionConflict) {
		return apiserver.ErrOAuthSecretCreateRejected
	}
	return err
}

func (d *baoConnectorDriver) Read(ctx context.Context, name string) ([]byte, error) {
	value, err := d.store.Read(ctx, name)
	if errors.Is(err, openbaoclient.ErrNotFound) {
		return nil, apiserver.ErrOAuthSecretNotFound
	}
	if err != nil || len(value) > 16384 {
		clear(value)
		return nil, errRuntimeUnavailable
	}
	return value, nil
}

func (d *baoConnectorDriver) Delete(ctx context.Context, name string) error {
	err := d.store.Delete(ctx, name)
	if errors.Is(err, openbaoclient.ErrNotFound) {
		return apiserver.ErrOAuthSecretNotFound
	}
	return err
}
