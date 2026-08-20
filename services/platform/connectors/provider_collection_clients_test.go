package connectors_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
)

func TestEveryFirstPartyProviderExportsACollectionClient(t *testing.T) {
	t.Parallel()
	api := collectionPageAPI{}
	store := collectionArtifacts{}
	clock := func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
	clients := []struct {
		name     string
		provider collection.Provider
		client   collection.ProviderClient
		err      error
	}{
		func() struct {
			name     string
			provider collection.Provider
			client   collection.ProviderClient
			err      error
		} {
			client, err := awsdiscovery.NewCollectionClient(api, store, awsdiscovery.CollectionClientConfig{Bucket: "zasp-evidence", CollectorVersion: "collector_v1", Clock: clock})
			return struct {
				name     string
				provider collection.Provider
				client   collection.ProviderClient
				err      error
			}{"aws", collection.ProviderAWS, client, err}
		}(),
		func() struct {
			name     string
			provider collection.Provider
			client   collection.ProviderClient
			err      error
		} {
			client, err := kubernetesdiscovery.NewCollectionClient(api, store, kubernetesdiscovery.CollectionClientConfig{Bucket: "zasp-evidence", CollectorVersion: "collector_v1", Clock: clock})
			return struct {
				name     string
				provider collection.Provider
				client   collection.ProviderClient
				err      error
			}{"kubernetes", collection.ProviderKubernetes, client, err}
		}(),
		func() struct {
			name     string
			provider collection.Provider
			client   collection.ProviderClient
			err      error
		} {
			client, err := githubdiscovery.NewCollectionClient(api, store, githubdiscovery.CollectionClientConfig{Bucket: "zasp-evidence", CollectorVersion: "collector_v1", Clock: clock})
			return struct {
				name     string
				provider collection.Provider
				client   collection.ProviderClient
				err      error
			}{"github", collection.ProviderGitHub, client, err}
		}(),
		func() struct {
			name     string
			provider collection.Provider
			client   collection.ProviderClient
			err      error
		} {
			client, err := idpdiscovery.NewOktaCollectionClient(api, store, idpdiscovery.CollectionClientConfig{Bucket: "zasp-evidence", CollectorVersion: "collector_v1", Clock: clock})
			return struct {
				name     string
				provider collection.Provider
				client   collection.ProviderClient
				err      error
			}{"okta", collection.ProviderOkta, client, err}
		}(),
	}
	for _, candidate := range clients {
		if candidate.err != nil || candidate.client == nil {
			t.Fatalf("%s collection client = %T, err=%v", candidate.name, candidate.client, candidate.err)
		}
		probe, ok := candidate.client.(collection.ReadinessProbe)
		if !ok {
			t.Fatalf("%s client does not expose provider readiness", candidate.name)
		}
		status := probe.Check(context.Background())
		if !status.Ready || status.Provider != candidate.provider || status.CollectorVersion != "collector_v1" || status.Code != collection.ReadinessReady {
			t.Fatalf("%s readiness = %#v", candidate.name, status)
		}
	}
}

type collectionPageAPI struct{}

func (collectionPageAPI) FetchCollectionPage(context.Context, []byte, awsdiscovery.CollectionPageRequest) (awsdiscovery.CollectionPage, error) {
	return awsdiscovery.CollectionPage{}, nil
}

func (collectionPageAPI) CheckCollectionReadiness(context.Context) error { return nil }

type collectionArtifacts struct{}

func (collectionArtifacts) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{Locator: request.Locator, MediaType: request.MediaType, Body: bytes.Clone(request.Body), Size: int64(len(request.Body)), SHA256: sha256.Sum256(request.Body)}, nil
}
func (collectionArtifacts) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrGet
}
func (collectionArtifacts) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}
