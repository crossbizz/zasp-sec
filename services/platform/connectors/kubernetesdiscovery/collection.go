package kubernetesdiscovery

import (
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

type CollectionAPI = providercollection.API
type CollectionPageRequest = providercollection.PageRequest
type CollectionPage = providercollection.Page

type CollectionClientConfig struct {
	Bucket           string
	CollectorVersion string
	Clock            func() time.Time
}

func NewCollectionClient(api CollectionAPI, artifacts artifactstore.ArtifactStore, config CollectionClientConfig) (collection.ProviderClient, error) {
	return providercollection.New(providercollection.Config{Provider: collection.ProviderKubernetes, API: api, Artifacts: artifacts, Bucket: config.Bucket, CollectorVersion: config.CollectorVersion, Clock: config.Clock})
}
