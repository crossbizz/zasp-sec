package saasdiscovery

import (
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

type CollectionAPI = providercollection.API
type CollectionPageRequest = providercollection.PageRequest
type CollectionPage = providercollection.Page
type CollectionArtifactAuthority = providercollection.ArtifactAuthority

type CollectionClientConfig struct {
	CollectorVersion string
	ParserVersion    string
	ToolVersion      string
	Clock            func() time.Time
}

// NewCollectionClient binds a collection API to the shared collection client
// that pages it, stores each page as an artifact and builds the snapshot.
func NewCollectionClient(api CollectionAPI, artifacts CollectionArtifactAuthority, config CollectionClientConfig) (collection.ProviderClient, error) {
	return providercollection.New(providercollection.Config{Provider: collection.ProviderSaaS, API: api, Artifacts: artifacts, CollectorVersion: config.CollectorVersion, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Clock: config.Clock})
}
