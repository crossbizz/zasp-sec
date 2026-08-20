package idpdiscovery

import (
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

func NewOktaCollectionPage(subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) (CollectionPage, error) {
	return providercollection.NewPage(collection.ProviderOkta, subject, cursor, complete, entities, relationships)
}

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

func NewOktaCollectionClient(api CollectionAPI, artifacts CollectionArtifactAuthority, config CollectionClientConfig) (collection.ProviderClient, error) {
	return providercollection.New(providercollection.Config{Provider: collection.ProviderOkta, API: api, Artifacts: artifacts, CollectorVersion: config.CollectorVersion, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Clock: config.Clock})
}
