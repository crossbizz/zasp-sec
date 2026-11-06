package kubernetesdiscovery

import (
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

func NewCollectionPage(subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) (CollectionPage, error) {
	return providercollection.NewPage(collection.ProviderKubernetes, subject, cursor, complete, entities, relationships)
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

func NewCollectionClient(api CollectionAPI, artifacts CollectionArtifactAuthority, config CollectionClientConfig) (collection.ProviderClient, error) {
	selected, capable := api.(interface{ NodePlacementEnabled() bool })
	if config.CollectorVersion == NodePlacementCollectorVersion && (!capable || !selected.NodePlacementEnabled()) || capable && selected.NodePlacementEnabled() && config.CollectorVersion != NodePlacementCollectorVersion {
		return nil, ErrInvalid
	}
	return providercollection.New(providercollection.Config{Provider: collection.ProviderKubernetes, API: api, Artifacts: artifacts, CollectorVersion: config.CollectorVersion, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Clock: config.Clock})
}
