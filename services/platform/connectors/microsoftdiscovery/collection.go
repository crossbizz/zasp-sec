// Package microsoftdiscovery lists the AI agents of a Microsoft tenant: Entra
// agent identities, third-party AI applications among its service principals,
// and Copilot Studio agents of one Dataverse environment.
package microsoftdiscovery

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

var ErrInvalid = errors.New("Microsoft connector input rejected")
var ErrProvider = errors.New("Microsoft connector provider rejected")

func NewMicrosoftCollectionPage(subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) (CollectionPage, error) {
	return providercollection.NewPage(collection.ProviderMicrosoft, subject, cursor, complete, entities, relationships)
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

func NewMicrosoftCollectionClient(api CollectionAPI, artifacts CollectionArtifactAuthority, config CollectionClientConfig) (collection.ProviderClient, error) {
	return providercollection.New(providercollection.Config{Provider: collection.ProviderMicrosoft, API: api, Artifacts: artifacts, CollectorVersion: config.CollectorVersion, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Clock: config.Clock})
}
