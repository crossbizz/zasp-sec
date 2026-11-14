// Package salesforcediscovery lists the Agentforce agents and Einstein bots
// of one Salesforce org for the discovery collection contract.
package salesforcediscovery

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

var ErrInvalid = errors.New("Salesforce connector input rejected")
var ErrProvider = errors.New("Salesforce connector provider rejected")

func NewSalesforceCollectionPage(subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) (CollectionPage, error) {
	return providercollection.NewPage(collection.ProviderSalesforce, subject, cursor, complete, entities, relationships)
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

func NewSalesforceCollectionClient(api CollectionAPI, artifacts CollectionArtifactAuthority, config CollectionClientConfig) (collection.ProviderClient, error) {
	return providercollection.New(providercollection.Config{Provider: collection.ProviderSalesforce, API: api, Artifacts: artifacts, CollectorVersion: config.CollectorVersion, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Clock: config.Clock})
}
