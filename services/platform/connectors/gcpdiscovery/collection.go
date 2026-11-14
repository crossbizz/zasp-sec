// Package gcpdiscovery lists the AI agents of Google Cloud projects without
// installing anything in them: Vertex AI Agent Engine reasoning engines,
// Conversational Agents (Dialogflow CX), Gemini Enterprise agents, Vertex AI
// endpoints and their deployed models, the Cloud Run services and Cloud
// Functions that call a model, and the service accounts they run as.
//
// It reads Google's REST APIs with a short-lived access token of a read-only
// service account the customer owns (token.go). It records names, states and
// IAM role names. It never records a secret, a token, the value of an
// environment variable, a prompt or a payload.
package gcpdiscovery

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

var ErrInvalid = errors.New("Google Cloud connector input rejected")
var ErrProvider = errors.New("Google Cloud connector provider rejected")

type CollectionAPI = providercollection.API
type CollectionPageRequest = providercollection.PageRequest
type CollectionPage = providercollection.Page
type CollectionArtifactAuthority = providercollection.ArtifactAuthority

func NewGCPCollectionPage(subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships, findings []json.RawMessage) (CollectionPage, error) {
	return providercollection.NewPageWithFindings(collection.ProviderGCP, subject, cursor, complete, entities, relationships, findings)
}

type CollectionClientConfig struct {
	CollectorVersion string
	ParserVersion    string
	ToolVersion      string
	Clock            func() time.Time
}

func NewGCPCollectionClient(api CollectionAPI, artifacts CollectionArtifactAuthority, config CollectionClientConfig) (collection.ProviderClient, error) {
	return providercollection.New(providercollection.Config{Provider: collection.ProviderGCP, API: api, Artifacts: artifacts, CollectorVersion: config.CollectorVersion, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Clock: config.Clock})
}
