package apiserver

import (
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// DiscoveryCollectionInput is loaded inside an Activity from the scoped product
// receipt. It never enters Temporal history and has no worker retry or lease.
// CheckpointVersion is the provider resume checkpoint, not the workflow receipt.
type DiscoveryCollectionInput struct {
	OrganizationID                  string                     `json:"organization_id"`
	WorkspaceID                     string                     `json:"workspace_id"`
	EnvironmentID                   string                     `json:"environment_id"`
	JobID                           string                     `json:"job_id"`
	SyncID                          string                     `json:"sync_id"`
	IntegrationID                   string                     `json:"integration_id"`
	ConnectionID                    string                     `json:"connection_id"`
	SnapshotID                      string                     `json:"snapshot_id"`
	Generation                      int64                      `json:"generation"`
	ObservationTime                 time.Time                  `json:"observation_time"`
	Provider                        collection.Provider        `json:"provider"`
	CollectorVersion                string                     `json:"collector_version"`
	CredentialClass                 collection.CredentialClass `json:"credential_class"`
	CredentialReference             string                     `json:"credential_reference"`
	SubjectKind                     string                     `json:"subject_kind"`
	SubjectID                       string                     `json:"subject_id"`
	CursorProvider                  *collection.Provider       `json:"cursor_provider"`
	CursorVersion                   *string                    `json:"cursor_version"`
	CursorValue                     *string                    `json:"cursor_value"`
	ParserVersion                   string                     `json:"parser_version"`
	ToolVersion                     string                     `json:"tool_version"`
	Configuration                   json.RawMessage            `json:"configuration"`
	CheckpointVersion               int64                      `json:"checkpoint_version"`
	CheckpointEffectID              string                     `json:"checkpoint_effect_id"`
	CheckpointDigest                []byte                     `json:"checkpoint_digest"`
	CheckpointManifestReference     string                     `json:"checkpoint_manifest_reference"`
	CheckpointManifestKey           string                     `json:"checkpoint_manifest_key"`
	CheckpointManifestVersionID     string                     `json:"checkpoint_manifest_version_id"`
	CheckpointManifestChecksum      []byte                     `json:"checkpoint_manifest_checksum"`
	CheckpointManifestSizeBytes     int64                      `json:"checkpoint_manifest_size_bytes"`
	CheckpointManifestMediaType     string                     `json:"checkpoint_manifest_media_type"`
	CheckpointManifestSchemaVersion string                     `json:"checkpoint_manifest_schema_version"`
	EffectID                        string                     `json:"effect_id"`
	Deadline                        time.Time                  `json:"deadline"`
}

func (input DiscoveryCollectionInput) CollectionRequest(scope domain.Scope) (collection.Request, error) {
	if scope.Validate() != nil || input.OrganizationID != scope.OrganizationID().String() || input.WorkspaceID != scope.WorkspaceID().String() || input.EnvironmentID != scope.EnvironmentID().String() || !validProductID(input.SyncID) || !validProductID(input.SnapshotID) || input.Generation < 1 || !validReferenceOnlyJSON(input.Configuration) || input.ObservationTime.IsZero() || input.ObservationTime.Nanosecond() != 0 || input.ObservationTime.Location() != time.UTC || !input.Deadline.After(input.ObservationTime) || !collection.ValidExecutionIdentity(0, input.EffectID) {
		return collection.Request{}, ErrRepositoryOperation
	}
	integration, ie := domain.ParseProductID(input.IntegrationID)
	connection, ce := domain.ParseProductID(input.ConnectionID)
	job, je := domain.ParseProductID(input.JobID)
	if ie != nil || ce != nil || je != nil {
		return collection.Request{}, ErrRepositoryOperation
	}
	request := collection.Request{Scope: scope, IntegrationID: integration, ConnectionID: connection, JobID: job, EffectID: input.EffectID, ObservationTime: input.ObservationTime, Provider: input.Provider, CollectorVersion: input.CollectorVersion, CredentialClass: input.CredentialClass, CredentialReference: input.CredentialReference, ExpectedSubject: collection.SubjectBinding{Kind: input.SubjectKind, ID: input.SubjectID}, ParserVersion: input.ParserVersion, ToolVersion: input.ToolVersion, Bounds: collection.Bounds{MaxPages: 10000, FreshPageLimit: 1, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 10 * time.Minute}}
	if input.CursorProvider != nil || input.CursorVersion != nil || input.CursorValue != nil {
		if input.CursorProvider == nil || input.CursorVersion == nil || input.CursorValue == nil {
			return collection.Request{}, ErrRepositoryOperation
		}
		request.Cursor = collection.Cursor{Provider: *input.CursorProvider, Version: *input.CursorVersion, Value: *input.CursorValue}
	}
	if request.Validate() != nil {
		return collection.Request{}, ErrRepositoryOperation
	}
	return request, nil
}
