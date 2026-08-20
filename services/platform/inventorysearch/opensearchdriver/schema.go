package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

const (
	schemaMarkerID  = "_zasp_schema_v1"
	indexSchemaJSON = `{"mappings":{"dynamic":"strict","properties":{"attributes":{"type":"nested","dynamic":"strict","properties":{"name":{"type":"keyword"},"value":{"type":"text"}}},"content_digest":{"type":"keyword"},"display_name":{"type":"text"},"document_id":{"type":"keyword"},"document_ids":{"type":"keyword"},"entity_id":{"type":"keyword"},"environment_id":{"type":"keyword"},"generation":{"type":"long"},"input_digest":{"type":"keyword"},"integration_id":{"type":"keyword"},"kind":{"type":"keyword"},"mapping_digest":{"type":"keyword"},"organization_id":{"type":"keyword"},"record_type":{"type":"keyword"},"schema_version":{"type":"integer"},"snapshot_id":{"type":"keyword"},"workspace_id":{"type":"keyword"}}}}`
)

type indexSchemaDefinition struct {
	Mappings json.RawMessage `json:"mappings"`
}

type schemaMarker struct {
	RecordType    string `json:"record_type"`
	SchemaVersion int    `json:"schema_version"`
	MappingDigest string `json:"mapping_digest"`
}

type schemaMarkerRecord struct {
	Index       string       `json:"_index"`
	ID          string       `json:"_id"`
	Version     int64        `json:"_version"`
	Sequence    int64        `json:"_seq_no"`
	PrimaryTerm int64        `json:"_primary_term"`
	Found       bool         `json:"found"`
	Source      schemaMarker `json:"_source"`
}

type createIndexResponse struct {
	Acknowledged       bool   `json:"acknowledged"`
	ShardsAcknowledged bool   `json:"shards_acknowledged"`
	Index              string `json:"index"`
}

// Ready proves the exact mapping and immutable schema marker using only signed
// read paths granted to projection workers.
func (driver *Driver) Ready(ctx context.Context) error {
	found, err := driver.exactSchemaMapping(ctx)
	if err != nil || !found {
		return readinessError(ctx, err)
	}
	found, err = driver.exactSchemaMarker(ctx)
	if err != nil || !found {
		return readinessError(ctx, err)
	}
	return nil
}

// InitializeSchema is the separately privileged, idempotent index-init path.
// Projection workers never need its PUT authorities.
func (driver *Driver) InitializeSchema(ctx context.Context) error {
	found, err := driver.exactSchemaMapping(ctx)
	if err != nil {
		return err
	}
	if !found {
		result, requestErr := driver.request(ctx, http.MethodPut, "/"+indexName, "application/json", []byte(indexSchemaJSON), true)
		if requestErr != nil {
			if !errors.Is(requestErr, inventorysearch.ErrUnknownOutcome) {
				return requestErr
			}
			found, requestErr = driver.exactSchemaMapping(ctx)
			if requestErr != nil || !found {
				return inventorysearch.ErrUnknownOutcome
			}
		} else {
			var response createIndexResponse
			if result.status != http.StatusOK || decodeExact(result.body, &response) != nil || !response.Acknowledged || !response.ShardsAcknowledged || response.Index != indexName {
				found, requestErr = driver.exactSchemaMapping(ctx)
				if requestErr != nil || !found {
					return inventorysearch.ErrUnknownOutcome
				}
			}
		}
	}
	found, err = driver.exactSchemaMarker(ctx)
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	body, _ := json.Marshal(expectedSchemaMarker())
	result, requestErr := driver.request(ctx, http.MethodPut, "/"+indexName+"/_doc/"+schemaMarkerID+"?op_type=create&refresh=wait_for", "application/json", body, true)
	if requestErr != nil {
		if !errors.Is(requestErr, inventorysearch.ErrUnknownOutcome) {
			return requestErr
		}
		found, requestErr = driver.exactSchemaMarker(ctx)
		if requestErr != nil || !found {
			return inventorysearch.ErrUnknownOutcome
		}
		return nil
	}
	var response indexResponse
	if result.status != http.StatusCreated || decodeExact(result.body, &response) != nil || response.Index != indexName || response.ID != schemaMarkerID || response.Version != 1 || response.Result != "created" || response.Sequence < 0 || response.PrimaryTerm < 1 || response.Shards.Total < 1 || response.Shards.Successful < 1 || response.Shards.Failed != 0 {
		found, requestErr = driver.exactSchemaMarker(ctx)
		if requestErr != nil || !found {
			return inventorysearch.ErrUnknownOutcome
		}
	}
	return nil
}

func (driver *Driver) exactSchemaMapping(ctx context.Context) (bool, error) {
	result, err := driver.request(ctx, http.MethodGet, "/"+indexName+"/_mapping", "", nil, false)
	if err != nil {
		return false, err
	}
	if result.status == http.StatusNotFound {
		return false, nil
	}
	if result.status != http.StatusOK {
		return false, inventorysearch.ErrUnavailable
	}
	var actual map[string]indexSchemaDefinition
	if decodeExact(result.body, &actual) != nil || len(actual) != 1 {
		return false, inventorysearch.ErrUnavailable
	}
	definition, ok := actual[indexName]
	var expected indexSchemaDefinition
	if !ok || json.Unmarshal([]byte(indexSchemaJSON), &expected) != nil || !equalCanonicalJSON(definition.Mappings, expected.Mappings) {
		return false, inventorysearch.ErrDrift
	}
	return true, nil
}

func (driver *Driver) exactSchemaMarker(ctx context.Context) (bool, error) {
	result, err := driver.request(ctx, http.MethodGet, "/"+indexName+"/_doc/"+schemaMarkerID, "", nil, false)
	if err != nil {
		return false, err
	}
	if result.status == http.StatusNotFound {
		return false, nil
	}
	if result.status != http.StatusOK {
		return false, inventorysearch.ErrUnavailable
	}
	var record schemaMarkerRecord
	if decodeExact(result.body, &record) != nil || !record.Found || record.Index != indexName || record.ID != schemaMarkerID || record.Version != 1 || record.Sequence < 0 || record.PrimaryTerm < 1 || record.Source != expectedSchemaMarker() {
		return false, inventorysearch.ErrDrift
	}
	return true, nil
}

func expectedSchemaMarker() schemaMarker {
	digest := sha256.Sum256([]byte(indexSchemaJSON))
	return schemaMarker{RecordType: "schema_marker", SchemaVersion: 1, MappingDigest: "sha256:" + hex.EncodeToString(digest[:])}
}

func equalCanonicalJSON(left, right json.RawMessage) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	leftCanonical, leftErr := json.Marshal(leftValue)
	rightCanonical, rightErr := json.Marshal(rightValue)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}

func readinessError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return inventorysearch.ErrCanceled
	}
	if errors.Is(err, inventorysearch.ErrDrift) {
		return inventorysearch.ErrDrift
	}
	return inventorysearch.ErrUnavailable
}
