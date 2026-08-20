package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

const (
	schemaMarkerID  = "_zasp_schema_v1"
	indexSchemaJSON = `{"mappings":{"dynamic":"strict","properties":{"action":{"type":"keyword"},"agent_id":{"type":"keyword"},"archive_reference":{"type":"keyword"},"archive_version_id":{"type":"keyword"},"batch_id":{"type":"keyword"},"content_digest":{"type":"keyword"},"document_id":{"type":"keyword"},"environment_id":{"type":"keyword"},"event_class":{"type":"keyword"},"event_id":{"type":"keyword"},"event_time":{"type":"date","format":"strict_date_time"},"evidence_id":{"type":"keyword"},"generation":{"type":"long"},"input_digest":{"type":"keyword"},"mapping_digest":{"type":"keyword"},"organization_id":{"type":"keyword"},"record_type":{"type":"keyword"},"sandbox_id":{"type":"keyword"},"schema_version":{"type":"integer"},"session_id":{"type":"keyword"},"source":{"type":"keyword"},"source_event_id":{"type":"keyword"},"span_id":{"type":"keyword"},"task_id":{"type":"keyword"},"tool_id":{"type":"keyword"},"trace_id":{"type":"keyword"},"workload_id":{"type":"keyword"},"workspace_id":{"type":"keyword"}}}}`
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

type createDocumentResponse struct {
	Index       string         `json:"_index"`
	ID          string         `json:"_id"`
	Version     int64          `json:"_version"`
	Result      string         `json:"result"`
	Shards      responseShards `json:"_shards"`
	Sequence    int64          `json:"_seq_no"`
	PrimaryTerm int64          `json:"_primary_term"`
}

func (driver *Driver) Ready(ctx context.Context) error {
	found, err := driver.exactSchemaMapping(ctx)
	if err != nil || !found {
		return schemaReadinessError(ctx, err)
	}
	found, err = driver.exactSchemaMarker(ctx)
	if err != nil || !found {
		return schemaReadinessError(ctx, err)
	}
	return nil
}

func (driver *Driver) InitializeSchema(ctx context.Context) error {
	found, err := driver.exactSchemaMapping(ctx)
	if err != nil {
		return err
	}
	if !found {
		result, requestErr := driver.request(ctx, http.MethodPut, "/"+indexName, "application/json", []byte(indexSchemaJSON), true)
		if requestErr != nil || result.status != http.StatusOK {
			found, requestErr = driver.exactSchemaMapping(ctx)
			if requestErr != nil || !found {
				return runtimeindex.ErrUnknownOutcome
			}
		} else {
			var response createIndexResponse
			if decodeExact(result.body, &response) != nil || !response.Acknowledged || !response.ShardsAcknowledged || response.Index != indexName {
				found, requestErr = driver.exactSchemaMapping(ctx)
				if requestErr != nil || !found {
					return runtimeindex.ErrUnknownOutcome
				}
			}
		}
	}
	found, err = driver.exactSchemaMarker(ctx)
	if err != nil || found {
		return err
	}
	body, _ := json.Marshal(expectedSchemaMarker())
	result, requestErr := driver.request(ctx, http.MethodPut, "/"+indexName+"/_doc/"+schemaMarkerID+"?op_type=create&refresh=wait_for", "application/json", body, true)
	if requestErr != nil || result.status != http.StatusCreated {
		found, requestErr = driver.exactSchemaMarker(ctx)
		if requestErr != nil || !found {
			return runtimeindex.ErrUnknownOutcome
		}
		return nil
	}
	var response createDocumentResponse
	if decodeExact(result.body, &response) != nil || response.Index != indexName || response.ID != schemaMarkerID || response.Version != 1 || response.Result != "created" || response.Sequence < 0 || response.PrimaryTerm < 1 || response.Shards.Total < 1 || response.Shards.Successful != response.Shards.Total || response.Shards.Failed != 0 {
		found, requestErr = driver.exactSchemaMarker(ctx)
		if requestErr != nil || !found {
			return runtimeindex.ErrUnknownOutcome
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
		return false, runtimeindex.ErrRetryable
	}
	var actual map[string]indexSchemaDefinition
	if decodeExact(result.body, &actual) != nil || len(actual) != 1 {
		return false, runtimeindex.ErrDrift
	}
	definition, ok := actual[indexName]
	var expected indexSchemaDefinition
	if !ok || json.Unmarshal([]byte(indexSchemaJSON), &expected) != nil || !equalCanonicalJSON(definition.Mappings, expected.Mappings) {
		return false, runtimeindex.ErrDrift
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
		return false, runtimeindex.ErrRetryable
	}
	var record schemaMarkerRecord
	if decodeExact(result.body, &record) != nil || !record.Found || record.Index != indexName || record.ID != schemaMarkerID || record.Version != 1 || record.Sequence < 0 || record.PrimaryTerm < 1 || record.Source != expectedSchemaMarker() {
		return false, runtimeindex.ErrDrift
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

func schemaReadinessError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return runtimeindex.ErrCanceled
	}
	if errors.Is(err, runtimeindex.ErrDrift) {
		return runtimeindex.ErrDrift
	}
	return runtimeindex.ErrRetryable
}
