package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

const (
	sessionIndexName       = "zasp-runtime-sessions-v1"
	sessionSchemaMarkerID  = "_zasp_session_schema_v1"
	sessionIndexSchemaJSON = `{"mappings":{"dynamic":"strict","properties":{"action":{"type":"keyword"},"agent_id":{"type":"keyword"},"archive_digest":{"type":"keyword"},"batch_id":{"type":"keyword"},"confidence":{"type":"keyword"},"credential_id":{"type":"keyword"},"decision":{"type":"keyword"},"document_id":{"type":"keyword"},"domain_digest":{"type":"keyword"},"environment_id":{"type":"keyword"},"event_class":{"type":"keyword"},"event_id":{"type":"keyword"},"event_time":{"type":"date","format":"strict_date_time"},"file_digest":{"type":"keyword"},"generation":{"type":"long"},"investigation_id":{"type":"keyword"},"mapping_digest":{"type":"keyword"},"metadata_version":{"type":"integer"},"observed_principal_id":{"type":"keyword"},"organization_id":{"type":"keyword"},"process_digest":{"type":"keyword"},"receipt_digest":{"type":"keyword"},"record_type":{"type":"keyword"},"resource_digest":{"type":"keyword"},"schema_version":{"type":"integer"},"source":{"type":"keyword"},"tool_id":{"type":"keyword"},"workspace_id":{"type":"keyword"}}}}`
)

// SessionIndex shares the bounded SigV4 transport, not the immutable raw-event
// index's mapping or write contract. Callers cannot select an index or raw DSL.
type SessionIndex struct{ transport *Driver }

func NewSessionIndex(config Config, credentials aws.CredentialsProvider, signer HTTPSigner, clock func() time.Time) (*SessionIndex, error) {
	transport, err := New(config, credentials, signer, clock)
	if err != nil {
		return nil, err
	}
	return &SessionIndex{transport: transport}, nil
}

func (index *SessionIndex) Close() {
	if index != nil {
		index.transport.Close()
	}
}

func expectedSessionSchemaMarker() schemaMarker {
	digest := sha256.Sum256([]byte(sessionIndexSchemaJSON))
	return schemaMarker{RecordType: "schema_marker", SchemaVersion: 1, MappingDigest: "sha256:" + hex.EncodeToString(digest[:])}
}

func (index *SessionIndex) Ready(ctx context.Context) error {
	found, err := index.exactMapping(ctx)
	if err != nil {
		return err
	}
	if !found {
		return runtimeindex.ErrRejected
	}
	found, err = index.exactMarker(ctx)
	if err != nil {
		return err
	}
	if !found {
		return runtimeindex.ErrRejected
	}
	return nil
}

// InitializeSchema creates only absent objects. Exact readback reconciles lost
// acknowledgements; existing mapping or marker drift is never overwritten.
func (index *SessionIndex) InitializeSchema(ctx context.Context) error {
	found, err := index.exactMapping(ctx)
	if err != nil {
		return err
	}
	if !found {
		result, writeErr := index.transport.request(ctx, http.MethodPut, "/"+sessionIndexName, "application/json", []byte(sessionIndexSchemaJSON), true)
		found, err = index.exactMapping(ctx)
		if err != nil {
			return err
		}
		if !found {
			return sessionSchemaMutationFailure(writeErr, result.status)
		}
	}
	found, err = index.exactMarker(ctx)
	if err != nil {
		return err
	}
	if !found {
		body, _ := json.Marshal(expectedSessionSchemaMarker())
		result, writeErr := index.transport.request(ctx, http.MethodPut, "/"+sessionIndexName+"/_doc/"+sessionSchemaMarkerID+"?op_type=create&refresh=wait_for", "application/json", body, true)
		found, err = index.exactMarker(ctx)
		if err != nil {
			return err
		}
		if !found {
			return sessionSchemaMutationFailure(writeErr, result.status)
		}
	}
	return nil
}

func sessionSchemaMutationFailure(writeErr error, status int) error {
	if writeErr != nil {
		return writeErr
	}
	if err := classifyStatus(status, true); err != nil {
		return err
	}
	return runtimeindex.ErrUnknownOutcome
}

func (index *SessionIndex) exactMapping(ctx context.Context) (bool, error) {
	if index == nil || index.transport == nil {
		return false, runtimeindex.ErrConfiguration
	}
	result, err := index.transport.request(ctx, http.MethodGet, "/"+sessionIndexName+"/_mapping", "", nil, false)
	if err != nil {
		return false, err
	}
	if result.status == http.StatusNotFound {
		return false, nil
	}
	if result.status != http.StatusOK {
		return false, sessionReadStatus(result.status)
	}
	var mappings map[string]indexSchemaDefinition
	var expected indexSchemaDefinition
	if decodeSessionResponse(result.body, &mappings) != nil || len(mappings) != 1 || json.Unmarshal([]byte(sessionIndexSchemaJSON), &expected) != nil || !equalCanonicalJSON(mappings[sessionIndexName].Mappings, expected.Mappings) {
		return false, runtimeindex.ErrDrift
	}
	return true, nil
}

func (index *SessionIndex) exactMarker(ctx context.Context) (bool, error) {
	result, err := index.transport.request(ctx, http.MethodGet, "/"+sessionIndexName+"/_doc/"+sessionSchemaMarkerID, "", nil, false)
	if err != nil {
		return false, err
	}
	if result.status == http.StatusNotFound {
		return false, nil
	}
	if result.status != http.StatusOK {
		return false, sessionReadStatus(result.status)
	}
	var marker schemaMarkerRecord
	if decodeSessionResponse(result.body, &marker) != nil || !marker.Found || marker.Index != sessionIndexName || marker.ID != sessionSchemaMarkerID || marker.Version != 1 || marker.Sequence < 0 || marker.PrimaryTerm < 1 || marker.Source != expectedSessionSchemaMarker() {
		return false, runtimeindex.ErrDrift
	}
	return true, nil
}

// SessionSearchPage contains candidate investigation IDs only. PostgreSQL must
// still authenticate the current principal and hydrate canonical session facts.
// After is the provider's validated composite continuation, not a public cursor.
type SessionSearchPage struct {
	InvestigationIDs []string
	After            string
}

type sessionSearchResponseWire struct {
	Took     *int  `json:"took"`
	TimedOut *bool `json:"timed_out"`
	// With size=0, OpenSearch 3.8 may terminate only the no-hit collector while
	// aggregation collection continues. The closed request pins terminate_after=0;
	// this field is not a timeout or shard-failure signal for that request shape.
	TerminatedEarly *bool `json:"terminated_early,omitempty"`
	Shards          *struct {
		Total      int  `json:"total"`
		Successful int  `json:"successful"`
		Skipped    int  `json:"skipped"`
		Failed     *int `json:"failed"`
	} `json:"_shards"`
	Hits *struct {
		Total    json.RawMessage   `json:"total,omitempty"`
		MaxScore json.RawMessage   `json:"max_score"`
		Hits     []json.RawMessage `json:"hits"`
	} `json:"hits"`
	Aggregations *struct {
		Sessions *struct {
			After   map[string]string `json:"after_key,omitempty"`
			Buckets []struct {
				Key struct {
					InvestigationID string `json:"investigation_id"`
				} `json:"key"`
				Count int64 `json:"doc_count"`
			} `json:"buckets"`
		} `json:"sessions"`
	} `json:"aggregations"`
}

func (index *SessionIndex) Search(ctx context.Context, scope domain.Scope, filters sessionsearch.Filters, after string, limit int) (SessionSearchPage, error) {
	body, err := sessionsearch.BuildQuery(scope, filters, after, limit)
	if err != nil {
		return SessionSearchPage{}, runtimeindex.ErrRejected
	}
	if err := index.Ready(ctx); err != nil {
		return SessionSearchPage{}, err
	}
	path := "/" + sessionIndexName + "/_search?allow_partial_search_results=false&request_cache=false&typed_keys=false&terminate_after=0&timeout=" + strconv.Itoa(int(index.transport.config.RequestTimeout/time.Second)) + "s"
	result, err := index.transport.request(ctx, http.MethodPost, path, "application/json", body, false)
	if err != nil {
		return SessionSearchPage{}, err
	}
	if result.status != http.StatusOK {
		return SessionSearchPage{}, sessionReadStatus(result.status)
	}
	var response sessionSearchResponseWire
	if decodeSessionResponse(result.body, &response) != nil || response.Took == nil || *response.Took < 0 || response.TimedOut == nil || response.Shards == nil || response.Shards.Failed == nil || response.Hits == nil || response.Aggregations == nil || response.Aggregations.Sessions == nil {
		return SessionSearchPage{}, runtimeindex.ErrDrift
	}
	if *response.TimedOut || *response.Shards.Failed != 0 || response.Shards.Successful != response.Shards.Total {
		return SessionSearchPage{}, runtimeindex.ErrRetryable
	}
	if response.Shards.Total < 1 || response.Shards.Skipped < 0 || response.Shards.Skipped > response.Shards.Total || response.Hits.Hits == nil || len(response.Hits.Hits) != 0 || string(response.Hits.MaxScore) != "null" {
		return SessionSearchPage{}, runtimeindex.ErrDrift
	}
	sessions := response.Aggregations.Sessions
	if sessions.Buckets == nil || len(sessions.Buckets) > limit {
		return SessionSearchPage{}, runtimeindex.ErrDrift
	}
	page := SessionSearchPage{InvestigationIDs: make([]string, 0, len(sessions.Buckets))}
	previous := after
	for _, bucket := range sessions.Buckets {
		id := bucket.Key.InvestigationID
		if !validSessionInvestigationID(id) || id <= previous || bucket.Count < 1 {
			return SessionSearchPage{}, runtimeindex.ErrDrift
		}
		previous = id
		page.InvestigationIDs = append(page.InvestigationIDs, id)
	}
	if len(sessions.Buckets) == 0 {
		if len(sessions.After) != 0 {
			return SessionSearchPage{}, runtimeindex.ErrDrift
		}
		return page, nil
	}
	// The provider's after_key is authoritative for composite pagination and is
	// not guaranteed to equal the final bucket key. It must still move forward.
	if len(sessions.After) != 1 || !validSessionInvestigationID(sessions.After["investigation_id"]) || sessions.After["investigation_id"] < previous {
		return SessionSearchPage{}, runtimeindex.ErrDrift
	}
	page.After = sessions.After["investigation_id"]
	return page, nil
}

func sessionReadStatus(status int) error {
	err := classifyStatus(status, false)
	if err == nil {
		return runtimeindex.ErrDrift
	}
	return err
}

func validSessionInvestigationID(value string) bool {
	if value == "unattributed" {
		return true
	}
	_, err := domain.ParseProductID(value)
	return err == nil
}

// Fail closed on duplicate keys, invalid UTF-8, deep JSON and unknown fields.
func decodeSessionResponse(body []byte, destination any) error {
	if len(body) == 0 || len(body) > maximumResponseBytes || !utf8.Valid(body) {
		return runtimeindex.ErrDrift
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var scan func(int) bool
	scan = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !scan(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !scan(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !scan(0) {
		return runtimeindex.ErrDrift
	}
	if _, err := decoder.Token(); err != io.EOF {
		return runtimeindex.ErrDrift
	}
	return decodeExact(body, destination)
}
