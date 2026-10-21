package opensearchdriver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

const retentionPurgeDocumentLimit = 64

// RetentionPurgeAuthority must be bound to the actual durable cleanup claim,
// purpose, source identity and worker lease. Scope/event IDs alone confer no
// authority. Recheck the original claim and current policy after blocking waits;
// never implement this callback as a generic privileged scope-only reader.
type RetentionPurgeAuthority interface {
	AuthorizeRetentionPurge(context.Context, domain.Scope, string) error
}

// RetentionPurgeObservation contains confirmed provider observations only.
// IndexObservedEmpty does not prove writer drainage, SQL claim settlement, or
// physical retention completion; those require the caller's actual protocol.
type RetentionPurgeObservation struct {
	DocumentsChecked   int
	DocumentsAbsent    int
	IndexObservedEmpty bool
}

type RetentionPurger struct {
	driver     *Driver
	authority  RetentionPurgeAuthority
	indexName  string
	recordType string
	raw        bool
	ready      func(context.Context) error
}

// NewRawRetentionPurger permits only the original fixed raw-event index.
func NewRawRetentionPurger(driver *Driver, authority RetentionPurgeAuthority) (*RetentionPurger, error) {
	if !validRetentionPurgeDriver(driver) || nilInterface(authority) {
		return nil, runtimeindex.ErrConfiguration
	}
	return &RetentionPurger{driver: driver, authority: authority, indexName: indexName, recordType: "runtime_event", raw: true, ready: driver.Ready}, nil
}

// NewSessionRetentionPurger permits only the explicitly selected fixed session
// generation; it cannot accept arbitrary targets, aliases, or wildcards.
func NewSessionRetentionPurger(index *SessionIndex, authority RetentionPurgeAuthority) (*RetentionPurger, error) {
	if index == nil || !validRetentionPurgeDriver(index.transport) || nilInterface(authority) {
		return nil, runtimeindex.ErrConfiguration
	}
	return &RetentionPurger{driver: index.transport, authority: authority, indexName: index.indexName(), recordType: "runtime_session_event", ready: index.Ready}, nil
}

func validRetentionPurgeDriver(driver *Driver) bool {
	if driver == nil || driver.endpoint == nil || nilInterface(driver.client) {
		return false
	}
	endpoint, err := validateConfig(driver.config, driver.credentials, driver.signer, driver.clock)
	return err == nil && endpoint.String() == driver.endpoint.String()
}

type retentionPurgeSource struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	EventID        string `json:"event_id"`
	DocumentID     string `json:"document_id"`
	RecordType     string `json:"record_type"`
}

type retentionPurgeHit struct {
	Index       string               `json:"_index"`
	ID          string               `json:"_id"`
	Sequence    *int64               `json:"_seq_no"`
	PrimaryTerm *int64               `json:"_primary_term"`
	Score       json.RawMessage      `json:"_score"`
	Sort        []string             `json:"sort"`
	Source      retentionPurgeSource `json:"_source"`
}

type retentionPurgeSearchResponse struct {
	Took            *int  `json:"took"`
	TimedOut        *bool `json:"timed_out"`
	TerminatedEarly bool  `json:"terminated_early,omitempty"`
	Shards          *struct {
		Total      int  `json:"total"`
		Successful int  `json:"successful"`
		Skipped    int  `json:"skipped"`
		Failed     *int `json:"failed"`
	} `json:"_shards"`
	Hits *struct {
		Total *struct {
			Value    int64  `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore json.RawMessage     `json:"max_score"`
		Hits     []retentionPurgeHit `json:"hits"`
	} `json:"hits"`
}

func (p *RetentionPurger) validIdentity(scope domain.Scope, eventID, id string, source retentionPurgeSource) bool {
	validID := documentIDPattern.MatchString(id)
	if !p.raw {
		decoded, err := hex.DecodeString(id)
		validID = err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == id
	}
	return validID && source.DocumentID == id && source.RecordType == p.recordType && source.OrganizationID == scope.OrganizationID().String() && source.WorkspaceID == scope.WorkspaceID().String() && source.EnvironmentID == scope.EnvironmentID().String() && source.EventID == eventID
}

func (p *RetentionPurger) authorize(ctx context.Context, scope domain.Scope, eventID string) error {
	if ctx.Err() != nil {
		return runtimeindex.ErrCanceled
	}
	if p.authority.AuthorizeRetentionPurge(ctx, scope, eventID) != nil {
		return runtimeindex.ErrDenied
	}
	if ctx.Err() != nil {
		return runtimeindex.ErrCanceled
	}
	return nil
}

func (p *RetentionPurger) search(ctx context.Context, scope domain.Scope, eventID string) ([]retentionPurgeHit, error) {
	filters := []any{}
	for _, term := range []struct{ field, value string }{{"organization_id", scope.OrganizationID().String()}, {"workspace_id", scope.WorkspaceID().String()}, {"environment_id", scope.EnvironmentID().String()}, {"record_type", p.recordType}, {"event_id", eventID}} {
		filters = append(filters, map[string]any{"term": map[string]string{term.field: term.value}})
	}
	body, _ := json.Marshal(map[string]any{"size": retentionPurgeDocumentLimit, "track_total_hits": true, "seq_no_primary_term": true, "_source": []string{"organization_id", "workspace_id", "environment_id", "record_type", "event_id", "document_id"}, "query": map[string]any{"bool": map[string]any{"filter": filters}}, "sort": []any{map[string]any{"document_id": map[string]string{"order": "asc"}}}})
	path := "/" + p.indexName + "/_search?allow_partial_search_results=false&request_cache=false&typed_keys=false&terminate_after=0&timeout=" + strconv.Itoa(int(p.driver.config.RequestTimeout/time.Second)) + "s"
	response, err := p.driver.request(ctx, http.MethodPost, path, "application/json", body, false)
	if err != nil {
		return nil, err
	}
	if response.status != http.StatusOK {
		return nil, sessionReadStatus(response.status)
	}
	var result retentionPurgeSearchResponse
	if decodeSessionResponse(response.body, &result) != nil || result.Took == nil || *result.Took < 0 || result.TimedOut == nil || result.Shards == nil || result.Shards.Failed == nil || result.Hits == nil || result.Hits.Total == nil || result.Hits.Hits == nil {
		return nil, runtimeindex.ErrDrift
	}
	if *result.TimedOut || result.TerminatedEarly || *result.Shards.Failed != 0 || result.Shards.Successful != result.Shards.Total {
		return nil, runtimeindex.ErrRetryable
	}
	if result.Shards.Total < 1 || result.Shards.Skipped < 0 || result.Shards.Skipped > result.Shards.Total || result.Hits.Total.Relation != "eq" || result.Hits.Total.Value < 0 || string(result.Hits.MaxScore) != "null" {
		return nil, runtimeindex.ErrDrift
	}
	count := result.Hits.Total.Value
	expected := count
	if expected > retentionPurgeDocumentLimit {
		expected = retentionPurgeDocumentLimit
	}
	if int64(len(result.Hits.Hits)) != expected {
		return nil, runtimeindex.ErrDrift
	}
	previous := ""
	for _, hit := range result.Hits.Hits {
		if hit.Index != p.indexName || !p.validIdentity(scope, eventID, hit.ID, hit.Source) || hit.ID <= previous || hit.Sequence == nil || *hit.Sequence < 0 || hit.PrimaryTerm == nil || *hit.PrimaryTerm < 1 || string(hit.Score) != "null" || len(hit.Sort) != 1 || hit.Sort[0] != hit.ID {
			return nil, runtimeindex.ErrDrift
		}
		previous = hit.ID
	}
	// This is one fully validated bounded page, not proof of the whole cohort.
	// Permanent scoped EventID expiry covers every batch; retries query the
	// first remaining page after confirmed conditional deletion and refresh.
	return result.Hits.Hits, nil
}

func (p *RetentionPurger) confirmAbsent(ctx context.Context, scope domain.Scope, eventID string, hit retentionPurgeHit) error {
	query := url.Values{"realtime": {"true"}, "_source_includes": {"organization_id,workspace_id,environment_id,record_type,event_id,document_id"}}
	response, err := p.driver.request(ctx, http.MethodGet, "/"+p.indexName+"/_doc/"+hit.ID+"?"+query.Encode(), "", nil, false)
	if err != nil {
		return err
	}
	if response.status != http.StatusOK && response.status != http.StatusNotFound {
		return sessionReadStatus(response.status)
	}
	var value struct {
		Index       string                `json:"_index"`
		ID          string                `json:"_id"`
		Found       *bool                 `json:"found"`
		Version     *int64                `json:"_version,omitempty"`
		Sequence    *int64                `json:"_seq_no,omitempty"`
		PrimaryTerm *int64                `json:"_primary_term,omitempty"`
		Source      *retentionPurgeSource `json:"_source,omitempty"`
	}
	if decodeSessionResponse(response.body, &value) != nil || value.Index != p.indexName || value.ID != hit.ID || value.Found == nil {
		return runtimeindex.ErrDrift
	}
	if response.status == http.StatusNotFound && !*value.Found && value.Source == nil {
		return nil
	}
	if response.status != http.StatusOK || !*value.Found || value.Source == nil || !p.validIdentity(scope, eventID, hit.ID, *value.Source) || value.Sequence == nil || value.PrimaryTerm == nil || *value.Sequence != *hit.Sequence || *value.PrimaryTerm != *hit.PrimaryTerm {
		return runtimeindex.ErrDrift
	}
	return runtimeindex.ErrRetryable
}

// PurgeEvent performs only conditional document deletes for one admitted
// permanent scoped EventID tombstone. Every hit is validated before any effect.
// A lost acknowledgement is reconciled by realtime readback, never blind retry.
// The caller must separately establish real writer drainage and settle its SQL
// claim; a final zero search is an observation, not proof of global completion.
func (p *RetentionPurger) PurgeEvent(ctx context.Context, scope domain.Scope, eventID string) (observation RetentionPurgeObservation, resultErr error) {
	if p == nil || p.driver == nil || p.ready == nil || nilInterface(p.authority) || ctx == nil || scope.Validate() != nil {
		return observation, runtimeindex.ErrRejected
	}
	if _, err := domain.ParseProductID(eventID); err != nil {
		return observation, runtimeindex.ErrRejected
	}
	operation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := p.authorize(operation, scope, eventID); err != nil {
		return observation, err
	}
	if err := p.ready(operation); err != nil {
		return observation, err
	}
	hits, err := p.search(operation, scope, eventID)
	if err != nil {
		return observation, err
	}
	observation.DocumentsChecked = len(hits)
	for _, hit := range hits {
		if err := p.authorize(operation, scope, eventID); err != nil {
			return observation, err
		}
		query := url.Values{"if_seq_no": {strconv.FormatInt(*hit.Sequence, 10)}, "if_primary_term": {strconv.FormatInt(*hit.PrimaryTerm, 10)}, "refresh": {"wait_for"}, "wait_for_active_shards": {"all"}, "timeout": {strconv.Itoa(int(p.driver.config.RequestTimeout/time.Second)) + "s"}}
		response, err := p.driver.request(operation, http.MethodDelete, "/"+p.indexName+"/_doc/"+hit.ID+"?"+query.Encode(), "", nil, true)
		if operation.Err() != nil {
			return observation, runtimeindex.ErrCanceled
		}
		if err != nil && !errors.Is(err, runtimeindex.ErrUnknownOutcome) {
			return observation, err
		}
		if err == nil {
			switch response.status {
			case http.StatusConflict:
				return observation, runtimeindex.ErrDrift
			case http.StatusUnauthorized, http.StatusForbidden:
				return observation, runtimeindex.ErrDenied
			case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
				return observation, runtimeindex.ErrRejected
			case http.StatusTooManyRequests:
				return observation, runtimeindex.ErrRetryable
			}
		}
		if err = p.confirmAbsent(operation, scope, eventID, hit); err != nil {
			return observation, err
		}
		observation.DocumentsAbsent++
	}
	remaining, err := p.search(operation, scope, eventID)
	if err != nil {
		return observation, err
	}
	if len(remaining) != 0 {
		return observation, runtimeindex.ErrRetryable
	}
	if err = p.authorize(operation, scope, eventID); err != nil {
		return observation, err
	}
	observation.IndexObservedEmpty = true
	return observation, nil
}

// FixedKind binds cleanup intent identity to this factory-selected target.
// Callers cannot use an intent for one session generation on the other index.
func (p *RetentionPurger) FixedKind() string {
	if p == nil {
		return ""
	}
	if p.raw && p.indexName == indexName {
		return "raw-index"
	}
	switch p.indexName {
	case sessionIndexName:
		return "session-index-v1"
	case "zasp-runtime-sessions-v2":
		return "session-index-v2"
	}
	return ""
}
