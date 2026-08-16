package main

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/eventstore"
)

const productTimestampLayout = "2006-01-02T15:04:05.000Z"

type openSearchEventDriver struct{ backend *httpBackend }

type productEventDocument struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	EventID        string `json:"event_id"`
	SessionID      string `json:"session_id"`
	AgentID        string `json:"agent_id"`
	Source         string `json:"source"`
	SourceEventID  string `json:"source_event_id"`
	EventClass     string `json:"event_class"`
	Action         string `json:"action"`
	Decision       string `json:"decision"`
	EventTime      string `json:"event_time"`
}

type productSearchHit struct {
	Index  string               `json:"_index"`
	ID     string               `json:"_id"`
	Score  *float64             `json:"_score"`
	Source productEventDocument `json:"_source"`
	Sort   []any                `json:"sort"`
}

type productSearchHits struct {
	Total    searchTotal        `json:"total"`
	MaxScore *float64           `json:"max_score"`
	Hits     []productSearchHit `json:"hits"`
}

type productSearchResponse struct {
	Took     int               `json:"took"`
	TimedOut bool              `json:"timed_out"`
	Shards   shardResult       `json:"_shards"`
	Hits     productSearchHits `json:"hits"`
}

type productGetResponse struct {
	Index       string               `json:"_index"`
	ID          string               `json:"_id"`
	Version     int                  `json:"_version"`
	Sequence    int                  `json:"_seq_no"`
	PrimaryTerm int                  `json:"_primary_term"`
	Found       bool                 `json:"found"`
	Source      productEventDocument `json:"_source"`
}

func newOpenSearchEventDriver(backend *httpBackend) (*openSearchEventDriver, error) {
	if backend == nil || backend.client == nil || backend.spec.Name == "" {
		return nil, errConfiguration
	}
	return &openSearchEventDriver{backend: backend}, nil
}

func (driver *openSearchEventDriver) Index(ctx context.Context, document eventstore.DriverDocument) (eventstore.DriverIndexed, error) {
	if driver == nil || driver.backend == nil || ctx == nil || !validProductDriverDocument(document) {
		return eventstore.DriverIndexed{}, errContent
	}
	stored := storedProductDocument(document)
	query := url.Values{"refresh": {"wait_for"}, "timeout": {"5s"}}
	path := "/" + url.PathEscape(driver.backend.spec.Name) + "/_create/" + url.PathEscape(document.EventID)
	raw, err := driver.backend.do(ctx, http.MethodPut, path, query, stored, false, http.StatusCreated)
	if err == nil {
		var response indexDocumentResponse
		if decodeExactJSON(raw, &response) == nil && response.Index == driver.backend.spec.Name && response.ID == document.EventID &&
			response.Version == 1 && response.Result == "created" && response.Shards.Total == 1 && response.Shards.Successful == 1 &&
			response.Shards.Failed == 0 && response.PrimaryTerm >= 1 && response.Sequence >= 0 {
			return eventstore.DriverIndexed{EventID: document.EventID}, nil
		}
		err = ambiguousMutationError()
	}
	if !isAmbiguousMutation(err) {
		return eventstore.DriverIndexed{}, err
	}
	current, reconcileErr := driver.get(ctx, document.EventID)
	if reconcileErr != nil || !reflect.DeepEqual(current, document) {
		return eventstore.DriverIndexed{}, err
	}
	return eventstore.DriverIndexed{EventID: document.EventID}, nil
}

func (driver *openSearchEventDriver) Search(ctx context.Context, query eventstore.DriverQuery) ([]eventstore.DriverDocument, error) {
	if driver == nil || driver.backend == nil || ctx == nil || !validProductDriverQuery(query) {
		return nil, errScope
	}
	body := productScopedQuery(query)
	raw, err := driver.backend.do(ctx, http.MethodPost, "/"+url.PathEscape(driver.backend.spec.Name)+"/_search", nil, body, true, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var response productSearchResponse
	if decodeExactJSON(raw, &response) != nil || response.TimedOut || response.Took < 0 || response.Shards.Total != 1 ||
		response.Shards.Successful != 1 || response.Shards.Skipped != 0 || response.Shards.Failed != 0 || response.Hits.MaxScore != nil ||
		response.Hits.Total.Relation != "eq" || response.Hits.Total.Value != len(response.Hits.Hits) || len(response.Hits.Hits) > query.Limit {
		return nil, errProvider
	}
	result := make([]eventstore.DriverDocument, 0, len(response.Hits.Hits))
	seen := make(map[string]struct{}, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		document := driverProductDocument(hit.Source)
		if hit.Index != driver.backend.spec.Name || hit.ID != document.EventID || hit.Score != nil || !validProductDriverDocument(document) ||
			document.OrganizationID != query.OrganizationID || document.WorkspaceID != query.WorkspaceID ||
			document.EnvironmentID != query.EnvironmentID || document.SessionID != query.SessionID || !validProductSort(hit.Sort, document) {
			return nil, errContent
		}
		if _, duplicate := seen[document.EventID]; duplicate {
			return nil, errContent
		}
		seen[document.EventID] = struct{}{}
		result = append(result, document)
	}
	return result, nil
}

func (driver *openSearchEventDriver) get(ctx context.Context, eventID string) (eventstore.DriverDocument, error) {
	path := "/" + url.PathEscape(driver.backend.spec.Name) + "/_doc/" + url.PathEscape(eventID)
	raw, err := driver.backend.do(ctx, http.MethodGet, path, nil, nil, true, http.StatusOK)
	if err != nil {
		return eventstore.DriverDocument{}, err
	}
	var response productGetResponse
	if decodeExactJSON(raw, &response) != nil || response.Index != driver.backend.spec.Name || response.ID != eventID || !response.Found ||
		response.Version < 1 || response.Sequence < 0 || response.PrimaryTerm < 1 {
		return eventstore.DriverDocument{}, errProvider
	}
	document := driverProductDocument(response.Source)
	if document.EventID != eventID || !validProductDriverDocument(document) {
		return eventstore.DriverDocument{}, errContent
	}
	return document, nil
}

func storedProductDocument(document eventstore.DriverDocument) productEventDocument {
	return productEventDocument{
		OrganizationID: document.OrganizationID, WorkspaceID: document.WorkspaceID, EnvironmentID: document.EnvironmentID,
		EventID: document.EventID, SessionID: document.SessionID, AgentID: document.AgentID, Source: document.Source,
		SourceEventID: document.SourceEventID, EventClass: document.Class, Action: document.Action,
		Decision: document.Decision, EventTime: document.EventTime,
	}
}

func driverProductDocument(document productEventDocument) eventstore.DriverDocument {
	return eventstore.DriverDocument{
		OrganizationID: document.OrganizationID, WorkspaceID: document.WorkspaceID, EnvironmentID: document.EnvironmentID,
		EventID: document.EventID, SessionID: document.SessionID, AgentID: document.AgentID, Source: document.Source,
		SourceEventID: document.SourceEventID, Class: document.EventClass, Action: document.Action,
		Decision: document.Decision, EventTime: document.EventTime,
	}
}

func productScopedQuery(query eventstore.DriverQuery) map[string]any {
	filters := []any{
		map[string]any{"term": map[string]any{"organization_id": query.OrganizationID}},
		map[string]any{"term": map[string]any{"workspace_id": query.WorkspaceID}},
		map[string]any{"term": map[string]any{"environment_id": query.EnvironmentID}},
		map[string]any{"term": map[string]any{"session_id": query.SessionID}},
	}
	return map[string]any{
		"size": query.Limit, "track_total_hits": true,
		"sort": []any{
			map[string]any{"event_time": map[string]any{"order": "asc"}},
			map[string]any{"event_id": map[string]any{"order": "asc"}},
		},
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
	}
}

func validProductDriverQuery(query eventstore.DriverQuery) bool {
	organization, organizationErr := domain.ParseProductID(query.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(query.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(query.EnvironmentID)
	session, sessionErr := domain.ParseProductID(query.SessionID)
	_, scopeErr := domain.NewScope(organization, workspace, environment)
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && sessionErr == nil && scopeErr == nil &&
		session.String() != "" && query.Limit > 0 && query.Limit <= 100 && reflect.DeepEqual(query.Sort, []string{"event_time", "event_id"})
}

func validProductDriverDocument(document eventstore.DriverDocument) bool {
	query := eventstore.DriverQuery{
		OrganizationID: document.OrganizationID, WorkspaceID: document.WorkspaceID, EnvironmentID: document.EnvironmentID,
		SessionID: document.SessionID, Limit: 1, Sort: []string{"event_time", "event_id"},
	}
	eventID, eventErr := domain.ParseProductID(document.EventID)
	agentID, agentErr := domain.ParseProductID(document.AgentID)
	eventTime, timeErr := time.Parse(productTimestampLayout, document.EventTime)
	return validProductDriverQuery(query) && eventErr == nil && agentErr == nil && eventID.String() != "" && agentID.String() != "" &&
		document.Source == "runtime_gateway" && document.Class == "tool" && document.Action == "invoke" &&
		(document.Decision == "allowed" || document.Decision == "monitored" || document.Decision == "blocked") &&
		validProductSourceEventID(document.SourceEventID) && timeErr == nil && eventTime.Format(productTimestampLayout) == document.EventTime
}

func validProductSourceEventID(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validProductSort(values []any, document eventstore.DriverDocument) bool {
	if len(values) != 2 {
		return false
	}
	timestamp, timestampOK := values[0].(float64)
	eventID, eventIDOK := values[1].(string)
	parsed, err := time.Parse(productTimestampLayout, document.EventTime)
	return timestampOK && eventIDOK && math.Trunc(timestamp) == timestamp && err == nil &&
		timestamp == float64(parsed.UnixMilli()) && eventID == document.EventID
}

var _ eventstore.Driver = (*openSearchEventDriver)(nil)
