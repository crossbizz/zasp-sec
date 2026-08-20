package opensearchdriver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

var searchSourceFields = []string{"record_type", "organization_id", "workspace_id", "environment_id", "integration_id", "snapshot_id", "generation", "input_digest", "content_digest", "document_id", "entity_id", "kind", "display_name", "attributes"}

type searchRequest struct {
	Size           int          `json:"size"`
	TrackTotalHits bool         `json:"track_total_hits"`
	Source         []string     `json:"_source"`
	Sort           []searchSort `json:"sort"`
	SearchAfter    []string     `json:"search_after,omitempty"`
	Query          searchQuery  `json:"query"`
}

type searchSort struct {
	EntityID searchSortOrder `json:"entity_id"`
}

type searchSortOrder struct {
	Order string `json:"order"`
}

type searchQuery struct {
	Bool searchBool `json:"bool"`
}

type searchBool struct {
	Filter []any `json:"filter"`
	Must   []any `json:"must,omitempty"`
}

type searchResponse struct {
	Took     int          `json:"took"`
	TimedOut bool         `json:"timed_out"`
	Shards   searchShards `json:"_shards"`
	Hits     searchHits   `json:"hits"`
}

type searchShards struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Skipped    int `json:"skipped"`
	Failed     int `json:"failed"`
}

type searchHits struct {
	Total    searchTotal `json:"total"`
	MaxScore *float64    `json:"max_score"`
	Hits     []searchHit `json:"hits"`
}

type searchTotal struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

type searchHit struct {
	Index  string         `json:"_index"`
	ID     string         `json:"_id"`
	Score  *float64       `json:"_score"`
	Source storedDocument `json:"_source"`
	Sort   []string       `json:"sort"`
}

func (driver *Driver) Search(ctx context.Context, input inventorysearch.DriverQuery) (inventorysearch.DriverSearchResult, error) {
	if !driver.usable() || ctx == nil || ctx.Err() != nil || !validQuery(input) {
		if ctx != nil && ctx.Err() != nil {
			return inventorysearch.DriverSearchResult{}, inventorysearch.ErrCanceled
		}
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrRejected
	}
	wanted := querySnapshot(input)
	current, found, err := driver.readMarker(ctx, wanted)
	if err != nil {
		return inventorysearch.DriverSearchResult{}, err
	}
	if !found {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrUnavailable
	}
	active, ok := snapshotFromMarker(current.Source)
	if !ok {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrDrift
	}
	if active.Generation > wanted.Generation {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrStale
	}
	if active != wanted {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrDrift
	}
	body, marshalErr := json.Marshal(searchBody(input))
	if marshalErr != nil || len(body) > driver.config.MaximumRequestBytes {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrRejected
	}
	result, requestErr := driver.request(ctx, http.MethodPost, "/"+indexName+"/_search", "application/json", body, false)
	if requestErr != nil {
		return inventorysearch.DriverSearchResult{}, requestErr
	}
	if classified := classifyStatus(result.status, false); classified != nil {
		return inventorysearch.DriverSearchResult{}, classified
	}
	var response searchResponse
	if decodeExact(result.body, &response) != nil || response.Took < 0 || response.TimedOut || response.Shards.Total < 1 || response.Shards.Successful < 1 || response.Shards.Failed != 0 || response.Shards.Successful+response.Shards.Skipped != response.Shards.Total || response.Hits.Total.Value < 0 || response.Hits.Total.Relation != "eq" && response.Hits.Total.Relation != "gte" || len(response.Hits.Hits) > input.Limit {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrUnavailable
	}
	activeIDs := make(map[string]struct{}, len(current.Source.DocumentIDs))
	for _, id := range current.Source.DocumentIDs {
		activeIDs[id] = struct{}{}
	}
	hits := make([]inventorysearch.DriverDocument, len(response.Hits.Hits))
	wantedKinds := make(map[string]struct{}, len(input.Kinds))
	for _, kind := range input.Kinds {
		wantedKinds[kind] = struct{}{}
	}
	previous := input.AfterEntityID
	for index, hit := range response.Hits.Hits {
		document, valid := driverFromStored(hit.Source)
		_, isActive := activeIDs[hit.ID]
		if !valid || hit.Index != indexName || hit.ID != document.DocumentID || !isActive || document.Snapshot != active || hit.Score != nil || len(hit.Sort) != 1 || hit.Sort[0] != document.EntityID || document.EntityID <= previous {
			return inventorysearch.DriverSearchResult{}, inventorysearch.ErrDrift
		}
		if len(wantedKinds) > 0 {
			if _, requested := wantedKinds[document.Kind]; !requested {
				return inventorysearch.DriverSearchResult{}, inventorysearch.ErrDrift
			}
		}
		previous = document.EntityID
		hits[index] = document
	}
	next := ""
	if len(hits) == input.Limit && len(hits) > 0 {
		next = hits[len(hits)-1].EntityID
	}
	verified, stillFound, verifyErr := driver.readMarker(ctx, wanted)
	if verifyErr != nil || !stillFound {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrUnavailable
	}
	verifiedActive, verifiedOK := snapshotFromMarker(verified.Source)
	if !verifiedOK {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrDrift
	}
	if verifiedActive.Generation > wanted.Generation {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrStale
	}
	if verifiedActive != wanted || !reflect.DeepEqual(verified.Source.DocumentIDs, current.Source.DocumentIDs) {
		return inventorysearch.DriverSearchResult{}, inventorysearch.ErrDrift
	}
	return inventorysearch.DriverSearchResult{Hits: hits, NextEntityID: next}, nil
}

func searchBody(input inventorysearch.DriverQuery) searchRequest {
	filters := []any{
		map[string]any{"term": map[string]string{"record_type": "document"}},
		map[string]any{"term": map[string]string{"organization_id": input.OrganizationID}},
		map[string]any{"term": map[string]string{"workspace_id": input.WorkspaceID}},
		map[string]any{"term": map[string]string{"environment_id": input.EnvironmentID}},
		map[string]any{"term": map[string]string{"integration_id": input.IntegrationID}},
		map[string]any{"term": map[string]string{"snapshot_id": input.SnapshotID}},
		map[string]any{"term": map[string]int64{"generation": input.Generation}},
		map[string]any{"term": map[string]string{"input_digest": hex.EncodeToString(input.InputDigest[:])}},
		map[string]any{"term": map[string]string{"content_digest": hex.EncodeToString(input.ContentDigest[:])}},
	}
	if len(input.Kinds) > 0 {
		filters = append(filters, map[string]any{"terms": map[string][]string{"kind": append([]string(nil), input.Kinds...)}})
	}
	must := []any(nil)
	if input.Text != "" {
		must = []any{map[string]any{"multi_match": map[string]any{"query": input.Text, "fields": []string{"display_name", "kind", "attributes.value"}, "type": "phrase_prefix"}}}
	}
	request := searchRequest{Size: input.Limit, TrackTotalHits: true, Source: append([]string(nil), searchSourceFields...), Sort: []searchSort{{EntityID: searchSortOrder{Order: "asc"}}}, Query: searchQuery{Bool: searchBool{Filter: filters, Must: must}}}
	if input.AfterEntityID != "" {
		request.SearchAfter = []string{input.AfterEntityID}
	}
	return request
}

func validQuery(input inventorysearch.DriverQuery) bool {
	snapshot := querySnapshot(input)
	if !validSnapshot(snapshot) || input.Limit < 1 || input.Limit > 100 || len(input.Kinds) > 32 || !reflect.DeepEqual(input.Sort, []string{"entity_id"}) || !validSearchText(input.Text, 256) {
		return false
	}
	if input.AfterEntityID != "" {
		if _, err := domain.ParseProductID(input.AfterEntityID); err != nil {
			return false
		}
	}
	previous := ""
	for _, kind := range input.Kinds {
		if !kindPattern.MatchString(kind) || kind <= previous {
			return false
		}
		previous = kind
	}
	return true
}

func querySnapshot(input inventorysearch.DriverQuery) inventorysearch.DriverSnapshot {
	return inventorysearch.DriverSnapshot{OrganizationID: input.OrganizationID, WorkspaceID: input.WorkspaceID, EnvironmentID: input.EnvironmentID, IntegrationID: input.IntegrationID, SnapshotID: input.SnapshotID, Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: input.ContentDigest}
}

func validSearchText(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
