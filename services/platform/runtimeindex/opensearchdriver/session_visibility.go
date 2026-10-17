package opensearchdriver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type visibilityResponse struct {
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
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore json.RawMessage `json:"max_score"`
		Hits     []struct {
			Index       string          `json:"_index"`
			ID          string          `json:"_id"`
			Version     int64           `json:"_version"`
			Sequence    *int64          `json:"_seq_no"`
			PrimaryTerm int64           `json:"_primary_term"`
			Score       json.RawMessage `json:"_score"`
			Source      json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// VerifyVisibleDocuments proves search visibility for one bounded scope. The
// expected documents must come from digest-validated committed receipt/archive
// bytes, never from search results. This method performs no writes or refresh.
func (index *SessionIndex) VerifyVisibleDocuments(ctx context.Context, expected []sessionsearch.Document) error {
	if index == nil || index.transport == nil {
		return runtimeindex.ErrConfiguration
	}
	if len(expected) == 0 || len(expected) > 1000 {
		return runtimeindex.ErrRejected
	}
	first := expected[0]
	for _, value := range []string{first.OrganizationID, first.WorkspaceID, first.EnvironmentID} {
		if _, err := domain.ParseProductID(value); err != nil {
			return runtimeindex.ErrRejected
		}
	}
	ids := make([]string, 0, len(expected))
	documents := make(map[string]sessionsearch.Document, len(expected))
	totalBytes := 0
	for _, document := range expected {
		decoded, err := hex.DecodeString(document.DocumentID)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != document.DocumentID || document.RecordType != "runtime_session_event" || document.OrganizationID != first.OrganizationID || document.WorkspaceID != first.WorkspaceID || document.EnvironmentID != first.EnvironmentID {
			return runtimeindex.ErrRejected
		}
		if _, exists := documents[document.DocumentID]; exists {
			return runtimeindex.ErrRejected
		}
		body, err := json.Marshal(document)
		totalBytes += len(body)
		if err != nil || totalBytes > index.transport.config.MaximumResponseBytes/2 {
			return runtimeindex.ErrRejected
		}
		documents[document.DocumentID] = document
		ids = append(ids, document.DocumentID)
	}
	sort.Strings(ids)
	filters := []any{
		map[string]any{"term": map[string]string{"organization_id": first.OrganizationID}},
		map[string]any{"term": map[string]string{"workspace_id": first.WorkspaceID}},
		map[string]any{"term": map[string]string{"environment_id": first.EnvironmentID}},
		map[string]any{"ids": map[string]any{"values": ids}},
	}
	body, err := json.Marshal(map[string]any{"size": len(ids), "track_total_hits": true, "version": true, "seq_no_primary_term": true, "query": map[string]any{"bool": map[string]any{"filter": filters}}})
	if err != nil || len(body) > index.transport.config.MaximumRequestBytes {
		return runtimeindex.ErrRejected
	}
	if err := index.Ready(ctx); err != nil {
		return err
	}
	path := "/" + index.indexName() + "/_search?allow_partial_search_results=false&request_cache=false&typed_keys=false&terminate_after=0&timeout=" + strconv.Itoa(int(index.transport.config.RequestTimeout/time.Second)) + "s"
	result, err := index.transport.request(ctx, http.MethodPost, path, "application/json", body, false)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return runtimeindex.ErrCanceled
	}
	if result.status != http.StatusOK {
		return sessionReadStatus(result.status)
	}
	var response visibilityResponse
	if decodeSessionResponse(result.body, &response) != nil || response.Took == nil || *response.Took < 0 || response.TimedOut == nil || response.Shards == nil || response.Shards.Failed == nil || response.Hits == nil || response.Hits.Total == nil {
		return runtimeindex.ErrDrift
	}
	if *response.TimedOut || response.TerminatedEarly || *response.Shards.Failed != 0 || response.Shards.Successful != response.Shards.Total {
		return runtimeindex.ErrRetryable
	}
	if response.Shards.Total < 1 || response.Shards.Skipped < 0 || response.Shards.Skipped > response.Shards.Total || response.Hits.Total.Relation != "eq" || response.Hits.Total.Value != len(expected) || len(response.Hits.Hits) != len(expected) {
		return runtimeindex.ErrDrift
	}
	seen := make(map[string]bool, len(expected))
	for _, hit := range response.Hits.Hits {
		document, found := documents[hit.ID]
		if !found || seen[hit.ID] || hit.Index != index.indexName() || hit.Version != 1 || hit.Sequence == nil || *hit.Sequence < 0 || hit.PrimaryTerm < 1 {
			return runtimeindex.ErrDrift
		}
		var source sessionsearch.Document
		canonical, _ := json.Marshal(document)
		if decodeSessionResponse(hit.Source, &source) != nil || source != document || !equalCanonicalJSON(hit.Source, canonical) {
			return runtimeindex.ErrDrift
		}
		seen[hit.ID] = true
	}
	if ctx.Err() != nil {
		return runtimeindex.ErrCanceled
	}
	return nil
}

const sessionRetentionWitnessLimit = 32

type sessionSearchBucket struct {
	Key struct {
		InvestigationID string `json:"investigation_id"`
	} `json:"key"`
	Count          int64                      `json:"doc_count"`
	MatchingEvents *sessionRetentionWitnesses `json:"matching_events,omitempty"`
}

type sessionRetentionWitnesses struct {
	Hits *struct {
		Total *struct {
			Value    int64  `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore json.RawMessage `json:"max_score"`
		Hits     []struct {
			Index  string          `json:"_index"`
			ID     string          `json:"_id"`
			Score  json.RawMessage `json:"_score"`
			Sort   []string        `json:"sort"`
			Source struct {
				OrganizationID  string `json:"organization_id"`
				WorkspaceID     string `json:"workspace_id"`
				EnvironmentID   string `json:"environment_id"`
				RecordType      string `json:"record_type"`
				InvestigationID string `json:"investigation_id"`
				EventID         string `json:"event_id"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func withSessionRetentionWitnesses(body []byte) ([]byte, error) {
	var query map[string]any
	if json.Unmarshal(body, &query) != nil {
		return nil, runtimeindex.ErrRejected
	}
	aggregations, ok := query["aggs"].(map[string]any)
	if !ok {
		return nil, runtimeindex.ErrRejected
	}
	sessions, ok := aggregations["sessions"].(map[string]any)
	if !ok {
		return nil, runtimeindex.ErrRejected
	}
	sessions["aggs"] = map[string]any{"matching_events": map[string]any{"top_hits": map[string]any{
		"size":    sessionRetentionWitnessLimit,
		"_source": []string{"organization_id", "workspace_id", "environment_id", "record_type", "investigation_id", "event_id"},
		"sort":    []any{map[string]any{"event_id": map[string]string{"order": "asc"}}, map[string]any{"document_id": map[string]string{"order": "asc"}}},
	}}}
	result, err := json.Marshal(query)
	if err != nil {
		return nil, runtimeindex.ErrRejected
	}
	return result, nil
}

func (index *SessionIndex) retainedSessionCandidates(ctx context.Context, scope domain.Scope, buckets []sessionSearchBucket) ([]string, error) {
	eventIDs := make([]string, 0, len(buckets)*sessionRetentionWitnessLimit)
	for _, bucket := range buckets {
		witnesses := bucket.MatchingEvents
		if witnesses == nil || witnesses.Hits == nil || witnesses.Hits.Total == nil || witnesses.Hits.Total.Value != bucket.Count || witnesses.Hits.Total.Relation != "eq" || string(witnesses.Hits.MaxScore) != "null" {
			return nil, runtimeindex.ErrDrift
		}
		hits := witnesses.Hits.Hits
		expected := bucket.Count
		if expected > sessionRetentionWitnessLimit {
			expected = sessionRetentionWitnessLimit
		}
		if hits == nil || int64(len(hits)) != expected {
			return nil, runtimeindex.ErrDrift
		}
		previousEvent, previousDocument := "", ""
		for _, hit := range hits {
			source := hit.Source
			decoded, err := hex.DecodeString(hit.ID)
			if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hit.ID || hit.Index != index.indexName() || string(hit.Score) != "null" || len(hit.Sort) != 2 || hit.Sort[0] != source.EventID || hit.Sort[1] != hit.ID || source.RecordType != "runtime_session_event" || source.InvestigationID != bucket.Key.InvestigationID || source.OrganizationID != scope.OrganizationID().String() || source.WorkspaceID != scope.WorkspaceID().String() || source.EnvironmentID != scope.EnvironmentID().String() {
				return nil, runtimeindex.ErrDrift
			}
			if _, err := domain.ParseProductID(source.EventID); err != nil {
				return nil, runtimeindex.ErrDrift
			}
			if source.EventID < previousEvent || source.EventID == previousEvent && hit.ID <= previousDocument {
				return nil, runtimeindex.ErrDrift
			}
			previousEvent, previousDocument = source.EventID, hit.ID
			eventIDs = append(eventIDs, source.EventID)
		}
	}
	states, err := runtimeindex.CheckEventVisibility(ctx, index.retention, scope, eventIDs)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		live := false
		for _, hit := range bucket.MatchingEvents.Hits.Hits {
			if states[hit.Source.EventID] {
				live = true
			}
		}
		if live {
			result = append(result, bucket.Key.InvestigationID)
		} else if int64(len(bucket.MatchingEvents.Hits.Hits)) != bucket.Count {
			return nil, runtimeindex.ErrRetryable
		}
	}
	return result, nil
}

// These witnesses remain opaque to API composition and JSON serialization.
// They bind a page to this exact index instance and scope; callers cannot forge
// event IDs or reuse a different request/index's visibility decision.
type sessionPageRetentionWitnesses struct {
	index          *SessionIndex
	scope          domain.Scope
	after          string
	investigations []string
	events         [][]string
}

func (index *SessionIndex) retainPageWitnesses(scope domain.Scope, page SessionSearchPage, buckets []sessionSearchBucket) *sessionPageRetentionWitnesses {
	witness := &sessionPageRetentionWitnesses{index: index, scope: scope, after: page.After, investigations: append([]string(nil), page.InvestigationIDs...), events: make([][]string, 0, len(page.InvestigationIDs))}
	retained := make(map[string]bool, len(page.InvestigationIDs))
	for _, id := range page.InvestigationIDs {
		retained[id] = true
	}
	for _, bucket := range buckets {
		if !retained[bucket.Key.InvestigationID] {
			continue
		}
		ids := make([]string, 0, len(bucket.MatchingEvents.Hits.Hits))
		for _, hit := range bucket.MatchingEvents.Hits.Hits {
			ids = append(ids, hit.Source.EventID)
		}
		witness.events = append(witness.events, ids)
	}
	return witness
}

// RecheckRetainedCandidates is the final collective barrier for a bounded
// multi-page API search. It checks every retained candidate's actual matching
// witnesses after all provider requests. A witness expiring between pages makes
// the search unavailable rather than inventing a short or exhausted page.
func (index *SessionIndex) RecheckRetainedCandidates(ctx context.Context, scope domain.Scope, pages []SessionSearchPage) error {
	if index == nil || index.retention == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || len(pages) < 1 || len(pages) > 8 {
		return runtimeindex.ErrRejected
	}
	all := make([]string, 0)
	candidates := make([][]string, 0)
	seen := make(map[string]bool)
	for _, page := range pages {
		witness := page.retentionWitnesses
		if witness == nil || witness.index != index || witness.scope != scope || witness.after != page.After || len(witness.investigations) != len(page.InvestigationIDs) || len(witness.events) != len(page.InvestigationIDs) {
			return runtimeindex.ErrRejected
		}
		for i, id := range page.InvestigationIDs {
			if id != witness.investigations[i] || seen[id] || !validSessionInvestigationID(id) || len(witness.events[i]) < 1 || len(witness.events[i]) > sessionRetentionWitnessLimit {
				return runtimeindex.ErrRejected
			}
			seen[id] = true
			candidates = append(candidates, witness.events[i])
			all = append(all, witness.events[i]...)
		}
	}
	if len(candidates) > 101 {
		return runtimeindex.ErrRejected
	}
	states, err := runtimeindex.CheckEventVisibility(ctx, index.retention, scope, all)
	if err != nil {
		return err
	}
	for _, ids := range candidates {
		live := false
		for _, id := range ids {
			if states[id] {
				live = true
			}
		}
		if !live {
			return runtimeindex.ErrRetryable
		}
	}
	return nil
}
