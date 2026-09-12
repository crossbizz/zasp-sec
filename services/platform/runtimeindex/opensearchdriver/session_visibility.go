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
