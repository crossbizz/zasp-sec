package opensearchhistory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

const maximumRetentionHistoryPages = 8

// Required pointer/slice fields distinguish an actual empty provider page from
// missing or null envelope data. Only the retention path uses this contract.
type retainedHistorySearchResponse struct {
	TimedOut *bool `json:"timed_out"`
	Hits     *struct {
		Hits []struct {
			ID     string                `json:"_id"`
			Sort   []string              `json:"sort"`
			Source historyStoredDocument `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// Fetch bounded continuation pages when expired matches consume the requested
// limit. Every provider row is checked by the original scope/order/shape rules
// before expiry can hide it. Recheck the complete candidate set after the last
// provider request so a previous page cannot retain stale visibility authority.
func (driver *Driver) searchRetainedPolicyActions(ctx context.Context, scope domain.Scope, trigger string, limit int) ([]platformpolicy.ActionContext, error) {
	if driver.Ready(ctx) != nil {
		return nil, ErrHistory
	}
	type candidate struct {
		eventID string
		value   platformpolicy.ActionContext
	}
	candidates := make([]candidate, 0, limit)
	seen := make(map[string]bool)
	var previousTime time.Time
	previousID := ""
	var after []string
	for page := 0; page < maximumRetentionHistoryPages; page++ {
		body, err := historyQuery(scope, trigger, limit)
		if err != nil {
			return nil, ErrHistory
		}
		if len(after) > 0 {
			var query map[string]any
			if json.Unmarshal(body, &query) != nil {
				return nil, ErrHistory
			}
			query["search_after"] = after
			body, err = json.Marshal(query)
			if err != nil {
				return nil, ErrHistory
			}
		}
		query := url.Values{"filter_path": {"hits.hits._id,hits.hits._source,hits.hits.sort,timed_out"}}
		response, err := driver.request(ctx, "/"+historyIndex+"/_search?"+query.Encode(), body)
		if err != nil {
			return nil, ErrHistory
		}
		if response.StatusCode != http.StatusOK || !validJSONMediaType(response.Header.Get("Content-Type")) {
			response.Body.Close()
			return nil, ErrHistory
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, driver.config.MaximumResponseBytes+1))
		response.Body.Close()
		if readErr != nil || int64(len(raw)) > driver.config.MaximumResponseBytes {
			return nil, ErrHistory
		}
		var decoded retainedHistorySearchResponse
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF || decoded.TimedOut == nil || *decoded.TimedOut || decoded.Hits == nil || decoded.Hits.Hits == nil || len(decoded.Hits.Hits) > limit {
			return nil, ErrHistory
		}
		for _, hit := range decoded.Hits.Hits {
			value, instant, ok := actionContext(scope, trigger, hit.ID, hit.Sort, hit.Source)
			if !ok || seen[hit.ID] || previousID != "" && (instant.After(previousTime) || instant.Equal(previousTime) && hit.ID <= previousID) {
				return nil, ErrHistory
			}
			seen[hit.ID] = true
			previousTime, previousID = instant, hit.ID
			after = append([]string(nil), hit.Sort...)
			candidates = append(candidates, candidate{eventID: hit.Source.EventID, value: value})
		}
		ids := make([]string, len(candidates))
		for i, item := range candidates {
			ids[i] = item.eventID
		}
		states, err := runtimeindex.CheckEventVisibility(ctx, driver.retention, scope, ids)
		if err != nil {
			return nil, ErrHistory
		}
		values := make([]platformpolicy.ActionContext, 0, limit)
		for _, item := range candidates {
			if states[item.eventID] {
				values = append(values, item.value)
				if len(values) == limit {
					break
				}
			}
		}
		if len(values) == limit || len(decoded.Hits.Hits) < limit {
			return values, nil
		}
	}
	// A bounded scan ending inside expired history is unavailable. Returning an
	// empty or short page here would invent exhaustion and bias policy simulation.
	return nil, ErrHistory
}
