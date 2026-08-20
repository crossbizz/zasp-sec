package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

const activeMarkerType = "active_snapshot"

type storedMarker struct {
	RecordType     string   `json:"record_type"`
	OrganizationID string   `json:"organization_id"`
	WorkspaceID    string   `json:"workspace_id"`
	EnvironmentID  string   `json:"environment_id"`
	IntegrationID  string   `json:"integration_id"`
	SnapshotID     string   `json:"snapshot_id"`
	Generation     int64    `json:"generation"`
	InputDigest    string   `json:"input_digest"`
	ContentDigest  string   `json:"content_digest"`
	DocumentIDs    []string `json:"document_ids"`
}

type markerRecord struct {
	Index       string       `json:"_index"`
	ID          string       `json:"_id"`
	Version     int64        `json:"_version"`
	Sequence    int64        `json:"_seq_no"`
	PrimaryTerm int64        `json:"_primary_term"`
	Found       bool         `json:"found"`
	Source      storedMarker `json:"_source"`
}

type indexResponse struct {
	Index       string         `json:"_index"`
	ID          string         `json:"_id"`
	Version     int64          `json:"_version"`
	Result      string         `json:"result"`
	Sequence    int64          `json:"_seq_no"`
	PrimaryTerm int64          `json:"_primary_term"`
	Shards      responseShards `json:"_shards"`
}

type responseShards struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

type bulkDeleteResponse struct {
	Errors bool             `json:"errors"`
	Took   int              `json:"took"`
	Items  []bulkDeleteItem `json:"items"`
}

type bulkDeleteItem struct {
	Delete bulkItemResult `json:"delete"`
}

type cleanupQuery struct {
	Query cleanupBool `json:"query"`
}

type cleanupBool struct {
	Bool cleanupFilters `json:"bool"`
}

type cleanupFilters struct {
	Filter []any `json:"filter"`
}

type deleteByQueryResponse struct {
	Took              int                  `json:"took"`
	TimedOut          bool                 `json:"timed_out"`
	Total             int                  `json:"total"`
	Deleted           int                  `json:"deleted"`
	Batches           int                  `json:"batches"`
	VersionConflicts  int                  `json:"version_conflicts"`
	Noops             int                  `json:"noops"`
	Retries           deleteByQueryRetries `json:"retries"`
	ThrottledMillis   int                  `json:"throttled_millis"`
	RequestsPerSecond float64              `json:"requests_per_second"`
	ThrottledUntil    int                  `json:"throttled_until_millis"`
	Failures          []json.RawMessage    `json:"failures"`
}

type deleteByQueryRetries struct {
	Bulk   int `json:"bulk"`
	Search int `json:"search"`
}

func (driver *Driver) Activate(ctx context.Context, input inventorysearch.DriverActivation) (inventorysearch.DriverActivated, error) {
	if !driver.usable() || ctx == nil || ctx.Err() != nil || !validActivation(input) {
		if ctx != nil && ctx.Err() != nil {
			return inventorysearch.DriverActivated{}, inventorysearch.ErrCanceled
		}
		return inventorysearch.DriverActivated{}, inventorysearch.ErrRejected
	}
	current, found, err := driver.readMarker(ctx, input.Snapshot)
	if err != nil {
		return inventorysearch.DriverActivated{}, err
	}
	if found {
		return driver.activateFromCurrent(ctx, input, current)
	}
	return driver.writeMarker(ctx, input, markerRecord{}, true)
}

func (driver *Driver) activateFromCurrent(ctx context.Context, input inventorysearch.DriverActivation, current markerRecord) (inventorysearch.DriverActivated, error) {
	active, ok := snapshotFromMarker(current.Source)
	if !ok || current.Index != indexName || current.ID != markerID(input.Snapshot) || current.Version < 1 || current.Sequence < 0 || current.PrimaryTerm < 1 {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrDrift
	}
	if active.Generation > input.Snapshot.Generation {
		return activeResult(active, current.Source.DocumentIDs, false), inventorysearch.ErrStale
	}
	if active.Generation == input.Snapshot.Generation {
		if active != input.Snapshot || !reflect.DeepEqual(current.Source.DocumentIDs, input.DocumentIDs) {
			return activeResult(active, current.Source.DocumentIDs, false), inventorysearch.ErrDrift
		}
		return activeResult(input.Snapshot, input.DocumentIDs, true), nil
	}
	return driver.writeMarker(ctx, input, current, false)
}

func (driver *Driver) writeMarker(ctx context.Context, input inventorysearch.DriverActivation, current markerRecord, create bool) (inventorysearch.DriverActivated, error) {
	body, err := json.Marshal(markerFromActivation(input))
	if err != nil || len(body) > driver.config.MaximumRequestBytes {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrRejected
	}
	query := url.Values{"refresh": {"wait_for"}, "timeout": {fmt.Sprintf("%ds", int(driver.config.RequestTimeout/time.Second))}}
	if create {
		query.Set("op_type", "create")
	} else {
		query.Set("if_primary_term", fmt.Sprintf("%d", current.PrimaryTerm))
		query.Set("if_seq_no", fmt.Sprintf("%d", current.Sequence))
	}
	path := "/" + indexName + "/_doc/" + markerID(input.Snapshot) + "?" + query.Encode()
	result, requestErr := driver.request(ctx, http.MethodPut, path, "application/json", body, true)
	if requestErr != nil {
		if errors.Is(requestErr, inventorysearch.ErrUnknownOutcome) {
			return driver.reconcileActivation(ctx, input)
		}
		return inventorysearch.DriverActivated{}, requestErr
	}
	if result.status == http.StatusConflict {
		return driver.reconcileActivation(ctx, input)
	}
	if classified := classifyStatus(result.status, true); classified != nil {
		if errors.Is(classified, inventorysearch.ErrUnknownOutcome) {
			return driver.reconcileActivation(ctx, input)
		}
		return inventorysearch.DriverActivated{}, classified
	}
	var response indexResponse
	wantResult := "updated"
	if create {
		wantResult = "created"
	}
	if decodeExact(result.body, &response) != nil || response.Index != indexName || response.ID != markerID(input.Snapshot) || response.Version < 1 || response.Result != wantResult || response.Sequence < 0 || response.PrimaryTerm < 1 || response.Shards.Total < 1 || response.Shards.Successful < 1 || response.Shards.Failed != 0 {
		return driver.reconcileActivation(ctx, input)
	}
	return activeResult(input.Snapshot, input.DocumentIDs, false), nil
}

func (driver *Driver) reconcileActivation(ctx context.Context, input inventorysearch.DriverActivation) (inventorysearch.DriverActivated, error) {
	if ctx.Err() != nil {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrUnknownOutcome
	}
	current, found, err := driver.readMarker(ctx, input.Snapshot)
	if err != nil || !found {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrUnknownOutcome
	}
	active, ok := snapshotFromMarker(current.Source)
	if !ok || current.Index != indexName || current.ID != markerID(input.Snapshot) || current.Version < 1 || current.Sequence < 0 || current.PrimaryTerm < 1 {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrUnknownOutcome
	}
	if active.Generation > input.Snapshot.Generation {
		return activeResult(active, current.Source.DocumentIDs, false), inventorysearch.ErrStale
	}
	if active.Generation == input.Snapshot.Generation {
		if active != input.Snapshot || !reflect.DeepEqual(current.Source.DocumentIDs, input.DocumentIDs) {
			return activeResult(active, current.Source.DocumentIDs, false), inventorysearch.ErrDrift
		}
		return activeResult(input.Snapshot, input.DocumentIDs, true), nil
	}
	return inventorysearch.DriverActivated{}, inventorysearch.ErrUnknownOutcome
}

func (driver *Driver) RemoveStale(ctx context.Context, input inventorysearch.DriverCleanup) (inventorysearch.DriverCleaned, error) {
	if !driver.usable() || ctx == nil || ctx.Err() != nil || !validSnapshot(input.ActiveSnapshot) {
		if ctx != nil && ctx.Err() != nil {
			return inventorysearch.DriverCleaned{}, inventorysearch.ErrCanceled
		}
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrRejected
	}
	current, found, err := driver.readMarker(ctx, input.ActiveSnapshot)
	if err != nil {
		return inventorysearch.DriverCleaned{}, err
	}
	if !found {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrUnknownOutcome
	}
	active, ok := snapshotFromMarker(current.Source)
	if !ok {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrDrift
	}
	if active.Generation > input.ActiveSnapshot.Generation {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrStale
	}
	if active != input.ActiveSnapshot {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrDrift
	}
	body, err := json.Marshal(cleanupQuery{Query: cleanupBool{Bool: cleanupFilters{Filter: []any{
		map[string]any{"term": map[string]string{"record_type": "document"}},
		map[string]any{"term": map[string]string{"organization_id": active.OrganizationID}},
		map[string]any{"term": map[string]string{"workspace_id": active.WorkspaceID}},
		map[string]any{"term": map[string]string{"environment_id": active.EnvironmentID}},
		map[string]any{"term": map[string]string{"integration_id": active.IntegrationID}},
		map[string]any{"range": map[string]any{"generation": map[string]int64{"lt": active.Generation}}},
	}}}})
	if err != nil || len(body) > driver.config.MaximumRequestBytes {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrRejected
	}
	query := url.Values{"conflicts": {"proceed"}, "refresh": {"true"}, "timeout": {fmt.Sprintf("%ds", int(driver.config.RequestTimeout/time.Second))}, "wait_for_completion": {"true"}}
	result, requestErr := driver.request(ctx, http.MethodPost, "/"+indexName+"/_delete_by_query?"+query.Encode(), "application/json", body, true)
	if requestErr != nil {
		return inventorysearch.DriverCleaned{}, requestErr
	}
	if classified := classifyStatus(result.status, true); classified != nil {
		return inventorysearch.DriverCleaned{}, classified
	}
	var response deleteByQueryResponse
	if decodeExact(result.body, &response) != nil || response.Took < 0 || response.TimedOut || response.Total < 0 || response.Deleted < 0 || response.Deleted > response.Total || response.Batches < 0 || response.VersionConflicts != 0 || response.Noops < 0 || response.Retries.Bulk != 0 || response.Retries.Search != 0 || response.ThrottledMillis < 0 || response.RequestsPerSecond < -1 || response.ThrottledUntil < 0 || len(response.Failures) != 0 {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrUnknownOutcome
	}
	verified, stillFound, verifyErr := driver.readMarker(ctx, input.ActiveSnapshot)
	if verifyErr != nil || !stillFound {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrUnknownOutcome
	}
	verifiedActive, verifiedOK := snapshotFromMarker(verified.Source)
	if !verifiedOK {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrDrift
	}
	if verifiedActive.Generation > input.ActiveSnapshot.Generation {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrStale
	}
	if verifiedActive != input.ActiveSnapshot || !reflect.DeepEqual(verified.Source.DocumentIDs, current.Source.DocumentIDs) {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrDrift
	}
	return inventorysearch.DriverCleaned{ActiveSnapshot: active, Removed: response.Deleted, Replayed: response.Deleted == 0}, nil
}

func (driver *Driver) readMarker(ctx context.Context, snapshot inventorysearch.DriverSnapshot) (markerRecord, bool, error) {
	result, err := driver.request(ctx, http.MethodGet, "/"+indexName+"/_doc/"+markerID(snapshot), "", nil, false)
	if err != nil {
		return markerRecord{}, false, err
	}
	if result.status == http.StatusNotFound {
		return markerRecord{}, false, nil
	}
	if classified := classifyStatus(result.status, false); classified != nil {
		return markerRecord{}, false, classified
	}
	var record markerRecord
	if decodeExact(result.body, &record) != nil || !record.Found || record.Index != indexName || record.ID != markerID(snapshot) || record.Version < 1 || record.Sequence < 0 || record.PrimaryTerm < 1 {
		return markerRecord{}, false, inventorysearch.ErrDrift
	}
	return record, true, nil
}

func (driver *Driver) DiscardStage(ctx context.Context, input inventorysearch.DriverDiscard) (inventorysearch.DriverDiscarded, error) {
	if !driver.usable() || ctx == nil || ctx.Err() != nil || !validDiscard(input) {
		if ctx != nil && ctx.Err() != nil {
			return inventorysearch.DriverDiscarded{}, inventorysearch.ErrCanceled
		}
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrRejected
	}
	current, found, err := driver.readMarker(ctx, input.ExpectedActiveSnapshot)
	if err != nil {
		return inventorysearch.DriverDiscarded{}, err
	}
	if !found {
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnknownOutcome
	}
	activeSnapshot, ok := snapshotFromMarker(current.Source)
	if !ok || activeSnapshot != input.ExpectedActiveSnapshot || !reflect.DeepEqual(current.Source.DocumentIDs, input.ExpectedActiveDocumentIDs) {
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrStale
	}
	active := make(map[string]struct{}, len(input.ExpectedActiveDocumentIDs))
	for _, id := range input.ExpectedActiveDocumentIDs {
		active[id] = struct{}{}
	}
	ids := make([]string, 0, len(input.CandidateDocumentIDs))
	for _, id := range input.CandidateDocumentIDs {
		if _, isActive := active[id]; !isActive {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return driver.finishDiscard(ctx, input, 0, true)
	}
	var body bytes.Buffer
	for _, id := range ids {
		action, err := json.Marshal(bulkAction{Delete: &bulkActionTarget{Index: indexName, ID: id}})
		if err != nil || body.Len()+len(action)+1 > driver.config.MaximumRequestBytes {
			return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnknownOutcome
		}
		body.Write(action)
		body.WriteByte('\n')
	}
	query := url.Values{"refresh": {"wait_for"}, "timeout": {fmt.Sprintf("%ds", int(driver.config.RequestTimeout/time.Second))}}
	result, err := driver.request(ctx, http.MethodPost, "/"+indexName+"/_bulk?"+query.Encode(), "application/x-ndjson", body.Bytes(), true)
	if err != nil || result.status != http.StatusOK {
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnknownOutcome
	}
	var response bulkDeleteResponse
	if decodeExact(result.body, &response) != nil || response.Errors || response.Took < 0 || len(response.Items) != len(ids) {
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnknownOutcome
	}
	for index, item := range response.Items {
		if item.Delete.Index != indexName || item.Delete.ID != ids[index] || item.Delete.Error != nil || item.Delete.Status != http.StatusOK && item.Delete.Status != http.StatusNotFound || item.Delete.Result != "deleted" && item.Delete.Result != "not_found" {
			return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnknownOutcome
		}
	}
	removed := 0
	replayed := true
	for _, item := range response.Items {
		if item.Delete.Result == "deleted" {
			removed++
			replayed = false
		}
	}
	return driver.finishDiscard(ctx, input, removed, replayed)
}

func (driver *Driver) finishDiscard(ctx context.Context, input inventorysearch.DriverDiscard, removed int, replayed bool) (inventorysearch.DriverDiscarded, error) {
	current, found, err := driver.readMarker(ctx, input.ExpectedActiveSnapshot)
	if err != nil || !found {
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnknownOutcome
	}
	active, ok := snapshotFromMarker(current.Source)
	if !ok || active != input.ExpectedActiveSnapshot || !reflect.DeepEqual(current.Source.DocumentIDs, input.ExpectedActiveDocumentIDs) {
		return inventorysearch.DriverDiscarded{}, inventorysearch.ErrStale
	}
	return discardedResult(input, removed, replayed), nil
}

func validActivation(input inventorysearch.DriverActivation) bool {
	if !validSnapshot(input.Snapshot) || !validMarkerIDs(input.DocumentIDs) {
		return false
	}
	return true
}

func validDiscard(input inventorysearch.DriverDiscard) bool {
	if !validSnapshot(input.CandidateSnapshot) || !validSnapshot(input.ExpectedActiveSnapshot) || input.CandidateSnapshot.OrganizationID != input.ExpectedActiveSnapshot.OrganizationID || input.CandidateSnapshot.WorkspaceID != input.ExpectedActiveSnapshot.WorkspaceID || input.CandidateSnapshot.EnvironmentID != input.ExpectedActiveSnapshot.EnvironmentID || input.CandidateSnapshot.IntegrationID != input.ExpectedActiveSnapshot.IntegrationID || !validMarkerIDs(input.CandidateDocumentIDs) || !validMarkerIDs(input.ExpectedActiveDocumentIDs) {
		return false
	}
	return input.ExpectedActiveSnapshot.Generation >= input.CandidateSnapshot.Generation && input.ExpectedActiveSnapshot != input.CandidateSnapshot
}

func markerFromActivation(input inventorysearch.DriverActivation) storedMarker {
	return storedMarker{
		RecordType: activeMarkerType, OrganizationID: input.Snapshot.OrganizationID, WorkspaceID: input.Snapshot.WorkspaceID, EnvironmentID: input.Snapshot.EnvironmentID,
		IntegrationID: input.Snapshot.IntegrationID, SnapshotID: input.Snapshot.SnapshotID, Generation: input.Snapshot.Generation,
		InputDigest: hex.EncodeToString(input.Snapshot.InputDigest[:]), ContentDigest: hex.EncodeToString(input.Snapshot.ContentDigest[:]), DocumentIDs: append([]string{}, input.DocumentIDs...),
	}
}

func snapshotFromMarker(marker storedMarker) (inventorysearch.DriverSnapshot, bool) {
	inputDigest, inputErr := decodeDigest(marker.InputDigest)
	contentDigest, contentErr := decodeDigest(marker.ContentDigest)
	snapshot := inventorysearch.DriverSnapshot{OrganizationID: marker.OrganizationID, WorkspaceID: marker.WorkspaceID, EnvironmentID: marker.EnvironmentID, IntegrationID: marker.IntegrationID, SnapshotID: marker.SnapshotID, Generation: marker.Generation, InputDigest: inputDigest, ContentDigest: contentDigest}
	return snapshot, marker.RecordType == activeMarkerType && inputErr == nil && contentErr == nil && validSnapshot(snapshot) && validMarkerIDs(marker.DocumentIDs)
}

func validMarkerIDs(ids []string) bool {
	if len(ids) > maximumStageDocuments {
		return false
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !documentIDPattern.MatchString(id) {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func activeResult(snapshot inventorysearch.DriverSnapshot, ids []string, replayed bool) inventorysearch.DriverActivated {
	return inventorysearch.DriverActivated{ActiveSnapshot: snapshot, ActiveDocumentIDs: append([]string(nil), ids...), Replayed: replayed}
}

func discardedResult(input inventorysearch.DriverDiscard, removed int, replayed bool) inventorysearch.DriverDiscarded {
	return inventorysearch.DriverDiscarded{CandidateSnapshot: input.CandidateSnapshot, ActiveSnapshot: input.ExpectedActiveSnapshot, ActiveDocumentIDs: append([]string(nil), input.ExpectedActiveDocumentIDs...), Removed: removed, Replayed: replayed}
}

func markerID(snapshot inventorysearch.DriverSnapshot) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{snapshot.OrganizationID, snapshot.WorkspaceID, snapshot.EnvironmentID, snapshot.IntegrationID}, "\x1f")))
	return "active_" + hex.EncodeToString(digest[:])
}
