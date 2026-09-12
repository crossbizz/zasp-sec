package runtimeevent

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

// PreciseRecord is consumed only by explicitly versioned workers. Its embedded
// record retains the V2 marker so qualified observations cannot enter V1 paths.
type PreciseRecord struct {
	Record
	ObservedLineage runtimelineage.PreciseObservation
}

type PreciseArchivedBatch struct {
	Source  string
	Records []PreciseRecord
}

type preciseIngestInput struct {
	Source string               `json:"source"`
	Events []preciseIngestEvent `json:"events"`
}

type preciseIngestEvent struct {
	ingestEvent
	ObservedLineage runtimelineage.PreciseObservation `json:"observed_lineage,omitzero"`
}

const preciseArchiveVersion = "runtime-archive-v2"

type preciseArchive struct {
	Version string `json:"version"`
	preciseIngestInput
}

// DecodePreciseArchivedBatch trusts scope only from the authenticated job lease.
// It does not authenticate artifact ownership or apply upload freshness to old
// durable jobs. Callers must verify the lease-bound artifact digest first.
func DecodePreciseArchivedBatch(scope domain.Scope, body []byte) (PreciseArchivedBatch, error) {
	var archive preciseArchive
	if scope.Validate() != nil || decodeCanonicalPreciseJSON(body, &archive) != nil || archive.Version != preciseArchiveVersion || !validPreciseInput(archive.preciseIngestInput) {
		return PreciseArchivedBatch{}, ErrProductionIngest
	}
	batch := PreciseArchivedBatch{Source: archive.Source, Records: make([]PreciseRecord, len(archive.Events))}
	for index, event := range archive.Events {
		record, err := event.toPreciseRecord(scope)
		if err != nil {
			return PreciseArchivedBatch{}, ErrProductionIngest
		}
		batch.Records[index] = record
	}
	return batch, nil
}

// Preparation is private to the explicit precise handler. Historical HTTP
// construction never dispatches to this versioned archive path.
func decodePreciseProductionInput(body []byte, authority IngestAuthority, now time.Time) (preciseIngestInput, []byte, error) {
	var input preciseIngestInput
	if !validIngestAuthority(authority) || authority.Source != "tetragon" || now.IsZero() || now.Location() != time.UTC || decodeCanonicalPreciseJSON(body, &input) != nil || !validPreciseInput(input) {
		return preciseIngestInput{}, nil, ErrProductionIngest
	}
	for index, event := range input.Events {
		record, err := event.toPreciseRecord(authority.Scope)
		if err != nil || record.EventTime.Before(now.Add(-24*time.Hour)) || record.EventTime.After(now.Add(5*time.Minute)) {
			return preciseIngestInput{}, nil, ErrProductionIngest
		}
		// Precision was validated separately; keep legacy content validation and
		// collection-mode behavior unchanged on this local copy.
		base := record.Record
		base.ObservedLineage = runtimelineage.Observation{}
		filtered, err := FilterRecord(base, authority.Mode)
		if err != nil {
			return preciseIngestInput{}, nil, ErrProductionIngest
		}
		canonical, err := canonicalIngestEvent(filtered)
		if err != nil {
			return preciseIngestInput{}, nil, ErrProductionIngest
		}
		input.Events[index] = preciseIngestEvent{ingestEvent: canonical, ObservedLineage: record.ObservedLineage}
	}
	archive, err := json.Marshal(preciseArchive{Version: preciseArchiveVersion, preciseIngestInput: input})
	if err != nil || len(archive) > maximumProductionIngestBytes {
		return preciseIngestInput{}, nil, ErrProductionIngest
	}
	return input, archive, nil
}

func (event preciseIngestEvent) toPreciseRecord(scope domain.Scope) (PreciseRecord, error) {
	base := event.ingestEvent
	base.ObservedLineage = runtimelineage.Observation{}
	record, err := base.toRecord(scope, "tetragon")
	if err != nil || event.EventTime != record.EventTime.Format(timestampLayout) || event.ObservedLineage != (runtimelineage.PreciseObservation{}) && !event.ObservedLineage.ValidAt(record.EventTime) {
		return PreciseRecord{}, ErrProductionIngest
	}
	record.ObservedLineage = event.ObservedLineage.Observation
	return PreciseRecord{Record: record, ObservedLineage: event.ObservedLineage}, nil
}

func validPreciseInput(input preciseIngestInput) bool {
	return input.Source == "tetragon" && len(input.Events) > 0 && len(input.Events) <= maximumProductionEvents
}

func decodeCanonicalPreciseJSON(body []byte, target any) error {
	if len(body) == 0 || len(body) > maximumProductionIngestBytes || !utf8.Valid(body) || !uniqueProductionJSON(body) {
		return ErrProductionIngest
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrProductionIngest
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, body) {
		return ErrProductionIngest
	}
	return nil
}
