package runtimeindex

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// WritePartition supplements the original immutable source receipt. Written
// means exact provider write/readback succeeded; suppressed means a tombstone
// deliberately prevented a write. Neither means an old provider copy was purged.
type WritePartition struct {
	WrittenDocumentIDs    []string          `json:"written_document_ids"`
	SuppressedDocumentIDs []string          `json:"suppressed_document_ids"`
	ProviderContentDigest [sha256.Size]byte `json:"provider_content_digest"`
}
type RetainedWriteReceipt struct {
	EventIDs                           []string
	Scope                              domain.Scope
	BatchID                            string
	Generation                         int64
	InputDigest, OriginalContentDigest [sha256.Size]byte
	ArchiveReference, ArchiveVersionID string
	DocumentIDs                        []string
	Partition                          WritePartition
}

// Before SQL projection, write authority may admit untombstoned events only
// from the wholly validated archive under its original private index lease.
// This never supplies a human-reader fallback for an unknown SQL relation.
type RetainedWriteAuthority interface {
	EventVisibility
	// RecordRetainedWrite confirms a durable supplementary receipt under the
	// original private lease before ordinary stage completion can be admitted.
	RecordRetainedWrite(context.Context, RetainedWriteReceipt) error
}

// RetainedDriver guarantees that a mutation with an ambiguous acknowledgement
// cannot become successful merely because matching documents can be read back.
// Historical drivers preserve their existing reconciliation contract.
type RetainedDriver interface {
	Driver
	ApplyRetained(context.Context, DriverBatch) (DriverResult, error)
}

type retainedDriverAdapter struct{ driver RetainedDriver }

func (d retainedDriverAdapter) Apply(ctx context.Context, input DriverBatch) (DriverResult, error) {
	return d.driver.ApplyRetained(ctx, input)
}

func NewRetained(driver Driver, config Config, authority RetainedWriteAuthority) (*Store, error) {
	if nilInterface(driver) || nilInterface(authority) {
		return nil, ErrConfiguration
	}
	retained, ok := driver.(RetainedDriver)
	if !ok || nilInterface(retained) {
		return nil, ErrConfiguration
	}
	return New(&retainedWriteDriver{driver: retainedDriverAdapter{driver: retained}, authority: authority}, config)
}

type retainedWriteDriver struct {
	driver    Driver
	authority RetainedWriteAuthority
}

func (d *retainedWriteDriver) Apply(ctx context.Context, input DriverBatch) (DriverResult, error) {
	ids := make([]string, len(input.Documents))
	events := make([]string, len(input.Documents))
	for i, doc := range input.Documents {
		ids[i], events[i] = doc.DocumentID, doc.EventID
	}
	states, err := CheckEventVisibility(ctx, d.authority, input.Scope, events)
	if err != nil {
		return DriverResult{}, err
	}
	selected := cloneDriverBatch(input)
	selected.Documents = nil
	partition := WritePartition{WrittenDocumentIDs: []string{}, SuppressedDocumentIDs: []string{}}
	for _, doc := range input.Documents {
		if states[doc.EventID] {
			selected.Documents = append(selected.Documents, doc)
			partition.WrittenDocumentIDs = append(partition.WrittenDocumentIDs, doc.DocumentID)
		} else {
			partition.SuppressedDocumentIDs = append(partition.SuppressedDocumentIDs, doc.DocumentID)
		}
	}
	providerBody, err := json.Marshal(selected)
	if err != nil {
		return DriverResult{}, ErrInput
	}
	partition.ProviderContentDigest = sha256.Sum256(providerBody)
	replayed := false
	if len(selected.Documents) > 0 {
		out, err := callDriver(d.driver, ctx, selected)
		if err != nil {
			return DriverResult{}, sanitizeDriverError(err)
		}
		if out.BatchID != input.BatchID || out.Generation != input.Generation || out.InputDigest != input.InputDigest || out.ContentDigest != input.ContentDigest || !equalStrings(out.DocumentIDs, partition.WrittenDocumentIDs) {
			return DriverResult{}, ErrDrift
		}
		replayed = out.Replayed
	}
	if _, err := CheckEventVisibility(ctx, d.authority, input.Scope, events); err != nil {
		return DriverResult{}, err
	}
	receipt := RetainedWriteReceipt{Scope: input.Scope, BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, OriginalContentDigest: input.ContentDigest, ArchiveReference: input.ArchiveReference, ArchiveVersionID: input.ArchiveVersionID, DocumentIDs: append([]string(nil), ids...), EventIDs: append([]string(nil), events...), Partition: partition}
	if d.authority.RecordRetainedWrite(ctx, receipt) != nil {
		return DriverResult{}, ErrUnknownOutcome
	}
	return DriverResult{BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: input.ContentDigest, DocumentIDs: ids, Replayed: replayed, Retention: &partition}, nil
}
