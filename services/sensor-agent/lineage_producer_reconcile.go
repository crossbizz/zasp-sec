package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageProducerConfig struct {
	EnrollmentBinding string
	Destination       string
	ConsumerUID       uint32
}
type lineageProducerWork struct {
	ID                                                          string
	Source                                                      sensoradapter.LineageSource
	Reservation, HasSource, Active, Sealed, HasIntent, Complete bool
}
type lineageProducerProgress struct {
	ReservationsDiscarded, SourcesClosed, SourcesReclaimed, CompletionsCollected, Active, AwaitingConsumer int
}

func (spool *lineageSpool) ListProducerWork(ctx context.Context, config lineageProducerConfig) ([]lineageProducerWork, error) {
	if spool == nil || ctx == nil || ctx.Err() != nil || !enrollmentBindingPattern.MatchString(config.EnrollmentBinding) || !validLineageDestination(config.Destination) || config.ConsumerUID == ^uint32(0) {
		return nil, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	inventory, err := spool.reclaimInventory()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool, len(inventory.directories)+len(inventory.markers))
	for id := range inventory.directories {
		ids[id] = true
	}
	for id := range inventory.markers {
		ids[id] = true
	}
	work := make([]lineageProducerWork, 0, len(ids))
	for id := range ids {
		if ctx.Err() != nil || !spool.valid() {
			return nil, errLineageSpool
		}
		item, err := spool.producerWork(id, inventory, config)
		if err != nil {
			return nil, err
		}
		work = append(work, item)
	}
	// Resume durable intents before unrelated work that shares the one scratch
	// slot. This is a bounded snapshot, not authority for a later mutation.
	sort.Slice(work, func(i, j int) bool {
		if work[i].HasIntent != work[j].HasIntent {
			return work[i].HasIntent
		}
		return work[i].ID < work[j].ID
	})
	if ctx.Err() != nil || !spool.valid() {
		return nil, errLineageSpool
	}
	return work, nil
}

// Called under the producer lifetime mutex. Every source comes from its owned
// manifest or physically bound durable reclaim intent, never from an ACK.
func (spool *lineageSpool) producerWork(id string, inventory lineageSpoolInventory, config lineageProducerConfig) (lineageProducerWork, error) {
	item := lineageProducerWork{ID: id, HasIntent: inventory.markers[id], Active: spool.active != nil && spool.active.source.GenerationID == id}
	name := inventory.directories[id]
	switch name {
	case ".creating-" + id, ".discard-" + id:
		if item.HasIntent || item.Active {
			return item, errLineageSpool
		}
		reservation, err := spool.openLineageReservation(name, id)
		if err != nil {
			return item, err
		}
		defer reservation.close()
		reservation.expectedEnrollment = config.EnrollmentBinding
		if !reservation.valid() {
			return item, errLineageSpool
		}
		item.Reservation = true
	case "generation-" + id:
		reader, err := newLineageSpoolReader(filepath.Join(spool.root.Name(), name), config.EnrollmentBinding, spool.owner)
		if err != nil {
			return item, err
		}
		defer reader.Close()
		parent, err := reader.parentDir.Stat()
		held, heldErr := spool.dir.Stat()
		if err != nil || heldErr != nil || !os.SameFile(parent, held) {
			return item, errLineageSpool
		}
		item.Source, item.HasSource = reader.Source(), true
		// Active writers own their own seal transition. Avoid scanning their
		// mutable pending file; mutation methods recheck active ownership.
		if !item.Active {
			_, item.Sealed, err = reader.ReadSeal()
			if err != nil {
				return item, err
			}
		}
	case ".reclaim-" + id:
		if !item.HasIntent || item.Active {
			return item, errLineageSpool
		}
		item.HasSource = true
	case "":
		if !item.HasIntent || item.Active {
			return item, errLineageSpool
		}
	default:
		return item, errLineageSpool
	}
	if item.HasIntent {
		if item.Active {
			return item, errLineageSpool
		}
		marker, err := spool.readReclaimMarker("reclaim-" + id + ".json")
		if err != nil {
			return item, err
		}
		defer marker.file.Close()
		record := marker.record
		if record.Request.Source.EnrollmentBinding != config.EnrollmentBinding || record.Request.Destination != config.Destination || record.Request.ConsumerUID != config.ConsumerUID || item.Source.GenerationID != "" && item.Source != record.Request.Source || record.Complete && name != "" {
			return item, errLineageSpool
		}
		item.Source, item.Complete = record.Request.Source, record.Complete
	}
	return item, nil
}

// One bounded tick. Validate the entire installation snapshot before changing
// anything, then reauthorize each operation through its existing crash-safe
// primitive. A failed item doesn't prevent independent work in this snapshot.
func (spool *lineageSpool) ReconcileProducer(ctx context.Context, receipts *lineageReceiptReader, config lineageProducerConfig) (lineageProducerProgress, error) {
	var progress lineageProducerProgress
	if receipts == nil || receipts.owner != config.ConsumerUID {
		return progress, errLineageSpool
	}
	receipts.mu.Lock()
	valid := receipts.valid()
	receipts.mu.Unlock()
	if !valid {
		return progress, errLineageSpool
	}
	work, err := spool.ListProducerWork(ctx, config)
	if err != nil {
		return progress, err
	}
	var failures []error
	for _, item := range work {
		if ctx.Err() != nil {
			failures = append(failures, errLineageSpool)
			break
		}
		if item.Active {
			progress.Active++
			continue
		}
		if item.Reservation {
			done, err := spool.discardUnpublished(ctx, item.ID, config.EnrollmentBinding)
			if err != nil {
				failures = append(failures, errors.New("producer reservation recovery failed"))
			} else if done {
				progress.ReservationsDiscarded++
			}
			continue
		}
		if item.HasSource && !item.Sealed && !item.HasIntent {
			done, err := spool.SealInterrupted(ctx, item.Source)
			if err != nil || !done {
				failures = append(failures, errors.New("producer source closure failed"))
				continue
			}
			progress.SourcesClosed++
		}
		request := lineageReclaimRequest{Source: item.Source, Destination: config.Destination, ConsumerUID: config.ConsumerUID}
		done, err := spool.ReclaimAcknowledged(ctx, receipts, request)
		if err != nil {
			failures = append(failures, errors.New("producer source reclamation failed"))
			continue
		}
		if !done {
			progress.AwaitingConsumer++
			continue
		}
		if item.HasSource {
			progress.SourcesReclaimed++
		}
		done, err = spool.collectProducerCompletion(ctx, receipts, request)
		if err != nil {
			failures = append(failures, errors.New("producer completion collection failed"))
			continue
		}
		if done {
			progress.CompletionsCollected++
		} else {
			progress.AwaitingConsumer++
		}
	}
	return progress, errors.Join(failures...)
}

func (spool *lineageSpool) collectProducerCompletion(ctx context.Context, receipts *lineageReceiptReader, request lineageReclaimRequest) (bool, error) {
	waiting, err := spool.producerCompletionWaiting(ctx, receipts, request)
	if err != nil || waiting {
		return false, err
	}
	return spool.CollectCompletion(ctx, receipts, request)
}

// An original ACK is a normal handoff delay only when it still exactly matches
// this producer's completed intent. A parse failure isn't a waiting receipt.
func (spool *lineageSpool) producerCompletionWaiting(ctx context.Context, receipts *lineageReceiptReader, request lineageReclaimRequest) (bool, error) {
	spool.mu.Lock()
	defer spool.mu.Unlock()
	receipts.mu.Lock()
	defer receipts.mu.Unlock()
	if ctx.Err() != nil || !spool.valid() || !receipts.valid() {
		return false, errLineageSpool
	}
	marker, err := spool.readReclaimMarker("reclaim-" + request.Source.GenerationID + ".json")
	if err != nil {
		return false, err
	}
	defer marker.file.Close()
	if !marker.record.Complete || marker.record.Request != request || !lineageSourceNamesAbsent(spool.root, request.Source.GenerationID) {
		return false, errLineageSpool
	}
	name := "ack-" + request.Source.GenerationID + ".json"
	if _, err := receipts.root.Lstat(name); os.IsNotExist(err) {
		return true, nil
	} else if err != nil {
		return false, errLineageSpool
	}
	ack, err := pinLineageExactFile(receipts.root, name, receipts.owner, lineageAckBytes, nil)
	if err != nil {
		return false, err
	}
	defer ack.file.Close()
	var original lineageConsumptionAck
	if lineageDecodeCanonical(ack.raw, &original) && original == marker.record.Ack {
		return true, nil
	}
	var retired lineageRetirementAck
	if !lineageDecodeCanonical(ack.raw, &retired) || !validRetirementAck(retired) || retired.Request != request || retired.CompletionDigest != lineageHash(marker.raw) || !retirementDirectoriesMatch(retired, spool.dir, receipts.dir) {
		return false, errLineageSpool
	}
	return false, nil
}
