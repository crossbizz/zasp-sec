package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageConsumerWork struct {
	Seal                                                lineageSpoolSeal
	HasSeal                                             bool
	Source                                              sensoradapter.LineageSource
	Assignment                                          lineageSlotAssignment
	Assigned, HasSource, Reclaiming, Complete, Retiring bool
	SourceDevice, SourceInode                           uint64
}

type lineageConsumerProgress struct {
	SourcesProcessed, Acknowledged, Retired, Released, Waiting int
	Read, Submitted                                            int
	ProducerDroppedTotal                                       uint64
	CoverageUnknown                                            bool
}

// Read-only, bounded hints. Producer-owned manifests and reclaim records provide
// source identity; current host identity and consumer ACKs never invent a source.
// Private reservations are counted and checked but never opened by the consumer.
func (slots *lineageConsumerSlots) ListConsumerWork(ctx context.Context) ([]lineageConsumerWork, error) {
	if slots == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	unlock := slots.lockInputs()
	defer unlock()
	local, err := slots.scan()
	if err != nil {
		return nil, err
	}
	work := map[string]*lineageConsumerWork{}
	for index, assignment := range local.assignments {
		if assignment != nil {
			work[assignment.Source.GenerationID] = &lineageConsumerWork{Source: assignment.Source, Assignment: *assignment, Assigned: true, Retiring: local.retirementScratch[index] != ""}
		}
		if retired := local.retirements[index]; retired != nil {
			a := retired.Assignment
			work[a.Source.GenerationID] = &lineageConsumerWork{Source: a.Source, Assignment: a, Assigned: true, Retiring: true, Seal: retired.Completion.Ack.Seal, HasSeal: true}
		}
	}
	producer := slots.config.Producer.directory
	dir, err := producer.root.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	entries, err := dir.ReadDir(2*lineageSpoolSlots + 3)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) > 2*lineageSpoolSlots+2 {
		return nil, errLineageSpoolFull
	}
	directories := map[string]string{}
	markers := map[string]lineageReclaimRecord{}
	lockFound := false
	for _, entry := range entries {
		if ctx.Err() != nil || !producer.valid() {
			return nil, errLineageSpool
		}
		name := entry.Name()
		info, err := producer.root.Lstat(name)
		if err != nil {
			return nil, errLineageSpool
		}
		if name == ".producer.lock" {
			if !lineageOwnedRegular(info, producer.owner, 0600) || info.Size() != 0 {
				return nil, errLineageSpool
			}
			lockFound = true
			continue
		}
		if name == ".reclaim.pending" {
			if (!lineageOwnedRegular(info, producer.owner, 0600) && !lineageOwnedRegular(info, producer.owner, 0440)) || info.Size() < 0 || info.Size() > lineageReclaimBytes {
				return nil, errLineageSpool
			}
			continue
		}
		if strings.HasPrefix(name, "reclaim-") && strings.HasSuffix(name, ".json") {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "reclaim-"), ".json")
			if !validLineageUUID(id) {
				return nil, errLineageSpool
			}
			file, err := pinLineageExactFile(producer.root, name, producer.owner, lineageReclaimBytes, nil)
			if err != nil {
				return nil, err
			}
			var record lineageReclaimRecord
			device, inode, identityErr := lineageSlotIdentity(producer.dir)
			valid := lineageDecodeCanonical(file.raw, &record) && validReclaimRecord(record) && record.Request.Source.GenerationID == id && record.Request.Source.EnrollmentBinding == slots.config.EnrollmentBinding && record.Request.Destination == slots.config.Destination && record.Request.ConsumerUID == slots.owner && identityErr == nil && record.SpoolDevice == device && record.SpoolInode == inode && file.valid()
			file.file.Close()
			if !valid {
				return nil, errLineageSpool
			}
			markers[id] = record
			continue
		}
		id := ""
		for _, prefix := range []string{"generation-", ".reclaim-", ".creating-", ".discard-"} {
			if strings.HasPrefix(name, prefix) {
				id = strings.TrimPrefix(name, prefix)
				break
			}
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !validLineageUUID(id) || !ok || !info.IsDir() || stat.Uid != producer.owner || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (info.Mode().Perm() != 0700 && info.Mode().Perm() != 0750) || directories[id] != "" {
			return nil, errLineageSpool
		}
		directories[id] = name
	}
	if !lockFound || len(directories) > lineageSpoolSlots || len(markers) > lineageSpoolSlots {
		return nil, errLineageSpool
	}
	for id, name := range directories {
		if ctx.Err() != nil {
			return nil, errLineageSpool
		}
		marker, hasMarker := markers[id]
		if name == ".creating-"+id || name == ".discard-"+id {
			if hasMarker || work[id] != nil {
				return nil, errLineageSpool
			}
			continue
		}
		if name == ".reclaim-"+id {
			if !hasMarker || marker.Complete {
				return nil, errLineageSpool
			}
			info, err := producer.root.Lstat(name)
			if err != nil {
				return nil, errLineageSpool
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || uint64(stat.Dev) != marker.Ack.Consumption.Device || stat.Ino != marker.Ack.Consumption.Inode {
				return nil, errLineageSpool
			}
			continue
		}
		reader, err := newLineageSpoolReader(filepath.Join(producer.root.Name(), name), slots.config.EnrollmentBinding, producer.owner)
		if err != nil {
			return nil, err
		}
		source := reader.Source()
		parent, parentErr := reader.parentDir.Stat()
		root, rootErr := producer.dir.Stat()
		device, inode, identityErr := lineageSlotIdentity(reader.dir)
		valid := parentErr == nil && rootErr == nil && os.SameFile(parent, root) && identityErr == nil && reader.valid()
		reader.Close()
		if !valid || hasMarker && (marker.Complete || marker.Request.Source != source || marker.Ack.Consumption.Device != device || marker.Ack.Consumption.Inode != inode) {
			return nil, errLineageSpool
		}
		item := work[id]
		if item == nil {
			item = &lineageConsumerWork{Source: source}
			work[id] = item
		}
		if item.Source != source || item.Assigned && (item.Assignment.SourceDevice != device || item.Assignment.SourceInode != inode) || item.Retiring {
			return nil, errLineageSpool
		}
		item.HasSource, item.SourceDevice, item.SourceInode = true, device, inode
	}
	for id, record := range markers {
		if record.Complete && directories[id] != "" {
			return nil, errLineageSpool
		}
		item := work[id]
		if item == nil {
			item = &lineageConsumerWork{Source: record.Request.Source}
			work[id] = item
		}
		if item.Source != record.Request.Source || item.Assigned && (item.Assignment.SourceDevice != record.Ack.Consumption.Device || item.Assignment.SourceInode != record.Ack.Consumption.Inode) {
			return nil, errLineageSpool
		}
		item.Reclaiming, item.Complete = true, record.Complete
		item.Seal, item.HasSeal = record.Ack.Seal, true
	}
	for index, name := range local.scratch {
		if name == "" {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, fmt.Sprintf(".assignment-%d-", index)), ".pending")
		item := work[id]
		if item == nil || !item.HasSource || item.Assigned || item.Reclaiming || item.Retiring {
			return nil, errLineageSpool
		}
	}
	result := make([]lineageConsumerWork, 0, len(work))
	for _, item := range work {
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if (a.Retiring || a.Complete) != (b.Retiring || b.Complete) {
			return a.Retiring || a.Complete
		}
		if a.Assigned != b.Assigned {
			return a.Assigned
		}
		return a.Source.GenerationID < b.Source.GenerationID
	})
	if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() {
		return nil, errLineageSpool
	}
	return result, nil
}

// One tick processes at most one chunk per public generation (at most eight),
// after local retirement work. All mutations revalidate saved identity. A nil
// client still permits retirement/release; failed items don't starve others.
func (slots *lineageConsumerSlots) ReconcileConsumer(ctx context.Context, client *sensoradapter.ProductionClient, maximum int) (progress lineageConsumerProgress, resultErr error) {
	if slots == nil || ctx == nil || ctx.Err() != nil || maximum < 1 || maximum > 100_000 {
		return progress, errLineageSpool
	}
	slots.reconcileMu.Lock()
	defer slots.reconcileMu.Unlock()
	// Admit the entire producer snapshot before creating any consumer state.
	work, err := slots.ListConsumerWork(ctx)
	if err != nil {
		return progress, err
	}
	coverage, err := slots.health(ctx)
	if err != nil {
		progress.CoverageUnknown = true
		return progress, err
	}
	progress.ProducerDroppedTotal, progress.CoverageUnknown = coverage.Dropped, coverage.Unknown
	defer func() {
		coverage, err := slots.health(ctx)
		if err != nil {
			progress.CoverageUnknown = true
			resultErr = errors.Join(resultErr, err)
		} else {
			progress.ProducerDroppedTotal, progress.CoverageUnknown = coverage.Dropped, coverage.Unknown
		}
	}()
	// A timed-out request must not consume every future tick. Keep retirement
	// first, then walk public sources cyclically past the last attempt. This
	// volatile hint grants no authority and never bypasses snapshot validation.
	sort.SliceStable(work, func(i, j int) bool {
		a, b := work[i], work[j]
		retireA, retireB := a.Retiring || a.Complete, b.Retiring || b.Complete
		if retireA != retireB {
			return retireA
		}
		if retireA {
			return a.Source.GenerationID < b.Source.GenerationID
		}
		afterA, afterB := a.Source.GenerationID > slots.lastAttempt, b.Source.GenerationID > slots.lastAttempt
		if afterA != afterB {
			return afterA
		}
		return a.Source.GenerationID < b.Source.GenerationID
	})
	var failures []error
	for _, item := range work {
		if ctx.Err() != nil {
			failures = append(failures, errLineageSpool)
			break
		}
		if item.Retiring || item.Complete {
			if !item.Assigned {
				failures = append(failures, errors.New("consumer retirement assignment missing"))
				continue
			}
			if !item.HasSeal || slots.accountSeal(ctx, item.Assignment, item.Seal) != nil {
				failures = append(failures, errors.New("consumer retirement coverage accounting failed"))
				continue
			}
			done, err := slots.Retire(ctx, item.Assignment, maximum)
			if err != nil {
				failures = append(failures, errors.New("consumer slot retirement failed"))
				continue
			}
			if !done {
				progress.Waiting++
				continue
			}
			progress.Retired++
			done, err = slots.Release(ctx, item.Assignment)
			if err != nil {
				failures = append(failures, errors.New("consumer slot release failed"))
			} else if done {
				progress.Released++
			} else {
				progress.Waiting++
			}
			continue
		}
		if item.Reclaiming {
			progress.Waiting++
			continue
		}
		if !item.HasSource {
			failures = append(failures, errors.New("consumer assigned source missing"))
			continue
		}
		if client == nil {
			failures = append(failures, errors.New("consumer upload client unavailable"))
			continue
		}
		slots.lastAttempt = item.Source.GenerationID
		result, ack, err := slots.processConsumerSource(ctx, client, maximum, item)
		if err != nil {
			failures = append(failures, errors.New("consumer source processing failed"))
			continue
		}
		progress.SourcesProcessed++
		progress.Read += result.Read
		progress.Submitted += result.Submitted
		if ack {
			progress.Acknowledged++
		} else {
			progress.Waiting++
		}
	}
	return progress, errors.Join(failures...)
}

func (slots *lineageConsumerSlots) processConsumerSource(ctx context.Context, client *sensoradapter.ProductionClient, maximum int, item lineageConsumerWork) (sensoradapter.StreamResult, bool, error) {
	var zero sensoradapter.StreamResult
	producer := slots.config.Producer.directory
	reader, err := newLineageSpoolReader(filepath.Join(producer.root.Name(), "generation-"+item.Source.GenerationID), slots.config.EnrollmentBinding, producer.owner)
	if err != nil {
		return zero, false, err
	}
	defer reader.Close()
	device, inode, err := lineageSlotIdentity(reader.dir)
	if err != nil || reader.Source() != item.Source || device != item.SourceDevice || inode != item.SourceInode {
		return zero, false, errLineageSpool
	}
	assignment, err := slots.Reserve(ctx, reader)
	if err != nil || item.Assigned && assignment != item.Assignment {
		return zero, false, errLineageSpool
	}
	cursor, err := slots.CursorPath(assignment)
	if err != nil {
		return zero, false, err
	}
	consumer, err := newAssignedLineageChunkConsumer(reader, client, cursor, maximum, slots.config.ProtectedInputs, slots.config.Acknowledgments, assignment)
	if err != nil {
		return zero, false, err
	}
	defer consumer.Close()
	result, err := consumer.ProcessAvailable(ctx)
	if err != nil {
		return result, false, err
	}
	seal, sealed, err := reader.ReadSeal()
	if err != nil {
		return result, false, err
	}
	if !sealed {
		return result, false, nil
	}
	// Persist loss evidence before ACK allows the producer to erase its source.
	if err := slots.accountSeal(ctx, assignment, seal); err != nil {
		return result, false, err
	}
	committed, durable, err := consumer.Committed()
	if err != nil {
		return result, false, err
	}
	if !durable || committed.NextSequence != seal.Chunks+1 {
		return result, false, nil
	}
	if err := consumer.Acknowledge(ctx); err != nil {
		return result, false, err
	}
	return result, true, nil
}
