package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
)

const (
	lineageHealthName        = "coverage.json"
	lineageHealthPending     = ".coverage.pending"
	lineageHealthBytes       = 64 << 10
	lineageReportedDropLimit = uint64(1_000_000_000)
)

type lineageHealthEntry struct {
	Assignment lineageSlotAssignment `json:"assignment"`
	Seal       lineageSpoolSeal      `json:"seal"`
}

// One fixed-size lifetime counter and one deduplication watermark per bounded
// slot. A watermark outlives retirement; only a new authenticated assignment in
// that same slot replaces it. No unbounded per-generation history accumulates.
type lineageHealth struct {
	Version           string                                 `json:"version"`
	EnrollmentBinding string                                 `json:"enrollment_binding"`
	Destination       string                                 `json:"destination"`
	ConsumerUID       uint32                                 `json:"consumer_uid"`
	StateDevice       uint64                                 `json:"state_device"`
	StateInode        uint64                                 `json:"state_inode"`
	SpoolDevice       uint64                                 `json:"spool_device"`
	SpoolInode        uint64                                 `json:"spool_inode"`
	Dropped           uint64                                 `json:"producer_dropped"`
	Unknown           bool                                   `json:"counters_unknown"`
	Slots             [lineageSpoolSlots]*lineageHealthEntry `json:"slots"`
}

func (slots *lineageConsumerSlots) healthIdentity() (lineageHealth, error) {
	stateDevice, stateInode, err := lineageSlotIdentity(slots.dir)
	spoolDevice, spoolInode, spoolErr := lineageSlotIdentity(slots.config.Producer.directory.dir)
	if err != nil || spoolErr != nil {
		return lineageHealth{}, errLineageSpool
	}
	return lineageHealth{Version: "tetragon-consumer-coverage-v1", EnrollmentBinding: slots.config.EnrollmentBinding,
		Destination: slots.config.Destination, ConsumerUID: slots.owner,
		StateDevice: stateDevice, StateInode: stateInode, SpoolDevice: spoolDevice, SpoolInode: spoolInode}, nil
}

func (slots *lineageConsumerSlots) validHealth(record lineageHealth) bool {
	want, err := slots.healthIdentity()
	identity := record
	identity.Dropped, identity.Unknown, identity.Slots = 0, false, [lineageSpoolSlots]*lineageHealthEntry{}
	if err != nil || identity != want || record.Dropped > lineageReportedDropLimit {
		return false
	}
	seen := map[string]bool{}
	var minimum uint64
	for index, entry := range record.Slots {
		if entry == nil {
			continue
		}
		a, seal := entry.Assignment, entry.Seal
		manifest, err := lineageManifestBytes(a.Source)
		if !slots.validAssignment(a) || a.Slot != index || seen[a.Source.GenerationID] || err != nil ||
			seal.Manifest != lineageHash(manifest) || seal.Version != "tetragon-spool-closed-v1" ||
			seal.CoverageComplete || !validLineageSealRecovery(seal) ||
			seal.Chunks < 0 || seal.Chunks > lineageSpoolChunks || seal.Records < seal.Chunks || seal.Records > seal.Chunks*1000 ||
			seal.Bytes < int64(seal.Records)*2 || seal.Bytes > lineageSpoolBytes || seal.Chunks == 0 && (seal.Records != 0 || seal.Bytes != 0) ||
			seal.CountersUnknown && !record.Unknown {
			return false
		}
		seen[a.Source.GenerationID] = true
		minimum = min(lineageReportedDropLimit, minimum+min(lineageReportedDropLimit, seal.Dropped))
	}
	return record.Dropped >= minimum
}

// Caller holds slots and borrowed input locks. A read re-syncs an earlier
// possibly-uncertain rename before the caller may acknowledge any generation.
func (slots *lineageConsumerSlots) readHealthLocked() (lineageHealth, *lineageExactFile, error) {
	file, err := pinLineageExactFile(slots.root, lineageHealthName, slots.owner, lineageHealthBytes, nil)
	if err != nil {
		return lineageHealth{}, nil, err
	}
	var record lineageHealth
	if !lineageDecodeCanonical(file.raw, &record) || !slots.validHealth(record) || !file.valid() {
		file.file.Close()
		return lineageHealth{}, nil, errLineageSpool
	}
	return record, file, nil
}

func (slots *lineageConsumerSlots) persistHealthLocked(ctx context.Context, record lineageHealth, previous *lineageExactFile) error {
	if !slots.validHealth(record) || slots.lock == nil {
		return errLineageSpool
	}
	// Scratch is never acceptance evidence. Under the lifetime controller lock,
	// an interrupted pre-rename write can be discarded and recomputed from the
	// old committed counter plus the still-unacknowledged immutable source.
	if info, err := slots.root.Lstat(lineageHealthPending); err == nil {
		if (!lineageOwnedRegular(info, slots.owner, 0600) && !lineageOwnedRegular(info, slots.owner, 0440)) || info.Size() < 0 || info.Size() > lineageHealthBytes || ctx.Err() != nil || !slots.valid() || !slots.inputsValid() {
			return errLineageSpool
		}
		if slots.root.Remove(lineageHealthPending) != nil || slots.dir.Sync() != nil {
			return errLineageSpool
		}
	} else if !os.IsNotExist(err) {
		return errLineageSpool
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > lineageHealthBytes {
		return errLineageSpool
	}
	return slots.publishSlotBytes(ctx, raw, lineageHealthPending, lineageHealthName, previous, func() bool {
		return ctx.Err() == nil && slots.valid() && slots.inputsValid() && slots.validHealth(record)
	})
}

func (slots *lineageConsumerSlots) health(ctx context.Context) (lineageHealth, error) {
	var zero lineageHealth
	if slots == nil || ctx == nil || ctx.Err() != nil {
		return zero, errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	unlock := slots.lockInputs()
	defer unlock()
	// Establish fresh-state evidence before ensureController creates its lock.
	if _, err := slots.scan(); err != nil {
		return zero, err
	}
	entries, err := slots.root.Open(".")
	if err != nil {
		return zero, errLineageSpool
	}
	names, readErr := entries.Readdirnames(1)
	entries.Close()
	if readErr != nil && readErr != io.EOF {
		return zero, errLineageSpool
	}
	fresh := len(names) == 0 && readErr == io.EOF
	if slots.ensureController(ctx) != nil {
		return zero, errLineageSpool
	}
	if _, err := slots.root.Lstat(lineageHealthName); os.IsNotExist(err) {
		record, err := slots.healthIdentity()
		if err != nil {
			return zero, err
		}
		// Existing state without accounting predates this contract or lost its
		// counter. Its historical coverage is unknown, never silently zero.
		record.Unknown = !fresh
		if err := slots.persistHealthLocked(ctx, record, nil); err != nil {
			return zero, err
		}
	} else if err != nil {
		return zero, errLineageSpool
	}
	record, file, err := slots.readHealthLocked()
	if err != nil {
		return zero, err
	}
	defer file.file.Close()
	if file.file.Sync() != nil || slots.dir.Sync() != nil || !file.valid() || ctx.Err() != nil {
		return zero, errLineageSpool
	}
	return record, nil
}

func (slots *lineageConsumerSlots) accountSeal(ctx context.Context, assignment lineageSlotAssignment, seal lineageSpoolSeal) error {
	if ctx == nil || ctx.Err() != nil {
		return errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	unlock := slots.lockInputs()
	defer unlock()
	if slots.ensureController(ctx) != nil || !slots.validAssignment(assignment) {
		return errLineageSpool
	}
	inventory, err := slots.scan()
	if err != nil {
		return errLineageSpool
	}
	current, retired := inventory.assignments[assignment.Slot], inventory.retirements[assignment.Slot]
	if current != nil && *current != assignment || retired != nil && retired.Assignment != assignment || current == nil && retired == nil {
		return errLineageSpool
	}
	record, file, err := slots.readHealthLocked()
	if err != nil {
		return err
	}
	defer file.file.Close()
	entry := lineageHealthEntry{Assignment: assignment, Seal: seal}
	if previous := record.Slots[assignment.Slot]; previous != nil && previous.Assignment.Source.GenerationID == assignment.Source.GenerationID {
		if *previous != entry || file.file.Sync() != nil || slots.dir.Sync() != nil || !file.valid() || ctx.Err() != nil {
			return errLineageSpool
		}
		return nil
	}
	record.Slots[assignment.Slot] = &entry
	record.Dropped = min(lineageReportedDropLimit, record.Dropped+min(lineageReportedDropLimit, seal.Dropped))
	record.Unknown = record.Unknown || seal.CountersUnknown
	return slots.persistHealthLocked(ctx, record, file)
}
