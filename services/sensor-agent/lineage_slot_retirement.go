package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

const lineageSlotRetirementBytes = lineageReclaimBytes + lineageAckBytes

type lineageSlotRetirement struct {
	Version    string                `json:"version"`
	Assignment lineageSlotAssignment `json:"assignment"`
	Completion lineageReclaimRecord  `json:"completion"`
	AckDevice  uint64                `json:"ack_device"`
	AckInode   uint64                `json:"ack_inode"`
	AckRetired bool                  `json:"ack_retired"`
}

func (slots *lineageConsumerSlots) Retire(ctx context.Context, assignment lineageSlotAssignment, maximum int) (bool, error) {
	if slots == nil || ctx == nil || ctx.Err() != nil || maximum < 1 || maximum > 100_000 {
		return false, errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	record, found, err := slots.prepareSlotRetirement(ctx, assignment)
	if err != nil || !found {
		return false, err
	}
	if record.AckRetired {
		return true, nil
	}
	if done, err := slots.markSlotRetired(ctx, record); err != nil || done {
		return done, err
	}
	// Keep controller ownership, but don't hold borrowed mutexes across a
	// primitive that acquires them and the cursor flock itself.
	done, err := slots.config.Acknowledgments.retireBoundCheckpoint(ctx, slots.config.Producer, record.Completion.Request, filepath.Join(slots.root.Name(), lineageSlotCursor(assignment.Slot)), maximum, slots.config.ProtectedInputs, true, lineageAssignmentBinding(assignment))
	if err != nil || !done {
		return false, err
	}
	return slots.markSlotRetired(ctx, record)
}
func (slots *lineageConsumerSlots) Release(ctx context.Context, assignment lineageSlotAssignment) (bool, error) {
	if slots == nil || ctx == nil || ctx.Err() != nil {
		return false, errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	unlock := slots.lockInputs()
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	if !slots.validAssignment(assignment) || slots.ensureController(ctx) != nil {
		return false, errLineageSpool
	}
	inventory, err := slots.scan()
	if err != nil {
		return false, err
	}
	index := assignment.Slot
	if inventory.scratch[index] != "" || inventory.retirementScratch[index] != "" || inventory.assignments[index] != nil && *inventory.assignments[index] != assignment {
		return false, errLineageSpool
	}
	record := inventory.retirements[index]
	if record != nil && record.Assignment != assignment {
		return false, errLineageSpool
	}
	if record == nil && inventory.assignments[index] != nil || record != nil && !record.AckRetired {
		return false, nil
	}
	lockName := lineageSlotCursor(index) + ".lock"
	lock, err := slots.root.OpenFile(lockName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, errLineageSpool
	}
	defer lock.Close()
	if !slots.validLock(lockName, lock) || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !slots.validLock(lockName, lock) {
		return false, errLineageSpool
	}
	var retirement, assigned *lineageExactFile
	if record != nil {
		raw, _ := json.Marshal(record)
		retirement, err = pinLineageExactFile(slots.root, lineageSlotRetirementName(index), slots.owner, lineageSlotRetirementBytes, raw)
		if err != nil {
			return false, err
		}
		defer retirement.file.Close()
	}
	if inventory.assignments[index] != nil {
		raw, _ := json.Marshal(assignment)
		assigned, err = pinLineageExactFile(slots.root, lineageSlotName(index), slots.owner, lineageAckBytes, raw)
		if err != nil {
			return false, err
		}
		defer assigned.file.Close()
	}
	valid := func() bool {
		if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() || !slots.validAssignment(assignment) || !slots.validLock(lockName, lock) || !slots.slotCursorAbsent(index) {
			return false
		}
		if _, err := slots.scan(); err != nil {
			return false
		}
		for _, item := range []struct {
			file *lineageExactFile
			name string
		}{{assigned, lineageSlotName(index)}, {retirement, lineageSlotRetirementName(index)}} {
			if item.file != nil {
				if !item.file.valid() {
					return false
				}
			} else if _, err := slots.root.Lstat(item.name); !os.IsNotExist(err) {
				return false
			}
		}
		return true
	}
	if !valid() {
		return false, errLineageSpool
	}
	if record != nil {
		if err := slots.matchRetirementReceipt(*record, true); err != nil {
			return false, err
		}
		unlock()
		unlock = nil
		done, err := slots.config.Acknowledgments.ForgetRetirement(ctx, slots.config.Producer, record.Completion.Request)
		unlock = slots.lockInputs()
		if err != nil || !done {
			return false, err
		}
	}
	clean := func() bool { return valid() && slots.slotRemoteAbsent(assignment) }
	if !clean() || slots.config.Producer.directory.dir.Sync() != nil || slots.config.Acknowledgments.dir.Sync() != nil || slots.dir.Sync() != nil || !clean() {
		return false, errLineageSpool
	}
	if retirement != nil && retirement.file.Sync() != nil {
		return false, errLineageSpool
	}
	if assigned != nil {
		if assigned.file.Sync() != nil || !clean() || slots.root.Remove(assigned.name) != nil {
			return false, errLineageSpool
		}
		assigned = nil
		if ctx.Err() != nil || slots.dir.Sync() != nil || !clean() {
			return false, errLineageSpool
		}
	}
	if retirement != nil {
		if !clean() || slots.root.Remove(retirement.name) != nil {
			return false, errLineageSpool
		}
		retirement = nil
		if ctx.Err() != nil || slots.dir.Sync() != nil || !clean() {
			return false, errLineageSpool
		}
	}
	// A retry with neither record only reports durable clean state. It never
	// proves delivery, deletes a cursor, or deletes a newly assigned slot.
	if !clean() {
		return false, errLineageSpool
	}
	return true, nil
}

// Include record-only cleanup after assignment unlink. These are recovery hints;
// Retire and Release revalidate exact evidence under ownership before acting.
func (slots *lineageConsumerSlots) ListRetiring(ctx context.Context) ([]lineageSlotAssignment, error) {
	if slots == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	unlock := slots.lockInputs()
	defer unlock()
	inventory, err := slots.scan()
	if err != nil {
		return nil, err
	}
	result := make([]lineageSlotAssignment, 0, lineageSpoolSlots)
	for index, record := range inventory.retirements {
		if record != nil {
			result = append(result, record.Assignment)
		} else if inventory.retirementScratch[index] != "" {
			result = append(result, *inventory.assignments[index])
		}
	}
	if ctx.Err() != nil {
		return nil, errLineageSpool
	}
	return result, nil
}

func lineageSlotRetirementName(index int) string { return fmt.Sprintf("retirement-%d.json", index) }
func lineageSlotRetirementScratch(assignment lineageSlotAssignment) string {
	return fmt.Sprintf(".retirement-%d-%s.pending", assignment.Slot, assignment.Source.GenerationID)
}
func (slots *lineageConsumerSlots) validSlotRetirement(record lineageSlotRetirement) bool {
	a := record.Assignment
	c := record.Completion
	if record.Version != "tetragon-slot-retirement-v1" || !slots.validAssignment(a) || !c.Complete || !validReclaimRecord(c) || c.Request != (lineageReclaimRequest{Source: a.Source, Destination: a.Destination, ConsumerUID: a.ConsumerUID}) || c.SpoolDevice != a.SpoolDevice || c.SpoolInode != a.SpoolInode || c.Ack.Consumption.Device != a.SourceDevice || c.Ack.Consumption.Inode != a.SourceInode {
		return false
	}
	device, inode, err := lineageSlotIdentity(slots.config.Acknowledgments.dir)
	return err == nil && record.AckDevice == device && record.AckInode == inode
}
func (slots *lineageConsumerSlots) scanRetirementEntry(name string, info os.FileInfo, index int, inventory *lineageSlotInventory) (bool, error) {
	if name == lineageSlotRetirementName(index) {
		file, err := pinLineageExactFile(slots.root, name, slots.owner, lineageSlotRetirementBytes, nil)
		if err != nil {
			return true, err
		}
		defer file.file.Close()
		var record lineageSlotRetirement
		if !lineageDecodeCanonical(file.raw, &record) || !slots.validSlotRetirement(record) || record.Assignment.Slot != index {
			return true, errLineageSpool
		}
		inventory.retirements[index] = &record
		return true, nil
	}
	prefix := fmt.Sprintf(".retirement-%d-", index)
	if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".pending") {
		id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".pending")
		if !validLineageUUID(id) || inventory.retirementScratch[index] != "" || (!lineageOwnedRegular(info, slots.owner, 0600) && !lineageOwnedRegular(info, slots.owner, 0440)) || info.Size() < 0 || info.Size() > lineageSlotRetirementBytes {
			return true, errLineageSpool
		}
		inventory.retirementScratch[index] = name
		return true, nil
	}
	return false, nil
}
func (slots *lineageConsumerSlots) ensureController(ctx context.Context) error {
	if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() {
		return errLineageSpool
	}
	if _, err := slots.scan(); err != nil {
		return err
	}
	if slots.lock == nil {
		var err error
		slots.lock, err = slots.openLock(".slots.lock")
		if err != nil {
			return err
		}
	}
	if slots.lock.Sync() != nil || slots.dir.Sync() != nil || ctx.Err() != nil || !slots.valid() {
		return errLineageSpool
	}
	return nil
}
func (slots *lineageConsumerSlots) prepareSlotRetirement(ctx context.Context, assignment lineageSlotAssignment) (lineageSlotRetirement, bool, error) {
	var zero lineageSlotRetirement
	unlock := slots.lockInputs()
	defer unlock()
	if !slots.validAssignment(assignment) || slots.ensureController(ctx) != nil {
		return zero, false, errLineageSpool
	}
	inventory, err := slots.scan()
	if err != nil {
		return zero, false, err
	}
	index := assignment.Slot
	if inventory.scratch[index] != "" || inventory.assignments[index] != nil && *inventory.assignments[index] != assignment {
		return zero, false, errLineageSpool
	}
	if record := inventory.retirements[index]; record != nil {
		if record.Assignment != assignment {
			return zero, false, errLineageSpool
		}
		raw, _ := json.Marshal(record)
		file, err := pinLineageExactFile(slots.root, lineageSlotRetirementName(index), slots.owner, lineageSlotRetirementBytes, raw)
		if err != nil {
			return zero, false, err
		}
		defer file.file.Close()
		if ctx.Err() != nil || file.file.Sync() != nil || slots.dir.Sync() != nil || ctx.Err() != nil || !file.valid() || !slots.valid() || !slots.inputsValid() {
			return zero, false, errLineageSpool
		}
		return *record, true, nil
	}
	if inventory.assignments[index] == nil {
		return zero, false, errLineageSpool
	}
	assignmentRaw, _ := json.Marshal(assignment)
	assigned, err := pinLineageExactFile(slots.root, lineageSlotName(index), slots.owner, lineageAckBytes, assignmentRaw)
	if err != nil {
		return zero, false, err
	}
	defer assigned.file.Close()
	request := lineageReclaimRequest{Source: assignment.Source, Destination: assignment.Destination, ConsumerUID: assignment.ConsumerUID}
	completion, found, err := slots.config.Producer.read(request)
	if err != nil || !found {
		return zero, false, err
	}
	defer completion.file.file.Close()
	ackRaw, _ := json.Marshal(completion.record.Ack)
	ack, err := pinLineageExactFile(slots.config.Acknowledgments.root, "ack-"+assignment.Source.GenerationID+".json", slots.owner, lineageAckBytes, ackRaw)
	if err != nil {
		return zero, false, err
	}
	defer ack.file.Close()
	record := lineageSlotRetirement{Version: "tetragon-slot-retirement-v1", Assignment: assignment, Completion: completion.record}
	record.AckDevice, record.AckInode, err = lineageSlotIdentity(slots.config.Acknowledgments.dir)
	if err != nil || !slots.validSlotRetirement(record) {
		return zero, false, errLineageSpool
	}
	authorize := func() bool {
		if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() || !assigned.valid() || !completion.valid() || !ack.valid() {
			return false
		}
		_, err := slots.scan()
		return err == nil
	}
	if !authorize() || completion.sync(ctx) != nil || ack.file.Sync() != nil || slots.config.Acknowledgments.dir.Sync() != nil || !authorize() {
		return zero, false, errLineageSpool
	}
	raw, _ := json.Marshal(record)
	if len(raw) > lineageSlotRetirementBytes || slots.publishSlotBytes(ctx, raw, lineageSlotRetirementScratch(assignment), lineageSlotRetirementName(index), nil, authorize) != nil {
		return zero, false, errLineageSpool
	}
	return record, true, nil
}
func expectedSlotRetiredAck(record lineageSlotRetirement) lineageRetirementAck {
	raw, _ := json.Marshal(record.Completion)
	return lineageRetirementAck{Version: "tetragon-retirement-ack-v1", Request: record.Completion.Request, CompletionDigest: lineageHash(raw), SpoolDevice: record.Assignment.SpoolDevice, SpoolInode: record.Assignment.SpoolInode, AckDevice: record.AckDevice, AckInode: record.AckInode}
}
func (slots *lineageConsumerSlots) matchRetirementReceipt(record lineageSlotRetirement, allowAbsent bool) error {
	name := "ack-" + record.Assignment.Source.GenerationID + ".json"
	if _, err := slots.config.Acknowledgments.root.Lstat(name); os.IsNotExist(err) && allowAbsent {
		return nil
	}
	expected, _ := json.Marshal(expectedSlotRetiredAck(record))
	file, err := pinLineageExactFile(slots.config.Acknowledgments.root, name, slots.owner, lineageAckBytes, expected)
	if err != nil {
		return err
	}
	defer file.file.Close()
	return nil
}
func (slots *lineageConsumerSlots) markSlotRetired(ctx context.Context, record lineageSlotRetirement) (bool, error) {
	unlock := slots.lockInputs()
	defer unlock()
	if !slots.valid() || !slots.inputsValid() || !slots.validSlotRetirement(record) {
		return false, errLineageSpool
	}
	previousRaw, _ := json.Marshal(record)
	previous, err := pinLineageExactFile(slots.root, lineageSlotRetirementName(record.Assignment.Slot), slots.owner, lineageSlotRetirementBytes, previousRaw)
	if err != nil {
		return false, err
	}
	defer previous.file.Close()
	ack, err := pinLineageExactFile(slots.config.Acknowledgments.root, "ack-"+record.Assignment.Source.GenerationID+".json", slots.owner, lineageAckBytes, nil)
	if err != nil {
		return false, err
	}
	defer ack.file.Close()
	retiredRaw, _ := json.Marshal(expectedSlotRetiredAck(record))
	if !bytes.Equal(ack.raw, retiredRaw) {
		originalRaw, _ := json.Marshal(record.Completion.Ack)
		if bytes.Equal(ack.raw, originalRaw) {
			return false, nil
		}
		return false, errLineageSpool
	}
	next := record
	next.AckRetired = true
	authorize := func() bool {
		if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() || !ack.valid() || !slots.slotCursorAbsent(record.Assignment.Slot) {
			return false
		}
		inventory, err := slots.scan()
		if err != nil {
			return false
		}
		current := inventory.retirements[record.Assignment.Slot]
		if current == nil || current.Assignment != record.Assignment {
			return false
		}
		raw, _ := json.Marshal(current)
		nextRaw, _ := json.Marshal(next)
		return bytes.Equal(raw, previousRaw) || bytes.Equal(raw, nextRaw)
	}
	if !authorize() || ack.file.Sync() != nil || slots.config.Acknowledgments.dir.Sync() != nil || previous.file.Sync() != nil || slots.dir.Sync() != nil || !authorize() {
		return false, errLineageSpool
	}
	raw, _ := json.Marshal(next)
	if slots.publishSlotBytes(ctx, raw, lineageSlotRetirementScratch(record.Assignment), lineageSlotRetirementName(record.Assignment.Slot), previous, authorize) != nil {
		return false, errLineageSpool
	}
	return true, nil
}
func (slots *lineageConsumerSlots) slotCursorAbsent(index int) bool {
	names := sensoradapter.ReservedCursorNames(lineageSlotCursor(index))
	for _, name := range []string{names[0], names[2]} {
		if _, err := slots.root.Lstat(name); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}
func (slots *lineageConsumerSlots) slotRemoteAbsent(assignment lineageSlotAssignment) bool {
	producer := slots.config.Producer.directory.root
	id := assignment.Source.GenerationID
	for _, name := range []string{"generation-" + id, ".reclaim-" + id, ".creating-" + id, ".discard-" + id, "reclaim-" + id + ".json"} {
		if _, err := producer.Lstat(name); !os.IsNotExist(err) {
			return false
		}
	}
	_, err := slots.config.Acknowledgments.root.Lstat("ack-" + id + ".json")
	return os.IsNotExist(err)
}
