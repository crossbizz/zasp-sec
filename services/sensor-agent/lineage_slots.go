package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

type lineageSlotConfig struct {
	EnrollmentBinding, Destination string
	Producer                       *lineageCompletionReader
	Acknowledgments                *lineageAcknowledgments
	ProtectedInputs                []sensoradapter.PinnedInput
}

type lineageSlotAssignment struct {
	Version      string                      `json:"version"`
	Slot         int                         `json:"slot"`
	Source       sensoradapter.LineageSource `json:"source"`
	Destination  string                      `json:"destination"`
	ConsumerUID  uint32                      `json:"consumer_uid"`
	StateDevice  uint64                      `json:"state_device"`
	StateInode   uint64                      `json:"state_inode"`
	SpoolDevice  uint64                      `json:"spool_device"`
	SpoolInode   uint64                      `json:"spool_inode"`
	SourceDevice uint64                      `json:"source_device"`
	SourceInode  uint64                      `json:"source_inode"`
}

type lineageConsumerSlots struct {
	mu                   sync.Mutex
	reconcileMu          sync.Mutex
	lastAttempt          string // Scheduling hint only, protected by reconcileMu.
	parent, root         *os.Root
	parentDir, dir, lock *os.File
	name                 string
	owner                uint32
	config               lineageSlotConfig
	closed               bool
}

// Admission is read-only. The first reservation takes a persistent controller
// lock. Lock order is slots, source reader (when present), ACK store, producer
// directory, then cursor slot flock. Borrowed inputs outlive the slot store.
// Retire and Release require authenticated durable retirement evidence; file
// absence alone never authorizes releasing an assignment.
func newLineageConsumerSlots(path string, config lineageSlotConfig) (_ *lineageConsumerSlots, err error) {
	if !validAbsolute(path) || filepath.Dir(path) == path || !enrollmentBindingPattern.MatchString(config.EnrollmentBinding) || !validLineageDestination(config.Destination) || config.Producer == nil || config.Producer.directory == nil || config.Acknowledgments == nil || len(config.ProtectedInputs) > 8 {
		return nil, errLineageSpool
	}
	slots := &lineageConsumerSlots{name: filepath.Base(path), owner: uint32(os.Geteuid()), config: config}
	slots.config.ProtectedInputs = append([]sensoradapter.PinnedInput(nil), config.ProtectedInputs...)
	defer func() {
		if err != nil {
			slots.Close()
		}
	}()
	slots.parent, err = os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errLineageSpool
	}
	slots.parentDir, err = slots.parent.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	slots.root, err = slots.parent.OpenRoot(slots.name)
	if err != nil {
		return nil, errLineageSpool
	}
	slots.dir, err = slots.root.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	config.Acknowledgments.mu.Lock()
	defer config.Acknowledgments.mu.Unlock()
	config.Producer.directory.mu.Lock()
	defer config.Producer.directory.mu.Unlock()
	if !slots.valid() || !slots.inputsValid() {
		return nil, errLineageSpool
	}
	if _, err = slots.scan(); err != nil {
		return nil, err
	}
	return slots, nil
}

func lineageSlotCursor(index int) string { return fmt.Sprintf("cursor-%d.json", index) }
func lineageSlotName(index int) string   { return fmt.Sprintf("assignment-%d.json", index) }
func lineageSlotScratch(index int, id string) string {
	return fmt.Sprintf(".assignment-%d-%s.pending", index, id)
}

func (slots *lineageConsumerSlots) valid() bool {
	if slots == nil || slots.closed || slots.parent == nil || slots.root == nil || slots.parentDir == nil || slots.dir == nil || !lineageOwnedDirectory(slots.dir, slots.owner) || (!lineageOwnedDirectory(slots.parentDir, slots.owner) && !lineageOwnedDirectory(slots.parentDir, 0)) {
		return false
	}
	held, err := slots.dir.Stat()
	named, nameErr := slots.parent.Lstat(slots.name)
	if err != nil || nameErr != nil || held.Mode().Perm() != 0700 || !named.IsDir() || !os.SameFile(held, named) {
		return false
	}
	return slots.lock == nil || slots.validLock(".slots.lock", slots.lock)
}
func (slots *lineageConsumerSlots) validLock(name string, file *os.File) bool {
	held, err := file.Stat()
	named, nameErr := slots.root.Lstat(name)
	return err == nil && nameErr == nil && lineageOwnedRegular(held, slots.owner, 0600) && held.Size() == 0 && lineageOwnedRegular(named, slots.owner, 0600) && os.SameFile(held, named)
}
func (slots *lineageConsumerSlots) openLock(name string) (*os.File, error) {
	file, err := slots.root.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errLineageSpool
	}
	if !slots.validLock(name, file) || syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !slots.validLock(name, file) {
		file.Close()
		return nil, errLineageSpool
	}
	return file, nil
}
func (slots *lineageConsumerSlots) inputsValid() bool {
	acks, producer := slots.config.Acknowledgments, slots.config.Producer.directory
	if !acks.valid() || !producer.valid() || acks.owner != slots.owner {
		return false
	}
	state, err := slots.dir.Stat()
	if err != nil {
		return false
	}
	spool, err := producer.dir.Stat()
	if err != nil {
		return false
	}
	ack, err := acks.dir.Stat()
	if err != nil || os.SameFile(state, spool) || os.SameFile(state, ack) || os.SameFile(spool, ack) {
		return false
	}
	for _, input := range slots.config.ProtectedInputs {
		if input.Parent == nil || input.Name == "" || input.Name == "." || input.Name == ".." || filepath.Base(input.Name) != input.Name {
			return false
		}
		info, err := lineageReadOnlyRootInfo(input.Parent)
		if err != nil || os.SameFile(state, info) || os.SameFile(ack, info) || os.SameFile(spool, info) {
			return false
		}
	}
	return true
}
func lineageSlotIdentity(file *os.File) (uint64, uint64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, 0, errLineageSpool
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, 0, errLineageSpool
	}
	return uint64(stat.Dev), stat.Ino, nil
}
func (slots *lineageConsumerSlots) validAssignment(record lineageSlotAssignment) bool {
	if record.Version != "tetragon-consumer-slot-v1" || record.Slot < 0 || record.Slot >= lineageSpoolSlots || record.ConsumerUID != slots.owner || record.Source.EnrollmentBinding != slots.config.EnrollmentBinding || record.Destination != slots.config.Destination || record.SourceInode == 0 {
		return false
	}
	if _, err := lineageManifestBytes(record.Source); err != nil {
		return false
	}
	stateDevice, stateInode, err := lineageSlotIdentity(slots.dir)
	spoolDevice, spoolInode, spoolErr := lineageSlotIdentity(slots.config.Producer.directory.dir)
	return err == nil && spoolErr == nil && record.StateDevice == stateDevice && record.StateInode == stateInode && record.SpoolDevice == spoolDevice && record.SpoolInode == spoolInode && record.SourceDevice == spoolDevice
}

type lineageSlotInventory struct {
	assignments       [lineageSpoolSlots]*lineageSlotAssignment
	scratch           [lineageSpoolSlots]string
	cursor, temporary [lineageSpoolSlots]bool
	retirements       [lineageSpoolSlots]*lineageSlotRetirement
	retirementScratch [lineageSpoolSlots]string
}

func (slots *lineageConsumerSlots) scan() (lineageSlotInventory, error) {
	var inventory lineageSlotInventory
	if !slots.valid() || !slots.inputsValid() {
		return inventory, errLineageSpool
	}
	dir, err := slots.root.Open(".")
	if err != nil {
		return inventory, errLineageSpool
	}
	entries, err := dir.ReadDir(7*lineageSpoolSlots + 4)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) > 7*lineageSpoolSlots+3 {
		return inventory, errLineageSpool
	}
	seen := map[string]int{}
	controllerPresent := false
	claim := func(id string, index int) bool {
		previous, found := seen[id]
		if found && previous != index {
			return false
		}
		seen[id] = index
		return true
	}
	for _, entry := range entries {
		name := entry.Name()
		info, err := slots.root.Lstat(name)
		if err != nil {
			return inventory, errLineageSpool
		}
		if name == ".slots.lock" {
			if !lineageOwnedRegular(info, slots.owner, 0600) || info.Size() != 0 {
				return inventory, errLineageSpool
			}
			controllerPresent = true
			continue
		}
		if name == lineageHealthName || name == lineageHealthPending {
			if (!lineageOwnedRegular(info, slots.owner, 0440) && (name != lineageHealthPending || !lineageOwnedRegular(info, slots.owner, 0600))) || info.Size() < 0 || info.Size() > lineageHealthBytes {
				return inventory, errLineageSpool
			}
			if name == lineageHealthName {
				if _, file, err := slots.readHealthLocked(); err != nil {
					return inventory, err
				} else {
					file.file.Close()
				}
			}
			continue
		}
		matched := false
		for index := 0; index < lineageSpoolSlots; index++ {
			if name == lineageSlotName(index) {
				file, err := pinLineageExactFile(slots.root, name, slots.owner, lineageAckBytes, nil)
				if err != nil {
					return inventory, err
				}
				var record lineageSlotAssignment
				valid := lineageDecodeCanonical(file.raw, &record) && slots.validAssignment(record) && record.Slot == index
				file.file.Close()
				if !valid || !claim(record.Source.GenerationID, index) {
					return inventory, errLineageSpool
				}
				inventory.assignments[index] = &record
				matched = true
				break
			}
			prefix := fmt.Sprintf(".assignment-%d-", index)
			if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".pending") {
				id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".pending")
				if !validLineageUUID(id) || inventory.scratch[index] != "" || !claim(id, index) || (!lineageOwnedRegular(info, slots.owner, 0600) && !lineageOwnedRegular(info, slots.owner, 0440)) || info.Size() < 0 || info.Size() > lineageAckBytes {
					return inventory, errLineageSpool
				}
				inventory.scratch[index] = name
				matched = true
				break
			}
			if matchedRetirement, err := slots.scanRetirementEntry(name, info, index, &inventory); err != nil {
				return inventory, err
			} else if matchedRetirement {
				matched = true
				break
			}
			names := sensoradapter.ReservedCursorNames(lineageSlotCursor(index))
			for kind, candidate := range names {
				if name != candidate {
					continue
				}
				if !lineageOwnedRegular(info, slots.owner, 0600) || info.Size() < 0 || info.Size() > 32<<20 || kind == 1 && info.Size() != 0 {
					return inventory, errLineageSpool
				}
				if kind == 0 {
					inventory.cursor[index] = true
				}
				if kind == 2 {
					inventory.temporary[index] = true
				}
				matched = true
				break
			}
			if matched {
				break
			}
		}
		if !matched {
			return inventory, errLineageSpool
		}
	}
	for index := 0; index < lineageSpoolSlots; index++ {
		if !controllerPresent && (inventory.assignments[index] != nil || inventory.scratch[index] != "" || inventory.retirements[index] != nil || inventory.retirementScratch[index] != "" || inventory.cursor[index] || inventory.temporary[index]) {
			return inventory, errLineageSpool
		}
		if inventory.assignments[index] != nil && inventory.scratch[index] != "" || inventory.assignments[index] == nil && (inventory.cursor[index] || inventory.temporary[index]) {
			return inventory, errLineageSpool
		}
		retirement := inventory.retirements[index]
		if retirement != nil {
			if !claim(retirement.Assignment.Source.GenerationID, index) || inventory.assignments[index] != nil && *inventory.assignments[index] != retirement.Assignment || inventory.assignments[index] == nil && !retirement.AckRetired {
				return inventory, errLineageSpool
			}
		}
		if scratch := inventory.retirementScratch[index]; scratch != "" {
			var assignment *lineageSlotAssignment
			if retirement != nil {
				assignment = &retirement.Assignment
			} else {
				assignment = inventory.assignments[index]
			}
			if assignment == nil || scratch != lineageSlotRetirementScratch(*assignment) || !claim(assignment.Source.GenerationID, index) {
				return inventory, errLineageSpool
			}
		}
		if inventory.scratch[index] != "" && (retirement != nil || inventory.retirementScratch[index] != "") {
			return inventory, errLineageSpool
		}
	}
	return inventory, nil
}

func (slots *lineageConsumerSlots) lockInputs() func() {
	slots.config.Acknowledgments.mu.Lock()
	slots.config.Producer.directory.mu.Lock()
	return func() { slots.config.Producer.directory.mu.Unlock(); slots.config.Acknowledgments.mu.Unlock() }
}

func (slots *lineageConsumerSlots) Reserve(ctx context.Context, reader *lineageSpoolReader) (lineageSlotAssignment, error) {
	var zero lineageSlotAssignment
	if slots == nil || reader == nil || ctx == nil || ctx.Err() != nil {
		return zero, errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	reader.mu.Lock()
	defer reader.mu.Unlock()
	unlock := slots.lockInputs()
	defer unlock()
	if !slots.valid() || !slots.inputsValid() || !reader.valid() || reader.Source().EnrollmentBinding != slots.config.EnrollmentBinding || reader.owner != slots.config.Producer.directory.owner {
		return zero, errLineageSpool
	}
	parent, err := reader.parentDir.Stat()
	producer, producerErr := slots.config.Producer.directory.dir.Stat()
	state, stateErr := slots.dir.Stat()
	source, sourceErr := reader.dir.Stat()
	if err != nil || producerErr != nil || stateErr != nil || sourceErr != nil || !os.SameFile(parent, producer) || os.SameFile(state, source) {
		return zero, errLineageSpool
	}
	if _, err := slots.scan(); err != nil {
		return zero, err
	}
	if slots.lock == nil {
		slots.lock, err = slots.openLock(".slots.lock")
		if err != nil {
			return zero, err
		}
	}
	if slots.lock.Sync() != nil || slots.dir.Sync() != nil || !slots.valid() {
		return zero, errLineageSpool
	}
	inventory, err := slots.scan()
	if err != nil {
		return zero, err
	}
	record := lineageSlotAssignment{Version: "tetragon-consumer-slot-v1", Source: reader.Source(), Destination: slots.config.Destination, ConsumerUID: slots.owner}
	record.StateDevice, record.StateInode, err = lineageSlotIdentity(slots.dir)
	if err != nil {
		return zero, err
	}
	record.SpoolDevice, record.SpoolInode, err = lineageSlotIdentity(slots.config.Producer.directory.dir)
	if err != nil {
		return zero, err
	}
	record.SourceDevice, record.SourceInode, err = lineageSlotIdentity(reader.dir)
	if err != nil {
		return zero, err
	}
	selected := -1
	for index, existing := range inventory.assignments {
		if retirement := inventory.retirements[index]; retirement != nil && retirement.Assignment.Source.GenerationID == record.Source.GenerationID {
			return zero, errLineageSpool
		}
		if existing != nil && existing.Source.GenerationID == record.Source.GenerationID {
			if inventory.retirements[index] != nil || inventory.retirementScratch[index] != "" {
				return zero, errLineageSpool
			}
			record.Slot = index
			if *existing != record {
				return zero, errLineageSpool
			}
			return record, slots.syncAssignment(ctx, reader, record)
		}
		if inventory.scratch[index] == lineageSlotScratch(index, record.Source.GenerationID) {
			selected = index
		}
	}
	if selected < 0 {
		for index := 0; index < lineageSpoolSlots; index++ {
			if inventory.assignments[index] == nil && inventory.scratch[index] == "" && inventory.retirements[index] == nil && inventory.retirementScratch[index] == "" {
				selected = index
				break
			}
		}
	}
	if selected < 0 {
		return zero, errLineageSpoolFull
	}
	record.Slot = selected
	lockName := lineageSlotCursor(selected) + ".lock"
	lock, err := slots.openLock(lockName)
	if err != nil {
		return zero, err
	}
	defer lock.Close()
	authorize := func() bool {
		if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() || !reader.valid() || !slots.validLock(lockName, lock) || !slots.validAssignment(record) {
			return false
		}
		current, err := slots.scan()
		if err != nil || current.retirements[selected] != nil || current.retirementScratch[selected] != "" || current.assignments[selected] != nil && *current.assignments[selected] != record || current.scratch[selected] != "" && current.scratch[selected] != lineageSlotScratch(selected, record.Source.GenerationID) {
			return false
		}
		for _, name := range []string{sensoradapter.ReservedCursorNames(lineageSlotCursor(selected))[0], sensoradapter.ReservedCursorNames(lineageSlotCursor(selected))[2]} {
			if _, err := slots.root.Lstat(name); !os.IsNotExist(err) {
				return false
			}
		}
		return true
	}
	if !authorize() || lock.Sync() != nil || slots.dir.Sync() != nil || !authorize() {
		return zero, errLineageSpool
	}
	if err := slots.publishAssignment(ctx, record, authorize); err != nil {
		return zero, err
	}
	return record, nil
}
func (slots *lineageConsumerSlots) List(ctx context.Context) ([]lineageSlotAssignment, error) {
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
	records := make([]lineageSlotAssignment, 0, lineageSpoolSlots)
	for _, record := range inventory.assignments {
		if record != nil {
			records = append(records, *record)
		}
	}
	if ctx.Err() != nil {
		return nil, errLineageSpool
	}
	return records, nil
}
func (slots *lineageConsumerSlots) CursorPath(assignment lineageSlotAssignment) (string, error) {
	if slots == nil {
		return "", errLineageSpool
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	unlock := slots.lockInputs()
	defer unlock()
	inventory, err := slots.scan()
	if err != nil || !slots.validAssignment(assignment) || inventory.assignments[assignment.Slot] == nil || *inventory.assignments[assignment.Slot] != assignment {
		return "", errLineageSpool
	}
	if inventory.retirements[assignment.Slot] != nil || inventory.retirementScratch[assignment.Slot] != "" {
		return "", errLineageSpool
	}
	if slots.lock == nil {
		slots.lock, err = slots.openLock(".slots.lock")
		if err != nil {
			return "", err
		}
	}
	if err := slots.syncAssignment(context.Background(), nil, assignment); err != nil {
		return "", err
	}
	return filepath.Join(slots.root.Name(), lineageSlotCursor(assignment.Slot)), nil
}
func (slots *lineageConsumerSlots) Close() error {
	if slots == nil {
		return nil
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	if slots.closed {
		return nil
	}
	slots.closed = true
	var first error
	for _, file := range []*os.File{slots.lock, slots.dir, slots.parentDir} {
		if file != nil {
			if err := file.Close(); first == nil {
				first = err
			}
		}
	}
	for _, root := range []*os.Root{slots.root, slots.parent} {
		if root != nil {
			if err := root.Close(); first == nil {
				first = err
			}
		}
	}
	return first
}

func (slots *lineageConsumerSlots) syncAssignment(ctx context.Context, reader *lineageSpoolReader, record lineageSlotAssignment) error {
	raw, _ := json.Marshal(record)
	file, err := pinLineageExactFile(slots.root, lineageSlotName(record.Slot), slots.owner, lineageAckBytes, raw)
	if err != nil {
		return err
	}
	defer file.file.Close()
	if ctx.Err() != nil || !slots.valid() || !slots.inputsValid() || reader != nil && !reader.valid() || !file.valid() || file.file.Sync() != nil || slots.dir.Sync() != nil || ctx.Err() != nil || !slots.valid() || !slots.inputsValid() || reader != nil && !reader.valid() || !file.valid() {
		return errLineageSpool
	}
	return nil
}

func (slots *lineageConsumerSlots) publishAssignment(ctx context.Context, record lineageSlotAssignment, authorize func() bool) error {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > lineageAckBytes {
		return errLineageSpool
	}
	name := lineageSlotScratch(record.Slot, record.Source.GenerationID)
	return slots.publishSlotBytes(ctx, raw, name, lineageSlotName(record.Slot), nil, authorize)
}

func (slots *lineageConsumerSlots) publishSlotBytes(ctx context.Context, raw []byte, name, final string, previousRecord *lineageExactFile, authorize func() bool) error {
	file, err := slots.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if os.IsExist(err) {
		file, err = slots.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return errLineageSpool
	}
	defer func() { file.Close() }()
	info, err := file.Stat()
	if err != nil || (!lineageOwnedRegular(info, slots.owner, 0600) && !lineageOwnedRegular(info, slots.owner, 0440)) || info.Size() < 0 || info.Size() > int64(len(raw)) {
		return errLineageSpool
	}
	previous, err := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
	if err != nil || !bytes.HasPrefix(raw, previous) {
		return errLineageSpool
	}
	pinned := &lineageSlotFile{root: slots.root, file: file, name: name, scratch: name, owner: slots.owner, raw: previous}
	if !authorize() || !pinned.valid() || slots.dir.Sync() != nil || !authorize() || !pinned.valid() {
		return errLineageSpool
	}
	if len(previous) < len(raw) {
		if file.Chmod(0600) != nil || !authorize() || !pinned.valid() {
			return errLineageSpool
		}
		writer, err := slots.root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errLineageSpool
		}
		held, heldErr := file.Stat()
		next, nextErr := writer.Stat()
		if heldErr != nil || nextErr != nil || !os.SameFile(held, next) || !pinned.valid() {
			writer.Close()
			return errLineageSpool
		}
		file.Close()
		file = writer
		pinned.file = writer
		if !authorize() || !pinned.valid() {
			return errLineageSpool
		}
		if n, err := file.WriteAt(raw[len(previous):], int64(len(previous))); err != nil || n != len(raw)-len(previous) {
			return errLineageSpool
		}
		pinned.raw = raw
	}
	if !authorize() || !pinned.valid() || file.Chmod(0440) != nil || file.Sync() != nil || !authorize() || !pinned.valid() {
		return errLineageSpool
	}
	if previousRecord == nil {
		if _, err := slots.root.Lstat(final); !os.IsNotExist(err) {
			return errLineageSpool
		}
	} else if previousRecord.name != final || !previousRecord.valid() {
		return errLineageSpool
	}
	if !authorize() || !pinned.valid() || slots.root.Rename(name, final) != nil {
		return errLineageSpool
	}
	pinned.name = final
	if ctx.Err() != nil || slots.dir.Sync() != nil || !authorize() || !pinned.valid() {
		return errLineageSpool
	}
	return nil
}

type lineageSlotFile struct {
	root          *os.Root
	file          *os.File
	name, scratch string
	owner         uint32
	raw           []byte
}

func (file *lineageSlotFile) valid() bool {
	held, err := file.file.Stat()
	named, nameErr := file.root.Lstat(file.name)
	if err != nil || nameErr != nil || !os.SameFile(held, named) || held.Size() != int64(len(file.raw)) {
		return false
	}
	mode := held.Mode().Perm()
	if mode != 0440 && (file.name != file.scratch || mode != 0600) || !lineageOwnedRegular(held, file.owner, mode) || !lineageOwnedRegular(named, file.owner, mode) {
		return false
	}
	raw := make([]byte, len(file.raw))
	n, err := file.file.ReadAt(raw, 0)
	return err == nil && n == len(raw) && bytes.Equal(raw, file.raw)
}
