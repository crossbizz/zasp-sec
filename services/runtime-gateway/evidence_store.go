package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	maximumGatewayEvidenceMetadataBytes = 1024 * 1024
	maximumGatewayEvidenceReceiptBytes  = 128 * 1024
	maximumGatewayEvidenceAckBytes      = 1024
	gatewayEvidenceExpiredReason        = "record_window_expired"
	gatewayEvidenceStoreContractVersion = 2
	gatewayEvidenceStoreMagic           = 0x5a01
	gatewayEvidenceCleanupBatch         = 1024
	gatewayEvidenceMinimumPhysicalBytes = 64 << 20
	gatewayEvidencePhysicalWriteReserve = 32 << 20
)

var (
	gatewayEvidenceMetadataKey = []byte("metadata/state")
	gatewayEvidenceReceiptRoot = []byte("receipt/")
	gatewayEvidenceExpiryRoot  = []byte("expiry/")
	gatewayEvidenceAckRoot     = []byte("ack/")
)

type gatewayQuarantinedDecisionEvent struct {
	Event         gatewayDecisionEvent
	Reason        string
	QuarantinedAt time.Time
}

type gatewayEvaluationReceipt struct {
	EventID       string
	RequestDigest [sha256.Size]byte
	Result        gatewayEvaluationResult
	EvaluatedAt   time.Time
}

type gatewayEvidenceState struct {
	AuthorityConfirmed bool
	ConfirmedFloor     uint64
	ObservedAt         time.Time
	Pending            []gatewayDecisionEvent
	Quarantined        []gatewayQuarantinedDecisionEvent
	Receipts           []gatewayEvaluationReceipt
}

type gatewayEvidenceUsage struct {
	ReceiptBytes         uint64
	MaximumBytes         uint64
	ReceiptCount         uint64
	DatabaseBytes        uint64
	MaximumDatabaseBytes uint64
}

type gatewayEvidenceStore interface {
	Load() (gatewayEvidenceState, error)
	Store(gatewayEvidenceState) error
	Receipt(string, time.Time) (gatewayEvaluationReceipt, bool, error)
	Maintain(time.Time) (gatewayEvidenceUsage, error)
	Acknowledge(gatewayEvidenceState, gatewayQuarantineAcknowledgment, time.Time) (bool, error)
	Close() error
}

type gatewayEvidenceDiskStore struct {
	mu sync.Mutex

	parent               *os.Root
	root                 *os.Root
	directory            *os.File
	parentName           string
	database             *badger.DB
	expected             gatewayAuthority
	maximum              int
	maximumBytes         uint64
	maximumDatabaseBytes uint64
	closed               bool
}

type gatewayEvidenceDiskState struct {
	ContractVersion    int                        `json:"contract_version"`
	OrganizationID     string                     `json:"organization_id"`
	WorkspaceID        string                     `json:"workspace_id"`
	EnvironmentID      string                     `json:"environment_id"`
	DeviceID           string                     `json:"device_id"`
	CredentialID       string                     `json:"credential_id"`
	AuthorityConfirmed bool                       `json:"authority_confirmed"`
	ConfirmedFloor     uint64                     `json:"confirmed_floor"`
	ObservedAt         string                     `json:"observed_at"`
	Pending            []gatewayDecisionEventWire `json:"pending"`
	Quarantined        []gatewayQuarantinedWire   `json:"quarantined"`
	ReceiptBytes       uint64                     `json:"receipt_bytes"`
	ReceiptCount       uint64                     `json:"receipt_count"`
}

func newGatewayEvidenceDiskStore(path string, expected gatewayAuthority, maximum int, maximumBytes uint64) (*gatewayEvidenceDiskStore, error) {
	if !validGatewayAuthority(expected, expected.CredentialID) || maximum < 1 || maximum > 1024 || maximumBytes < 1024*1024 || maximumBytes > 64<<30 {
		return nil, errGatewayRuntime
	}
	parent, root, directory, parentName, pinnedPath, err := openGatewayEvidenceDirectory(path)
	if err != nil {
		return nil, errGatewayRuntime
	}
	fail := func() (*gatewayEvidenceDiskStore, error) {
		_ = directory.Close()
		_ = root.Close()
		_ = parent.Close()
		return nil, errGatewayRuntime
	}
	options := badger.LSMOnlyOptions(pinnedPath).
		WithSyncWrites(true).
		WithLogger(nil).
		WithMetricsEnabled(false).
		WithMemTableSize(8 << 20).
		WithBaseTableSize(8 << 20).
		WithBaseLevelSize(32 << 20).
		WithBlockCacheSize(16 << 20).
		WithIndexCacheSize(8 << 20).
		WithNumMemtables(3).
		WithNumCompactors(2).
		WithCompactL0OnClose(false).
		WithVerifyValueChecksum(true).
		WithNumVersionsToKeep(1).
		WithExternalMagic(gatewayEvidenceStoreMagic)
	beforeOpen, _, safeBeforeOpen := gatewayEvidenceDirectorySnapshot(root)
	if !safeBeforeOpen {
		return fail()
	}
	database, err := badger.Open(options)
	if err != nil {
		return fail()
	}
	maximumDatabaseBytes := maximumBytes * 2
	if maximumDatabaseBytes < gatewayEvidenceMinimumPhysicalBytes {
		maximumDatabaseBytes = gatewayEvidenceMinimumPhysicalBytes
	}
	store := &gatewayEvidenceDiskStore{parent: parent, root: root, directory: directory, parentName: parentName, database: database, expected: expected, maximum: maximum, maximumBytes: maximumBytes, maximumDatabaseBytes: maximumDatabaseBytes}
	if !secureNewGatewayEvidenceFiles(root, beforeOpen) {
		_ = store.Close()
		return nil, errGatewayRuntime
	}
	_, _, safeAfterOpen := gatewayEvidenceDirectorySnapshot(root)
	if !safeAfterOpen || !store.validDirectoryLocked() {
		_ = store.Close()
		return nil, errGatewayRuntime
	}
	if _, err := store.Load(); err != nil {
		_ = store.Close()
		return nil, errGatewayRuntime
	}
	return store, nil
}

func (store *gatewayEvidenceDiskStore) Load() (gatewayEvidenceState, error) {
	if store == nil {
		return gatewayEvidenceState{}, errGatewayRuntime
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.availableLocked() {
		return gatewayEvidenceState{}, errGatewayRuntime
	}
	state, _, found, err := store.loadStateLocked()
	if err != nil {
		return gatewayEvidenceState{}, errGatewayRuntime
	}
	if !found {
		return emptyGatewayEvidenceState(), nil
	}
	return cloneGatewayEvidenceState(state), nil
}

func (store *gatewayEvidenceDiskStore) Store(state gatewayEvidenceState) error {
	if store == nil {
		return errGatewayRuntime
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.availableLocked() || !validGatewayEvidenceState(state, store.expected, store.maximum) {
		return errGatewayRuntime
	}
	_, physicalBytes, physicalOK := gatewayEvidenceDirectorySnapshot(store.root)
	if !physicalOK {
		return errGatewayRuntime
	}
	err := store.database.Update(func(transaction *badger.Txn) error {
		_, usage, found, err := loadGatewayEvidenceMetadata(transaction, store.expected, store.maximum, store.maximumBytes)
		if err != nil {
			return err
		}
		if !found {
			usage = gatewayEvidenceUsage{MaximumBytes: store.maximumBytes}
		}
		for _, receipt := range state.Receipts {
			raw, err := marshalGatewayEvaluationReceipt(receipt)
			if err != nil {
				return err
			}
			receiptKey := gatewayEvidenceReceiptKey(receipt.EventID)
			expiryKey := gatewayEvidenceExpiryKey(receipt)
			item, getErr := transaction.Get(receiptKey)
			switch {
			case getErr == nil:
				existing, copyErr := item.ValueCopy(nil)
				if copyErr != nil || !bytes.Equal(existing, raw) {
					return errGatewayRuntime
				}
			case errors.Is(getErr, badger.ErrKeyNotFound):
				if physicalBytes > store.maximumDatabaseBytes-gatewayEvidencePhysicalWriteReserve {
					return errGatewayRuntime
				}
				logicalBytes := gatewayEvidenceReceiptLogicalBytes(receiptKey, expiryKey, raw)
				if logicalBytes > store.maximumBytes-usage.ReceiptBytes || usage.ReceiptCount == ^uint64(0) {
					return errGatewayRuntime
				}
				if transaction.Set(receiptKey, raw) != nil || transaction.Set(expiryKey, []byte{}) != nil {
					return errGatewayRuntime
				}
				usage.ReceiptBytes += logicalBytes
				usage.ReceiptCount++
			default:
				return errGatewayRuntime
			}
		}
		raw, err := marshalGatewayEvidenceMetadata(state, store.expected, store.maximum, usage)
		if err != nil || transaction.Set(gatewayEvidenceMetadataKey, raw) != nil {
			return errGatewayRuntime
		}
		return nil
	})
	if err != nil {
		return errGatewayRuntime
	}
	return nil
}

func (store *gatewayEvidenceDiskStore) Receipt(eventID string, now time.Time) (gatewayEvaluationReceipt, bool, error) {
	if store == nil || !validGatewayProductID(eventID) || !validGatewayTime(now) {
		return gatewayEvaluationReceipt{}, false, errGatewayRuntime
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.availableLocked() {
		return gatewayEvaluationReceipt{}, false, errGatewayRuntime
	}
	var receipt gatewayEvaluationReceipt
	found := false
	err := store.database.View(func(transaction *badger.Txn) error {
		state, _, metadataFound, err := loadGatewayEvidenceMetadata(transaction, store.expected, store.maximum, store.maximumBytes)
		if err != nil {
			return err
		}
		if !metadataFound {
			return nil
		}
		item, err := transaction.Get(gatewayEvidenceReceiptKey(eventID))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return errGatewayRuntime
		}
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return errGatewayRuntime
		}
		receipt, err = decodeGatewayEvaluationReceipt(raw)
		if err != nil || receipt.EventID != eventID {
			return errGatewayRuntime
		}
		if !gatewayEvidenceEventActive(state, eventID) && !receipt.EvaluatedAt.After(now.Add(-gatewayEvidenceRecordWindow)) {
			return nil
		}
		found = true
		return nil
	})
	if err != nil {
		return gatewayEvaluationReceipt{}, false, errGatewayRuntime
	}
	return receipt, found, nil
}

func (store *gatewayEvidenceDiskStore) Maintain(now time.Time) (gatewayEvidenceUsage, error) {
	if store == nil || !validGatewayTime(now) {
		return gatewayEvidenceUsage{}, errGatewayRuntime
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.availableLocked() {
		return gatewayEvidenceUsage{}, errGatewayRuntime
	}
	usage := gatewayEvidenceUsage{MaximumBytes: store.maximumBytes, MaximumDatabaseBytes: store.maximumDatabaseBytes}
	err := store.database.Update(func(transaction *badger.Txn) error {
		state, current, found, err := loadGatewayEvidenceMetadata(transaction, store.expected, store.maximum, store.maximumBytes)
		if err != nil {
			return err
		}
		usage = current
		if !found {
			return nil
		}
		options := badger.DefaultIteratorOptions
		options.Prefix = gatewayEvidenceExpiryRoot
		options.PrefetchValues = false
		iterator := transaction.NewIterator(options)
		defer iterator.Close()
		deleted := 0
		for iterator.Rewind(); iterator.ValidForPrefix(gatewayEvidenceExpiryRoot) && deleted < gatewayEvidenceCleanupBatch; iterator.Next() {
			expiryKey := iterator.Item().KeyCopy(nil)
			expiresAt, eventID, ok := parseGatewayEvidenceExpiryKey(expiryKey)
			if !ok {
				return errGatewayRuntime
			}
			if expiresAt.After(now) {
				break
			}
			if gatewayEvidenceEventActive(state, eventID) {
				continue
			}
			receiptKey := gatewayEvidenceReceiptKey(eventID)
			item, err := transaction.Get(receiptKey)
			if err != nil {
				return errGatewayRuntime
			}
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return errGatewayRuntime
			}
			receipt, err := decodeGatewayEvaluationReceipt(raw)
			if err != nil || !receipt.EvaluatedAt.Add(gatewayEvidenceRecordWindow).Equal(expiresAt) {
				return errGatewayRuntime
			}
			logicalBytes := gatewayEvidenceReceiptLogicalBytes(receiptKey, expiryKey, raw)
			if usage.ReceiptBytes < logicalBytes || usage.ReceiptCount == 0 || transaction.Delete(receiptKey) != nil || transaction.Delete(expiryKey) != nil || transaction.Delete(gatewayEvidenceAckKey(eventID)) != nil {
				return errGatewayRuntime
			}
			usage.ReceiptBytes -= logicalBytes
			usage.ReceiptCount--
			deleted++
		}
		if deleted > 0 {
			raw, err := marshalGatewayEvidenceMetadata(state, store.expected, store.maximum, usage)
			if err != nil || transaction.Set(gatewayEvidenceMetadataKey, raw) != nil {
				return errGatewayRuntime
			}
		}
		return nil
	})
	if err != nil || !store.secureDirectoryFilesLocked() || !store.validDirectoryLocked() {
		return gatewayEvidenceUsage{}, errGatewayRuntime
	}
	_, physicalBytes, physicalOK := gatewayEvidenceDirectorySnapshot(store.root)
	if !physicalOK {
		return gatewayEvidenceUsage{}, errGatewayRuntime
	}
	usage.DatabaseBytes = physicalBytes
	usage.MaximumDatabaseBytes = store.maximumDatabaseBytes
	return usage, nil
}

func (store *gatewayEvidenceDiskStore) Acknowledge(state gatewayEvidenceState, acknowledgment gatewayQuarantineAcknowledgment, acknowledgedAt time.Time) (bool, error) {
	if store == nil || !validGatewayQuarantineAcknowledgment(acknowledgment) || !validGatewayTime(acknowledgedAt) {
		return false, errGatewayRuntime
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.availableLocked() || !validGatewayEvidenceState(state, store.expected, store.maximum) || !state.ObservedAt.Equal(acknowledgedAt) {
		return false, errGatewayRuntime
	}
	replayed := false
	err := store.database.Update(func(transaction *badger.Txn) error {
		current, usage, found, err := loadGatewayEvidenceMetadata(transaction, store.expected, store.maximum, store.maximumBytes)
		if err != nil || !found {
			return errGatewayRuntime
		}
		ackKey := gatewayEvidenceAckKey(acknowledgment.EventID)
		if item, getErr := transaction.Get(ackKey); getErr == nil {
			raw, copyErr := item.ValueCopy(nil)
			existing, decodeErr := decodeGatewayQuarantineAcknowledgment(raw)
			expected := cloneGatewayEvidenceState(current)
			expected.ObservedAt = state.ObservedAt
			if copyErr != nil || decodeErr != nil || !sameGatewayQuarantineAcknowledgment(existing.Acknowledgment, acknowledgment) || state.ObservedAt.Before(current.ObservedAt) || !sameGatewayEvidenceMetadataState(expected, state, store.expected, store.maximum, usage) {
				return errGatewayRuntime
			}
			if !state.ObservedAt.Equal(current.ObservedAt) {
				metadata, err := marshalGatewayEvidenceMetadata(state, store.expected, store.maximum, usage)
				if err != nil || transaction.Set(gatewayEvidenceMetadataKey, metadata) != nil {
					return errGatewayRuntime
				}
			}
			replayed = true
			return nil
		} else if !errors.Is(getErr, badger.ErrKeyNotFound) {
			return errGatewayRuntime
		}
		quarantineIndex := -1
		var quarantined gatewayQuarantinedDecisionEvent
		for index, candidate := range current.Quarantined {
			if candidate.Event.EventID == acknowledgment.EventID {
				quarantineIndex = index
				quarantined = candidate
				break
			}
		}
		if quarantineIndex < 0 || current.ConfirmedFloor != acknowledgment.ConfirmedFloor {
			return errGatewayRuntime
		}
		receiptItem, err := transaction.Get(gatewayEvidenceReceiptKey(acknowledgment.EventID))
		if err != nil {
			return errGatewayRuntime
		}
		receiptRaw, err := receiptItem.ValueCopy(nil)
		if err != nil {
			return errGatewayRuntime
		}
		receipt, err := decodeGatewayEvaluationReceipt(receiptRaw)
		if err != nil || receipt.RequestDigest != acknowledgment.RequestDigest || !gatewayReceiptMatchesEvent(receipt, quarantined.Event) {
			return errGatewayRuntime
		}
		expected := cloneGatewayEvidenceState(current)
		expected.Quarantined = append(cloneGatewayQuarantinedDecisionEvents(current.Quarantined[:quarantineIndex]), cloneGatewayQuarantinedDecisionEvents(current.Quarantined[quarantineIndex+1:])...)
		expected.ObservedAt = acknowledgedAt
		if !sameGatewayEvidenceMetadataState(expected, state, store.expected, store.maximum, usage) {
			return errGatewayRuntime
		}
		ackRaw, err := marshalGatewayQuarantineAcknowledgment(gatewayStoredQuarantineAcknowledgment{Acknowledgment: acknowledgment, AcknowledgedAt: acknowledgedAt})
		if err != nil || transaction.Set(ackKey, ackRaw) != nil {
			return errGatewayRuntime
		}
		metadata, err := marshalGatewayEvidenceMetadata(state, store.expected, store.maximum, usage)
		if err != nil || transaction.Set(gatewayEvidenceMetadataKey, metadata) != nil {
			return errGatewayRuntime
		}
		return nil
	})
	if err != nil {
		return false, errGatewayRuntime
	}
	return replayed, nil
}

func (store *gatewayEvidenceDiskStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	directoryValid := store.validDirectoryIdentityLocked()
	store.closed = true
	var result error
	if !directoryValid {
		result = errGatewayRuntime
	}
	if store.database != nil && store.database.Close() != nil {
		result = errGatewayRuntime
	}
	store.database = nil
	if store.root != nil && !store.secureDirectoryFilesLocked() {
		result = errGatewayRuntime
	}
	if store.directory != nil && store.directory.Close() != nil {
		result = errGatewayRuntime
	}
	store.directory = nil
	if store.root != nil && store.root.Close() != nil {
		result = errGatewayRuntime
	}
	store.root = nil
	if store.parent != nil && store.parent.Close() != nil {
		result = errGatewayRuntime
	}
	store.parent = nil
	return result
}

func (store *gatewayEvidenceDiskStore) loadStateLocked() (gatewayEvidenceState, gatewayEvidenceUsage, bool, error) {
	var state gatewayEvidenceState
	var usage gatewayEvidenceUsage
	found := false
	err := store.database.View(func(transaction *badger.Txn) error {
		decoded, decodedUsage, metadataFound, err := loadGatewayEvidenceMetadata(transaction, store.expected, store.maximum, store.maximumBytes)
		if err != nil || !metadataFound {
			return err
		}
		state = decoded
		usage = decodedUsage
		found = true
		active := gatewayEvidenceActiveEventIDs(state)
		state.Receipts = make([]gatewayEvaluationReceipt, 0, len(active))
		for _, eventID := range active {
			item, err := transaction.Get(gatewayEvidenceReceiptKey(eventID))
			if err != nil {
				return errGatewayRuntime
			}
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return errGatewayRuntime
			}
			receipt, err := decodeGatewayEvaluationReceipt(raw)
			if err != nil || receipt.EventID != eventID {
				return errGatewayRuntime
			}
			state.Receipts = append(state.Receipts, receipt)
		}
		sortGatewayEvaluationReceipts(state.Receipts)
		if !validGatewayEvidenceState(state, store.expected, store.maximum) {
			return errGatewayRuntime
		}
		return nil
	})
	if err != nil {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, false, errGatewayRuntime
	}
	return state, usage, found, nil
}

func (store *gatewayEvidenceDiskStore) availableLocked() bool {
	return !store.closed && store.database != nil && store.secureDirectoryFilesLocked() && store.validDirectoryLocked()
}

func loadGatewayEvidenceMetadata(transaction *badger.Txn, expected gatewayAuthority, maximum int, maximumBytes uint64) (gatewayEvidenceState, gatewayEvidenceUsage, bool, error) {
	item, err := transaction.Get(gatewayEvidenceMetadataKey)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return emptyGatewayEvidenceState(), gatewayEvidenceUsage{MaximumBytes: maximumBytes}, false, nil
	}
	if err != nil {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, false, errGatewayRuntime
	}
	raw, err := item.ValueCopy(nil)
	if err != nil {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, false, errGatewayRuntime
	}
	state, usage, err := decodeGatewayEvidenceMetadata(raw, expected, maximum, maximumBytes)
	if err != nil {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, false, errGatewayRuntime
	}
	canonical, err := marshalGatewayEvidenceMetadata(state, expected, maximum, usage)
	if err != nil || !bytes.Equal(raw, canonical) {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, false, errGatewayRuntime
	}
	return state, usage, true, nil
}

func marshalGatewayEvidenceMetadata(state gatewayEvidenceState, expected gatewayAuthority, maximum int, usage gatewayEvidenceUsage) ([]byte, error) {
	if !validGatewayEvidenceMetadataState(state, expected, maximum) || usage.MaximumBytes < 1024*1024 || usage.ReceiptBytes > usage.MaximumBytes {
		return nil, errGatewayRuntime
	}
	pending := make([]gatewayDecisionEventWire, len(state.Pending))
	for index, event := range state.Pending {
		pending[index] = gatewayDecisionEventToWire(event)
	}
	quarantined := make([]gatewayQuarantinedWire, len(state.Quarantined))
	for index, event := range state.Quarantined {
		quarantined[index] = gatewayQuarantinedWire{Event: gatewayDecisionEventToWire(event.Event), Reason: event.Reason, QuarantinedAt: event.QuarantinedAt.Format("2006-01-02T15:04:05Z")}
	}
	raw, err := json.Marshal(gatewayEvidenceDiskState{
		ContractVersion: gatewayEvidenceStoreContractVersion, OrganizationID: expected.OrganizationID, WorkspaceID: expected.WorkspaceID,
		EnvironmentID: expected.EnvironmentID, DeviceID: expected.DeviceID, CredentialID: expected.CredentialID,
		AuthorityConfirmed: state.AuthorityConfirmed, ConfirmedFloor: state.ConfirmedFloor, ObservedAt: state.ObservedAt.Format("2006-01-02T15:04:05Z"),
		Pending: pending, Quarantined: quarantined, ReceiptBytes: usage.ReceiptBytes, ReceiptCount: usage.ReceiptCount,
	})
	if err != nil || len(raw) < 2 || len(raw) > maximumGatewayEvidenceMetadataBytes {
		return nil, errGatewayRuntime
	}
	return raw, nil
}

func decodeGatewayEvidenceMetadata(raw []byte, expected gatewayAuthority, maximum int, maximumBytes uint64) (gatewayEvidenceState, gatewayEvidenceUsage, error) {
	if len(raw) < 2 || len(raw) > maximumGatewayEvidenceMetadataBytes {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire gatewayEvidenceDiskState
	if decoder.Decode(&wire) != nil {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || wire.ContractVersion != gatewayEvidenceStoreContractVersion || wire.OrganizationID != expected.OrganizationID || wire.WorkspaceID != expected.WorkspaceID || wire.EnvironmentID != expected.EnvironmentID || wire.DeviceID != expected.DeviceID || wire.CredentialID != expected.CredentialID || wire.ReceiptBytes > maximumBytes {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
	}
	observedAt, err := time.Parse("2006-01-02T15:04:05Z", wire.ObservedAt)
	if err != nil {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
	}
	state := gatewayEvidenceState{AuthorityConfirmed: wire.AuthorityConfirmed, ConfirmedFloor: wire.ConfirmedFloor, ObservedAt: observedAt, Pending: make([]gatewayDecisionEvent, len(wire.Pending)), Quarantined: make([]gatewayQuarantinedDecisionEvent, len(wire.Quarantined)), Receipts: []gatewayEvaluationReceipt{}}
	for index, event := range wire.Pending {
		decoded, err := gatewayDecisionEventFromWire(event)
		if err != nil {
			return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
		}
		state.Pending[index] = decoded
	}
	for index, event := range wire.Quarantined {
		decoded, err := gatewayDecisionEventFromWire(event.Event)
		if err != nil {
			return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
		}
		quarantinedAt, err := time.Parse("2006-01-02T15:04:05Z", event.QuarantinedAt)
		if err != nil {
			return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
		}
		state.Quarantined[index] = gatewayQuarantinedDecisionEvent{Event: decoded, Reason: event.Reason, QuarantinedAt: quarantinedAt}
	}
	if !validGatewayEvidenceMetadataState(state, expected, maximum) {
		return gatewayEvidenceState{}, gatewayEvidenceUsage{}, errGatewayRuntime
	}
	return state, gatewayEvidenceUsage{ReceiptBytes: wire.ReceiptBytes, MaximumBytes: maximumBytes, ReceiptCount: wire.ReceiptCount}, nil
}

func marshalGatewayEvaluationReceipt(receipt gatewayEvaluationReceipt) ([]byte, error) {
	if !validGatewayEvaluationReceipt(receipt) {
		return nil, errGatewayRuntime
	}
	raw, err := json.Marshal(gatewayEvaluationReceiptToWire(receipt))
	if err != nil || len(raw) < 2 || len(raw) > maximumGatewayEvidenceReceiptBytes {
		return nil, errGatewayRuntime
	}
	return raw, nil
}

func decodeGatewayEvaluationReceipt(raw []byte) (gatewayEvaluationReceipt, error) {
	if len(raw) < 2 || len(raw) > maximumGatewayEvidenceReceiptBytes {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire gatewayEvaluationWire
	if decoder.Decode(&wire) != nil {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	receipt, err := gatewayEvaluationReceiptFromWire(wire)
	if err != nil {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	canonical, err := marshalGatewayEvaluationReceipt(receipt)
	if err != nil || !bytes.Equal(raw, canonical) {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	return receipt, nil
}

var _ gatewayEvidenceStore = (*gatewayEvidenceDiskStore)(nil)
