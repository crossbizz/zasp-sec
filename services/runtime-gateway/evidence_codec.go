package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

type gatewayQuarantinedWire struct {
	Event         gatewayDecisionEventWire `json:"event"`
	Reason        string                   `json:"reason"`
	QuarantinedAt string                   `json:"quarantined_at"`
}

type gatewayDecisionEventWire struct {
	CredentialID   string            `json:"credential_id"`
	DeviceID       string            `json:"device_id"`
	EventID        string            `json:"event_id"`
	ExpectedFloor  uint64            `json:"expected_floor"`
	NextFloor      uint64            `json:"next_floor"`
	PolicyVersion  uint64            `json:"policy_version"`
	Decision       string            `json:"decision"`
	ActionKind     string            `json:"action_kind"`
	Classification map[string]string `json:"classification"`
	OccurredAt     string            `json:"occurred_at"`
}

type gatewayEvaluationWire struct {
	EventID          string   `json:"event_id"`
	RequestDigest    string   `json:"request_digest"`
	Decision         string   `json:"decision"`
	PolicyVersion    uint64   `json:"policy_version"`
	CacheState       string   `json:"cache_state"`
	MatchedPolicyIDs []string `json:"matched_policy_ids"`
	EvaluatedAt      string   `json:"evaluated_at"`
}

type gatewayStoredQuarantineAcknowledgment struct {
	Acknowledgment gatewayQuarantineAcknowledgment
	AcknowledgedAt time.Time
}

type gatewayQuarantineAcknowledgmentWire struct {
	ContractVersion int    `json:"contract_version"`
	EventID         string `json:"event_id"`
	RequestDigest   string `json:"request_digest"`
	ConfirmedFloor  uint64 `json:"confirmed_floor"`
	IncidentID      string `json:"incident_id"`
	AcknowledgedAt  string `json:"acknowledged_at"`
}

func validGatewayEvidenceState(state gatewayEvidenceState, expected gatewayAuthority, maximum int) bool {
	if !validGatewayEvidenceMetadataState(state, expected, maximum) || len(state.Receipts) != len(state.Pending)+len(state.Quarantined) {
		return false
	}
	receipts := make(map[string]gatewayEvaluationReceipt, len(state.Receipts))
	var previous gatewayEvaluationReceipt
	for index, receipt := range state.Receipts {
		if !validGatewayEvaluationReceipt(receipt) || receipt.EvaluatedAt.After(state.ObservedAt) || index > 0 && (receipt.EvaluatedAt.Before(previous.EvaluatedAt) || receipt.EvaluatedAt.Equal(previous.EvaluatedAt) && receipt.EventID <= previous.EventID) {
			return false
		}
		if _, exists := receipts[receipt.EventID]; exists {
			return false
		}
		receipts[receipt.EventID] = receipt
		previous = receipt
	}
	for _, event := range state.Pending {
		receipt, exists := receipts[event.EventID]
		if !exists || !gatewayReceiptMatchesEvent(receipt, event) {
			return false
		}
	}
	for _, quarantined := range state.Quarantined {
		receipt, exists := receipts[quarantined.Event.EventID]
		if !exists || !gatewayReceiptMatchesEvent(receipt, quarantined.Event) {
			return false
		}
	}
	return true
}

func validGatewayEvidenceMetadataState(state gatewayEvidenceState, expected gatewayAuthority, maximum int) bool {
	if !validGatewayAuthority(expected, expected.CredentialID) || maximum < 1 || maximum > 1024 || !validGatewayTime(state.ObservedAt) || len(state.Pending)+len(state.Quarantined) > maximum || !state.AuthorityConfirmed && (state.ConfirmedFloor != 0 || len(state.Quarantined) != 0) {
		return false
	}
	seen := make(map[string]struct{}, len(state.Pending)+len(state.Quarantined))
	for _, quarantined := range state.Quarantined {
		event := quarantined.Event
		if !validGatewayEvidenceEvent(event, expected) || event.OccurredAt.After(state.ObservedAt) || event.ExpectedFloor == ^uint64(0) || event.NextFloor != event.ExpectedFloor+1 || quarantined.Reason != gatewayEvidenceExpiredReason || !validGatewayTime(quarantined.QuarantinedAt) || quarantined.QuarantinedAt.After(state.ObservedAt) || !quarantined.QuarantinedAt.After(event.OccurredAt) {
			return false
		}
		if _, exists := seen[event.EventID]; exists {
			return false
		}
		seen[event.EventID] = struct{}{}
	}
	next := state.ConfirmedFloor
	for _, event := range state.Pending {
		if !validGatewayEvidenceEvent(event, expected) || event.OccurredAt.After(state.ObservedAt) {
			return false
		}
		if _, exists := seen[event.EventID]; exists {
			return false
		}
		seen[event.EventID] = struct{}{}
		if state.AuthorityConfirmed {
			if next == ^uint64(0) || event.ExpectedFloor != next || event.NextFloor != next+1 {
				return false
			}
			next = event.NextFloor
		} else if event.ExpectedFloor != 0 || event.NextFloor != 0 {
			return false
		}
	}
	return true
}

func cloneGatewayEvidenceState(state gatewayEvidenceState) gatewayEvidenceState {
	result := gatewayEvidenceState{AuthorityConfirmed: state.AuthorityConfirmed, ConfirmedFloor: state.ConfirmedFloor, ObservedAt: state.ObservedAt, Pending: make([]gatewayDecisionEvent, len(state.Pending)), Quarantined: cloneGatewayQuarantinedDecisionEvents(state.Quarantined), Receipts: cloneGatewayEvaluationReceipts(state.Receipts)}
	for index, event := range state.Pending {
		result.Pending[index] = cloneGatewayDecisionEvent(event)
	}
	return result
}

func emptyGatewayEvidenceState() gatewayEvidenceState {
	return gatewayEvidenceState{Pending: []gatewayDecisionEvent{}, Quarantined: []gatewayQuarantinedDecisionEvent{}, Receipts: []gatewayEvaluationReceipt{}}
}

func cloneGatewayEvaluationReceipts(receipts []gatewayEvaluationReceipt) []gatewayEvaluationReceipt {
	result := make([]gatewayEvaluationReceipt, len(receipts))
	for index, receipt := range receipts {
		result[index] = gatewayEvaluationReceipt{EventID: receipt.EventID, RequestDigest: receipt.RequestDigest, Result: cloneGatewayEvaluationResult(receipt.Result), EvaluatedAt: receipt.EvaluatedAt}
	}
	return result
}

func sortGatewayEvaluationReceipts(receipts []gatewayEvaluationReceipt) {
	sort.Slice(receipts, func(left, right int) bool {
		if receipts[left].EvaluatedAt.Equal(receipts[right].EvaluatedAt) {
			return receipts[left].EventID < receipts[right].EventID
		}
		return receipts[left].EvaluatedAt.Before(receipts[right].EvaluatedAt)
	})
}

func cloneGatewayQuarantinedDecisionEvents(events []gatewayQuarantinedDecisionEvent) []gatewayQuarantinedDecisionEvent {
	result := make([]gatewayQuarantinedDecisionEvent, len(events))
	for index, event := range events {
		result[index] = gatewayQuarantinedDecisionEvent{Event: cloneGatewayDecisionEvent(event.Event), Reason: event.Reason, QuarantinedAt: event.QuarantinedAt}
	}
	return result
}

func validGatewayEvidenceEvent(event gatewayDecisionEvent, expected gatewayAuthority) bool {
	return event.CredentialID == expected.CredentialID && event.DeviceID == expected.DeviceID && validGatewayProductID(event.EventID) && event.PolicyVersion > 0 &&
		(event.Decision == "allow" || event.Decision == "monitor" || event.Decision == "block") && (event.ActionKind == "http" || event.ActionKind == "mcp") && validGatewayClassification(event.Classification) && validGatewayTime(event.OccurredAt)
}

func validGatewayEvaluationReceipt(receipt gatewayEvaluationReceipt) bool {
	return validGatewayProductID(receipt.EventID) && validGatewayEvaluationResult(receipt.Result) && validGatewayTime(receipt.EvaluatedAt)
}

func validGatewayEvaluationResult(result gatewayEvaluationResult) bool {
	if result.PolicyVersion == 0 || result.MatchedPolicyIDs == nil || result.Decision != "allow" && result.Decision != "monitor" && result.Decision != "block" || result.CacheState != policy.GatewayPolicyValid && result.CacheState != policy.GatewayPolicyExpiredOpen && result.CacheState != policy.GatewayPolicyExpiredClosed || len(result.MatchedPolicyIDs) > 512 {
		return false
	}
	for index, policyID := range result.MatchedPolicyIDs {
		if !boundedGatewayText(policyID, 128) || index > 0 && result.MatchedPolicyIDs[index-1] >= policyID {
			return false
		}
	}
	switch result.CacheState {
	case policy.GatewayPolicyExpiredOpen:
		return result.Decision == "allow" && len(result.MatchedPolicyIDs) == 0
	case policy.GatewayPolicyExpiredClosed:
		return result.Decision == "block" && len(result.MatchedPolicyIDs) == 0
	default:
		return result.Decision == "allow" && len(result.MatchedPolicyIDs) == 0 || result.Decision != "allow" && len(result.MatchedPolicyIDs) > 0
	}
}

func gatewayReceiptMatchesEvent(receipt gatewayEvaluationReceipt, event gatewayDecisionEvent) bool {
	return receipt.EventID == event.EventID && receipt.Result.PolicyVersion == event.PolicyVersion && receipt.Result.Decision == event.Decision && receipt.EvaluatedAt.Equal(event.OccurredAt)
}

func gatewayEvaluationReceiptToWire(receipt gatewayEvaluationReceipt) gatewayEvaluationWire {
	result := cloneGatewayEvaluationResult(receipt.Result)
	return gatewayEvaluationWire{EventID: receipt.EventID, RequestDigest: hex.EncodeToString(receipt.RequestDigest[:]), Decision: result.Decision, PolicyVersion: result.PolicyVersion, CacheState: result.CacheState, MatchedPolicyIDs: result.MatchedPolicyIDs, EvaluatedAt: receipt.EvaluatedAt.Format("2006-01-02T15:04:05Z")}
}

func gatewayEvaluationReceiptFromWire(receipt gatewayEvaluationWire) (gatewayEvaluationReceipt, error) {
	digest, err := hex.DecodeString(receipt.RequestDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != receipt.RequestDigest {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	evaluatedAt, err := time.Parse("2006-01-02T15:04:05Z", receipt.EvaluatedAt)
	if err != nil {
		return gatewayEvaluationReceipt{}, errGatewayRuntime
	}
	var requestDigest [sha256.Size]byte
	copy(requestDigest[:], digest)
	result := cloneGatewayEvaluationResult(gatewayEvaluationResult{Decision: receipt.Decision, PolicyVersion: receipt.PolicyVersion, CacheState: receipt.CacheState, MatchedPolicyIDs: receipt.MatchedPolicyIDs})
	return gatewayEvaluationReceipt{EventID: receipt.EventID, RequestDigest: requestDigest, Result: result, EvaluatedAt: evaluatedAt}, nil
}

func gatewayDecisionEventToWire(event gatewayDecisionEvent) gatewayDecisionEventWire {
	return gatewayDecisionEventWire{CredentialID: event.CredentialID, DeviceID: event.DeviceID, EventID: event.EventID, ExpectedFloor: event.ExpectedFloor, NextFloor: event.NextFloor, PolicyVersion: event.PolicyVersion, Decision: event.Decision, ActionKind: event.ActionKind, Classification: cloneGatewayStrings(event.Classification), OccurredAt: event.OccurredAt.Format("2006-01-02T15:04:05Z")}
}

func gatewayDecisionEventFromWire(event gatewayDecisionEventWire) (gatewayDecisionEvent, error) {
	occurredAt, err := time.Parse("2006-01-02T15:04:05Z", event.OccurredAt)
	if err != nil {
		return gatewayDecisionEvent{}, errGatewayRuntime
	}
	return gatewayDecisionEvent{CredentialID: event.CredentialID, DeviceID: event.DeviceID, EventID: event.EventID, ExpectedFloor: event.ExpectedFloor, NextFloor: event.NextFloor, PolicyVersion: event.PolicyVersion, Decision: event.Decision, ActionKind: event.ActionKind, Classification: cloneGatewayStrings(event.Classification), OccurredAt: occurredAt}, nil
}

func sameGatewayDecisionEvent(left, right gatewayDecisionEvent) bool {
	if left.CredentialID != right.CredentialID || left.DeviceID != right.DeviceID || left.EventID != right.EventID || left.ExpectedFloor != right.ExpectedFloor || left.NextFloor != right.NextFloor || left.PolicyVersion != right.PolicyVersion || left.Decision != right.Decision || left.ActionKind != right.ActionKind || !left.OccurredAt.Equal(right.OccurredAt) || len(left.Classification) != len(right.Classification) {
		return false
	}
	for key, value := range left.Classification {
		if right.Classification[key] != value {
			return false
		}
	}
	return true
}

func gatewayEvidenceActiveEventIDs(state gatewayEvidenceState) []string {
	ids := make([]string, 0, len(state.Pending)+len(state.Quarantined))
	for _, event := range state.Pending {
		ids = append(ids, event.EventID)
	}
	for _, quarantined := range state.Quarantined {
		ids = append(ids, quarantined.Event.EventID)
	}
	sort.Strings(ids)
	return ids
}

func gatewayEvidenceEventActive(state gatewayEvidenceState, eventID string) bool {
	for _, event := range state.Pending {
		if event.EventID == eventID {
			return true
		}
	}
	for _, quarantined := range state.Quarantined {
		if quarantined.Event.EventID == eventID {
			return true
		}
	}
	return false
}

func gatewayEvidenceReceiptKey(eventID string) []byte {
	return append(append([]byte{}, gatewayEvidenceReceiptRoot...), eventID...)
}

func gatewayEvidenceAckKey(eventID string) []byte {
	return append(append([]byte{}, gatewayEvidenceAckRoot...), eventID...)
}

func gatewayEvidenceExpiryKey(receipt gatewayEvaluationReceipt) []byte {
	expires := receipt.EvaluatedAt.Add(gatewayEvidenceRecordWindow).Unix()
	return []byte(fmt.Sprintf("expiry/%020d/%s", expires, receipt.EventID))
}

func parseGatewayEvidenceExpiryKey(key []byte) (time.Time, string, bool) {
	value := string(key)
	if len(value) <= len("expiry/")+20+1 || !strings.HasPrefix(value, "expiry/") || value[len("expiry/")+20] != '/' {
		return time.Time{}, "", false
	}
	seconds, err := strconv.ParseInt(value[len("expiry/"):len("expiry/")+20], 10, 64)
	eventID := value[len("expiry/")+21:]
	if err != nil || seconds < 0 || !validGatewayProductID(eventID) {
		return time.Time{}, "", false
	}
	expires := time.Unix(seconds, 0).UTC()
	return expires, eventID, validGatewayTime(expires)
}

func gatewayEvidenceReceiptLogicalBytes(receiptKey, expiryKey, raw []byte) uint64 {
	return uint64(len(receiptKey) + len(expiryKey) + len(raw))
}

func validGatewayQuarantineAcknowledgment(acknowledgment gatewayQuarantineAcknowledgment) bool {
	return validGatewayProductID(acknowledgment.EventID) && validGatewayProductID(acknowledgment.IncidentID)
}

func sameGatewayQuarantineAcknowledgment(left, right gatewayQuarantineAcknowledgment) bool {
	return left.EventID == right.EventID && left.RequestDigest == right.RequestDigest && left.ConfirmedFloor == right.ConfirmedFloor && left.IncidentID == right.IncidentID
}

func marshalGatewayQuarantineAcknowledgment(value gatewayStoredQuarantineAcknowledgment) ([]byte, error) {
	if !validGatewayQuarantineAcknowledgment(value.Acknowledgment) || !validGatewayTime(value.AcknowledgedAt) {
		return nil, errGatewayRuntime
	}
	raw, err := json.Marshal(gatewayQuarantineAcknowledgmentWire{
		ContractVersion: 1,
		EventID:         value.Acknowledgment.EventID,
		RequestDigest:   hex.EncodeToString(value.Acknowledgment.RequestDigest[:]),
		ConfirmedFloor:  value.Acknowledgment.ConfirmedFloor,
		IncidentID:      value.Acknowledgment.IncidentID,
		AcknowledgedAt:  value.AcknowledgedAt.Format("2006-01-02T15:04:05Z"),
	})
	if err != nil || len(raw) < 2 || len(raw) > maximumGatewayEvidenceAckBytes {
		return nil, errGatewayRuntime
	}
	return raw, nil
}

func decodeGatewayQuarantineAcknowledgment(raw []byte) (gatewayStoredQuarantineAcknowledgment, error) {
	if len(raw) < 2 || len(raw) > maximumGatewayEvidenceAckBytes {
		return gatewayStoredQuarantineAcknowledgment{}, errGatewayRuntime
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire gatewayQuarantineAcknowledgmentWire
	if decoder.Decode(&wire) != nil {
		return gatewayStoredQuarantineAcknowledgment{}, errGatewayRuntime
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || wire.ContractVersion != 1 {
		return gatewayStoredQuarantineAcknowledgment{}, errGatewayRuntime
	}
	digest, err := hex.DecodeString(wire.RequestDigest)
	acknowledgedAt, timeErr := time.Parse("2006-01-02T15:04:05Z", wire.AcknowledgedAt)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != wire.RequestDigest || timeErr != nil {
		return gatewayStoredQuarantineAcknowledgment{}, errGatewayRuntime
	}
	var requestDigest [sha256.Size]byte
	copy(requestDigest[:], digest)
	value := gatewayStoredQuarantineAcknowledgment{
		Acknowledgment: gatewayQuarantineAcknowledgment{EventID: wire.EventID, RequestDigest: requestDigest, ConfirmedFloor: wire.ConfirmedFloor, IncidentID: wire.IncidentID},
		AcknowledgedAt: acknowledgedAt,
	}
	if !validGatewayQuarantineAcknowledgment(value.Acknowledgment) || !validGatewayTime(value.AcknowledgedAt) {
		return gatewayStoredQuarantineAcknowledgment{}, errGatewayRuntime
	}
	canonical, err := marshalGatewayQuarantineAcknowledgment(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return gatewayStoredQuarantineAcknowledgment{}, errGatewayRuntime
	}
	return value, nil
}

func sameGatewayEvidenceMetadataState(left, right gatewayEvidenceState, expected gatewayAuthority, maximum int, usage gatewayEvidenceUsage) bool {
	leftRaw, leftErr := marshalGatewayEvidenceMetadata(left, expected, maximum, usage)
	rightRaw, rightErr := marshalGatewayEvidenceMetadata(right, expected, maximum, usage)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func sameGatewayEvidenceState(left, right gatewayEvidenceState, expected gatewayAuthority, maximum int) bool {
	usage := gatewayEvidenceUsage{MaximumBytes: 1 << 20}
	if !sameGatewayEvidenceMetadataState(left, right, expected, maximum, usage) || len(left.Receipts) != len(right.Receipts) {
		return false
	}
	leftReceipts := cloneGatewayEvaluationReceipts(left.Receipts)
	rightReceipts := cloneGatewayEvaluationReceipts(right.Receipts)
	sortGatewayEvaluationReceipts(leftReceipts)
	sortGatewayEvaluationReceipts(rightReceipts)
	for index := range leftReceipts {
		leftRaw, leftErr := marshalGatewayEvaluationReceipt(leftReceipts[index])
		rightRaw, rightErr := marshalGatewayEvaluationReceipt(rightReceipts[index])
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftRaw, rightRaw) {
			return false
		}
	}
	return true
}

func canonicalGatewayEvaluationReceipt(raw []byte) (gatewayEvaluationReceipt, error) {
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
	return gatewayEvaluationReceiptFromWire(wire)
}
