package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

var (
	errGatewayRuntime       = errors.New("gateway runtime unavailable")
	errGatewayRecordExpired = errors.New("gateway record expired")
)

var gatewayClassificationValuePattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,63}$`)

const (
	gatewayPolicyAudience       = "runtime-gateway-policy"
	gatewayEvidenceRecordWindow = 24 * time.Hour
	gatewayEvidenceRecordMargin = time.Minute
	gatewayEvidenceMaximumAge   = gatewayEvidenceRecordWindow - gatewayEvidenceRecordMargin
	gatewayEvidenceClockPersist = 30 * time.Second
)

type gatewayAuthority struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	DeviceID       string
	CredentialID   string
	ReplayFloor    uint64
}

func (authority gatewayAuthority) Binding() policy.GatewayPolicyBinding {
	return policy.GatewayPolicyBinding{
		OrganizationID: authority.OrganizationID,
		WorkspaceID:    authority.WorkspaceID,
		EnvironmentID:  authority.EnvironmentID,
		DeviceID:       authority.DeviceID,
	}
}

type gatewayDecisionEvent struct {
	CredentialID   string
	DeviceID       string
	EventID        string
	ExpectedFloor  uint64
	NextFloor      uint64
	PolicyVersion  uint64
	Decision       string
	ActionKind     string
	Classification map[string]string
	OccurredAt     time.Time
}

type gatewayControlPlane interface {
	Ready(context.Context) error
	Authority(context.Context, string) (gatewayAuthority, error)
	Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error)
	Record(context.Context, gatewayDecisionEvent) error
}

type gatewayRuntimeConfig struct {
	Control              gatewayControlPlane
	Cache                *policy.GatewayPolicyCache
	Evidence             gatewayEvidenceStore
	ExpectedAuthority    gatewayAuthority
	CredentialID         string
	BootstrapFailureMode string
	MaximumPendingEvents int
	Now                  func() time.Time
}

type gatewayEvaluationRequest struct {
	EventID        string            `json:"event_id"`
	ActionKind     string            `json:"action_kind"`
	Attributes     map[string]string `json:"attributes"`
	Classification map[string]string `json:"classification"`
}

type gatewayEvaluationResult struct {
	Decision         string   `json:"decision"`
	PolicyVersion    uint64   `json:"policy_version"`
	CacheState       string   `json:"cache_state"`
	MatchedPolicyIDs []string `json:"matched_policy_ids"`
}

type gatewayQuarantineAcknowledgment struct {
	EventID        string
	RequestDigest  [sha256.Size]byte
	ConfirmedFloor uint64
	IncidentID     string
}

type gatewayRuntime struct {
	mu sync.Mutex

	control              gatewayControlPlane
	cache                *policy.GatewayPolicyCache
	evidence             gatewayEvidenceStore
	credentialID         string
	bootstrapFailureMode string
	maximumPendingEvents int
	now                  func() time.Time

	authority          gatewayAuthority
	authorityConfirmed bool
	evidenceHealthy    bool
	policySequence     uint64
	confirmedFloor     uint64
	nextFloor          uint64
	observedAt         time.Time
	pending            []gatewayDecisionEvent
	quarantined        []gatewayQuarantinedDecisionEvent
	receipts           []gatewayEvaluationReceipt
	evidenceUsage      gatewayEvidenceUsage
}

func newGatewayRuntime(config gatewayRuntimeConfig) (*gatewayRuntime, error) {
	if config.Control == nil || config.Cache == nil || !validGatewayProductID(config.CredentialID) ||
		config.BootstrapFailureMode != "open" && config.BootstrapFailureMode != "closed" ||
		config.MaximumPendingEvents < 1 || config.MaximumPendingEvents > 1024 || config.Now == nil {
		return nil, errGatewayRuntime
	}
	now := config.Now()
	if !validGatewayTime(now) {
		return nil, errGatewayRuntime
	}
	runtime := &gatewayRuntime{
		control:              config.Control,
		cache:                config.Cache,
		evidence:             config.Evidence,
		credentialID:         config.CredentialID,
		bootstrapFailureMode: config.BootstrapFailureMode,
		maximumPendingEvents: config.MaximumPendingEvents,
		now:                  config.Now,
		evidenceHealthy:      true,
		observedAt:           now,
		pending:              make([]gatewayDecisionEvent, 0, config.MaximumPendingEvents),
		receipts:             make([]gatewayEvaluationReceipt, 0, config.MaximumPendingEvents),
	}
	if config.Evidence == nil {
		return runtime, nil
	}
	if !validGatewayAuthority(config.ExpectedAuthority, config.CredentialID) {
		return nil, errGatewayRuntime
	}
	state, err := config.Evidence.Load()
	if err != nil {
		return nil, errGatewayRuntime
	}
	needsStore := false
	if state.ObservedAt.IsZero() {
		if state.AuthorityConfirmed || state.ConfirmedFloor != 0 || len(state.Pending) != 0 || len(state.Quarantined) != 0 || len(state.Receipts) != 0 {
			return nil, errGatewayRuntime
		}
		state.ObservedAt = now
		needsStore = true
	} else if !validGatewayEvidenceState(state, config.ExpectedAuthority, config.MaximumPendingEvents) {
		return nil, errGatewayRuntime
	}
	if now.After(state.ObservedAt) {
		state.ObservedAt = now
		needsStore = true
	}
	if needsStore && !storeGatewayEvidenceExact(config.Evidence, state, config.ExpectedAuthority, config.MaximumPendingEvents) {
		return nil, errGatewayRuntime
	}
	runtime.authority = config.ExpectedAuthority
	runtime.authorityConfirmed = state.AuthorityConfirmed
	runtime.confirmedFloor = state.ConfirmedFloor
	runtime.nextFloor = state.ConfirmedFloor
	runtime.observedAt = state.ObservedAt
	runtime.pending = make([]gatewayDecisionEvent, len(state.Pending), config.MaximumPendingEvents)
	for index, event := range state.Pending {
		runtime.pending[index] = cloneGatewayDecisionEvent(event)
		if state.AuthorityConfirmed {
			runtime.nextFloor = event.NextFloor
		}
	}
	runtime.quarantined = cloneGatewayQuarantinedDecisionEvents(state.Quarantined)
	runtime.receipts = cloneGatewayEvaluationReceipts(state.Receipts)
	return runtime, nil
}

func (runtime *gatewayRuntime) SyncOnce(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errGatewayRuntime
		}
	}()
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	if _, ok := runtime.gatewayTimeLocked(); !ok {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	runtime.mu.Unlock()
	if err := runtime.control.Ready(ctx); err != nil {
		return errGatewayRuntime
	}
	authority, err := runtime.control.Authority(ctx, runtime.credentialID)
	if err != nil || !validGatewayAuthority(authority, runtime.credentialID) {
		return errGatewayRuntime
	}

	runtime.mu.Lock()
	if runtime.authority.CredentialID != "" && !sameGatewayAuthority(runtime.authority, authority) {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	if runtime.authorityConfirmed && (authority.ReplayFloor < runtime.confirmedFloor || len(runtime.pending) > 0 && authority.ReplayFloor != runtime.confirmedFloor) {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	afterSequence := runtime.policySequence
	runtime.mu.Unlock()

	envelope, err := runtime.control.Policy(ctx, runtime.credentialID, afterSequence)
	if err != nil {
		return errGatewayRuntime
	}
	if envelope != nil {
		if envelope.Audience != gatewayPolicyAudience || envelope.Sequence <= afterSequence || runtime.cache.Store(*envelope) != nil {
			return errGatewayRuntime
		}
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	observedAt, ok := runtime.gatewayTimeLocked()
	if !ok {
		return errGatewayRuntime
	}
	if runtime.authority.CredentialID != "" && !sameGatewayAuthority(runtime.authority, authority) {
		return errGatewayRuntime
	}
	if runtime.authorityConfirmed && (authority.ReplayFloor < runtime.confirmedFloor || len(runtime.pending) > 0 && authority.ReplayFloor != runtime.confirmedFloor) {
		return errGatewayRuntime
	}
	pending := make([]gatewayDecisionEvent, len(runtime.pending))
	for index, event := range runtime.pending {
		pending[index] = cloneGatewayDecisionEvent(event)
	}
	nextFloor := authority.ReplayFloor
	if runtime.authorityConfirmed {
		if len(pending) > 0 {
			nextFloor = pending[len(pending)-1].NextFloor
		}
	} else {
		for index := range pending {
			if nextFloor == ^uint64(0) {
				return errGatewayRuntime
			}
			pending[index].ExpectedFloor = nextFloor
			pending[index].NextFloor = nextFloor + 1
			nextFloor++
		}
	}
	if runtime.storeEvidenceLocked(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: authority.ReplayFloor, ObservedAt: observedAt, Pending: pending, Quarantined: runtime.quarantined, Receipts: runtime.receipts}) != nil {
		return errGatewayRuntime
	}
	runtime.authority = authority
	runtime.authorityConfirmed = true
	runtime.confirmedFloor = authority.ReplayFloor
	runtime.nextFloor = nextFloor
	runtime.pending = pending
	if envelope != nil {
		runtime.policySequence = envelope.Sequence
	}
	return nil
}

func (runtime *gatewayRuntime) Evaluate(ctx context.Context, request gatewayEvaluationRequest) (gatewayEvaluationResult, error) {
	if runtime == nil || ctx == nil || ctx.Err() != nil || !validGatewayEvaluationRequest(request) {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	requestDigest, err := gatewayEvaluationRequestDigest(request)
	if err != nil {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	runtime.mu.Lock()
	now, ok := runtime.gatewayTimeLocked()
	if !ok {
		runtime.mu.Unlock()
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	if result, found, exact, replayErr := runtime.evaluationReplayLocked(request.EventID, requestDigest, now); replayErr != nil {
		runtime.mu.Unlock()
		return gatewayEvaluationResult{}, errGatewayRuntime
	} else if found {
		runtime.mu.Unlock()
		if !exact {
			return gatewayEvaluationResult{}, errGatewayRuntime
		}
		return result, nil
	}
	runtime.mu.Unlock()

	envelope, state, cacheErr := runtime.cache.Current()
	result := gatewayEvaluationResult{Decision: "allow", MatchedPolicyIDs: []string{}}
	switch {
	case cacheErr != nil:
		result.Decision = gatewayFailureDecision(runtime.bootstrapFailureMode)
		result.CacheState = "unavailable_" + runtime.bootstrapFailureMode
	case state == policy.GatewayPolicyExpiredOpen:
		result.Decision = "allow"
		result.PolicyVersion = envelope.PolicyVersion
		result.CacheState = state
	case state == policy.GatewayPolicyExpiredClosed:
		result.Decision = "block"
		result.PolicyVersion = envelope.PolicyVersion
		result.CacheState = state
	case state == policy.GatewayPolicyValid:
		result.PolicyVersion = envelope.PolicyVersion
		result.CacheState = state
		trigger := gatewayTrigger(request.ActionKind)
		for _, compiled := range envelope.Policies {
			if compiled.Trigger != trigger {
				continue
			}
			decision, err := policy.Evaluate(ctx, compiled, request.Attributes)
			if err != nil {
				return gatewayEvaluationResult{}, errGatewayRuntime
			}
			if !decision.Matched {
				continue
			}
			result.MatchedPolicyIDs = append(result.MatchedPolicyIDs, compiled.ID)
			if decision.Action == policy.ActionBlock {
				result.Decision = "block"
			} else if result.Decision == "allow" {
				result.Decision = "monitor"
			}
		}
		sort.Strings(result.MatchedPolicyIDs)
	default:
		return gatewayEvaluationResult{}, errGatewayRuntime
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now, ok = runtime.gatewayTimeLocked()
	if !ok {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	if replayed, found, exact, replayErr := runtime.evaluationReplayLocked(request.EventID, requestDigest, now); replayErr != nil {
		return gatewayEvaluationResult{}, errGatewayRuntime
	} else if found {
		if !exact {
			return gatewayEvaluationResult{}, errGatewayRuntime
		}
		return replayed, nil
	}
	if runtime.authority.CredentialID == "" || result.PolicyVersion == 0 {
		return result, nil
	}
	if len(runtime.quarantined) > 0 || len(runtime.pending)+len(runtime.quarantined) >= runtime.maximumPendingEvents || runtime.nextFloor == ^uint64(0) {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	if len(runtime.pending) > 0 && gatewayEvidenceExpired(runtime.pending[0], now) {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	receipts := runtime.receiptsForStateLocked(now, runtime.pending, runtime.quarantined)
	expectedFloor, nextFloor := uint64(0), uint64(0)
	if runtime.authorityConfirmed {
		expectedFloor, nextFloor = runtime.nextFloor, runtime.nextFloor+1
	}
	event := gatewayDecisionEvent{
		CredentialID:   runtime.authority.CredentialID,
		DeviceID:       runtime.authority.DeviceID,
		EventID:        request.EventID,
		ExpectedFloor:  expectedFloor,
		NextFloor:      nextFloor,
		PolicyVersion:  result.PolicyVersion,
		Decision:       result.Decision,
		ActionKind:     request.ActionKind,
		Classification: cloneGatewayStrings(request.Classification),
		OccurredAt:     now,
	}
	pending := make([]gatewayDecisionEvent, len(runtime.pending), len(runtime.pending)+1)
	for index, current := range runtime.pending {
		pending[index] = cloneGatewayDecisionEvent(current)
	}
	pending = append(pending, cloneGatewayDecisionEvent(event))
	receipts = append(receipts, gatewayEvaluationReceipt{EventID: request.EventID, RequestDigest: requestDigest, Result: cloneGatewayEvaluationResult(result), EvaluatedAt: now})
	sortGatewayEvaluationReceipts(receipts)
	if runtime.storeEvidenceLocked(gatewayEvidenceState{AuthorityConfirmed: runtime.authorityConfirmed, ConfirmedFloor: runtime.confirmedFloor, ObservedAt: now, Pending: pending, Quarantined: runtime.quarantined, Receipts: receipts}) != nil {
		return gatewayEvaluationResult{}, errGatewayRuntime
	}
	if runtime.authorityConfirmed {
		runtime.nextFloor = event.NextFloor
	}
	runtime.pending = pending
	runtime.receipts = receipts
	return cloneGatewayEvaluationResult(result), nil
}

func (runtime *gatewayRuntime) RecordOnce(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errGatewayRuntime
		}
	}()
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	if len(runtime.pending) == 0 {
		runtime.mu.Unlock()
		return nil
	}
	if !runtime.authorityConfirmed {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	now, ok := runtime.gatewayTimeLocked()
	if !ok {
		runtime.mu.Unlock()
		return errGatewayRuntime
	}
	event := cloneGatewayDecisionEvent(runtime.pending[0])
	confirmedFloor := runtime.confirmedFloor
	authority := runtime.authority
	runtime.mu.Unlock()
	if err := runtime.control.Record(ctx, event); err != nil {
		if errors.Is(err, errGatewayRecordExpired) && gatewayEvidenceExpired(event, now) {
			return runtime.quarantineExpiredEvidence(ctx, event, authority, confirmedFloor, now)
		}
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	observedAt, ok := runtime.gatewayTimeLocked()
	if !ok {
		return errGatewayRuntime
	}
	if len(runtime.pending) == 0 || runtime.pending[0].EventID != event.EventID || runtime.pending[0].NextFloor != event.NextFloor {
		return errGatewayRuntime
	}
	pending := make([]gatewayDecisionEvent, len(runtime.pending)-1)
	for index, current := range runtime.pending[1:] {
		pending[index] = cloneGatewayDecisionEvent(current)
	}
	receipts := runtime.receiptsForStateLocked(observedAt, pending, runtime.quarantined)
	if runtime.storeEvidenceLocked(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: event.NextFloor, ObservedAt: observedAt, Pending: pending, Quarantined: runtime.quarantined, Receipts: receipts}) != nil {
		return errGatewayRuntime
	}
	runtime.pending = pending
	runtime.confirmedFloor = event.NextFloor
	runtime.receipts = receipts
	return nil
}

func (runtime *gatewayRuntime) Run(ctx context.Context, syncInterval, recordInterval time.Duration) error {
	if runtime == nil || ctx == nil || ctx.Err() != nil || syncInterval < time.Millisecond || syncInterval > 5*time.Minute || recordInterval < time.Millisecond || recordInterval > time.Second {
		return errGatewayRuntime
	}
	syncTicker := time.NewTicker(syncInterval)
	recordTicker := time.NewTicker(recordInterval)
	defer syncTicker.Stop()
	defer recordTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-syncTicker.C:
			_ = runtime.SyncOnce(ctx)
		case <-recordTicker.C:
			_ = runtime.RecordOnce(ctx)
		}
	}
}

func (runtime *gatewayRuntime) Ready(ctx context.Context) error {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now, ok := runtime.gatewayTimeLocked()
	if !ok {
		return errGatewayRuntime
	}
	if runtime.evidence != nil {
		usage, err := runtime.evidence.Maintain(now)
		if err != nil {
			runtime.evidenceHealthy = false
			return errGatewayRuntime
		}
		runtime.evidenceHealthy = true
		runtime.evidenceUsage = usage
		if usage.MaximumBytes == 0 || usage.ReceiptBytes >= usage.MaximumBytes || usage.MaximumDatabaseBytes == 0 || usage.DatabaseBytes >= usage.MaximumDatabaseBytes {
			return errGatewayRuntime
		}
	}
	if len(runtime.quarantined) > 0 || len(runtime.pending)+len(runtime.quarantined) >= runtime.maximumPendingEvents || len(runtime.pending) > 0 && gatewayEvidenceExpired(runtime.pending[0], now) {
		return errGatewayRuntime
	}
	if !runtime.evidenceHealthy || now.Sub(runtime.observedAt) >= gatewayEvidenceClockPersist {
		receipts := runtime.receiptsForStateLocked(now, runtime.pending, runtime.quarantined)
		if runtime.storeEvidenceLocked(gatewayEvidenceState{AuthorityConfirmed: runtime.authorityConfirmed, ConfirmedFloor: runtime.confirmedFloor, ObservedAt: now, Pending: runtime.pending, Quarantined: runtime.quarantined, Receipts: receipts}) != nil {
			return errGatewayRuntime
		}
		runtime.receipts = receipts
	}
	return nil
}

func (runtime *gatewayRuntime) Metrics() string {
	if runtime == nil {
		return ""
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if now, ok := runtime.gatewayTimeLocked(); ok && runtime.evidence != nil {
		if usage, err := runtime.evidence.Maintain(now); err == nil {
			runtime.evidenceHealthy = true
			runtime.evidenceUsage = usage
		} else {
			runtime.evidenceHealthy = false
		}
	}
	usage := runtime.evidenceUsage
	utilization := float64(0)
	if usage.MaximumBytes > 0 {
		utilization = float64(usage.ReceiptBytes) / float64(usage.MaximumBytes)
	}
	physicalUtilization := float64(0)
	if usage.MaximumDatabaseBytes > 0 {
		physicalUtilization = float64(usage.DatabaseBytes) / float64(usage.MaximumDatabaseBytes)
	}
	var metrics strings.Builder
	metrics.WriteString("zasp_gateway_evidence_receipt_bytes ")
	metrics.WriteString(strconv.FormatUint(usage.ReceiptBytes, 10))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_receipt_capacity_bytes ")
	metrics.WriteString(strconv.FormatUint(usage.MaximumBytes, 10))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_receipt_utilization_ratio ")
	metrics.WriteString(strconv.FormatFloat(utilization, 'g', -1, 64))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_receipts ")
	metrics.WriteString(strconv.FormatUint(usage.ReceiptCount, 10))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_database_bytes ")
	metrics.WriteString(strconv.FormatUint(usage.DatabaseBytes, 10))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_database_capacity_bytes ")
	metrics.WriteString(strconv.FormatUint(usage.MaximumDatabaseBytes, 10))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_database_utilization_ratio ")
	metrics.WriteString(strconv.FormatFloat(physicalUtilization, 'g', -1, 64))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_pending ")
	metrics.WriteString(strconv.Itoa(len(runtime.pending)))
	metrics.WriteByte('\n')
	metrics.WriteString("zasp_gateway_evidence_quarantined ")
	metrics.WriteString(strconv.Itoa(len(runtime.quarantined)))
	metrics.WriteByte('\n')
	return metrics.String()
}

func (runtime *gatewayRuntime) AcknowledgeQuarantine(ctx context.Context, acknowledgment gatewayQuarantineAcknowledgment) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errGatewayRuntime
		}
	}()
	if runtime == nil || runtime.evidence == nil || ctx == nil || ctx.Err() != nil || !validGatewayQuarantineAcknowledgment(acknowledgment) {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	expectedAuthority := runtime.authority
	expectedFloor := runtime.confirmedFloor
	authorityConfirmed := runtime.authorityConfirmed
	runtime.mu.Unlock()
	if !authorityConfirmed || expectedFloor != acknowledgment.ConfirmedFloor || runtime.control.Ready(ctx) != nil {
		return errGatewayRuntime
	}
	authority, err := runtime.control.Authority(ctx, runtime.credentialID)
	if err != nil || !validGatewayAuthority(authority, runtime.credentialID) || !sameGatewayAuthority(authority, expectedAuthority) || authority.ReplayFloor != acknowledgment.ConfirmedFloor {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	observedAt, ok := runtime.gatewayTimeLocked()
	if !ok || !runtime.authorityConfirmed || runtime.confirmedFloor != acknowledgment.ConfirmedFloor || !sameGatewayAuthority(runtime.authority, authority) {
		return errGatewayRuntime
	}
	quarantineIndex := -1
	for index, quarantined := range runtime.quarantined {
		if quarantined.Event.EventID == acknowledgment.EventID {
			quarantineIndex = index
			break
		}
	}
	quarantined := cloneGatewayQuarantinedDecisionEvents(runtime.quarantined)
	if quarantineIndex >= 0 {
		receiptFound := false
		for _, receipt := range runtime.receipts {
			if receipt.EventID == acknowledgment.EventID {
				if receipt.RequestDigest != acknowledgment.RequestDigest || !gatewayReceiptMatchesEvent(receipt, runtime.quarantined[quarantineIndex].Event) {
					return errGatewayRuntime
				}
				receiptFound = true
				break
			}
		}
		if !receiptFound {
			return errGatewayRuntime
		}
		quarantined = make([]gatewayQuarantinedDecisionEvent, 0, len(runtime.quarantined)-1)
		quarantined = append(quarantined, cloneGatewayQuarantinedDecisionEvents(runtime.quarantined[:quarantineIndex])...)
		quarantined = append(quarantined, cloneGatewayQuarantinedDecisionEvents(runtime.quarantined[quarantineIndex+1:])...)
	}
	receipts := runtime.receiptsForStateLocked(observedAt, runtime.pending, quarantined)
	target := gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: runtime.confirmedFloor, ObservedAt: observedAt, Pending: runtime.pending, Quarantined: quarantined, Receipts: receipts}
	replayed, err := runtime.evidence.Acknowledge(target, acknowledgment, observedAt)
	if err != nil || quarantineIndex >= 0 && replayed || quarantineIndex < 0 && !replayed {
		runtime.evidenceHealthy = false
		return errGatewayRuntime
	}
	runtime.evidenceHealthy = true
	runtime.observedAt = observedAt
	runtime.quarantined = quarantined
	runtime.receipts = receipts
	return nil
}

func (runtime *gatewayRuntime) quarantineExpiredEvidence(ctx context.Context, event gatewayDecisionEvent, expectedAuthority gatewayAuthority, expectedFloor uint64, quarantinedAt time.Time) error {
	if runtime.control.Ready(ctx) != nil {
		return errGatewayRuntime
	}
	authority, err := runtime.control.Authority(ctx, runtime.credentialID)
	if err != nil || !validGatewayAuthority(authority, runtime.credentialID) || !sameGatewayAuthority(authority, expectedAuthority) || authority.ReplayFloor != expectedFloor {
		return errGatewayRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	observedAt, ok := runtime.gatewayTimeLocked()
	if !ok {
		return errGatewayRuntime
	}
	if len(runtime.pending) == 0 || runtime.pending[0].EventID != event.EventID || runtime.pending[0].ExpectedFloor != event.ExpectedFloor || runtime.pending[0].NextFloor != event.NextFloor || runtime.confirmedFloor != expectedFloor || !sameGatewayAuthority(runtime.authority, authority) {
		return errGatewayRuntime
	}
	pending := make([]gatewayDecisionEvent, len(runtime.pending)-1)
	nextFloor := runtime.confirmedFloor
	for index, current := range runtime.pending[1:] {
		if nextFloor == ^uint64(0) {
			return errGatewayRuntime
		}
		pending[index] = cloneGatewayDecisionEvent(current)
		pending[index].ExpectedFloor = nextFloor
		pending[index].NextFloor = nextFloor + 1
		nextFloor++
	}
	quarantined := cloneGatewayQuarantinedDecisionEvents(runtime.quarantined)
	if observedAt.After(quarantinedAt) {
		quarantinedAt = observedAt
	}
	quarantined = append(quarantined, gatewayQuarantinedDecisionEvent{Event: cloneGatewayDecisionEvent(event), Reason: gatewayEvidenceExpiredReason, QuarantinedAt: quarantinedAt})
	receipts := runtime.receiptsForStateLocked(observedAt, pending, quarantined)
	if runtime.storeEvidenceLocked(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: runtime.confirmedFloor, ObservedAt: observedAt, Pending: pending, Quarantined: quarantined, Receipts: receipts}) != nil {
		return errGatewayRuntime
	}
	runtime.pending = pending
	runtime.quarantined = quarantined
	runtime.nextFloor = nextFloor
	runtime.receipts = receipts
	return nil
}

func gatewayEvidenceExpired(event gatewayDecisionEvent, now time.Time) bool {
	return !event.OccurredAt.After(now.Add(-gatewayEvidenceMaximumAge))
}

func (runtime *gatewayRuntime) storeEvidenceLocked(state gatewayEvidenceState) error {
	if !validGatewayTime(state.ObservedAt) || state.ObservedAt.Before(runtime.observedAt) {
		runtime.evidenceHealthy = false
		return errGatewayRuntime
	}
	if runtime.evidence == nil {
		runtime.evidenceHealthy = true
		runtime.observedAt = state.ObservedAt
		return nil
	}
	if !storeGatewayEvidenceExact(runtime.evidence, state, runtime.authority, runtime.maximumPendingEvents) {
		runtime.evidenceHealthy = false
		return errGatewayRuntime
	}
	runtime.evidenceHealthy = true
	runtime.observedAt = state.ObservedAt
	return nil
}

func storeGatewayEvidenceExact(store gatewayEvidenceStore, state gatewayEvidenceState, expected gatewayAuthority, maximum int) bool {
	if store == nil {
		return false
	}
	if store.Store(state) == nil {
		return true
	}
	persisted, err := store.Load()
	return err == nil && sameGatewayEvidenceState(persisted, state, expected, maximum)
}

func (runtime *gatewayRuntime) gatewayTimeLocked() (time.Time, bool) {
	if runtime == nil || runtime.now == nil {
		return time.Time{}, false
	}
	now := runtime.now()
	return now, validGatewayTime(now) && !now.Before(runtime.observedAt)
}

func gatewayEvaluationRequestDigest(request gatewayEvaluationRequest) ([sha256.Size]byte, error) {
	raw, err := json.Marshal(struct {
		EventID        string            `json:"event_id"`
		ActionKind     string            `json:"action_kind"`
		Attributes     map[string]string `json:"attributes"`
		Classification map[string]string `json:"classification"`
	}{EventID: request.EventID, ActionKind: request.ActionKind, Attributes: cloneGatewayStrings(request.Attributes), Classification: cloneGatewayStrings(request.Classification)})
	if err != nil {
		return [sha256.Size]byte{}, errGatewayRuntime
	}
	return sha256.Sum256(raw), nil
}

func (runtime *gatewayRuntime) evaluationReplayLocked(eventID string, requestDigest [sha256.Size]byte, now time.Time) (gatewayEvaluationResult, bool, bool, error) {
	for _, receipt := range runtime.receipts {
		if receipt.EventID == eventID {
			return cloneGatewayEvaluationResult(receipt.Result), true, receipt.RequestDigest == requestDigest, nil
		}
	}
	if runtime.evidence == nil {
		return gatewayEvaluationResult{}, false, false, nil
	}
	receipt, found, err := runtime.evidence.Receipt(eventID, now)
	if err != nil {
		runtime.evidenceHealthy = false
		return gatewayEvaluationResult{}, false, false, errGatewayRuntime
	}
	runtime.evidenceHealthy = true
	if !found {
		return gatewayEvaluationResult{}, false, false, nil
	}
	return cloneGatewayEvaluationResult(receipt.Result), true, receipt.RequestDigest == requestDigest, nil
}

func (runtime *gatewayRuntime) retainedEvaluationReceiptsLocked(now time.Time) []gatewayEvaluationReceipt {
	active := make(map[string]struct{}, len(runtime.pending)+len(runtime.quarantined))
	for _, event := range runtime.pending {
		active[event.EventID] = struct{}{}
	}
	for _, event := range runtime.quarantined {
		active[event.Event.EventID] = struct{}{}
	}
	retained := make([]gatewayEvaluationReceipt, 0, len(runtime.receipts))
	cutoff := now.Add(-gatewayEvidenceRecordWindow)
	for _, receipt := range runtime.receipts {
		_, isActive := active[receipt.EventID]
		if isActive || receipt.EvaluatedAt.After(cutoff) {
			retained = append(retained, gatewayEvaluationReceipt{EventID: receipt.EventID, RequestDigest: receipt.RequestDigest, Result: cloneGatewayEvaluationResult(receipt.Result), EvaluatedAt: receipt.EvaluatedAt})
		}
	}
	return retained
}

func (runtime *gatewayRuntime) receiptsForStateLocked(now time.Time, pending []gatewayDecisionEvent, quarantined []gatewayQuarantinedDecisionEvent) []gatewayEvaluationReceipt {
	if runtime.evidence == nil {
		return runtime.retainedEvaluationReceiptsLocked(now)
	}
	active := make(map[string]struct{}, len(pending)+len(quarantined))
	for _, event := range pending {
		active[event.EventID] = struct{}{}
	}
	for _, event := range quarantined {
		active[event.Event.EventID] = struct{}{}
	}
	receipts := make([]gatewayEvaluationReceipt, 0, len(active))
	for _, receipt := range runtime.receipts {
		if _, exists := active[receipt.EventID]; exists {
			receipts = append(receipts, gatewayEvaluationReceipt{EventID: receipt.EventID, RequestDigest: receipt.RequestDigest, Result: cloneGatewayEvaluationResult(receipt.Result), EvaluatedAt: receipt.EvaluatedAt})
		}
	}
	sortGatewayEvaluationReceipts(receipts)
	return receipts
}

func (runtime *gatewayRuntime) Drain(ctx context.Context) error {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	for {
		runtime.mu.Lock()
		remaining := len(runtime.pending)
		runtime.mu.Unlock()
		if remaining == 0 {
			return nil
		}
		if err := runtime.RecordOnce(ctx); err != nil {
			return errGatewayRuntime
		}
	}
}

func validGatewayAuthority(authority gatewayAuthority, credentialID string) bool {
	return validGatewayProductID(authority.OrganizationID) && validGatewayProductID(authority.WorkspaceID) &&
		validGatewayProductID(authority.EnvironmentID) && validGatewayProductID(authority.DeviceID) &&
		validGatewayProductID(authority.CredentialID) && authority.CredentialID == credentialID
}

func sameGatewayAuthority(left, right gatewayAuthority) bool {
	return left.OrganizationID == right.OrganizationID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.DeviceID == right.DeviceID &&
		left.CredentialID == right.CredentialID
}

func validGatewayEvaluationRequest(request gatewayEvaluationRequest) bool {
	if !validGatewayProductID(request.EventID) || request.ActionKind != "http" && request.ActionKind != "mcp" ||
		len(request.Attributes) < 1 || len(request.Attributes) > 8 || !validGatewayClassification(request.Classification) {
		return false
	}
	allowed := map[string]struct{}{"resource.class": {}, "principal.class": {}}
	if request.ActionKind == "http" {
		allowed["http.method"] = struct{}{}
		allowed["http.route_class"] = struct{}{}
		if request.Attributes["http.method"] == "" || request.Attributes["http.route_class"] == "" {
			return false
		}
	} else {
		allowed["tool.name"] = struct{}{}
		if request.Attributes["tool.name"] == "" {
			return false
		}
	}
	for key, value := range request.Attributes {
		if _, exists := allowed[key]; !exists || !boundedGatewayText(value, 256) {
			return false
		}
	}
	return true
}

func validGatewayClassification(classification map[string]string) bool {
	if len(classification) != 4 {
		return false
	}
	for _, key := range []string{"category", "route_class", "resource_class", "outcome"} {
		if !gatewayClassificationValuePattern.MatchString(classification[key]) {
			return false
		}
	}
	return true
}

func validGatewayProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func validGatewayTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func boundedGatewayText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func gatewayTrigger(actionKind string) string {
	if actionKind == "mcp" {
		return "tool_call"
	}
	return "http_request"
}

func gatewayFailureDecision(mode string) string {
	if mode == "open" {
		return "allow"
	}
	return "block"
}

func cloneGatewayStrings(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneGatewayEvaluationResult(value gatewayEvaluationResult) gatewayEvaluationResult {
	if value.MatchedPolicyIDs != nil {
		matched := make([]string, len(value.MatchedPolicyIDs))
		copy(matched, value.MatchedPolicyIDs)
		value.MatchedPolicyIDs = matched
	}
	return value
}

func cloneGatewayDecisionEvent(value gatewayDecisionEvent) gatewayDecisionEvent {
	value.Classification = cloneGatewayStrings(value.Classification)
	return value
}
