package redteamadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"slices"
)

// InvocationJournal must durably commit Start before returning. Its production
// implementation must enforce full scoped admission, not only persistence.
// Start may return "started" only for a new reservation committed by this call;
// an existing unresolved start must fail, including after a lost acknowledgement.
// Terminal replay must match scope, run, attempt, lease and request association.
// TargetBinding must come from the stored journal resolution, never from echoing
// the caller's request or resolving a replacement target during replay.
// This coordinator is not registered on an HTTP route until that authority ships.
type InvocationJournal interface {
	Start(context.Context, JournalRequest) (InvocationReceipt, error)
	Complete(context.Context, JournalRequest, int, InvocationObservation) error
}

type JournalRequest struct {
	Invocation    Invocation
	LeaseToken    string
	EffectKey     string
	RequestDigest string
}

type InvocationReceipt struct {
	TargetComparison json.RawMessage
	TargetBinding    TargetBinding
	State            string
	Attempt          int
	RequestDigest    string
	EffectKey        string
	Observation      *InvocationObservation
}

// InvokeJournaled returns structured evidence only. It never fabricates raw
// provider output when replaying a redacted terminal receipt.
func (invoker *HTTPSInvoker) InvokeJournaled(ctx context.Context, request JournalRequest, journal InvocationJournal) (InvocationObservation, error) {
	invocation := request.Invocation
	_, runErr := domain.ParseProductID(invocation.RunID)
	if invoker == nil || invoker.client == nil || invoker.credentials == nil || ctx == nil || ctx.Err() != nil || journal == nil || runErr != nil || invocation.Scope.Validate() != nil || !validJournalAuthority(request.LeaseToken, request.EffectKey) || !validBinding(invocation.Binding) || invocation.RunID == invocation.Binding.TargetID || !validRequestBody(requestBody{TargetID: invocation.Binding.TargetID, TargetKind: invocation.Binding.TargetKind, Category: invocation.Category, Input: invocation.Input}) {
		return InvocationObservation{}, ErrAdapter
	}
	payload, err := targetPayload(invocation)
	if err != nil {
		return InvocationObservation{}, ErrAdapter
	}
	digest := sha256.Sum256(payload)
	expected := hex.EncodeToString(digest[:])
	if request.RequestDigest != "" && request.RequestDigest != expected {
		return InvocationObservation{}, ErrAdapter
	}
	request.RequestDigest = expected
	receipt, err := journal.Start(ctx, request)
	if err != nil || receipt.Attempt < 1 || receipt.Attempt > 5 || receipt.RequestDigest != expected || receipt.TargetBinding != invocation.Binding || receipt.EffectKey != request.EffectKey {
		return InvocationObservation{}, ErrAdapter
	}
	comparisonBytes, err := decodeTargetComparison(receipt.TargetComparison, request)
	if err != nil {
		return InvocationObservation{}, ErrAdapter
	}
	var comparison TargetComparison
	if json.Unmarshal(comparisonBytes, &comparison) != nil {
		return InvocationObservation{}, ErrAdapter
	}
	if receipt.State == "completed" {
		if receipt.Observation == nil || !validInvocationObservation(*receipt.Observation) {
			return InvocationObservation{}, ErrAdapter
		}
		replayedComparison, err := json.Marshal(receipt.Observation.TargetComparison)
		if err != nil || !bytes.Equal(replayedComparison, comparisonBytes) {
			return InvocationObservation{}, ErrAdapter
		}
		return copyInvocationObservation(*receipt.Observation), nil
	}
	if receipt.State != "started" || receipt.Observation != nil || ctx.Err() != nil {
		return InvocationObservation{}, ErrAdapter
	}
	_, observation, err := invoker.InvokeObserved(ctx, invocation)
	if err != nil || !validInvocationObservation(observation) {
		return InvocationObservation{}, ErrAdapter
	}
	observation.TargetComparison = &comparison
	if journal.Complete(ctx, request, receipt.Attempt, copyInvocationObservation(observation)) != nil {
		return InvocationObservation{}, ErrAdapter
	}
	return observation, nil
}

func ValidEffectKey(key string) bool {
	return releaseDigestPattern.MatchString(key) && key != "0000000000000000000000000000000000000000000000000000000000000000"
}

func validJournalAuthority(lease, effect string) bool {
	return lease == "" && ValidEffectKey(effect) || effect == "" && runLeaseRE.MatchString(lease)
}

func targetPayload(invocation Invocation) ([]byte, error) {
	return json.Marshal(targetWireRequest{SchemaVersion: "red-team-target-v1", RunID: invocation.RunID, TargetID: invocation.Binding.TargetID, TargetKind: invocation.Binding.TargetKind, Category: invocation.Category, Input: invocation.Input})
}

func validInvocationObservation(value InvocationObservation) bool {
	return value.HTTPStatus == 200 && releaseDigestPattern.MatchString(value.ResponseDigest) && value.Protected != nil
}

func copyInvocationObservation(value InvocationObservation) InvocationObservation {
	protected := *value.Protected
	value.Protected = &protected
	if value.TargetComparison != nil {
		comparison := *value.TargetComparison
		comparison.Categories = slices.Clone(comparison.Categories)
		value.TargetComparison = &comparison
	}
	return value
}
