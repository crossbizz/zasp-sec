package apiserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type nativeConnectorContextKey struct{}
type nativeConnectorReservation struct {
	reference connectormaintenance.Reference
	lease     ConnectorEffectLease
	captured  json.RawMessage
}

type NativeConnectorRepository struct {
	executor     *connectormaintenance.Executor
	authority    *connectormaintenance.Authority
	mu           sync.Mutex
	reservations map[string]*nativeConnectorReservation
}

func NewNativeConnectorRepository(ctx context.Context, executor *connectormaintenance.Executor, authority *connectormaintenance.Authority) (*NativeConnectorRepository, error) {
	if ctx == nil || ctx.Err() != nil || executor == nil || authority == nil || executor.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &NativeConnectorRepository{executor: executor, authority: authority, reservations: map[string]*nativeConnectorReservation{}}, nil
}
func nativeConnectorKey(lease ConnectorEffectLease) string {
	raw, _ := json.Marshal([]string{lease.OrganizationID, lease.WorkspaceID, lease.EnvironmentID, lease.ID, lease.LeaseOwner, lease.LeaseToken})
	return string(raw)
}
func validNativeConnectorRepository(r *NativeConnectorRepository, ctx context.Context) bool {
	return r != nil && r.executor != nil && r.authority != nil && ctx != nil && ctx.Err() == nil
}
func connectorNativeLeaseEqual(a, b ConnectorEffectLease) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
func connectorNativeError(err error) error {
	if errors.Is(err, connectormaintenance.ErrDenied) {
		return ErrAuthorizationDenied
	}
	return ErrRepositoryUnavailable
}
func (r *NativeConnectorRepository) withLease(ctx context.Context, lease ConnectorEffectLease) context.Context {
	return context.WithValue(ctx, nativeConnectorContextKey{}, nativeConnectorKey(lease))
}
func (r *NativeConnectorRepository) reservation(key string) (nativeConnectorReservation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.reservations[key]
	if !ok {
		return nativeConnectorReservation{}, false
	}
	copy := *v
	copy.captured = append(json.RawMessage(nil), v.captured...)
	return copy, true
}
func (r *NativeConnectorRepository) RecoverExpiredFinalAttempts(ctx context.Context, owner string, seconds, limit int) (int, error) {
	if !validNativeConnectorRepository(r, ctx) || len(owner) < 3 || len(owner) > 128 || seconds < 5 || seconds > 300 || limit < 1 || limit > 100 {
		return 0, ErrRepositoryOperation
	}
	q, _ := json.Marshal(map[string]any{"owner": owner, "seconds": seconds, "limit": limit})
	raw, err := r.executor.Invoke(ctx, connectormaintenance.RecoverExpiredFinalAttempts, q, nil)
	if err != nil {
		return 0, connectorNativeError(err)
	}
	var result struct {
		Recovered *int `json:"recovered"`
	}
	if decodeStrictDiscovery(raw, &result) != nil || result.Recovered == nil || *result.Recovered < 0 || *result.Recovered > limit {
		return 0, ErrRepositoryUnavailable
	}
	return *result.Recovered, nil
}
func (r *NativeConnectorRepository) ClaimReconciliation(ctx context.Context, owner string, seconds, limit int) ([]ConnectorEffectLease, error) {
	if !validNativeConnectorRepository(r, ctx) || len(owner) < 3 || len(owner) > 128 || seconds < 5 || seconds > 300 || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	q, _ := json.Marshal(map[string]any{"owner": owner, "seconds": seconds, "limit": limit})
	raw, err := r.executor.Invoke(ctx, connectormaintenance.ReserveReconciliation, q, nil)
	if err != nil {
		return nil, connectorNativeError(err)
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if decodeStrictDiscovery(raw, &page) != nil || page.Items == nil || len(page.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	leases := make([]ConnectorEffectLease, 0, len(page.Items))
	pending := make(map[string]*nativeConnectorReservation, len(page.Items))
	for _, item := range page.Items {
		// Admission remains strict after removing this ONE separately bounded field.
		var object map[string]json.RawMessage
		if json.Unmarshal(item, &object) != nil {
			return nil, ErrRepositoryUnavailable
		}
		var intent string
		if json.Unmarshal(object["intent_digest"], &intent) != nil {
			return nil, ErrRepositoryUnavailable
		}
		delete(object, "intent_digest")
		remaining, _ := json.Marshal(object)
		var lease ConnectorEffectLease
		if decodeStrictDiscovery(remaining, &lease) != nil {
			return nil, ErrRepositoryUnavailable
		}
		check := lease
		check.Attempt++
		digest, err := hex.DecodeString(intent)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != intent || !validConnectorLease(check) || lease.Attempt < 0 || lease.Attempt >= 100 || lease.LeaseOwner != owner || lease.LeaseExpiresAt.After(time.Now().Add(time.Duration(seconds)*time.Second+time.Second)) || !stringIn(lease.Operation, "authorize", "revoke", "pkce_cleanup") {
			return nil, ErrRepositoryUnavailable
		}
		key := nativeConnectorKey(lease)
		if pending[key] != nil {
			return nil, ErrRepositoryUnavailable
		}
		ref := connectormaintenance.Reference{Organization: lease.OrganizationID, Workspace: lease.WorkspaceID, Environment: lease.EnvironmentID, Effect: lease.ID, Integration: lease.IntegrationID, Owner: lease.LeaseOwner, Token: lease.LeaseToken, IntentDigest: intent}
		pending[key] = &nativeConnectorReservation{reference: ref, lease: lease}
		leases = append(leases, lease)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, value := range r.reservations {
		if !value.lease.LeaseExpiresAt.After(time.Now()) {
			delete(r.reservations, key)
		}
	}
	for key, value := range pending {
		if previous := r.reservations[key]; previous != nil {
			return nil, ErrRepositoryUnavailable
		}
		r.reservations[key] = value
	}
	return leases, nil
}

// prepare begins only the actual first effect, after live authorization. A
// repeated forward call rechecks authority; compensation uses captured proof.
func (r *NativeConnectorRepository) prepare(ctx context.Context, lease *ConnectorEffectLease, secret bool) error {
	if !validNativeConnectorRepository(r, ctx) || lease == nil {
		return ErrRepositoryUnavailable
	}
	key := nativeConnectorKey(*lease)
	state, ok := r.reservation(key)
	if !ok || !connectorNativeLeaseEqual(*lease, state.lease) {
		return ErrRepositoryUnavailable
	}
	phase := connectormaintenance.BeforeProvider
	if secret {
		phase = connectormaintenance.BeforeSecrets
	}
	if _, err := r.authority.Authorize(ctx, state.reference, phase); err != nil {
		return connectorNativeError(err)
	}
	if len(state.captured) != 0 {
		return nil
	}
	proof, err := r.authority.Authorize(ctx, state.reference, connectormaintenance.BeforeProvider)
	if err != nil {
		return connectorNativeError(err)
	}
	q, _ := json.Marshal(state.reference)
	raw, err := r.executor.Invoke(ctx, connectormaintenance.BeginProviderAttempt, q, proof)
	if err != nil {
		return connectorNativeError(err)
	}
	var result struct {
		Created *bool           `json:"created"`
		Attempt *int            `json:"attempt"`
		Proof   json.RawMessage `json:"captured_proof"`
	}
	if decodeStrictDiscovery(raw, &result) != nil || result.Created == nil || !*result.Created || result.Attempt == nil || *result.Attempt != state.lease.Attempt+1 || len(result.Proof) == 0 || string(result.Proof) == "null" {
		return ErrRepositoryUnavailable
	}
	r.mu.Lock()
	current := r.reservations[key]
	if current == nil || len(current.captured) != 0 {
		r.mu.Unlock()
		return ErrRepositoryUnavailable
	}
	current.captured = append(json.RawMessage(nil), result.Proof...)
	current.lease.Attempt = *result.Attempt
	r.mu.Unlock()
	lease.Attempt = *result.Attempt
	return nil
}
func (r *NativeConnectorRepository) releaseUnattempted(ctx context.Context, lease ConnectorEffectLease, cause error) error {
	key := nativeConnectorKey(lease)
	state, ok := r.reservation(key)
	if !ok || len(state.captured) != 0 {
		return nil
	}
	deadline := state.lease.LeaseExpiresAt.Add(-100 * time.Millisecond)
	if sooner := time.Now().Add(2 * time.Second); sooner.Before(deadline) {
		deadline = sooner
	}
	cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	q, _ := json.Marshal(state.reference)
	op := connectormaintenance.ReleaseUnattempted
	if errors.Is(cause, ErrAuthorizationDenied) {
		op = connectormaintenance.PauseDenied
	}
	raw, err := r.executor.Invoke(cleanup, op, q, nil)
	if err != nil {
		return connectorNativeError(err)
	}
	var result struct {
		Transition string `json:"transition"`
	}
	want := "released"
	if op == connectormaintenance.PauseDenied {
		want = "paused_denied"
	}
	if decodeStrictDiscovery(raw, &result) != nil || result.Transition != want {
		return ErrRepositoryUnavailable
	}
	r.mu.Lock()
	delete(r.reservations, key)
	r.mu.Unlock()
	return nil
}
func (r *NativeConnectorRepository) GetWorkflow(ctx context.Context, scope domain.Scope, kind, id string) (WorkflowValue, error) {
	var result WorkflowValue
	if !validNativeConnectorRepository(r, ctx) || scope.Validate() != nil || kind != "integration" {
		return result, ErrRepositoryOperation
	}
	key, ok := ctx.Value(nativeConnectorContextKey{}).(string)
	if !ok {
		return result, ErrRepositoryUnavailable
	}
	state, ok := r.reservation(key)
	if !ok || state.reference.Organization != scope.OrganizationID().String() || state.reference.Workspace != scope.WorkspaceID().String() || state.reference.Environment != scope.EnvironmentID().String() || state.reference.Integration != id {
		return result, ErrRepositoryUnavailable
	}
	proof, err := r.authority.Authorize(ctx, state.reference, connectormaintenance.BeforeMetadata)
	if err != nil {
		return result, connectorNativeError(err)
	}
	q, _ := json.Marshal(state.reference)
	raw, err := r.executor.Invoke(ctx, connectormaintenance.ReadWorkflow, q, proof)
	if err != nil {
		return result, connectorNativeError(err)
	}
	if decodeStrictDiscovery(raw, &result) != nil || result.Version < 1 || !json.Valid(result.Body) {
		return WorkflowValue{}, ErrRepositoryUnavailable
	}
	return result, nil
}
func (r *NativeConnectorRepository) settlement(ctx context.Context, op connectormaintenance.Operation, lease ConnectorEffectLease, payload any) (json.RawMessage, error) {
	if !validNativeConnectorRepository(r, ctx) || !validConnectorLease(lease) {
		return nil, ErrRepositoryOperation
	}
	state, ok := r.reservation(nativeConnectorKey(lease))
	if !ok || len(state.captured) == 0 || !connectorNativeLeaseEqual(lease, state.lease) {
		return nil, ErrRepositoryUnavailable
	}
	q, err := json.Marshal(map[string]any{"reference": state.reference, "payload": payload})
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	raw, err := r.executor.Invoke(ctx, op, q, state.captured)
	if err != nil {
		return nil, connectorNativeError(err)
	}
	if op != connectormaintenance.CompleteOAuth {
		r.mu.Lock()
		delete(r.reservations, nativeConnectorKey(lease))
		r.mu.Unlock()
	}
	return raw, nil
}

func (repository *NativeConnectorRepository) CompletePKCECleanupReconciliation(ctx context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	if !validNativeConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "pkce_cleanup" {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.settlement(ctx, connectormaintenance.CompletePKCECleanup, lease, struct{}{})
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, lease.ID, "reconciled", lease.Attempt)
}

func (repository *NativeConnectorRepository) CompleteOAuthReconciliation(ctx context.Context, lease ConnectorEffectLease, input OAuthCompletion) (OAuthCompletionRecord, error) {
	if !validNativeConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "authorize" || input.AttemptID != lease.OAuthAttemptID || input.EffectID != lease.ID || !validOAuthCompletion(input) {
		return OAuthCompletionRecord{}, ErrRepositoryOperation
	}
	canonicalMetadata, digest := connectorOAuthCompletionDigest(input)
	payload, err := repository.settlement(ctx, connectormaintenance.CompleteOAuth, lease, map[string]any{"attempt_id": input.AttemptID, "effect_id": input.EffectID, "connection_id": input.ConnectionID, "connection_reference": input.ConnectionReference, "provider_subject": input.ProviderSubject, "credential_id": input.CredentialID, "credential_class": input.CredentialClass, "metadata": json.RawMessage(canonicalMetadata), "completion_digest": hex.EncodeToString(digest[:])})
	if err != nil {
		return OAuthCompletionRecord{}, discoveryProviderError(err)
	}
	var result OAuthCompletionRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.AttemptID != input.AttemptID || result.ConnectionID != input.ConnectionID || result.Status != "succeeded" || !validPastServerTime(result.CompletedAt) {
		return OAuthCompletionRecord{}, ErrRepositoryUnavailable
	}
	result.CompletedAt = result.CompletedAt.UTC()
	return result, nil
}

func (repository *NativeConnectorRepository) CompleteConnectorCleanupReconciliation(ctx context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	if !validNativeConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "authorize" {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.settlement(ctx, connectormaintenance.CompleteCleanup, lease, struct{}{})
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, lease.ID, "reconciled", lease.Attempt)
}

func (repository *NativeConnectorRepository) QuarantineConnectorReconciliation(ctx context.Context, lease ConnectorEffectLease, errorCode string) (ConnectorEffectTransition, error) {
	validReason := lease.Operation == "authorize" && stringIn(errorCode, "provider_outcome_ambiguous", "provider_cleanup_ambiguous") || lease.Operation == "revoke" && errorCode == "provider_revocation_ambiguous" || lease.Operation == "pkce_cleanup" && errorCode == "pkce_cleanup_ambiguous"
	if !validNativeConnectorRepository(repository, ctx) || !validConnectorLeaseIdentity(lease) || lease.Attempt != 100 || !validReason {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.settlement(ctx, connectormaintenance.Quarantine, lease, map[string]string{"reason": errorCode})
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	return decodeConnectorTransition(payload, lease.ID, "unknown", lease.Attempt)
}

func (repository *NativeConnectorRepository) FailConnectorReconciliation(ctx context.Context, lease ConnectorEffectLease, errorCode string) (ConnectorEffectTransition, error) {
	if !validNativeConnectorRepository(repository, ctx) || !validConnectorLease(lease) || !connectorCodePattern.MatchString(errorCode) {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.settlement(ctx, connectormaintenance.Fail, lease, map[string]string{"reason": errorCode})
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	var result ConnectorEffectTransition
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != lease.ID || result.Status != "failed" || result.Attempt != lease.Attempt || !validPastServerTime(result.UpdatedAt) {
		return ConnectorEffectTransition{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func (repository *NativeConnectorRepository) CompleteConnectorRevocation(ctx context.Context, lease ConnectorEffectLease) (ConnectorEffectTransition, error) {
	if !validNativeConnectorRepository(repository, ctx) || !validConnectorLease(lease) || lease.Operation != "revoke" {
		return ConnectorEffectTransition{}, ErrRepositoryOperation
	}
	payload, err := repository.settlement(ctx, connectormaintenance.CompleteRevocation, lease, struct{}{})
	if err != nil {
		return ConnectorEffectTransition{}, discoveryProviderError(err)
	}
	var result ConnectorEffectTransition
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != lease.ID || result.Status != "reconciled" || result.Attempt != lease.Attempt || !validPastServerTime(result.UpdatedAt) {
		return ConnectorEffectTransition{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

// prepareCompensation admits cleanup for a genuine unattempted authorization
// origin using current grantor and task/service authority. Existing attempted
// work retains captured-only compensation, including after permission changes.
func (r *NativeConnectorRepository) prepareCompensation(ctx context.Context, lease *ConnectorEffectLease) error {
	if !validNativeConnectorRepository(r, ctx) || lease == nil {
		return ErrRepositoryUnavailable
	}
	state, ok := r.reservation(nativeConnectorKey(*lease))
	if !ok || !connectorNativeLeaseEqual(*lease, state.lease) {
		return ErrRepositoryUnavailable
	}
	if len(state.captured) == 0 {
		if lease.Operation != "authorize" {
			return ErrRepositoryUnavailable
		}
		if err := r.prepare(ctx, lease, false); err != nil {
			return err
		}
	}
	return r.compensation(ctx, *lease)
}

// Captured compensation cannot authorize another recovery/revocation attempt.
// The native call rechecks the exact attempted lease before touching a provider.
func (r *NativeConnectorRepository) compensation(ctx context.Context, lease ConnectorEffectLease) error {
	if !validNativeConnectorRepository(r, ctx) {
		return ErrRepositoryUnavailable
	}
	state, ok := r.reservation(nativeConnectorKey(lease))
	if !ok || len(state.captured) == 0 || !connectorNativeLeaseEqual(lease, state.lease) {
		return ErrRepositoryUnavailable
	}
	q, _ := json.Marshal(state.reference)
	raw, err := r.executor.Invoke(ctx, connectormaintenance.BeforeCompensation, q, state.captured)
	if err != nil {
		return connectorNativeError(err)
	}
	var result struct {
		Valid *bool `json:"valid"`
	}
	if decodeStrictDiscovery(raw, &result) != nil || result.Valid == nil || !*result.Valid {
		return ErrRepositoryUnavailable
	}
	return nil
}

// Authorized local preparation failures retain the original finite attempt
// budget. Permission denial/cancellation releases or pauses without increment;
// a failure may consume an attempt only after a fresh live native/FGA decision.
func (r *NativeConnectorRepository) finishPreparation(ctx context.Context, lease ConnectorEffectLease, cause error, providerDeadline time.Time) error {
	state, ok := r.reservation(nativeConnectorKey(lease))
	if !ok || len(state.captured) != 0 {
		return nil
	}
	if cause == nil || errors.Is(cause, ErrAuthorizationDenied) || ctx.Err() != nil || providerDeadline.IsZero() || !providerDeadline.After(time.Now()) {
		return r.releaseUnattempted(ctx, lease, cause)
	}
	authorized, cancel := context.WithDeadline(ctx, providerDeadline)
	defer cancel()
	proof, err := r.authority.Authorize(authorized, state.reference, connectormaintenance.BeforeSecretFailure)
	if err != nil {
		return r.releaseUnattempted(ctx, lease, connectorNativeError(err))
	}
	q, _ := json.Marshal(state.reference)
	raw, err := r.executor.Invoke(authorized, connectormaintenance.BeginSecretFailureAttempt, q, proof)
	if err != nil {
		return connectorNativeError(err)
	} // ambiguous Begin never releases
	var result struct {
		Created *bool           `json:"created"`
		Attempt *int            `json:"attempt"`
		Proof   json.RawMessage `json:"captured_proof"`
	}
	if decodeStrictDiscovery(raw, &result) != nil || result.Created == nil || !*result.Created || result.Attempt == nil || *result.Attempt != state.lease.Attempt+1 || len(result.Proof) == 0 || string(result.Proof) == "null" {
		return ErrRepositoryUnavailable
	}
	r.mu.Lock()
	current := r.reservations[nativeConnectorKey(lease)]
	if current == nil || len(current.captured) != 0 {
		r.mu.Unlock()
		return ErrRepositoryUnavailable
	}
	current.captured = append(json.RawMessage(nil), result.Proof...)
	current.lease.Attempt = *result.Attempt
	lease = current.lease
	r.mu.Unlock()
	if lease.Attempt < 100 {
		return nil
	} // original expiry/backoff owns the next retry
	reason := "provider_outcome_ambiguous"
	if lease.Operation == "pkce_cleanup" {
		reason = "pkce_cleanup_ambiguous"
	} else if lease.Operation == "revoke" {
		reason = "provider_revocation_ambiguous"
	} else if lease.LastErrorCode == "cleanup_pending" {
		reason = "provider_cleanup_ambiguous"
	}
	cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), lease.LeaseExpiresAt.Add(-100*time.Millisecond))
	defer stop()
	_, err = r.QuarantineConnectorReconciliation(cleanup, lease, reason)
	return err
}
