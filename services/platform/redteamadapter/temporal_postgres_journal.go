package redteamadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const temporalInvocationSQL = `SELECT zasp_temporal68.invocation($1::jsonb)`
const temporalAdapterReadySQL = `SELECT to_jsonb(zasp_temporal68.adapter_ready($1,$2))`

// TemporalPostgresJournal commits one scoped category intent before a send.
// Its database must be autocommit, with commit errors returned to the caller.
type TemporalPostgresJournal struct {
	database                JSONDatabase
	checksum, fingerprint   string
	invocationSQL, readySQL string
	forward, compensation   *authorization.WorkerExecutor
	workerFamily            workerJournalFamily
}

func NewTemporalPostgresJournal(database JSONDatabase, checksum, fingerprint string) (*TemporalPostgresJournal, error) {
	if nilJSONDatabase(database) || !releaseDigestPattern.MatchString(checksum) || !releaseDigestPattern.MatchString(fingerprint) {
		return nil, ErrAdapter
	}
	return &TemporalPostgresJournal{database: database, checksum: checksum, fingerprint: fingerprint, invocationSQL: temporalInvocationSQL, readySQL: temporalAdapterReadySQL}, nil
}

// NewSingleTestPostgresJournal selects the explicit lease-free74 journal. Its
// receipt format is shared with68; ownership and authority are not shared.
func NewSingleTestPostgresJournal(database JSONDatabase, checksum, fingerprint string) (*TemporalPostgresJournal, error) {
	j, err := NewTemporalPostgresJournal(database, checksum, fingerprint)
	if err != nil {
		return nil, err
	}
	j.invocationSQL = `SELECT zasp_temporal74.invocation($1::jsonb)`
	j.readySQL = `SELECT to_jsonb(zasp_temporal74.adapter_ready($1,$2))`
	return j, nil
}

// NewWorkerSingleTestPostgresJournal binds the separately configured adapter
// and compensation clients. It does not enable the partial production profile.
func NewWorkerSingleTestPostgresJournal(database JSONDatabase, checksum, fingerprint string, forward, compensation *authorization.WorkerExecutor) (*TemporalPostgresJournal, error) {
	if forward == nil || compensation == nil {
		return nil, ErrAdapter
	}
	j, err := NewSingleTestPostgresJournal(database, checksum, fingerprint)
	if err != nil {
		return nil, err
	}
	j.forward, j.compensation = forward, compensation
	j.workerFamily = workerJournalSingle74
	return j, nil
}

func (j *TemporalPostgresJournal) Ready(ctx context.Context) error {
	if j == nil || nilJSONDatabase(j.database) || ctx == nil || ctx.Err() != nil {
		return ErrAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if j.forward != nil || j.compensation != nil || j.workerFamily != workerJournalNone {
		resolve, err := j.workerOperation("resolve")
		complete, completeErr := j.workerOperation("complete")
		if err != nil || completeErr != nil || j.forward.ReadyFor(ctx, resolve) != nil || j.compensation.ReadyFor(ctx, complete) != nil {
			return ErrAdapter
		}
	}
	raw, err := j.database.QueryJSON(ctx, j.readySQL, j.checksum, j.fingerprint)
	if err != nil || string(raw) != "true" || ctx.Err() != nil {
		return ErrAdapter
	}
	return nil
}

func (j *TemporalPostgresJournal) query(ctx context.Context, scope domain.Scope, run, key, op string, payload any) (json.RawMessage, error) {
	if j == nil || nilJSONDatabase(j.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !ValidEffectKey(key) {
		return nil, ErrAdapter
	}
	if _, err := domain.ParseProductID(run); err != nil {
		return nil, ErrAdapter
	}
	request, err := json.Marshal(map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "run_id": run, "effect_key": key, "operation": op, "payload": payload, "checksum": j.checksum, "fingerprint": j.fingerprint})
	if err != nil {
		return nil, ErrAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if j.forward != nil || j.compensation != nil || j.workerFamily != workerJournalNone {
		operation, err := j.workerOperation(op)
		if err != nil {
			return nil, ErrAdapter
		}
		client := j.forward
		switch op {
		case "resolve", "start":
		case "complete":
			client = j.compensation
		default:
			return nil, ErrAdapter
		}
		decision, err := client.Authorize(ctx, operation, request)
		if err != nil {
			return nil, ErrAdapter
		}
		raw, err := client.Execute(ctx, decision)
		if err != nil {
			return nil, ErrAdapter
		}
		return raw, nil
	}
	return j.database.QueryJSON(ctx, j.invocationSQL, request)
}

func (j *TemporalPostgresJournal) ResolveTarget(ctx context.Context, r TargetResolution) (TargetBinding, error) {
	if r.LeaseToken != "" || r.RunID == r.TargetID || !validRequestBody(requestBody{TargetID: r.TargetID, TargetKind: r.TargetKind, Category: r.Category, Input: curatedInputs[r.Category]}) {
		return TargetBinding{}, ErrAdapter
	}
	raw, err := j.query(ctx, r.Scope, r.RunID, r.EffectKey, "resolve", map[string]any{"target_id": r.TargetID, "target_kind": r.TargetKind, "category": r.Category})
	if err != nil || len(raw) > 16384 {
		return TargetBinding{}, ErrAdapter
	}
	fields, err := exactJournalObject(raw, "target_id target_kind endpoint credential_reference version")
	var binding TargetBinding
	if err != nil || len(fields) != 5 || json.Unmarshal(raw, &binding) != nil || !validBinding(binding) || binding.TargetID != r.TargetID || binding.TargetKind != r.TargetKind {
		return TargetBinding{}, ErrAdapter
	}
	return binding, nil
}

func temporalJournalRequestValid(r JournalRequest) bool {
	if r.LeaseToken != "" || !ValidEffectKey(r.EffectKey) || !validBinding(r.Invocation.Binding) || r.Invocation.RunID == r.Invocation.Binding.TargetID || !validRequestBody(requestBody{TargetID: r.Invocation.Binding.TargetID, TargetKind: r.Invocation.Binding.TargetKind, Category: r.Invocation.Category, Input: r.Invocation.Input}) {
		return false
	}
	body, err := targetPayload(r.Invocation)
	digest := sha256.Sum256(body)
	return err == nil && r.RequestDigest == hex.EncodeToString(digest[:])
}

func (j *TemporalPostgresJournal) Start(ctx context.Context, r JournalRequest) (InvocationReceipt, error) {
	if !temporalJournalRequestValid(r) {
		return InvocationReceipt{}, ErrAdapter
	}
	raw, err := j.query(ctx, r.Invocation.Scope, r.Invocation.RunID, r.EffectKey, "start", map[string]any{"category": r.Invocation.Category, "request_digest": r.RequestDigest})
	if err != nil {
		return InvocationReceipt{}, ErrAdapter
	}
	return decodeTemporalJournalReceipt(raw, r)
}

func (j *TemporalPostgresJournal) Complete(ctx context.Context, r JournalRequest, attempt int, o InvocationObservation) error {
	if !temporalJournalRequestValid(r) || attempt != 1 || !validInvocationObservation(o) || !validCredentialVersionDigest(o.CredentialVersionDigest) {
		return ErrAdapter
	}
	raw, err := j.query(ctx, r.Invocation.Scope, r.Invocation.RunID, r.EffectKey, "complete", map[string]any{"category": r.Invocation.Category, "request_digest": r.RequestDigest, "http_status": o.HTTPStatus, "response_digest": o.ResponseDigest, "protected": o.Protected, "credential_version_digest": o.CredentialVersionDigest})
	if err != nil {
		return ErrAdapter
	}
	if j.forward != nil {
		switch j.workerFamily {
		case workerJournalSingle74, workerJournalOrdered68:
			return validateWorkerCompletion(raw, r, o)
		default:
			return ErrAdapter
		}
	}
	receipt, err := decodeTemporalJournalReceipt(raw, r)
	if err != nil || receipt.State != "completed" || receipt.Observation == nil || receipt.Observation.HTTPStatus != o.HTTPStatus || receipt.Observation.ResponseDigest != o.ResponseDigest || receipt.Observation.CredentialVersionDigest != o.CredentialVersionDigest || receipt.Observation.Protected == nil || o.Protected == nil || *receipt.Observation.Protected != *o.Protected {
		return ErrAdapter
	}
	return nil
}

func decodeTemporalJournalReceipt(raw []byte, r JournalRequest) (InvocationReceipt, error) {
	if len(raw) > 16384 {
		return InvocationReceipt{}, ErrAdapter
	}
	fields, err := exactJournalObject(raw, "state attempt category input_digest request_digest target_binding target_provenance target_comparison run_id http_status response_digest protected completed_at credential_version_digest effect_key")
	var key string
	if err != nil || json.Unmarshal(fields["effect_key"], &key) != nil || !ValidEffectKey(key) || key != r.EffectKey {
		return InvocationReceipt{}, ErrAdapter
	}
	delete(fields, "effect_key")
	body, err := json.Marshal(fields)
	if err != nil {
		return InvocationReceipt{}, ErrAdapter
	}
	receipt, err := decodeJournalReceipt(body, r)
	if err != nil || receipt.Attempt != 1 {
		return InvocationReceipt{}, ErrAdapter
	}
	receipt.EffectKey = key
	return receipt, nil
}

// The standalone facade still requires its original run lease. It cannot
// resolve a linked child, even when that child has a valid effect identity.
type TemporalStandaloneResolver struct{ journal *TemporalPostgresJournal }

func (j *TemporalPostgresJournal) StandaloneResolver() *TemporalStandaloneResolver {
	if j == nil || j.invocationSQL != temporalInvocationSQL {
		return nil
	}
	return &TemporalStandaloneResolver{j}
}
func (s *TemporalStandaloneResolver) ResolveTarget(ctx context.Context, r TargetResolution) (TargetBinding, error) {
	if s == nil || s.journal == nil || ctx == nil || ctx.Err() != nil || r.Scope.Validate() != nil || r.EffectKey != "" || !runLeaseRE.MatchString(r.LeaseToken) || r.RunID == r.TargetID || !validRequestBody(requestBody{TargetID: r.TargetID, TargetKind: r.TargetKind, Category: r.Category, Input: curatedInputs[r.Category]}) {
		return TargetBinding{}, ErrAdapter
	}
	if _, err := domain.ParseProductID(r.RunID); err != nil {
		return TargetBinding{}, ErrAdapter
	}
	j := s.journal
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := j.database.QueryJSON(ctx, `SELECT zasp_temporal68.standalone_resolve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.Scope.OrganizationID().String(), r.Scope.WorkspaceID().String(), r.Scope.EnvironmentID().String(), r.TargetID, r.TargetKind, r.RunID, r.LeaseToken, r.Category, j.checksum, j.fingerprint)
	if err != nil || len(raw) > 16384 {
		return TargetBinding{}, ErrAdapter
	}
	fields, err := exactJournalObject(raw, "target_id target_kind endpoint credential_reference version")
	var binding TargetBinding
	if err != nil || len(fields) != 5 || json.Unmarshal(raw, &binding) != nil || !validBinding(binding) || binding.TargetID != r.TargetID || binding.TargetKind != r.TargetKind {
		return TargetBinding{}, ErrAdapter
	}
	return binding, nil
}
