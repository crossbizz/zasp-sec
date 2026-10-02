package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"io"
	"reflect"
	"regexp"
	"time"
	"unicode/utf8"
)

const singleTestRecoveryPreflightSQL = `SELECT zasp_temporal_single_recovery.preflight($1::jsonb)`
const singleTestRecoveryAdmitSQL = `SELECT zasp_temporal_single_recovery.admit($1::jsonb)`
const singleTestRecoveryGetSQL = `SELECT zasp_temporal_single_recovery.get($1,$2,$3,$4,$5)`

var singleRecoveryDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type SingleTestRecoveryMutation struct {
	RunID                                             string
	DefinitionVersion                                 int64
	InputDigest                                       string
	ExpectedVersion                                   int64
	IdempotencyKey, AuditID, CorrelationID, ReceiptID string
}
type SingleTestRecoveryCompletion struct {
	ReceiptID      string `json:"receipt_id"`
	EvidenceKind   string `json:"evidence_kind"`
	EvidenceDigest string `json:"evidence_digest"`
	Outcome        string `json:"outcome"`
	CompletedAt    string `json:"completed_at"`
}
type SingleTestRecoveryView struct {
	RequestIdentity SingleTestRecoveryRequestIdentity    `json:"request_identity"`
	RunID           string                               `json:"run_id"`
	Status          string                               `json:"status"`
	Reason          string                               `json:"reason"`
	ParentVersion   int64                                `json:"parent_version"`
	Command         *orchestration.SingleTestRecoveryRef `json:"command"`
	AcceptedAt      *string                              `json:"accepted_at"`
	Completion      *SingleTestRecoveryCompletion        `json:"completion"`
}
type SingleTestRecoveryMutationResult struct {
	Body          SingleTestRecoveryView `json:"body"`
	AuditID       string                 `json:"audit_id"`
	CorrelationID string                 `json:"correlation_id"`
	ReceiptID     string                 `json:"receipt_id"`
	Replayed      bool                   `json:"replayed"`
}
type SingleTestRecoveryRequestIdentity struct {
	DefinitionVersion int64  `json:"definition_version"`
	InputDigest       string `json:"input_digest"`
}
type singleTestRecoveryWire struct {
	OrganizationID    string `json:"organization_id"`
	WorkspaceID       string `json:"workspace_id"`
	EnvironmentID     string `json:"environment_id"`
	RunID             string `json:"run_id"`
	ActorID           string `json:"actor_id"`
	ExpectedVersion   int64  `json:"expected_version"`
	DefinitionVersion int64  `json:"definition_version"`
	InputDigest       string `json:"input_digest"`
	IdempotencyKey    string `json:"idempotency_key"`
	Diagnostic        string `json:"diagnostic"`
	StopOriginal      bool   `json:"stop_original"`
	AuditID           string `json:"audit_id"`
	CorrelationID     string `json:"correlation_id"`
	ReceiptID         string `json:"receipt_id"`
}
type singleTestRecoveryAdmission struct {
	singleTestRecoveryWire
	Observation orchestration.SingleTestOriginalObservation `json:"observation"`
}
type singleTestRecoveryPreflight struct {
	Start      orchestration.StartRequest        `json:"start"`
	RunVersion int64                             `json:"run_version"`
	WorkflowID string                            `json:"workflow_id"`
	Replay     *SingleTestRecoveryMutationResult `json:"replay"`
}
type SingleTestRecoveryRepository struct {
	database JSONDatabase
	observer orchestration.SingleTestOriginalObserver
}

func NewSingleTestRecoveryRepository(db JSONDatabase, o orchestration.SingleTestOriginalObserver) (*SingleTestRecoveryRepository, error) {
	if nilInterface(db) || nilInterface(o) {
		return nil, ErrRepositoryConfiguration
	}
	return &SingleTestRecoveryRepository{db, o}, nil
}
func recoveryWire(id RequestIdentity, q SingleTestRecoveryMutation) singleTestRecoveryWire {
	return singleTestRecoveryWire{id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), q.RunID, id.PrincipalID.String(), q.ExpectedVersion, q.DefinitionVersion, q.InputDigest, q.IdempotencyKey, "history_unavailable", true, q.AuditID, q.CorrelationID, q.ReceiptID}
}
func (q singleTestRecoveryWire) valid() bool {
	for _, s := range []string{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.ActorID, q.AuditID, q.CorrelationID, q.ReceiptID} {
		if !validProductID(s) {
			return false
		}
	}
	return q.AuditID != q.CorrelationID && q.AuditID != q.ReceiptID && q.CorrelationID != q.ReceiptID && public62MutationVersion(q.ExpectedVersion) && q.DefinitionVersion >= 1 && q.DefinitionVersion <= 1000000 && singleRecoveryDigest.MatchString(q.InputDigest) && validPublicIdempotency(q.IdempotencyKey) && q.Diagnostic == "history_unavailable" && q.StopOriginal
}
func (q singleTestRecoveryWire) start() orchestration.StartRequest {
	return orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: q.OrganizationID, WorkspaceID: q.WorkspaceID, EnvironmentID: q.EnvironmentID, RunID: q.RunID}, DefinitionVersion: q.DefinitionVersion, InputDigest: q.InputDigest}
}

// Exact DTO keys, duplicates, nulls and numeric spellings are checked before
// decoding. Temporal IDs exceed public62's short public-string bound.
func recoveryFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for n := 0; n < t.NumField(); n++ {
		f := t.Field(n)
		if f.Anonymous {
			for name, typ := range recoveryFields(f.Type) {
				fields[name] = typ
			}
		} else {
			fields[f.Tag.Get("json")] = f.Type
		}
	}
	return fields
}
func recoveryShape(raw []byte, t reflect.Type, depth int) bool {
	if depth > 12 || !utf8.Valid(raw) {
		return false
	}
	if t.Kind() == reflect.Pointer {
		return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || recoveryShape(raw, t.Elem(), depth+1)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	if t == reflect.TypeOf(time.Time{}) {
		var s string
		return json.Unmarshal(raw, &s) == nil && len(s) <= 64
	}
	if t.Kind() != reflect.Struct {
		return json.Unmarshal(raw, reflect.New(t).Interface()) == nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	fields := recoveryFields(t)
	for d.More() {
		k, e := d.Token()
		s, ok := k.(string)
		if e != nil || !ok || seen[s] {
			return false
		}
		seen[s] = true
		ft := fields[s]
		var value json.RawMessage
		if ft == nil || d.Decode(&value) != nil || !recoveryShape(value, ft, depth+1) {
			return false
		}
	}
	token, e = d.Token()
	if e != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return false
	}
	_, e = d.Token()
	return e == io.EOF
}
func recoveryDecode(raw []byte, max int, v any) error {
	if len(raw) > max || !recoveryShape(raw, reflect.TypeOf(v).Elem(), 0) || json.Unmarshal(raw, v) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}
func recoveryError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		err = classifyPostgresError(pg)
	}
	for _, safe := range []error{ErrRepositoryConflict, ErrRepositoryOperation, ErrRepositoryAuthentication, ErrRepositoryNotFound} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrRepositoryUnavailable
}
func (r *SingleTestRecoveryRepository) query(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v, e := r.database.QueryJSON(bounded, sql, args...)
	if e != nil {
		return nil, recoveryError(e)
	}
	if bounded.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	return v, nil
}
func recoveryViewValid(v SingleTestRecoveryView, id RequestIdentity, run string) bool {
	if v.RunID != run || v.ParentVersion < 1 || v.RequestIdentity.DefinitionVersion < 1 || v.RequestIdentity.DefinitionVersion > 1000000 || !singleRecoveryDigest.MatchString(v.RequestIdentity.InputDigest) || !stringIn(v.Status, "not_requested", "queued", "pending", "repair_required", "complete") || !stringIn(v.Reason, "not_requested", "queued", "cleanup_pending", "dependency_unavailable", "evidence_conflict", "verified") {
		return false
	}
	if v.Status == "not_requested" {
		return v.Reason == "not_requested" && v.Command == nil && v.AcceptedAt == nil && v.Completion == nil
	}
	if v.Status == "queued" && v.Reason != "queued" || v.Status == "pending" && !stringIn(v.Reason, "cleanup_pending", "dependency_unavailable") || v.Status == "repair_required" && v.Reason != "evidence_conflict" || v.Status == "complete" && v.Reason != "verified" {
		return false
	}
	if v.AcceptedAt == nil || v.Reason == "not_requested" {
		return false
	}
	stamp, e := time.Parse(time.RFC3339Nano, *v.AcceptedAt)
	if e != nil || stamp.IsZero() {
		return false
	}
	if v.Command != nil {
		ref := v.Command
		if ref.Start.DefinitionVersion != v.RequestIdentity.DefinitionVersion || ref.Start.InputDigest != v.RequestIdentity.InputDigest {
			return false
		}
		if _, e := orchestration.SingleTestRecoveryWorkflowID(*ref); e != nil {
			return false
		}
		scope := ref.Start.Ref
		if scope.OrganizationID != id.Scope.OrganizationID().String() || scope.WorkspaceID != id.Scope.WorkspaceID().String() || scope.EnvironmentID != id.Scope.EnvironmentID().String() || scope.RunID != run {
			return false
		}
		expected, e := CanonicalDiscoveryID(id.Scope, "single_test_cleanup_recovery", run)
		if e != nil || expected != ref.CommandID {
			return false
		}
	}
	if v.Status == "complete" {
		c := v.Completion
		if c == nil || !validProductID(c.ReceiptID) || !singleRecoveryDigest.MatchString(c.EvidenceDigest) || !stringIn(c.EvidenceKind, "parent", "stop", "planning_terminal", "already_complete") || !stringIn(c.Outcome, "cancelled", "failed", "inconclusive", "needs_human", "remediated", "contained") {
			return false
		}
		_, e = time.Parse(time.RFC3339Nano, c.CompletedAt)
		return e == nil && v.Reason == "verified"
	}
	return v.Command != nil && v.Completion == nil && v.Reason != "verified"
}
func recoveryResultValid(v SingleTestRecoveryMutationResult, id RequestIdentity, q singleTestRecoveryWire) bool {
	if v.Body.Status == "not_requested" || v.Body.RequestIdentity.DefinitionVersion != q.DefinitionVersion || v.Body.RequestIdentity.InputDigest != q.InputDigest {
		return false
	}
	return recoveryViewValid(v.Body, id, q.RunID) && validProductID(v.AuditID) && validProductID(v.CorrelationID) && validProductID(v.ReceiptID) && (v.Replayed || v.AuditID == q.AuditID && v.CorrelationID == q.CorrelationID && v.ReceiptID == q.ReceiptID) && (v.Body.Command == nil || v.Body.Command.Start == q.start())
}
func (r *SingleTestRecoveryRepository) Request(ctx context.Context, id RequestIdentity, input SingleTestRecoveryMutation) (SingleTestRecoveryMutationResult, error) {
	var zero SingleTestRecoveryMutationResult
	q := recoveryWire(id, input)
	if r == nil || ctx == nil || nilInterface(r.database) || nilInterface(r.observer) || !q.valid() {
		return zero, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	wire, _ := json.Marshal(q)
	raw, err := r.query(bounded, singleTestRecoveryPreflightSQL, json.RawMessage(wire))
	if err != nil {
		return zero, err
	}
	var p singleTestRecoveryPreflight
	workflowID, _ := orchestration.SingleTestWorkflowID(q.start().Ref)
	if recoveryDecode(raw, 16384, &p) != nil || p.Start != q.start() || p.WorkflowID != workflowID || p.RunVersion < 1 {
		return zero, ErrRepositoryUnavailable
	}
	if p.Replay != nil {
		if !p.Replay.Replayed || !recoveryResultValid(*p.Replay, id, q) {
			return zero, ErrRepositoryUnavailable
		}
		return *p.Replay, nil
	}
	if p.RunVersion != q.ExpectedVersion {
		return zero, ErrRepositoryConflict
	}
	observeCtx, stop := context.WithTimeout(bounded, 5*time.Second)
	observation, err := r.observer.ObserveOriginal(observeCtx, p.Start)
	expired := observeCtx.Err()
	stop()
	if errors.Is(err, orchestration.ErrConflict) {
		return zero, ErrRepositoryConflict
	}
	if err != nil || expired != nil {
		return zero, ErrRepositoryUnavailable
	}
	if !recoveryObservationValid(observation, workflowID, time.Now()) {
		return zero, ErrRepositoryUnavailable
	}
	payload, _ := json.Marshal(singleTestRecoveryAdmission{singleTestRecoveryWire: q, Observation: observation})
	raw, err = r.query(bounded, singleTestRecoveryAdmitSQL, json.RawMessage(payload))
	if err != nil {
		return zero, err
	}
	var result SingleTestRecoveryMutationResult
	if recoveryDecode(raw, 16384, &result) != nil || !recoveryResultValid(result, id, q) {
		return zero, ErrRepositoryUnavailable
	}
	return result, nil
}
func recoveryObservationValid(v orchestration.SingleTestOriginalObservation, id string, now time.Time) bool {
	return v.WorkflowID == id && !v.ObservedAt.IsZero() && v.ObservedAt.Location() == time.UTC && !v.ObservedAt.Before(now.Add(-30*time.Second)) && !v.ObservedAt.After(now.Add(5*time.Second)) && (v.Status == "absent" && v.RunID == nil || v.Status == "closed" && v.RunID != nil && len(*v.RunID) > 0 && len(*v.RunID) <= 256 && utf8.ValidString(*v.RunID))
}
func (r *SingleTestRecoveryRepository) Get(ctx context.Context, id RequestIdentity, run string) (SingleTestRecoveryView, error) {
	var v SingleTestRecoveryView
	if r == nil || ctx == nil || !validProductID(run) || !validProductID(id.PrincipalID.String()) {
		return v, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, singleTestRecoveryGetSQL, id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), run, id.PrincipalID.String())
	if err != nil {
		return v, err
	}
	if recoveryDecode(raw, 16384, &v) != nil || !recoveryViewValid(v, id, run) {
		return SingleTestRecoveryView{}, ErrRepositoryUnavailable
	}
	return v, nil
}
