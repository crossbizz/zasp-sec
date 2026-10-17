package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type retentionJournalDatabase interface {
	CommitRetentionJournal(context.Context, string, []byte, string) (json.RawMessage, error)
}

func (d *retentionWorkerDatabase) CommitRetentionJournal(ctx context.Context, q string, body []byte, pin string) (json.RawMessage, error) {
	if d == nil || d.pool == nil || ctx == nil || ctx.Err() != nil || len(body) > 1<<20 || !migrations.IsRetentionJournalProfileChecksum(pin) {
		return nil, errRuntimeUnavailable
	}
	captured := false
	switch q {
	case `SELECT zasp_retention_journal_v1.begin_execution($1::jsonb)`, `SELECT zasp_retention_journal_v1.admit_execution($1::jsonb)`, `SELECT zasp_retention_journal_v1.reserve_request($1::jsonb)`, `SELECT zasp_retention_journal_v1.claim_send($1::jsonb)`, `SELECT zasp_retention_journal_v1.close_inventory($1::jsonb)`, `SELECT zasp_retention_journal_v1.seal_partition($1::jsonb)`:
	case `SELECT zasp_retention_journal_v1.append_terminal($1::jsonb)`, `SELECT zasp_retention_journal_v1.execution_status($1::jsonb)`:
		captured = true
	default:
		return nil, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := d.pool.BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	// Captured append is authorized by the exact stored execution/capability and
	// raw journal seal inside SQL, never fresh forward membership.
	if !captured {
		var ready bool
		if tx.QueryRow(bounded, `SELECT zasp_retention_journal_v1.ready($1)`, pin).Scan(&ready) != nil || !ready {
			return nil, errRuntimeUnavailable
		}
	}
	var raw []byte
	maximumResponse := 128 << 10
	if q == `SELECT zasp_retention_journal_v1.execution_status($1::jsonb)` {
		maximumResponse = 1 << 20
	}
	if tx.QueryRow(bounded, q, body).Scan(&raw) != nil || len(raw) == 0 || len(raw) > maximumResponse || !json.Valid(raw) {
		return nil, errRuntimeUnavailable
	}
	if tx.Commit(bounded) != nil {
		// Preserve this accepted precommit response, never a dependency error. It
		// cannot authorize a send until an exact private lookup confirms custody.
		return append(json.RawMessage(nil), raw...), errRetentionJournalCommitUnknown
	}
	return append(json.RawMessage(nil), raw...), nil
}

type retentionJournalIndexVisibility struct {
	*retentionIndexVisibility
	journal    retentionJournalDatabase
	journalPin string
	receipts   artifactstore.ObjectReferencingArtifactStore
}

func newRetentionJournalIndexVisibility(database recoveryJSONDatabase, pin, journalPin string, receipts artifactstore.ObjectReferencingArtifactStore) (*retentionJournalIndexVisibility, error) {
	base, err := newRetentionIndexVisibility(database, pin)
	db, ok := database.(retentionJournalDatabase)
	if err != nil || !ok || nilWorkerDependency(db) || nilWorkerDependency(receipts) || !migrations.IsRetentionJournalProfileChecksum(journalPin) {
		return nil, errRuntimeUnavailable
	}
	return &retentionJournalIndexVisibility{base, db, journalPin, receipts}, nil
}
func (g *retentionJournalIndexVisibility) Ready(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	raw, err := g.database.QueryJSON(ctx, `SELECT zasp_retention_journal_v1.ready($1)`, g.journalPin)
	var ready bool
	if err != nil || decodeStrictWorkerJSON(raw, &ready) != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}

type retentionWriterJournal struct {
	owner                   *retentionJournalIndexVisibility
	input                   runtimeindex.RetainedExecutionInput
	executionID, capability string
	mu                      sync.Mutex
	admissions              []string
	reservation, dispatch   string
	requests                int
	terminal                bool
	originalBinding         json.RawMessage
}

func (*retentionWriterJournal) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "retained-writer-journal[redacted]")
}
func retentionJournalRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errRuntimeUnavailable
	}
	s := hex.EncodeToString(b[:])
	clear(b[:])
	return s, nil
}
func (g *retentionJournalIndexVisibility) BeginRetainedExecution(ctx context.Context, input runtimeindex.RetainedExecutionInput) (runtimeindex.RetainedExecutionJournal, error) {
	if g == nil || input.Scope.Validate() != nil || len(input.EventIDs) == 0 || len(input.DocumentIDs) != len(input.EventIDs) {
		return nil, errRuntimeUnavailable
	}
	j := &retentionWriterJournal{owner: g, input: input, admissions: []string{}}
	var err error
	j.executionID, err = retentionJournalRandom()
	if err != nil {
		return nil, err
	}
	j.capability, err = retentionJournalRandom()
	if err != nil {
		return nil, err
	}
	binding, session, err := g.request(ctx, input.Scope, input.EventIDs)
	if err != nil || binding["batch_id"] != input.BatchID || binding["generation"] != input.Generation {
		return nil, errRuntimeUnavailable
	}
	expectedKind := "raw-index"
	digestKey := "input_digest"
	if session {
		expectedKind = "session-index-v1"
		digestKey = "receipt_digest"
		if binding["index_family"] == "sandbox-v2" {
			expectedKind = "session-index-v2"
		}
	}
	if input.Kind != expectedKind || binding[digestKey] != hexRetentionDigest(input.InputDigest) {
		return nil, errRuntimeUnavailable
	}
	j.originalBinding = normalizeRetentionJournalBinding(binding, false)
	if len(j.originalBinding) == 0 {
		return nil, errRuntimeUnavailable
	}
	var response struct {
		ExecutionID string `json:"execution_id"`
		State       string `json:"state"`
	}
	if j.call(ctx, "begin_execution", map[string]any{"kind": input.Kind, "binding": binding}, &response) != nil || response.ExecutionID != j.executionID || response.State != "begun" {
		return nil, errRuntimeUnavailable
	}
	return j, nil
}
func (j *retentionWriterJournal) call(ctx context.Context, operation string, fields map[string]any, out any) error {
	if j == nil || j.owner == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	fields["execution_id"], fields["capability"] = j.executionID, j.capability
	body, err := json.Marshal(fields)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer clear(body)
	// Only these literals reach the database; operation never comes from callers.
	q := ""
	switch operation {
	case "begin_execution":
		q = `SELECT zasp_retention_journal_v1.begin_execution($1::jsonb)`
	case "admit_execution":
		q = `SELECT zasp_retention_journal_v1.admit_execution($1::jsonb)`
	case "reserve_request":
		q = `SELECT zasp_retention_journal_v1.reserve_request($1::jsonb)`
	case "claim_send":
		q = `SELECT zasp_retention_journal_v1.claim_send($1::jsonb)`
	case "append_terminal":
		q = `SELECT zasp_retention_journal_v1.append_terminal($1::jsonb)`
	case "close_inventory":
		q = `SELECT zasp_retention_journal_v1.close_inventory($1::jsonb)`
	case "seal_partition":
		q = `SELECT zasp_retention_journal_v1.seal_partition($1::jsonb)`
	default:
		return errRuntimeUnavailable
	}
	raw, err := j.owner.journal.CommitRetentionJournal(ctx, q, body, j.owner.journalPin)
	if errors.Is(err, errRetentionJournalCommitUnknown) && len(raw) > 0 {
		if j.confirmUnknownCommit(ctx, operation, fields, raw) {
			err = nil
		}
	}
	if err != nil || decodeStrictWorkerJSON(raw, out) != nil {
		return errRuntimeUnavailable
	}
	return nil
}
func (j *retentionWriterJournal) binding(ctx context.Context) (map[string]any, error) {
	q, _, err := j.owner.request(ctx, j.input.Scope, j.input.EventIDs)
	return q, err
}
func (g *retentionJournalIndexVisibility) execution(ctx context.Context) (*retentionWriterJournal, error) {
	j, ok := runtimeindex.RetainedJournalFromContext(ctx).(*retentionWriterJournal)
	if !ok || j == nil || j.owner != g {
		return nil, errRuntimeUnavailable
	}
	return j, nil
}
func (g *retentionJournalIndexVisibility) VisibleEvents(ctx context.Context, scope domain.Scope, ids []string) (map[string]bool, error) {
	j, err := g.execution(ctx)
	if err != nil || scope != j.input.Scope {
		return nil, errRuntimeUnavailable
	}
	binding, _, err := g.request(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	key, err := retentionJournalRandom()
	if err != nil {
		return nil, err
	}
	var response struct {
		AdmissionID string `json:"admission_id"`
		Items       []struct {
			EventID string `json:"event_id"`
			Visible *bool  `json:"visible"`
		} `json:"items"`
	}
	if j.call(ctx, "admit_execution", map[string]any{"admission_key": key, "binding": binding}, &response) != nil || !retentionCycleKeyPattern.MatchString(response.AdmissionID) || len(response.Items) != len(ids) {
		return nil, errRuntimeUnavailable
	}
	out := make(map[string]bool, len(ids))
	for i, item := range response.Items {
		if item.EventID != ids[i] || item.Visible == nil {
			return nil, errRuntimeUnavailable
		}
		out[item.EventID] = *item.Visible
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.admissions) >= 1000 {
		return nil, errRuntimeUnavailable
	}
	for _, id := range j.admissions {
		if id == response.AdmissionID {
			return nil, errRuntimeUnavailable
		}
	}
	j.admissions = append(j.admissions, response.AdmissionID)
	return out, nil
}
func (j *retentionWriterJournal) ReserveRequest(ctx context.Context, d runtimeindex.RetainedRequestDescriptor) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	binding, err := j.binding(ctx)
	if err != nil || j.requests != 0 || len(j.admissions) == 0 {
		return errRuntimeUnavailable
	}
	target := "zasp-runtime-events-v1"
	if j.input.Kind == "session-index-v1" {
		target = "zasp-runtime-sessions-v1"
	}
	if j.input.Kind == "session-index-v2" {
		target = "zasp-runtime-sessions-v2"
	}
	seconds, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(d.Query, "refresh=wait_for&timeout="), "s"))
	if d.Ordinal != 0 || d.Method != "POST" || d.Target != target || d.Path != "/"+target+"/_bulk" || parseErr != nil || seconds < 1 || seconds > 30 || d.Query != "refresh=wait_for&timeout="+strconv.Itoa(seconds)+"s" || d.MediaType != "application/x-ndjson" || d.SerializerProfile != "runtime-retained-bulk-v1" || !retentionCycleKeyPattern.MatchString(d.BodySHA256) || d.BodyLength < 1 || d.BodyLength > 8<<20 || len(d.DocumentIDs) == 0 || len(d.DocumentIDs) != len(d.EventIDs) {
		return errRuntimeUnavailable
	}
	// No private lease/capability enters the public descriptor or artifact.
	descriptor := map[string]any{"ordinal": 0, "method": d.Method, "target": d.Target, "path": d.Path, "query": d.Query, "media_type": d.MediaType, "body_sha256": d.BodySHA256, "body_length": d.BodyLength, "document_ids": d.DocumentIDs, "event_ids": d.EventIDs, "serializer_profile": d.SerializerProfile, "admission_ids": append([]string(nil), j.admissions...)}
	descriptor["original_reference"], descriptor["original_version_id"], descriptor["original_digest"] = binding["input_reference"], binding["input_version_id"], binding["input_digest"]
	if j.input.Kind != "raw-index" {
		descriptor["original_reference"], descriptor["original_version_id"], descriptor["original_digest"] = binding["receipt_reference"], binding["receipt_version"], binding["receipt_digest"]
	}
	var response struct {
		Digest string `json:"reservation_digest"`
	}
	if j.call(ctx, "reserve_request", map[string]any{"binding": binding, "descriptor": descriptor}, &response) != nil || !retentionCycleKeyPattern.MatchString(response.Digest) {
		return errRuntimeUnavailable
	}
	j.reservation = response.Digest
	j.requests = 1
	return nil
}
func (j *retentionWriterJournal) ClaimSend(ctx context.Context) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	binding, err := j.binding(ctx)
	if err != nil || j.requests != 1 || j.dispatch != "" {
		return false, errRuntimeUnavailable
	}
	var response struct {
		Permitted bool   `json:"send_permitted"`
		Digest    string `json:"dispatch_digest"`
	}
	if j.call(ctx, "claim_send", map[string]any{"binding": binding, "reservation_digest": j.reservation}, &response) != nil || !response.Permitted || !retentionCycleKeyPattern.MatchString(response.Digest) {
		return false, errRuntimeUnavailable
	}
	j.dispatch = response.Digest
	return true, nil
}
func (j *retentionWriterJournal) AppendTerminal(ctx context.Context, status int, body []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.dispatch == "" || j.terminal || status != 200 || len(body) == 0 || len(body) > 8<<20 {
		return errRuntimeUnavailable
	}
	captured, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	digest := sha256.Sum256(body)
	seed := sha256.Sum256([]byte("runtime-writer-outcome-v1/" + j.executionID + "/" + hexRetentionDigest(digest)))
	seed[6] = (seed[6] & 15) | 64
	seed[8] = (seed[8] & 63) | 128
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%x-%x-%x-%x-%x", seed[:4], seed[4:6], seed[6:8], seed[8:10], seed[10:16]))
	if err != nil {
		return errRuntimeUnavailable
	}
	reference, err := domain.NewEvidenceRef(id)
	if err != nil {
		return errRuntimeUnavailable
	}
	locator := artifactstore.Locator{Scope: j.input.Scope, Reference: reference}
	artifact, putErr := j.owner.receipts.Put(captured, artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: bytes.Clone(body)})
	if putErr != nil {
		artifact, err = j.owner.receipts.Get(captured, locator)
		if err != nil {
			return errRuntimeUnavailable
		}
	}
	if artifact.Scope != locator.Scope || artifact.Reference != reference || artifact.VersionID == "" || artifact.MediaType != "application/json" || artifact.Size != int64(len(body)) || artifact.SHA256 != digest || !bytes.Equal(artifact.Body, body) {
		return errRuntimeUnavailable
	}
	locator.VersionID = artifact.VersionID
	pinned, err := j.owner.receipts.Get(captured, locator)
	if err != nil || pinned.Locator != locator || pinned.MediaType != "application/json" || pinned.Size != int64(len(body)) || pinned.SHA256 != digest || !bytes.Equal(pinned.Body, body) {
		return errRuntimeUnavailable
	}
	object, err := j.owner.receipts.ObjectReference(locator)
	if err != nil || object == "" {
		return errRuntimeUnavailable
	}
	observation := map[string]any{"reservation_digest": j.reservation, "dispatch_digest": j.dispatch, "reference": object, "version_id": locator.VersionID, "sha256": hexRetentionDigest(digest), "length": len(body), "http_status": status, "validator_profile": "runtime-retained-terminal-v1"}
	var result struct {
		Recorded bool `json:"recorded"`
	}
	if j.call(captured, "append_terminal", map[string]any{"observation": observation}, &result) != nil || !result.Recorded {
		return errRuntimeUnavailable
	}
	j.terminal = true
	return nil
}
func (g *retentionJournalIndexVisibility) RecordRetainedWrite(ctx context.Context, r runtimeindex.RetainedWriteReceipt) error {
	j, err := g.execution(ctx)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	q, session, err := g.request(ctx, r.Scope, r.EventIDs)
	if err != nil || q["batch_id"] != r.BatchID || q["generation"] != r.Generation || r.OriginalContentDigest == ([sha256.Size]byte{}) || r.Partition.ProviderContentDigest == ([sha256.Size]byte{}) {
		return errRuntimeUnavailable
	}
	digestKey := "input_digest"
	if session {
		digestKey = "receipt_digest"
	}
	if q[digestKey] != hexRetentionDigest(r.InputDigest) || len(j.admissions) == 0 || j.requests == 1 && !j.terminal {
		return errRuntimeUnavailable
	}
	binding, err := j.binding(ctx)
	if err != nil {
		return errRuntimeUnavailable
	}
	var closed struct {
		Digest string `json:"inventory_digest"`
	}
	if j.call(ctx, "close_inventory", map[string]any{"binding": binding, "admission_ids": append([]string(nil), j.admissions...), "request_count": j.requests}, &closed) != nil || !retentionCycleKeyPattern.MatchString(closed.Digest) {
		return errRuntimeUnavailable
	}
	q["admission_ids"] = append([]string(nil), j.admissions...)
	q["full_document_ids"], q["written_document_ids"], q["suppressed_document_ids"] = r.DocumentIDs, r.Partition.WrittenDocumentIDs, r.Partition.SuppressedDocumentIDs
	q["original_content_digest"], q["provider_content_digest"] = hexRetentionDigest(r.OriginalContentDigest), hexRetentionDigest(r.Partition.ProviderContentDigest)
	var result struct {
		Digest string `json:"partition_digest"`
	}
	if j.call(ctx, "seal_partition", map[string]any{"partition": q}, &result) != nil || !retentionCycleKeyPattern.MatchString(result.Digest) {
		return errRuntimeUnavailable
	}
	return nil
}
