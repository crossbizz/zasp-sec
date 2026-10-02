package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const auditExportWorkerReadySQL = `SELECT to_jsonb(zasp_audit_export_worker_readiness($1,$2,$3))`
const auditExportWorkerClaimSQL = `SELECT zasp_audit_export_claim($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
const auditExportWorkerHeartbeatSQL = `SELECT zasp_audit_export_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const auditExportWorkerCaptureSQL = `SELECT zasp_audit_export_capture($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
const auditExportWorkerFrozenPageSQL = `SELECT zasp_audit_export_frozen_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const auditExportWorkerPrepareChunkSQL = `SELECT zasp_audit_export_prepare_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const auditExportWorkerPrepareManifestSQL = `SELECT zasp_audit_export_prepare_manifest($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const auditExportWorkerRecordChunkSQL = `SELECT zasp_audit_export_record_chunk($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
const auditExportWorkerFinishSQL = `SELECT zasp_audit_export_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
const auditExportWorkerTerminalSQL = `SELECT zasp_audit_export_terminal($1,$2,$3,$4,$5,$6,$7,$8)`
const auditExportWorkerRetrySQL = `SELECT zasp_audit_export_retry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

func (authority *postgresAuditExportAuthority) Finish(ctx context.Context, lease auditExportLease, intent auditExportIntent, receipt auditExportArtifactReceipt, manifest audit.ExportManifest, completionAuditID string) error {
	if !authority.validIntent(lease, intent) || intent.Kind != "manifest" || !validAuditExportVersion(receipt.VersionID) || receipt.SizeBytes != intent.SizeBytes || hex.EncodeToString(receipt.SHA256[:]) != intent.SHA256 || !validRecoveryProductID(completionAuditID) || slices.Contains([]string{lease.Binding.OrganizationID, lease.Binding.WorkspaceID, lease.Binding.EnvironmentID, lease.Binding.ExportID, lease.Binding.CaptureID, intent.ArtifactID}, completionAuditID) {
		return errWorkerExecution
	}
	canonical, err := audit.EncodeExportManifest(manifest)
	if err != nil || manifest.Binding != lease.Binding || int64(len(canonical)) != intent.SizeBytes || sha256.Sum256(canonical) != receipt.SHA256 {
		return errWorkerExecution
	}
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return err
	}
	defer cancel()
	if authority.Ready(operation) != nil {
		return errWorkerExecution
	}
	body, err := authority.query(operation, 8192, auditExportWorkerFinishSQL, append(authority.leaseArguments(lease), receipt.VersionID, receipt.SHA256[:], receipt.SizeBytes, completionAuditID)...)
	if err != nil {
		return err
	}
	descriptor, err := audit.DecodeExportDescriptor(body)
	if err != nil || descriptor.Status != "ready" || !auditExportDescriptorBinding(descriptor, lease.Binding) || descriptor.ManifestSHA256 != intent.SHA256 || *descriptor.EventCount != manifest.EventCount || *descriptor.ChunkCount != manifest.ChunkCount || *descriptor.ChunkBytes != manifest.ChunkBytes || operation.Err() != nil {
		return errWorkerExecution
	}
	return nil
}
func (authority *postgresAuditExportAuthority) Terminal(ctx context.Context, scope domain.Scope, exportID string) (string, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validRecoveryProductID(exportID) {
		return "", errWorkerExecution
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if authority.Ready(operation) != nil {
		return "", errWorkerExecution
	}
	digest, _ := hex.DecodeString(authority.policy.PolicyDigest)
	body, err := authority.query(operation, 16384, auditExportWorkerTerminalSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), exportID, authority.policy.PolicyID, digest, authority.checksum, authority.fingerprint)
	if err != nil {
		return "", err
	}
	if fields, err := auditExportWorkerObject(body, 16384, "state"); err == nil {
		var state string
		if json.Unmarshal(fields["state"], &state) != nil || state != "nonterminal" || operation.Err() != nil {
			return "", errWorkerExecution
		}
		return state, nil
	}
	fields, err := auditExportWorkerObject(body, 16384, "state", "export")
	if err != nil {
		return "", errWorkerExecution
	}
	var state string
	if json.Unmarshal(fields["state"], &state) != nil || (state != "ready" && state != "failed") {
		return "", errWorkerExecution
	}
	descriptor, err := audit.DecodeExportDescriptor(fields["export"])
	binding := audit.ExportBinding{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ExportID: exportID}
	if err != nil || descriptor.Status != state || !auditExportDescriptorBinding(descriptor, binding) || operation.Err() != nil {
		return "", errWorkerExecution
	}
	return state, nil
}
func (authority *postgresAuditExportAuthority) Retry(ctx context.Context, lease auditExportLease, seconds int) (bool, error) {
	if _, ok := authority.validLease(lease); !ok || seconds < 0 || seconds > 300 {
		return false, errWorkerExecution
	}
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return false, err
	}
	defer cancel()
	if authority.Ready(operation) != nil {
		return false, errWorkerExecution
	}
	body, err := authority.query(operation, 1024, auditExportWorkerRetrySQL, append(authority.leaseArguments(lease), seconds, "execution_failed")...)
	if err != nil {
		return false, err
	}
	fields, err := auditExportWorkerObject(body, 1024, "state", "failure_code", "available_at")
	if err != nil {
		return false, errWorkerExecution
	}
	var state string
	if json.Unmarshal(fields["state"], &state) != nil {
		return false, errWorkerExecution
	}
	if state == "failed" {
		var code string
		if json.Unmarshal(fields["failure_code"], &code) != nil || code != "execution_failed" || !bytes.Equal(bytes.TrimSpace(fields["available_at"]), []byte("null")) || operation.Err() != nil {
			return false, errWorkerExecution
		}
		return true, nil
	}
	var available string
	if state != "retry" || seconds == 0 || !bytes.Equal(bytes.TrimSpace(fields["failure_code"]), []byte("null")) || json.Unmarshal(fields["available_at"], &available) != nil {
		return false, errWorkerExecution
	}
	const layout = "2006-01-02T15:04:05.000000Z"
	stamp, err := time.Parse(layout, available)
	if err != nil || stamp.IsZero() || stamp.Year() < 1 || stamp.Format(layout) != available || operation.Err() != nil {
		return false, errWorkerExecution
	}
	return false, nil
}

func auditExportDescriptorBinding(descriptor audit.ExportDescriptor, binding audit.ExportBinding) bool {
	return descriptor.ID == binding.ExportID && descriptor.OrganizationID == binding.OrganizationID && descriptor.WorkspaceID == binding.WorkspaceID && descriptor.EnvironmentID == binding.EnvironmentID
}

func (authority *postgresAuditExportAuthority) PrepareChunk(ctx context.Context, lease auditExportLease, body []byte) (auditExportIntent, error) {
	if _, ok := authority.validLease(lease); !ok || !lease.Captured || int64(len(body)) > lease.Policy.MaximumExportBytes {
		return auditExportIntent{}, errWorkerExecution
	}
	chunk, err := audit.DecodeExportChunk(body)
	if err != nil || chunk.Binding != lease.Binding {
		return auditExportIntent{}, errWorkerExecution
	}
	return authority.prepareIntent(ctx, lease, body, auditExportIntent{Binding: chunk.Binding, Policy: lease.Policy, Kind: "chunk", Ordinal: chunk.Ordinal, FirstEvent: chunk.FirstEvent, EventCount: chunk.EventCount, PreviousDigest: chunk.PreviousDigest})
}
func (authority *postgresAuditExportAuthority) PrepareManifest(ctx context.Context, lease auditExportLease, body []byte) (auditExportIntent, error) {
	if _, ok := authority.validLease(lease); !ok || !lease.Captured {
		return auditExportIntent{}, errWorkerExecution
	}
	manifest, err := audit.DecodeExportManifest(body)
	if err != nil || manifest.Binding != lease.Binding || manifest.ChunkBytes > lease.Policy.MaximumExportBytes-int64(len(body)) {
		return auditExportIntent{}, errWorkerExecution
	}
	return authority.prepareIntent(ctx, lease, body, auditExportIntent{Binding: manifest.Binding, Policy: lease.Policy, Kind: "manifest"})
}
func (authority *postgresAuditExportAuthority) RecordChunk(ctx context.Context, lease auditExportLease, intent auditExportIntent, receipt auditExportArtifactReceipt) error {
	if !authority.validIntent(lease, intent) || intent.Kind != "chunk" || !validAuditExportVersion(receipt.VersionID) || receipt.SizeBytes != intent.SizeBytes || hex.EncodeToString(receipt.SHA256[:]) != intent.SHA256 {
		return errWorkerExecution
	}
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return err
	}
	defer cancel()
	if authority.Ready(operation) != nil {
		return errWorkerExecution
	}
	body, err := authority.query(operation, 1024, auditExportWorkerRecordChunkSQL, append(authority.leaseArguments(lease), intent.Ordinal, receipt.VersionID, receipt.SHA256[:], receipt.SizeBytes)...)
	if err != nil {
		return err
	}
	fields, err := auditExportWorkerObject(body, 1024, "recorded")
	if err != nil || !bytes.Equal(bytes.TrimSpace(fields["recorded"]), []byte("true")) || operation.Err() != nil {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresAuditExportAuthority) prepareIntent(ctx context.Context, lease auditExportLease, body []byte, want auditExportIntent) (auditExportIntent, error) {
	digest := sha256.Sum256(body)
	want.SHA256 = hex.EncodeToString(digest[:])
	want.SizeBytes = int64(len(body))
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return auditExportIntent{}, err
	}
	defer cancel()
	if authority.Ready(operation) != nil {
		return auditExportIntent{}, errWorkerExecution
	}
	sql := auditExportWorkerPrepareChunkSQL
	keys := []string{"binding", "storage_policy", "kind", "artifact_id", "object_reference", "sha256", "size_bytes"}
	if want.Kind == "chunk" {
		keys = append(keys, "ordinal", "first_event", "event_count", "previous_digest")
	} else {
		sql = auditExportWorkerPrepareManifestSQL
	}
	// Preserve the caller's canonical body. Its digest/range expectation was
	// fixed before dispatch; a SQL transport cannot redefine it by mutating args.
	response, err := authority.query(operation, 16384, sql, append(authority.leaseArguments(lease), bytes.Clone(body))...)
	if err != nil {
		return auditExportIntent{}, err
	}
	fields, err := auditExportWorkerObject(response, 16384, keys...)
	if err != nil || !auditExportNonNull(fields) || !auditExportBindingObject(fields["binding"]) || !auditExportPolicyObject(fields["storage_policy"]) {
		return auditExportIntent{}, errWorkerExecution
	}
	var wire struct {
		Binding         audit.ExportBinding      `json:"binding"`
		Policy          auditExportStoragePolicy `json:"storage_policy"`
		Kind            string                   `json:"kind"`
		ArtifactID      string                   `json:"artifact_id"`
		ObjectReference string                   `json:"object_reference"`
		SHA256          string                   `json:"sha256"`
		SizeBytes       int64                    `json:"size_bytes"`
		Ordinal         int64                    `json:"ordinal"`
		FirstEvent      int64                    `json:"first_event"`
		EventCount      int64                    `json:"event_count"`
		PreviousDigest  string                   `json:"previous_digest"`
	}
	if json.Unmarshal(response, &wire) != nil {
		return auditExportIntent{}, errWorkerExecution
	}
	got := auditExportIntent{Binding: wire.Binding, Policy: wire.Policy, Kind: wire.Kind, ArtifactID: wire.ArtifactID, ObjectReference: wire.ObjectReference, SHA256: wire.SHA256, SizeBytes: wire.SizeBytes, Ordinal: wire.Ordinal, FirstEvent: wire.FirstEvent, EventCount: wire.EventCount, PreviousDigest: wire.PreviousDigest}
	want.ArtifactID = got.ArtifactID
	want.ObjectReference = got.ObjectReference
	if got != want || !authority.validIntent(lease, got) || operation.Err() != nil {
		return auditExportIntent{}, errWorkerExecution
	}
	return got, nil
}

func (authority *postgresAuditExportAuthority) validIntent(lease auditExportLease, intent auditExportIntent) bool {
	scope, ok := authority.validLease(lease)
	if !ok || !lease.Captured || intent.Binding != lease.Binding || intent.Policy != lease.Policy || !validRecoveryProductID(intent.ArtifactID) || !validAuditExportDigest(intent.SHA256) || intent.SizeBytes < 1 {
		return false
	}
	// Match retrieval authority: an artifact cannot alias a scope or job
	// identity, even when its scoped destination is changed consistently.
	if slices.Contains([]string{lease.Binding.OrganizationID, lease.Binding.WorkspaceID, lease.Binding.EnvironmentID, lease.Binding.ExportID, lease.Binding.CaptureID}, intent.ArtifactID) {
		return false
	}
	id, _ := domain.ParseProductID(intent.ArtifactID)
	key, err := bucketlayout.ExportKey(scope, id)
	if err != nil || intent.ObjectReference != "s3://"+lease.Policy.Bucket+"/"+key {
		return false
	}
	if intent.Kind == "manifest" {
		return intent.SizeBytes <= 2048 && intent.Ordinal == 0 && intent.FirstEvent == 0 && intent.EventCount == 0 && intent.PreviousDigest == ""
	}
	if intent.Kind != "chunk" || intent.SizeBytes > audit.ExportMaximumChunkBytes || intent.Ordinal < 1 || intent.Ordinal > 1<<53-1 || intent.FirstEvent < intent.Ordinal || intent.EventCount < 1 || intent.EventCount > audit.ExportMaximumChunkEvents || intent.FirstEvent > (1<<53-1)-intent.EventCount+1 || !validAuditExportDigest(intent.PreviousDigest) {
		return false
	}
	if intent.Ordinal == 1 {
		return intent.FirstEvent == 1 && intent.PreviousDigest == audit.ExportZeroDigest
	}
	return intent.PreviousDigest != audit.ExportZeroDigest && (intent.FirstEvent-2)/audit.ExportMaximumChunkEvents+1 <= intent.Ordinal-1
}

func validAuditExportDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validAuditExportVersion(value string) bool {
	if value == "" || value == "null" || len(value) > 1024 {
		return false
	}
	for _, char := range value {
		if char < 33 || char > 126 {
			return false
		}
	}
	return true
}

func (authority *postgresAuditExportAuthority) Capture(ctx context.Context, lease auditExportLease) (auditExportCapture, error) {
	if _, ok := authority.validLease(lease); !ok {
		return auditExportCapture{}, errWorkerExecution
	}
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return auditExportCapture{}, err
	}
	defer cancel()
	if authority.Ready(operation) != nil {
		return auditExportCapture{}, errWorkerExecution
	}
	body, err := authority.query(operation, 16384, auditExportWorkerCaptureSQL, authority.leaseArguments(lease)...)
	if err != nil {
		return auditExportCapture{}, err
	}
	// Failure has a separate closed shape. It cannot carry partial progress.
	if fields, err := auditExportWorkerObject(body, 16384, "state", "failure_code"); err == nil {
		var state, code string
		if json.Unmarshal(fields["state"], &state) != nil || json.Unmarshal(fields["failure_code"], &code) != nil || state != "failed" || (code != "capacity_exceeded" && code != "invalid_source") || operation.Err() != nil {
			return auditExportCapture{}, errWorkerExecution
		}
		return auditExportCapture{FailureCode: code}, nil
	}
	fields, err := auditExportWorkerObject(body, 16384, "state", "captured", "binding", "storage_policy", "event_count", "chunk_count", "chunk_bytes", "chain_root", "next_chunk", "next_event", "recorded_chunk_count", "recorded_chunk_bytes", "previous_digest")
	if err != nil || !auditExportNonNull(fields) || !auditExportBindingObject(fields["binding"]) || !auditExportPolicyObject(fields["storage_policy"]) {
		return auditExportCapture{}, errWorkerExecution
	}
	var wire struct {
		State              string                   `json:"state"`
		Captured           bool                     `json:"captured"`
		Binding            audit.ExportBinding      `json:"binding"`
		Policy             auditExportStoragePolicy `json:"storage_policy"`
		EventCount         int64                    `json:"event_count"`
		ChunkCount         int64                    `json:"chunk_count"`
		ChunkBytes         int64                    `json:"chunk_bytes"`
		ChainRoot          string                   `json:"chain_root"`
		NextChunk          int64                    `json:"next_chunk"`
		NextEvent          int64                    `json:"next_event"`
		RecordedChunkCount int64                    `json:"recorded_chunk_count"`
		RecordedChunkBytes int64                    `json:"recorded_chunk_bytes"`
		PreviousDigest     string                   `json:"previous_digest"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.State != "processing" || !wire.Captured || wire.Policy != lease.Policy {
		return auditExportCapture{}, errWorkerExecution
	}
	result := auditExportCapture{Manifest: audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: wire.Binding, EventCount: wire.EventCount, ChunkCount: wire.ChunkCount, ChunkBytes: wire.ChunkBytes, ChainRoot: wire.ChainRoot}, NextChunk: wire.NextChunk, NextEvent: wire.NextEvent, RecordedChunkCount: wire.RecordedChunkCount, RecordedChunkBytes: wire.RecordedChunkBytes, PreviousDigest: wire.PreviousDigest}
	if !validAuditExportCapture(result, lease) || operation.Err() != nil {
		return auditExportCapture{}, errWorkerExecution
	}
	return result, nil
}

func (authority *postgresAuditExportAuthority) ReadFrozenPage(ctx context.Context, lease auditExportLease, capture auditExportCapture) (auditExportFrozenPage, error) {
	if _, ok := authority.validLease(lease); !ok || !validAuditExportCapture(capture, lease) || capture.RecordedChunkCount == capture.Manifest.ChunkCount {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return auditExportFrozenPage{}, err
	}
	defer cancel()
	if authority.Ready(operation) != nil {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	body, err := authority.query(operation, audit.ExportMaximumChunkBytes, auditExportWorkerFrozenPageSQL, append(authority.leaseArguments(lease), capture.NextEvent)...)
	if err != nil {
		return auditExportFrozenPage{}, err
	}
	fields, err := auditExportWorkerObject(body, audit.ExportMaximumChunkBytes, "binding", "ordinal", "first_event", "event_count", "previous_digest", "events", "next_event")
	if err != nil || !auditExportBindingObject(fields["binding"]) {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	for key, value := range fields {
		if key != "next_event" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return auditExportFrozenPage{}, errWorkerExecution
		}
	}
	var wire struct {
		Binding        audit.ExportBinding `json:"binding"`
		Ordinal        int64               `json:"ordinal"`
		FirstEvent     int64               `json:"first_event"`
		EventCount     int64               `json:"event_count"`
		PreviousDigest string              `json:"previous_digest"`
		NextEvent      *int64              `json:"next_event"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Binding != lease.Binding || wire.Ordinal != capture.NextChunk || wire.FirstEvent != capture.NextEvent || wire.PreviousDigest != capture.PreviousDigest || wire.EventCount < 1 || wire.EventCount > audit.ExportMaximumChunkEvents || wire.EventCount > capture.Manifest.EventCount-wire.FirstEvent+1 {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	decoder := json.NewDecoder(bytes.NewReader(fields["events"]))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('[') {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	events := make([]audit.ExportEvent, 0, int(wire.EventCount))
	for decoder.More() {
		if len(events) >= int(wire.EventCount) {
			return auditExportFrozenPage{}, errWorkerExecution
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return auditExportFrozenPage{}, errWorkerExecution
		}
		event, err := audit.DecodeExportEvent(raw)
		if err != nil {
			return auditExportFrozenPage{}, errWorkerExecution
		}
		events = append(events, event)
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(']') || decoder.Decode(&struct{}{}) != io.EOF {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: wire.Binding, Ordinal: wire.Ordinal, FirstEvent: wire.FirstEvent, EventCount: wire.EventCount, PreviousDigest: wire.PreviousDigest, Events: events}
	canonical, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	digest := sha256.Sum256(canonical)
	after := capture
	after.NextChunk++
	after.NextEvent += wire.EventCount
	after.RecordedChunkCount++
	after.RecordedChunkBytes += int64(len(canonical))
	after.PreviousDigest = hex.EncodeToString(digest[:])
	if !validAuditExportCapture(after, lease) {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	if after.RecordedChunkCount == after.Manifest.ChunkCount {
		if wire.NextEvent != nil {
			return auditExportFrozenPage{}, errWorkerExecution
		}
	} else if wire.NextEvent == nil || *wire.NextEvent != after.NextEvent {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	if operation.Err() != nil {
		return auditExportFrozenPage{}, errWorkerExecution
	}
	return auditExportFrozenPage{Chunk: chunk, Body: canonical, NextEvent: wire.NextEvent}, nil
}

func auditExportNonNull(fields map[string]json.RawMessage) bool {
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func auditExportBindingObject(body []byte) bool {
	fields, err := auditExportWorkerObject(body, 1024, "organization_id", "workspace_id", "environment_id", "export_id", "capture_id")
	return err == nil && auditExportNonNull(fields)
}

func auditExportPolicyObject(body []byte) bool {
	fields, err := auditExportWorkerObject(body, 4096, "schema", "policy_id", "policy_digest", "bucket", "expected_bucket_owner", "kms_key_arn", "maximum_export_bytes", "maximum_retained_bytes", "maximum_inflight", "capture_timeout_seconds")
	return err == nil && auditExportNonNull(fields)
}

type postgresAuditExportAuthority struct {
	database              recoveryJSONDatabase
	policy                auditExportStoragePolicy
	checksum, fingerprint string
}

func newPostgresAuditExportAuthorityContext(ctx context.Context, database recoveryJSONDatabase, policy migrations.AuditExportConfiguration) (*postgresAuditExportAuthority, error) {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(database) {
		return nil, errRuntimeUnavailable
	}
	wire, err := auditExportPolicyWire(policy)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	authority := &postgresAuditExportAuthority{database: database, policy: wire, checksum: migrations.ProductionAuditExports().Checksum(), fingerprint: migrations.ProductionAuditExportsSemanticFingerprint()}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if authority.Ready(ctx) != nil {
		return nil, errRuntimeUnavailable
	}
	return authority, nil
}

func newPostgresAuditExportAuthority(database recoveryJSONDatabase, policy migrations.AuditExportConfiguration) (*postgresAuditExportAuthority, error) {
	return newPostgresAuditExportAuthorityContext(context.Background(), database, policy)
}

func (authority *postgresAuditExportAuthority) Ready(ctx context.Context) error {
	if authority.runContextReady(ctx) != nil {
		return errRuntimeUnavailable
	}
	body, err := authority.query(ctx, 16, auditExportWorkerReadySQL, authority.checksum, authority.fingerprint, "zasp_audit_export_worker")
	if err != nil || !bytes.Equal(bytes.TrimSpace(body), []byte("true")) {
		return errRuntimeUnavailable
	}
	return nil
}

// Actual PostgreSQL adapters expose the application-pinned54 check. Absence of
// the release preserves52/53 behavior; no presence or readiness is cached.
func (authority *postgresAuditExportAuthority) runContextReady(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = errWorkerExecution
		}
	}()
	if authority == nil || nilWorkerDependency(authority.database) || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	if release, ok := authority.database.(interface {
		SecurityAgentRunContextAvailable(context.Context) (bool, error)
	}); ok {
		if _, err := release.SecurityAgentRunContextAvailable(ctx); err != nil {
			return errWorkerExecution
		}
	}
	if ctx.Err() != nil {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresAuditExportAuthority) query(ctx context.Context, maximum int, sql string, args ...any) (body json.RawMessage, resultErr error) {
	defer func() {
		if recover() != nil {
			body = nil
			resultErr = errWorkerExecution
		}
	}()
	if authority == nil || nilWorkerDependency(authority.database) || ctx == nil || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	body, err := authority.database.QueryJSON(ctx, sql, args...)
	if err != nil || ctx.Err() != nil || len(body) < 1 || len(body) > maximum || !utf8.Valid(body) {
		return nil, errWorkerExecution
	}
	return body, nil
}

func (authority *postgresAuditExportAuthority) Claim(ctx context.Context, scope domain.Scope, exportID, worker, token string, seconds int) (*auditExportLease, error) {
	if authority == nil || scope.Validate() != nil || !validRecoveryProductID(exportID) || !validAuditExportWorkerCall(worker, token, seconds) || authority.Ready(ctx) != nil {
		return nil, errWorkerExecution
	}
	digest, _ := hex.DecodeString(authority.policy.PolicyDigest)
	body, err := authority.query(ctx, 16384, auditExportWorkerClaimSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), exportID, worker, token, seconds, authority.policy.PolicyID, digest, authority.checksum, authority.fingerprint)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil, nil
	}
	return authority.decodeLease(body, scope, exportID, worker, token, seconds)
}

func (authority *postgresAuditExportAuthority) Heartbeat(ctx context.Context, lease auditExportLease, seconds int) (auditExportLease, error) {
	scope, ok := authority.validLease(lease)
	if !ok || !validAuditExportWorkerCall(lease.worker, lease.token, seconds) || authority.Ready(ctx) != nil {
		return auditExportLease{}, errWorkerExecution
	}
	body, err := authority.query(ctx, 16384, auditExportWorkerHeartbeatSQL, append(authority.leaseArguments(lease), seconds)...)
	if err != nil {
		return auditExportLease{}, err
	}
	renewed, err := authority.decodeLease(body, scope, lease.Binding.ExportID, lease.worker, lease.token, seconds)
	if err != nil || renewed.Binding != lease.Binding || renewed.Generation != lease.Generation || renewed.Attempt != lease.Attempt || renewed.Captured != lease.Captured || renewed.ExpiresAt.Before(lease.ExpiresAt) {
		return auditExportLease{}, errWorkerExecution
	}
	return *renewed, nil
}

func validAuditExportWorkerCall(worker, token string, seconds int) bool {
	return workerIdentityPattern.MatchString(worker) && validAuditExportLeaseToken(token) && seconds >= 60 && seconds <= 300
}

func auditExportWorkerObject(body []byte, maximum int, keys ...string) (map[string]json.RawMessage, error) {
	if len(body) < 1 || len(body) > maximum || !utf8.Valid(body) {
		return nil, errWorkerExecution
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errWorkerExecution
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !slices.Contains(keys, name) || fields[name] != nil {
			return nil, errWorkerExecution
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, errWorkerExecution
		}
		fields[name] = raw
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || len(fields) != len(keys) {
		return nil, errWorkerExecution
	}
	return fields, nil
}

func (authority *postgresAuditExportAuthority) decodeLease(body []byte, scope domain.Scope, exportID, worker, token string, seconds int) (*auditExportLease, error) {
	fields, err := auditExportWorkerObject(body, 16384, "organization_id", "workspace_id", "environment_id", "export_id", "capture_id", "policy_id", "policy_digest", "generation", "attempt", "lease_expires_at", "captured", "storage_policy")
	if err != nil {
		return nil, err
	}
	if _, err := auditExportWorkerObject(fields["storage_policy"], 4096, "schema", "policy_id", "policy_digest", "bucket", "expected_bucket_owner", "kms_key_arn", "maximum_export_bytes", "maximum_retained_bytes", "maximum_inflight", "capture_timeout_seconds"); err != nil {
		return nil, err
	}
	var wire struct {
		Organization string                   `json:"organization_id"`
		Workspace    string                   `json:"workspace_id"`
		Environment  string                   `json:"environment_id"`
		Export       string                   `json:"export_id"`
		Capture      string                   `json:"capture_id"`
		PolicyID     string                   `json:"policy_id"`
		PolicyDigest string                   `json:"policy_digest"`
		Generation   int64                    `json:"generation"`
		Attempt      int                      `json:"attempt"`
		ExpiresAt    time.Time                `json:"lease_expires_at"`
		Captured     bool                     `json:"captured"`
		Policy       auditExportStoragePolicy `json:"storage_policy"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Organization != scope.OrganizationID().String() || wire.Workspace != scope.WorkspaceID().String() || wire.Environment != scope.EnvironmentID().String() || wire.Export != exportID || wire.PolicyID != authority.policy.PolicyID || wire.PolicyDigest != authority.policy.PolicyDigest || wire.Policy != authority.policy || wire.Generation < 1 || wire.Generation > 1<<53-1 || wire.Attempt < 1 || int64(wire.Attempt) > 1<<31-1 || !validSessionSearchDeadline(wire.ExpiresAt, seconds) {
		return nil, errWorkerExecution
	}
	captured := bytes.TrimSpace(fields["captured"])
	if !bytes.Equal(captured, []byte("true")) && !bytes.Equal(captured, []byte("false")) {
		return nil, errWorkerExecution
	}
	lease := &auditExportLease{Binding: audit.ExportBinding{OrganizationID: wire.Organization, WorkspaceID: wire.Workspace, EnvironmentID: wire.Environment, ExportID: wire.Export, CaptureID: wire.Capture}, Policy: wire.Policy, Generation: wire.Generation, Attempt: wire.Attempt, ExpiresAt: wire.ExpiresAt.UTC(), Captured: wire.Captured, worker: worker, token: token}
	if _, ok := authority.validLease(*lease); !ok {
		return nil, errWorkerExecution
	}
	return lease, nil
}

func (authority *postgresAuditExportAuthority) validLease(lease auditExportLease) (domain.Scope, bool) {
	if authority == nil || lease.Policy != authority.policy || lease.Generation < 1 || lease.Generation > 1<<53-1 || lease.Attempt < 1 || int64(lease.Attempt) > 1<<31-1 || !validAuditExportWorkerCall(lease.worker, lease.token, 60) || !lease.ExpiresAt.After(time.Now()) {
		return domain.Scope{}, false
	}
	if _, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: lease.Binding, ChainRoot: audit.ExportZeroDigest}); err != nil {
		return domain.Scope{}, false
	}
	org, _ := domain.ParseProductID(lease.Binding.OrganizationID)
	workspace, _ := domain.ParseProductID(lease.Binding.WorkspaceID)
	environment, _ := domain.ParseProductID(lease.Binding.EnvironmentID)
	scope, err := domain.NewScope(org, workspace, environment)
	return scope, err == nil
}

func (authority *postgresAuditExportAuthority) leaseArguments(lease auditExportLease) []any {
	digest, _ := hex.DecodeString(lease.Policy.PolicyDigest)
	return []any{lease.Binding.OrganizationID, lease.Binding.WorkspaceID, lease.Binding.EnvironmentID, lease.Binding.ExportID, lease.Binding.CaptureID, lease.Generation, lease.Attempt, lease.worker, lease.token, lease.Policy.PolicyID, digest, authority.checksum, authority.fingerprint}
}
