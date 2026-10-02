package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A configured revision supplies provider trust. SQL and queue payloads can
// only select/check this revision; they cannot construct a provider client.
type auditExportTrustedPolicy struct {
	Configuration migrations.AuditExportConfiguration
	Store         auditExportWorkerArtifacts
}

type auditExportWorkerArtifacts interface {
	Put(context.Context, artifactstore.PutRequest) (artifactstore.Artifact, error)
	Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error)
	ObjectReference(artifactstore.Locator) (string, error)
	PlannedObjectReference(artifactstore.Locator) (string, error)
}

type auditExportExecutorConfig struct {
	Database                   recoveryJSONDatabase
	Policy                     auditExportTrustedPolicy
	WorkerID                   string
	LeaseSeconds, RetrySeconds int
	NewLeaseToken              func() (string, error)
}

type auditExportExecutor struct {
	config    auditExportExecutorConfig
	authority *postgresAuditExportAuthority
}

func newAuditExportExecutorContext(ctx context.Context, config auditExportExecutorConfig) (*auditExportExecutor, error) {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(config.Database) || nilWorkerDependency(config.Policy.Store) || config.NewLeaseToken == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 60 || config.LeaseSeconds > 300 || config.RetrySeconds < 1 || config.RetrySeconds > 300 {
		return nil, errWorkerExecution
	}
	authority, err := newPostgresAuditExportAuthorityContext(ctx, config.Database, config.Policy.Configuration)
	if err != nil {
		return nil, errWorkerExecution
	}
	return &auditExportExecutor{config: config, authority: authority}, nil
}

func newAuditExportExecutor(config auditExportExecutorConfig) (*auditExportExecutor, error) {
	return newAuditExportExecutorContext(context.Background(), config)
}

// Nil means verified durable terminal authority, never an empty claim. The
// later queue adapter can acknowledge only this outcome. Each provider write
// follows a persisted intent; cancellation leaves that intent for recovery.
func (executor *auditExportExecutor) Execute(ctx context.Context, scope domain.Scope, exportID string) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || executor.authority == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validRecoveryProductID(exportID) {
		return errWorkerExecution
	}
	token, err := executor.config.NewLeaseToken()
	if err != nil || !validAuditExportLeaseToken(token) {
		return errWorkerExecution
	}
	lease, err := executor.authority.Claim(ctx, scope, exportID, executor.config.WorkerID, token, executor.config.LeaseSeconds)
	if err != nil {
		return errWorkerExecution
	}
	if lease == nil {
		return executor.terminal(ctx, scope, exportID)
	}
	capture, err := executor.authority.Capture(ctx, *lease)
	if err != nil {
		return executor.retry(ctx, *lease)
	}
	if capture.FailureCode != "" {
		return executor.terminal(ctx, scope, exportID)
	}
	// Capture changed persisted state; renewals must retain this new flag.
	lease.Captured = true
	for capture.RecordedChunkCount < capture.Manifest.ChunkCount {
		renewed, err := executor.authority.Heartbeat(ctx, *lease, executor.config.LeaseSeconds)
		if err != nil {
			return executor.retry(ctx, *lease)
		}
		*lease = renewed
		page, err := executor.authority.ReadFrozenPage(ctx, *lease, capture)
		if err != nil {
			return executor.retry(ctx, *lease)
		}
		intent, err := executor.authority.PrepareChunk(ctx, *lease, page.Body)
		if err != nil {
			return executor.retry(ctx, *lease)
		}
		receipt, err := executor.writeArtifact(ctx, *lease, intent, page.Body)
		if err != nil {
			return executor.retry(ctx, *lease)
		}
		if executor.authority.RecordChunk(ctx, *lease, intent, receipt) != nil {
			return executor.retry(ctx, *lease)
		}
		capture.NextChunk++
		capture.NextEvent += page.Chunk.EventCount
		capture.RecordedChunkCount++
		capture.RecordedChunkBytes += receipt.SizeBytes
		capture.PreviousDigest = intent.SHA256
		if !validAuditExportCapture(capture, *lease) {
			return executor.retry(ctx, *lease)
		}
	}
	renewed, err := executor.authority.Heartbeat(ctx, *lease, executor.config.LeaseSeconds)
	if err != nil {
		return executor.retry(ctx, *lease)
	}
	*lease = renewed
	manifest, err := audit.EncodeExportManifest(capture.Manifest)
	if err != nil {
		return executor.retry(ctx, *lease)
	}
	intent, err := executor.authority.PrepareManifest(ctx, *lease, manifest)
	if err != nil {
		return executor.retry(ctx, *lease)
	}
	receipt, err := executor.writeArtifact(ctx, *lease, intent, manifest)
	if err != nil {
		return executor.retry(ctx, *lease)
	}
	if executor.authority.Finish(ctx, *lease, intent, receipt, capture.Manifest, auditExportCompletionID(lease.Binding)) != nil {
		return executor.retry(ctx, *lease)
	}
	if ctx.Err() != nil {
		return errWorkerExecution
	}
	return nil
}

// Export SQL hashes the canonical 64-character text, not decoded bytes. Keep
// this contract separate from historical workers' broader token format.
func validAuditExportLeaseToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == token && !bytes.Equal(decoded, make([]byte, 32))
}

func (executor *auditExportExecutor) terminal(ctx context.Context, scope domain.Scope, exportID string) error {
	state, err := executor.authority.Terminal(ctx, scope, exportID)
	if err != nil || (state != "ready" && state != "failed") || ctx.Err() != nil {
		return errWorkerExecution
	}
	return nil
}

func (executor *auditExportExecutor) retry(ctx context.Context, lease auditExportLease) error {
	// Do not detach from a canceled caller or invent a renewed lease. If a
	// fenced transition cannot finish, the retained lease/intent must recover.
	terminal, err := executor.authority.Retry(ctx, lease, executor.config.RetrySeconds)
	if err == nil && terminal && ctx.Err() == nil {
		return nil
	}
	return errWorkerExecution
}

func (executor *auditExportExecutor) writeArtifact(ctx context.Context, lease auditExportLease, intent auditExportIntent, body []byte) (auditExportArtifactReceipt, error) {
	if !executor.authority.validIntent(lease, intent) || int64(len(body)) != intent.SizeBytes {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != intent.SHA256 {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	operation, cancel, err := auditExportCaptureContext(ctx, lease)
	if err != nil {
		return auditExportArtifactReceipt{}, err
	}
	defer cancel()
	bounded, stop := context.WithTimeout(operation, 30*time.Second)
	defer stop()
	scope, ok := executor.authority.validLease(lease)
	if !ok {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	reference, err := domain.ParseEvidenceRef(intent.ArtifactID)
	if err != nil {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	locator := artifactstore.Locator{Scope: scope, Reference: reference}
	store := executor.config.Policy.Store
	planned, err := store.PlannedObjectReference(locator)
	if err != nil || planned != intent.ObjectReference || bounded.Err() != nil {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	created, err := store.Put(bounded, artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: bytes.Clone(body)})
	if err != nil || !validAuditExportVersion(created.VersionID) || created.Scope != scope || created.Reference != reference {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	locator.VersionID = created.VersionID
	if !auditExportArtifactMatches(created, locator, body, digest) || bounded.Err() != nil {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	returned, err := store.ObjectReference(locator)
	if err != nil || returned != intent.ObjectReference || bounded.Err() != nil {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	readback, err := store.Get(bounded, locator)
	if err != nil || !auditExportArtifactMatches(readback, locator, body, digest) || bounded.Err() != nil {
		return auditExportArtifactReceipt{}, errWorkerExecution
	}
	return auditExportArtifactReceipt{VersionID: readback.VersionID, SHA256: readback.SHA256, SizeBytes: readback.Size}, nil
}

func auditExportArtifactMatches(artifact artifactstore.Artifact, locator artifactstore.Locator, body []byte, digest [sha256.Size]byte) bool {
	return artifact.Locator == locator && artifact.MediaType == "application/json" && artifact.Size == int64(len(body)) && artifact.SHA256 == digest && sha256.Sum256(artifact.Body) == digest && bytes.Equal(artifact.Body, body)
}

func auditExportCompletionID(binding audit.ExportBinding) string {
	digest := sha256.Sum256([]byte(binding.ExportID + "\x00" + binding.CaptureID + "\x00audit-export-completion"))
	digest[6] = (digest[6] & 15) | 64
	digest[8] = (digest[8] & 63) | 128
	value := hex.EncodeToString(digest[:16])
	return "pid_" + value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
}

type auditExportStoragePolicy struct {
	Schema                string `json:"schema"`
	PolicyID              string `json:"policy_id"`
	PolicyDigest          string `json:"policy_digest"`
	Bucket                string `json:"bucket"`
	ExpectedBucketOwner   string `json:"expected_bucket_owner"`
	KMSKeyARN             string `json:"kms_key_arn"`
	MaximumExportBytes    int64  `json:"maximum_export_bytes"`
	MaximumRetainedBytes  int64  `json:"maximum_retained_bytes"`
	MaximumInflight       int    `json:"maximum_inflight"`
	CaptureTimeoutSeconds int    `json:"capture_timeout_seconds"`
}

type auditExportLease struct {
	Binding       audit.ExportBinding
	Policy        auditExportStoragePolicy
	Generation    int64
	Attempt       int
	ExpiresAt     time.Time
	Captured      bool
	worker, token string
}

type auditExportCapture struct {
	Manifest                                                     audit.ExportManifest
	NextChunk, NextEvent, RecordedChunkCount, RecordedChunkBytes int64
	PreviousDigest                                               string
	FailureCode                                                  string
}

type auditExportFrozenPage struct {
	Chunk     audit.ExportChunk
	Body      []byte
	NextEvent *int64
}

type auditExportIntent struct {
	Binding                                   audit.ExportBinding
	Policy                                    auditExportStoragePolicy
	Kind, ArtifactID, ObjectReference, SHA256 string
	SizeBytes                                 int64
	Ordinal, FirstEvent, EventCount           int64
	PreviousDigest                            string
}

// Only the executor's exact pinned provider readback can supply this receipt.
// It carries no caller-selected destination; SQL uses the prepared intent.
type auditExportArtifactReceipt struct {
	VersionID string
	SHA256    [sha256.Size]byte
	SizeBytes int64
}

func auditExportCaptureContext(ctx context.Context, lease auditExportLease) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || lease.Policy.CaptureTimeoutSeconds < 1 || lease.Policy.CaptureTimeoutSeconds > 120 {
		return nil, nil, errWorkerExecution
	}
	now := time.Now()
	deadline := now.Add(time.Duration(lease.Policy.CaptureTimeoutSeconds) * time.Second)
	// Capture owns the SQL job/org locks. A concurrent heartbeat cannot extend
	// this confirmed budget. Leave five seconds for transaction finalization.
	if leaseDeadline := lease.ExpiresAt.Add(-5 * time.Second); leaseDeadline.Before(deadline) {
		deadline = leaseDeadline
	}
	if parent, ok := ctx.Deadline(); ok && parent.Add(-5*time.Second).Before(deadline) {
		deadline = parent.Add(-5 * time.Second)
	}
	if !deadline.After(now) {
		return nil, nil, errWorkerExecution
	}
	operation, cancel := context.WithDeadline(ctx, deadline)
	return operation, cancel, nil
}

func auditExportPolicyWire(configuration migrations.AuditExportConfiguration) (auditExportStoragePolicy, error) {
	digest, err := migrations.AuditExportPolicyDigest(configuration)
	if err != nil {
		return auditExportStoragePolicy{}, errWorkerExecution
	}
	return auditExportStoragePolicy{Schema: "audit-export-policy-v1", PolicyID: configuration.PolicyID, PolicyDigest: digest, Bucket: configuration.Bucket, ExpectedBucketOwner: configuration.ExpectedBucketOwner, KMSKeyARN: configuration.KMSKeyARN, MaximumExportBytes: configuration.MaximumExportBytes, MaximumRetainedBytes: configuration.MaximumRetainedBytes, MaximumInflight: configuration.MaximumInflight, CaptureTimeoutSeconds: configuration.CaptureTimeoutSeconds}, nil
}

// This checks structural feasibility, not provider durability. SQL owns the
// frozen plan and the contiguous recorded prefix; provider execution follows.
func validAuditExportCapture(capture auditExportCapture, lease auditExportLease) bool {
	m := capture.Manifest
	encoded, err := audit.EncodeExportManifest(m)
	if err != nil || capture.FailureCode != "" || m.Binding != lease.Binding || m.ChunkBytes > lease.Policy.MaximumExportBytes-int64(len(encoded)) ||
		capture.RecordedChunkCount < 0 || capture.RecordedChunkCount > m.ChunkCount || capture.RecordedChunkBytes < 0 || capture.RecordedChunkBytes > m.ChunkBytes ||
		capture.NextChunk != capture.RecordedChunkCount+1 || capture.NextChunk > 1<<53-1 || capture.NextEvent < 1 || capture.NextEvent > m.EventCount+1 || capture.NextEvent > 1<<53-1 {
		return false
	}
	prefix := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: m.Binding, EventCount: capture.NextEvent - 1, ChunkCount: capture.RecordedChunkCount, ChunkBytes: capture.RecordedChunkBytes, ChainRoot: capture.PreviousDigest}
	if _, err := audit.EncodeExportManifest(prefix); err != nil {
		return false
	}
	remainingChunks, remainingEvents, remainingBytes := m.ChunkCount-prefix.ChunkCount, m.EventCount-prefix.EventCount, m.ChunkBytes-prefix.ChunkBytes
	if remainingChunks == 0 {
		return remainingEvents == 0 && remainingBytes == 0 && capture.PreviousDigest == m.ChainRoot
	}
	return remainingEvents >= remainingChunks && (remainingEvents-1)/audit.ExportMaximumChunkEvents+1 <= remainingChunks &&
		remainingBytes >= remainingChunks && (remainingBytes-1)/audit.ExportMaximumChunkBytes+1 <= remainingChunks
}
