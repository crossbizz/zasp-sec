package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type runtimeSessionSearchLease struct {
	renewal *runtimeStageLeaseRenewal
	// Empty is the legacy v1 target; only a v2 authority can issue a v2 lease.
	indexName                        string
	projectionImplementationVersion  string
	Binding                          sessionsearch.ReceiptBinding
	ReceiptReference, ReceiptVersion string
	DocumentIDs                      []string
	Attempt                          int
	LeaseUntil                       time.Time
}

type runtimeSessionSearchIndex interface {
	Apply(context.Context, sessionsearch.ReceiptBinding, []byte, []byte) (opensearchdriver.SessionWriteResult, error)
}

func (lease runtimeSessionSearchLease) currentDeadline() time.Time {
	if lease.renewal == nil {
		return lease.LeaseUntil
	}
	lease.renewal.mu.RLock()
	defer lease.renewal.mu.RUnlock()
	return lease.renewal.expiresAt
}

type runtimeSessionSearchExecutor struct {
	precise  bool
	reader   runtimeArchivedBatchReader
	receipts artifactstore.ObjectReferencingArtifactStore
	index    runtimeSessionSearchIndex
}

func newRuntimeSessionSearchExecutor(reader runtimeArchivedBatchReader, receipts artifactstore.ObjectReferencingArtifactStore, index runtimeSessionSearchIndex) (*runtimeSessionSearchExecutor, error) {
	if nilWorkerDependency(reader) || nilWorkerDependency(receipts) || nilWorkerDependency(index) {
		return nil, errRuntimeUnavailable
	}
	return &runtimeSessionSearchExecutor{reader: reader, receipts: receipts, index: index}, nil
}

func validRuntimeSessionSearchLease(lease runtimeSessionSearchLease) bool {
	if lease.Binding.Scope.Validate() != nil || lease.Binding.BatchID.IsZero() || lease.Binding.Generation < 1 || lease.Binding.ReceiptDigest == ([sha256.Size]byte{}) || lease.Attempt < 1 || lease.Attempt > 100 || lease.LeaseUntil.IsZero() {
		return false
	}
	if _, ok := runtimeReceiptLocator(lease.Binding.Scope, lease.ReceiptReference, lease.ReceiptVersion); !ok {
		return false
	}
	if len(lease.DocumentIDs) < 1 || len(lease.DocumentIDs) > 1000 {
		return false
	}
	seen := make(map[string]bool, len(lease.DocumentIDs))
	for _, id := range lease.DocumentIDs {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != id || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// Execute receives a lease only from committed PostgreSQL outbox authority.
// It never accepts a request/receipt's own digest as authority and never writes
// source events or projection receipts. The returned IDs are checkpoint inputs,
// not proof until the independently fenced database transition accepts them.
func (executor *runtimeSessionSearchExecutor) Execute(ctx context.Context, lease runtimeSessionSearchLease) (ids []string, resultErr error) {
	defer func() {
		if recover() != nil {
			ids = nil
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !validRuntimeSessionSearchLease(lease) || !lease.currentDeadline().After(time.Now()) {
		return nil, errRuntimeStageMalformed
	}
	locator, _ := runtimeReceiptLocator(lease.Binding.Scope, lease.ReceiptReference, lease.ReceiptVersion)
	artifact, err := executor.receipts.Get(ctx, locator)
	if err != nil {
		return nil, errRuntimeStageRetryable
	}
	defer clear(artifact.Body)
	validArtifact := exactRuntimeReceiptArtifact(artifact, locator)
	if executor.precise && lease.indexName == "zasp-runtime-sessions-v2" {
		validArtifact = artifact.Locator == locator && artifact.MediaType == "application/json" && artifact.Size >= 1 && artifact.Size <= 4<<20 && artifact.Size == int64(len(artifact.Body)) && artifact.SHA256 == sha256.Sum256(artifact.Body)
	}
	if !validArtifact || artifact.SHA256 != lease.Binding.ReceiptDigest || sha256.Sum256(artifact.Body) != lease.Binding.ReceiptDigest {
		return nil, errRuntimeStageMalformed
	}
	reference, err := executor.receipts.ObjectReference(artifact.Locator)
	if err != nil || reference != lease.ReceiptReference {
		return nil, errRuntimeStageMalformed
	}
	receipt, err := runtimeprojection.DecodeReceipt(artifact.Body)
	precise := false
	if err != nil && executor.precise && lease.indexName == "zasp-runtime-sessions-v2" {
		receipt, err = runtimeprojection.DecodePreciseReceipt(artifact.Body)
		precise = err == nil
	}
	if err != nil || precise && lease.projectionImplementationVersion != "runtime-projection-v3" || lease.projectionImplementationVersion != "" && receipt.ImplementationVersion != lease.projectionImplementationVersion || receipt.Scope != lease.Binding.Scope || receipt.BatchID != lease.Binding.BatchID || receipt.Generation != lease.Binding.Generation ||
		(!precise && (!exactRuntimeReceiptArtifact(artifact, locator) || receipt.ImplementationVersion != "runtime-projection-v1" && !(receipt.ImplementationVersion == "runtime-projection-v2" && lease.indexName == "zasp-runtime-sessions-v2"))) {
		return nil, errRuntimeStageMalformed
	}
	indexVersion := "runtime-index-v1"
	build := sessionsearch.BuildDocuments
	apply := executor.index.Apply
	if precise {
		capability, ok := executor.index.(runtimePreciseSessionSearchIndex)
		if !ok || nilWorkerDependency(capability) {
			return nil, errRuntimeStageMalformed
		}
		indexVersion, build, apply = "runtime-index-v2", sessionsearch.BuildPreciseDocuments, capability.ApplyPrecise
	}
	archive, err := executor.reader.Read(ctx, runtimeevent.StageLease{Scope: lease.Binding.Scope, BatchID: lease.Binding.BatchID, Generation: lease.Binding.Generation, Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: indexVersion, Attempt: lease.Attempt, LeaseExpiresAt: lease.currentDeadline(), InputReference: receipt.ArchiveReference, InputVersionID: receipt.ArchiveVersionID, InputDigest: receipt.ArchiveDigest})
	if err != nil {
		return nil, err
	}
	defer clear(archive)
	documents, err := build(lease.Binding, artifact.Body, archive)
	if err != nil || len(documents) != len(lease.DocumentIDs) {
		return nil, errRuntimeStageMalformed
	}
	for i, document := range documents {
		if document.DocumentID != lease.DocumentIDs[i] {
			return nil, errRuntimeStageMalformed
		}
	}
	if precise && (ctx.Err() != nil || !lease.currentDeadline().After(time.Now())) {
		return nil, errRuntimeStageRetryable
	}
	result, err := apply(ctx, lease.Binding, artifact.Body, archive)
	if err != nil {
		return nil, errRuntimeStageRetryable
	}
	if ctx.Err() != nil || precise && !lease.currentDeadline().After(time.Now()) || result.Scope != lease.Binding.Scope || result.BatchID != lease.Binding.BatchID || result.Generation != lease.Binding.Generation || result.ReceiptDigest != lease.Binding.ReceiptDigest || !slices.Equal(result.DocumentIDs, lease.DocumentIDs) {
		return nil, errWorkerExecution
	}
	return slices.Clone(result.DocumentIDs), nil
}
