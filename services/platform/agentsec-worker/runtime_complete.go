package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

type runtimeCompleteExecutorConfig struct {
	Receipts              artifactstore.ObjectReferencingArtifactStore
	ImplementationVersion string
}

type runtimeCompleteExecutor struct {
	config runtimeCompleteExecutorConfig
}

func newRuntimeCompleteExecutor(config runtimeCompleteExecutorConfig) (*runtimeCompleteExecutor, error) {
	if nilWorkerDependency(config.Receipts) || (config.ImplementationVersion != "runtime-complete-v1" && config.ImplementationVersion != "runtime-complete-v2" && config.ImplementationVersion != "runtime-complete-v3") {
		return nil, errRuntimeUnavailable
	}
	return &runtimeCompleteExecutor{config: config}, nil
}

func (executor *runtimeCompleteExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	if executor == nil || lease.ImplementationVersion != "runtime-complete-v1" || !executor.SupportsRuntimeStageVersion(lease.Stage, executor.config.ImplementationVersion, lease.ImplementationVersion) {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	return executor.forVersion(lease.ImplementationVersion).execute(ctx, lease, nil)
}

func (executor *runtimeCompleteExecutor) ExecuteAuthorized(ctx context.Context, execution runtimeStageExecution) (runtimeStageEffect, error) {
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(execution.currentLease(), runtimeevent.RuntimeStageComplete) || !executor.SupportsRuntimeStageVersion(execution.lease.Stage, executor.config.ImplementationVersion, execution.lease.ImplementationVersion) || !workerIdentityPattern.MatchString(execution.workerID) || !runtimeLeaseToken(execution.leaseToken) {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	if execution.lease.ImplementationVersion != "runtime-complete-v1" && (execution.lease.PredecessorDigest == nil || *execution.lease.PredecessorDigest != execution.lease.InputDigest) {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	return executor.forVersion(execution.lease.ImplementationVersion).execute(ctx, execution.currentLease(), &execution)
}

func (executor *runtimeCompleteExecutor) SupportsRuntimeStageVersion(stage runtimeevent.RuntimeStage, configured, claimed string) bool {
	return executor != nil && stage == runtimeevent.RuntimeStageComplete && configured == executor.config.ImplementationVersion && (configured == "runtime-complete-v1" && claimed == configured || configured == "runtime-complete-v2" && (claimed == configured || claimed == "runtime-complete-v1") || configured == "runtime-complete-v3" && (claimed == configured || claimed == "runtime-complete-v1" || claimed == "runtime-complete-v2"))
}

func (executor *runtimeCompleteExecutor) forVersion(version string) *runtimeCompleteExecutor {
	if version == executor.config.ImplementationVersion {
		return executor
	}
	selected := *executor
	selected.config.ImplementationVersion = version
	return &selected
}

func (executor *runtimeCompleteExecutor) execute(ctx context.Context, lease runtimeevent.StageLease, execution *runtimeStageExecution) (effect runtimeStageEffect, resultErr error) {
	currentLease := func() runtimeevent.StageLease {
		if execution != nil {
			return execution.currentLease()
		}
		return lease
	}
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageComplete) || lease.ImplementationVersion != executor.config.ImplementationVersion || lease.ImplementationVersion != "runtime-complete-v1" && execution == nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	locator, ok := runtimeReceiptLocator(lease.Scope, lease.InputReference, lease.InputVersionID)
	if !ok {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	artifact, err := executor.config.Receipts.Get(ctx, locator)
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	}
	validArtifact := false
	if lease.ImplementationVersion == "runtime-complete-v3" {
		validArtifact = artifact.Locator == locator && artifact.MediaType == "application/json" && artifact.Size >= 1 && artifact.Size <= 4<<20 && artifact.Size == int64(len(artifact.Body)) && artifact.SHA256 == sha256.Sum256(artifact.Body)
	} else {
		validArtifact = exactRuntimeReceiptArtifact(artifact, locator)
	}
	if !validArtifact {
		clear(artifact.Body)
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	objectReference, err := executor.config.Receipts.ObjectReference(artifact.Locator)
	if err != nil || objectReference != lease.InputReference {
		clear(artifact.Body)
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	decodeReceipt := runtimeprojection.DecodeReceipt
	if lease.ImplementationVersion == "runtime-complete-v3" {
		decodeReceipt = runtimeprojection.DecodePreciseReceipt
	}
	projectionReceipt, err := decodeReceipt(artifact.Body)
	projectionBody := string(artifact.Body)
	clear(artifact.Body)
	compatiblePredecessor := lease.ImplementationVersion == "runtime-complete-v1" && projectionReceipt.ImplementationVersion == "runtime-projection-v1" || lease.ImplementationVersion == "runtime-complete-v2" && projectionReceipt.ImplementationVersion == "runtime-projection-v2"
	if lease.ImplementationVersion == "runtime-complete-v3" {
		compatiblePredecessor = projectionReceipt.ImplementationVersion == "runtime-projection-v3"
	}
	if err != nil || projectionReceipt.Scope != lease.Scope || projectionReceipt.BatchID != lease.BatchID || projectionReceipt.Generation != lease.Generation || projectionReceipt.EffectDigest != lease.InputDigest || !compatiblePredecessor {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	itemIDs := make([]string, len(projectionReceipt.Items))
	for index, item := range projectionReceipt.Items {
		itemIDs[index] = item.ID
	}
	sort.Strings(itemIDs)
	receiptBody, receiptDigest, reference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageComplete, ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: projectionReceipt.ArchiveReference, ArchiveVersionID: projectionReceipt.ArchiveVersionID, ArchiveDigest: projectionReceipt.ArchiveDigest, EffectDigest: projectionReceipt.EffectDigest, ItemIDs: itemIDs})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	if lease.ImplementationVersion != "runtime-complete-v1" && (ctx.Err() != nil || !exactRuntimeStageLease(currentLease(), runtimeevent.RuntimeStageComplete)) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	}
	stored, err := executor.config.Receipts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(receiptBody)})
	if err != nil || stored.Scope != lease.Scope || stored.Reference != reference || stored.VersionID == "" || stored.MediaType != "application/json" || stored.Size != int64(len(receiptBody)) || stored.SHA256 != receiptDigest || !bytes.Equal(stored.Body, receiptBody) {
		return runtimeStageEffect{}, errWorkerExecution
	}
	resultReference, err := executor.config.Receipts.ObjectReference(stored.Locator)
	if err != nil || resultReference == "" {
		return runtimeStageEffect{}, errWorkerExecution
	}
	if lease.ImplementationVersion != "runtime-complete-v1" && (ctx.Err() != nil || !exactRuntimeStageLease(currentLease(), runtimeevent.RuntimeStageComplete)) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	}
	return runtimeStageEffect{EffectDigest: projectionReceipt.EffectDigest, ResultReference: resultReference, ResultVersionID: stored.VersionID, ResultDigest: receiptDigest, ProjectionReceipt: projectionBody}, nil
}

var _ runtimeStageExecutor = (*runtimeCompleteExecutor)(nil)
