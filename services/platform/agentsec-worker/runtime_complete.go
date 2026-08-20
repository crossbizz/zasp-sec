package main

import (
	"bytes"
	"context"
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
	if nilWorkerDependency(config.Receipts) || config.ImplementationVersion != "runtime-complete-v1" {
		return nil, errRuntimeUnavailable
	}
	return &runtimeCompleteExecutor{config: config}, nil
}

func (executor *runtimeCompleteExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageComplete) || lease.ImplementationVersion != executor.config.ImplementationVersion {
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
	if !exactRuntimeReceiptArtifact(artifact, locator) {
		clear(artifact.Body)
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	objectReference, err := executor.config.Receipts.ObjectReference(artifact.Locator)
	if err != nil || objectReference != lease.InputReference {
		clear(artifact.Body)
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	projectionReceipt, err := runtimeprojection.DecodeReceipt(artifact.Body)
	clear(artifact.Body)
	if err != nil || projectionReceipt.Scope != lease.Scope || projectionReceipt.BatchID != lease.BatchID || projectionReceipt.Generation != lease.Generation || projectionReceipt.EffectDigest != lease.InputDigest || projectionReceipt.ImplementationVersion != "runtime-projection-v1" {
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
	stored, err := executor.config.Receipts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(receiptBody)})
	if err != nil || stored.Scope != lease.Scope || stored.Reference != reference || stored.VersionID == "" || stored.MediaType != "application/json" || stored.Size != int64(len(receiptBody)) || stored.SHA256 != receiptDigest || !bytes.Equal(stored.Body, receiptBody) {
		return runtimeStageEffect{}, errWorkerExecution
	}
	resultReference, err := executor.config.Receipts.ObjectReference(stored.Locator)
	if err != nil || resultReference == "" {
		return runtimeStageEffect{}, errWorkerExecution
	}
	return runtimeStageEffect{EffectDigest: projectionReceipt.EffectDigest, ResultReference: resultReference, ResultVersionID: stored.VersionID, ResultDigest: receiptDigest}, nil
}

var _ runtimeStageExecutor = (*runtimeCompleteExecutor)(nil)
