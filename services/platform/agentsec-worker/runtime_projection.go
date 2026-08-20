package main

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

type runtimeProjectionExecutorConfig struct {
	Reader                runtimeArchivedBatchReader
	Receipts              artifactstore.ObjectReferencingArtifactStore
	ImplementationVersion string
}

type runtimeProjectionExecutor struct {
	config runtimeProjectionExecutorConfig
}

func newRuntimeProjectionExecutor(config runtimeProjectionExecutorConfig) (*runtimeProjectionExecutor, error) {
	if nilWorkerDependency(config.Reader) || nilWorkerDependency(config.Receipts) || config.ImplementationVersion != "runtime-projection-v1" {
		return nil, errRuntimeUnavailable
	}
	return &runtimeProjectionExecutor{config: config}, nil
}

func (executor *runtimeProjectionExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageProject) || lease.ImplementationVersion != executor.config.ImplementationVersion {
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
	correlationReceipt, err := runtimecorrelation.DecodeReceipt(artifact.Body)
	clear(artifact.Body)
	if err != nil || correlationReceipt.Scope != lease.Scope || correlationReceipt.BatchID != lease.BatchID || correlationReceipt.Generation != lease.Generation || correlationReceipt.EffectDigest != lease.InputDigest || correlationReceipt.ImplementationVersion != "runtime-correlation-v1" {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	archiveLease := lease
	archiveLease.Stage = runtimeevent.RuntimeStageIndex
	archiveLease.ImplementationVersion = "runtime-index-v1"
	archiveLease.InputReference = correlationReceipt.ArchiveReference
	archiveLease.InputVersionID = correlationReceipt.ArchiveVersionID
	archiveLease.InputDigest = correlationReceipt.ArchiveDigest
	body, err := executor.config.Reader.Read(ctx, archiveLease)
	if err != nil {
		return runtimeStageEffect{}, err
	}
	defer clear(body)
	if sha256.Sum256(body) != correlationReceipt.ArchiveDigest {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	projectionBody := bytes.Clone(body)
	defer clear(projectionBody)
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveReference: correlationReceipt.ArchiveReference, ArchiveVersionID: correlationReceipt.ArchiveVersionID, ArchiveDigest: correlationReceipt.ArchiveDigest, Body: projectionBody, Correlations: correlationReceipt.Results})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	receiptBody, receiptDigest, reference, err := runtimeprojection.EncodeReceipt(runtimeprojection.Receipt{ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: correlationReceipt.ArchiveReference, ArchiveVersionID: correlationReceipt.ArchiveVersionID, ArchiveDigest: correlationReceipt.ArchiveDigest, EffectDigest: projected.ContentDigest, Items: projected.Items})
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
	return runtimeStageEffect{EffectDigest: projected.ContentDigest, ResultReference: resultReference, ResultVersionID: stored.VersionID, ResultDigest: receiptDigest}, nil
}

var _ runtimeStageExecutor = (*runtimeProjectionExecutor)(nil)
