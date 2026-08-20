package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type runtimeIndexStore interface {
	Apply(context.Context, runtimeindex.Batch) (runtimeindex.ApplyResult, error)
}

type runtimeIndexExecutorConfig struct {
	Reader                runtimeArchivedBatchReader
	Index                 runtimeIndexStore
	Receipts              artifactstore.ObjectReferencingArtifactStore
	ImplementationVersion string
}

type runtimeIndexExecutor struct{ config runtimeIndexExecutorConfig }

func newRuntimeIndexExecutor(config runtimeIndexExecutorConfig) (*runtimeIndexExecutor, error) {
	if nilWorkerDependency(config.Reader) || nilWorkerDependency(config.Index) || nilWorkerDependency(config.Receipts) || !workerVersionPattern.MatchString(config.ImplementationVersion) {
		return nil, errRuntimeUnavailable
	}
	return &runtimeIndexExecutor{config: config}, nil
}

func (executor *runtimeIndexExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageIndex) || lease.ImplementationVersion != executor.config.ImplementationVersion {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	body, err := executor.config.Reader.Read(ctx, lease)
	if err != nil {
		return runtimeStageEffect{}, err
	}
	defer clear(body)
	if sha256.Sum256(body) != lease.InputDigest {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	indexBody := bytes.Clone(body)
	defer clear(indexBody)
	result, err := executor.config.Index.Apply(ctx, runtimeindex.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputDigest: lease.InputDigest, ArchiveReference: lease.InputReference, ArchiveVersionID: lease.InputVersionID, Body: indexBody})
	if err != nil {
		return runtimeStageEffect{}, runtimeIndexError(err)
	}
	if result.BatchID != lease.BatchID || result.Generation != lease.Generation || result.InputDigest != lease.InputDigest || result.ContentDigest == ([sha256.Size]byte{}) || len(result.DocumentIDs) < 1 || len(result.DocumentIDs) > 1000 {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	itemIDs := append([]string(nil), result.DocumentIDs...)
	sort.Strings(itemIDs)
	receiptBody, receiptDigest, reference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{
		Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation,
		InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest,
		ArchiveReference: lease.InputReference, ArchiveVersionID: lease.InputVersionID, ArchiveDigest: lease.InputDigest,
		EffectDigest: result.ContentDigest, ItemIDs: itemIDs,
	})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	artifact, err := executor.config.Receipts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(receiptBody)})
	if err != nil {
		return runtimeStageEffect{}, errWorkerExecution
	}
	if artifact.Scope != lease.Scope || artifact.Reference != reference || artifact.VersionID == "" || artifact.MediaType != "application/json" || artifact.Size != int64(len(receiptBody)) || artifact.SHA256 != receiptDigest || !bytes.Equal(artifact.Body, receiptBody) {
		return runtimeStageEffect{}, errWorkerExecution
	}
	objectReference, err := executor.config.Receipts.ObjectReference(artifact.Locator)
	if err != nil || objectReference == "" {
		return runtimeStageEffect{}, errWorkerExecution
	}
	return runtimeStageEffect{EffectDigest: result.ContentDigest, ResultReference: objectReference, ResultVersionID: artifact.VersionID, ResultDigest: receiptDigest}, nil
}

func runtimeIndexError(err error) error {
	switch {
	case errors.Is(err, runtimeindex.ErrCanceled):
		return err
	case errors.Is(err, runtimeindex.ErrRetryable):
		return errRuntimeStageRetryable
	case errors.Is(err, runtimeindex.ErrDenied):
		return errRuntimeStageDenied
	case errors.Is(err, runtimeindex.ErrRejected), errors.Is(err, runtimeindex.ErrInput), errors.Is(err, runtimeindex.ErrDrift):
		return errRuntimeStageMalformed
	default:
		return errWorkerExecution
	}
}

var _ runtimeStageExecutor = (*runtimeIndexExecutor)(nil)
