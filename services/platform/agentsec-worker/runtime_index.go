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

type runtimePreciseIndexStore interface {
	ApplyPrecise(context.Context, runtimeindex.Batch) (runtimeindex.ApplyResult, error)
}

type runtimeIndexExecutorConfig struct {
	Reader                runtimeArchivedBatchReader
	Index                 runtimeIndexStore
	Receipts              artifactstore.ObjectReferencingArtifactStore
	ImplementationVersion string
}

type runtimeIndexExecutor struct{ config runtimeIndexExecutorConfig }

func (executor *runtimeIndexExecutor) ExecuteAuthorized(ctx context.Context, execution runtimeStageExecution) (runtimeStageEffect, error) {
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(execution.currentLease(), runtimeevent.RuntimeStageIndex) || !executor.SupportsRuntimeStageVersion(execution.lease.Stage, executor.config.ImplementationVersion, execution.lease.ImplementationVersion) || !workerIdentityPattern.MatchString(execution.workerID) || !runtimeLeaseToken(execution.leaseToken) {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	if execution.lease.ImplementationVersion == "runtime-index-v2" && (execution.lease.PredecessorDigest == nil || *execution.lease.PredecessorDigest != execution.lease.InputDigest) {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	selected := *executor
	selected.config.ImplementationVersion = execution.lease.ImplementationVersion
	return selected.execute(ctx, execution.currentLease(), &execution)
}

func (executor *runtimeIndexExecutor) SupportsRuntimeStageVersion(stage runtimeevent.RuntimeStage, configured, claimed string) bool {
	return executor != nil && stage == runtimeevent.RuntimeStageIndex && configured == executor.config.ImplementationVersion && (claimed == configured || configured == "runtime-index-v2" && claimed == "runtime-index-v1")
}

func newRuntimeIndexExecutor(config runtimeIndexExecutorConfig) (*runtimeIndexExecutor, error) {
	if nilWorkerDependency(config.Reader) || nilWorkerDependency(config.Index) || nilWorkerDependency(config.Receipts) || (config.ImplementationVersion != "runtime-index-v1" && config.ImplementationVersion != "runtime-index-v2") {
		return nil, errRuntimeUnavailable
	}
	if config.ImplementationVersion == "runtime-index-v2" {
		if precise, ok := config.Index.(runtimePreciseIndexStore); !ok || nilWorkerDependency(precise) {
			return nil, errRuntimeUnavailable
		}
	}
	return &runtimeIndexExecutor{config: config}, nil
}

func (executor *runtimeIndexExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	if executor == nil || lease.ImplementationVersion != "runtime-index-v1" || !executor.SupportsRuntimeStageVersion(lease.Stage, executor.config.ImplementationVersion, lease.ImplementationVersion) {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	selected := *executor
	selected.config.ImplementationVersion = lease.ImplementationVersion
	return selected.execute(ctx, lease, nil)
}

func (executor *runtimeIndexExecutor) execute(ctx context.Context, lease runtimeevent.StageLease, execution *runtimeStageExecution) (effect runtimeStageEffect, resultErr error) {
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
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageIndex) || lease.ImplementationVersion != executor.config.ImplementationVersion || lease.ImplementationVersion == "runtime-index-v2" && execution == nil {
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
	apply := executor.config.Index.Apply
	if lease.ImplementationVersion == "runtime-index-v2" {
		precise, ok := executor.config.Index.(runtimePreciseIndexStore)
		if !ok || nilWorkerDependency(precise) {
			return runtimeStageEffect{}, errRuntimeStageMalformed
		}
		apply = precise.ApplyPrecise
		if ctx.Err() != nil || !exactRuntimeStageLease(currentLease(), runtimeevent.RuntimeStageIndex) {
			return runtimeStageEffect{}, errRuntimeStageRetryable
		}
	}
	result, err := apply(ctx, runtimeindex.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputDigest: lease.InputDigest, ArchiveReference: lease.InputReference, ArchiveVersionID: lease.InputVersionID, Body: indexBody})
	if err != nil {
		return runtimeStageEffect{}, runtimeIndexError(err)
	}
	if lease.ImplementationVersion == "runtime-index-v2" && (ctx.Err() != nil || !exactRuntimeStageLease(currentLease(), runtimeevent.RuntimeStageIndex)) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
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
	if lease.ImplementationVersion == "runtime-index-v2" && (ctx.Err() != nil || !exactRuntimeStageLease(currentLease(), runtimeevent.RuntimeStageIndex)) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
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
	if lease.ImplementationVersion == "runtime-index-v2" && (ctx.Err() != nil || !exactRuntimeStageLease(currentLease(), runtimeevent.RuntimeStageIndex)) {
		return runtimeStageEffect{}, errRuntimeStageRetryable
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
