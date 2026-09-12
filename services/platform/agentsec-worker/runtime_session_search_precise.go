package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type runtimePreciseSessionSearchIndex interface {
	ApplyPrecise(context.Context, sessionsearch.ReceiptBinding, []byte, []byte) (opensearchdriver.SessionWriteResult, error)
}

func newRuntimePreciseSessionSearchExecutor(reader runtimeArchivedBatchReader, receipts artifactstore.ObjectReferencingArtifactStore, index runtimeSessionSearchIndex) (*runtimeSessionSearchExecutor, error) {
	capability, ok := index.(runtimePreciseSessionSearchIndex)
	if !ok || nilWorkerDependency(capability) {
		return nil, errRuntimeUnavailable
	}
	executor, err := newRuntimeSessionSearchExecutor(reader, receipts, index)
	if err != nil {
		return nil, err
	}
	executor.precise = true
	return executor, nil
}
