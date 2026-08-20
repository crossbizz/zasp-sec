package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/url"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type runtimeCorrelationExecutorConfig struct {
	Reader                runtimeArchivedBatchReader
	Receipts              artifactstore.ObjectReferencingArtifactStore
	ImplementationVersion string
}

type runtimeCorrelationExecutor struct {
	config runtimeCorrelationExecutorConfig
}

func newRuntimeCorrelationExecutor(config runtimeCorrelationExecutorConfig) (*runtimeCorrelationExecutor, error) {
	if nilWorkerDependency(config.Reader) || nilWorkerDependency(config.Receipts) || config.ImplementationVersion != "runtime-correlation-v1" {
		return nil, errRuntimeUnavailable
	}
	return &runtimeCorrelationExecutor{config: config}, nil
}

func (executor *runtimeCorrelationExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageCorrelate) || lease.ImplementationVersion != executor.config.ImplementationVersion {
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
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	objectReference, err := executor.config.Receipts.ObjectReference(artifact.Locator)
	if err != nil || objectReference != lease.InputReference {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	indexReceipt, err := runtimeevent.DecodeStageReceipt(artifact.Body)
	clear(artifact.Body)
	if err != nil || indexReceipt.Stage != runtimeevent.RuntimeStageIndex || indexReceipt.Scope != lease.Scope || indexReceipt.BatchID != lease.BatchID || indexReceipt.Generation != lease.Generation || indexReceipt.EffectDigest != lease.InputDigest || indexReceipt.ImplementationVersion != "runtime-index-v1" {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	archiveLease := lease
	archiveLease.Stage = runtimeevent.RuntimeStageIndex
	archiveLease.ImplementationVersion = indexReceipt.ImplementationVersion
	archiveLease.InputReference = indexReceipt.ArchiveReference
	archiveLease.InputVersionID = indexReceipt.ArchiveVersionID
	archiveLease.InputDigest = indexReceipt.ArchiveDigest
	body, err := executor.config.Reader.Read(ctx, archiveLease)
	if err != nil {
		return runtimeStageEffect{}, err
	}
	defer clear(body)
	if sha256.Sum256(body) != indexReceipt.ArchiveDigest {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	decoded, err := runtimeevent.DecodeArchivedBatch(lease.Scope, body)
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	candidates := trustedRuntimeCandidates(decoded)
	correlationBody := bytes.Clone(body)
	defer clear(correlationBody)
	correlated, err := runtimecorrelation.Correlate(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: indexReceipt.ArchiveDigest, Body: correlationBody, Candidates: candidates})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	receiptBody, receiptDigest, reference, err := runtimecorrelation.EncodeReceipt(runtimecorrelation.Receipt{ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: indexReceipt.ArchiveReference, ArchiveVersionID: indexReceipt.ArchiveVersionID, ArchiveDigest: indexReceipt.ArchiveDigest, EffectDigest: correlated.ContentDigest, Results: correlated.Results})
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
	return runtimeStageEffect{EffectDigest: correlated.ContentDigest, ResultReference: resultReference, ResultVersionID: stored.VersionID, ResultDigest: receiptDigest}, nil
}

func trustedRuntimeCandidates(batch runtimeevent.ArchivedBatch) []runtimeevent.Candidate {
	result := make([]runtimeevent.Candidate, 0, len(batch.Records))
	seen := map[string]struct{}{}
	for _, record := range batch.Records {
		if record.AgentID.IsZero() || record.SessionID.IsZero() {
			continue
		}
		candidate := runtimeevent.Candidate{AgentID: record.AgentID, SessionID: record.SessionID, SandboxID: record.SandboxID, ContainerID: record.ContainerID, CgroupID: record.CgroupID, ProcessID: record.ProcessID}
		key := candidate.AgentID.String() + "\x00" + candidate.SessionID.String() + "\x00" + candidate.SandboxID + "\x00" + candidate.ContainerID + "\x00" + candidate.CgroupID + "\x00" + candidate.ProcessID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func runtimeReceiptLocator(scope domain.Scope, objectReference, versionID string) (artifactstore.Locator, bool) {
	parsed, err := url.Parse(objectReference)
	if err != nil || parsed.String() != objectReference || parsed.Scheme != "s3" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return artifactstore.Locator{}, false
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "organizations" || parts[1] != scope.OrganizationID().String() || parts[2] != "workspaces" || parts[3] != scope.WorkspaceID().String() || parts[4] != "environments" || parts[5] != scope.EnvironmentID().String() || parts[6] != "artifacts" {
		return artifactstore.Locator{}, false
	}
	reference, err := domain.ParseEvidenceRef(parts[7])
	if err != nil || versionID == "" {
		return artifactstore.Locator{}, false
	}
	return artifactstore.Locator{Scope: scope, Reference: reference, VersionID: versionID}, true
}

func exactRuntimeReceiptArtifact(artifact artifactstore.Artifact, locator artifactstore.Locator) bool {
	return artifact.Locator == locator && artifact.MediaType == "application/json" && artifact.Size >= 1 && artifact.Size <= 1<<20 && artifact.Size == int64(len(artifact.Body)) && artifact.SHA256 == sha256.Sum256(artifact.Body)
}

var _ runtimeStageExecutor = (*runtimeCorrelationExecutor)(nil)
