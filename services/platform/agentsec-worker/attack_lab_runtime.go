package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type attackLabExecutionAuthority interface {
	Ready(context.Context) error
	ClaimAttackLabRun(context.Context, domain.Scope, string, string, string, int) (apiserver.AttackLabRunClaim, error)
	HeartbeatAttackLabRun(context.Context, domain.Scope, string, string, string, int) (apiserver.AttackLabRunHeartbeat, error)
	RetryAttackLabRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte, string, time.Time) (apiserver.AttackLabRunTransition, error)
	MarkAttackLabRunning(context.Context, domain.Scope, apiserver.AttackLabRunningInput) (apiserver.AttackLabRunTransition, error)
	BeginAttackLabCleanup(context.Context, domain.Scope, apiserver.AttackLabCleanupInput) (apiserver.AttackLabRunTransition, error)
	FinishAttackLabCleanup(context.Context, domain.Scope, string, string, string, [sha256.Size]byte) (apiserver.AttackLabRunTransition, error)
}

type attackLabSandboxProvider interface {
	Ready(context.Context) error
	Create(context.Context, attackLabSandboxRequest) (attackLabSandbox, error)
	Collect(context.Context, attackLabSandboxRequest, attackLabSandbox) (attackLabSandboxResult, error)
	Destroy(context.Context, attackLabSandbox) error
}

type attackLabEvidenceWriter interface {
	Write(context.Context, attackLabSandboxRequest, attackLabSandbox, attackLabSandboxResult) (attackLabEvidenceArtifact, error)
}

type attackLabSandboxRequest struct {
	Scope       domain.Scope
	Run         apiserver.AttackLabRun
	Preflight   apiserver.AttackLabPreflightSnapshot
	InputDigest [sha256.Size]byte
}

type attackLabSandbox struct{ Reference string }

type attackLabSandboxResult struct {
	Verdict                          string
	CriterionObserved, CanaryTouched bool
	ErrorCode                        string
	Evidence                         []string
}

type attackLabEvidenceArtifact struct {
	Reference, Key, VersionID string
	Checksum                  []byte
	SizeBytes                 int64
}

type attackLabProviderFailure struct {
	code       string
	retryAfter time.Duration
}

func (failure *attackLabProviderFailure) Error() string { return "attack lab provider failed" }

type attackLabProcessorConfig struct {
	Authority         attackLabExecutionAuthority
	Queue             discoveryQueue
	Provider          attackLabSandboxProvider
	Evidence          attackLabEvidenceWriter
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
}

type attackLabProcessor struct{ config attackLabProcessorConfig }

type attackLabDeliveryPayload struct {
	OrganizationID    string `json:"organization_id"`
	WorkspaceID       string `json:"workspace_id"`
	EnvironmentID     string `json:"environment_id"`
	RunID             string `json:"run_id"`
	SourceRunID       string `json:"source_run_id"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
	TargetID          string `json:"target_id"`
	TargetKind        string `json:"target_kind"`
	InputDigest       string `json:"input_digest"`
}

func newAttackLabProcessor(config attackLabProcessorConfig) (*attackLabProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	_, extendsVisibility := config.Queue.(jobqueue.VisibilityExtender)
	if config.Authority == nil || config.Queue == nil || !extendsVisibility || config.Provider == nil || config.Evidence == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 30 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 || config.Now == nil || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &attackLabProcessor{config: config}, nil
}

func (processor *attackLabProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Authority.Ready(ctx) != nil || processor.config.Provider.Ready(ctx) != nil {
		return errWorkerExecution
	}
	deliveries, err := processor.config.Queue.ConsumeBatch(ctx, processor.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	results := make(chan error, len(deliveries))
	for _, delivery := range deliveries {
		delivery := delivery
		go func() { results <- processor.process(ctx, delivery) }()
	}
	failed := false
	for range deliveries {
		if <-results != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *attackLabProcessor) process(ctx context.Context, delivery jobqueue.Delivery) error {
	payload, ok := validAttackLabDelivery(delivery)
	if !ok {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	claim, err := processor.config.Authority.ClaimAttackLabRun(ctx, delivery.Job.Scope, payload.RunID, processor.config.WorkerID, token, processor.config.LeaseSeconds)
	if err != nil {
		return errWorkerExecution
	}
	switch claim.Disposition {
	case "retry_later":
		return nil
	case "ack_terminal":
		return processor.acknowledge(ctx, delivery.Receipt)
	case "claimed", "running", "cleanup":
	default:
		return errWorkerExecution
	}
	if !attackLabClaimMatchesDelivery(delivery, payload, claim) {
		return errWorkerExecution
	}
	return processor.runClaim(ctx, delivery, claim, token)
}

func (processor *attackLabProcessor) runClaim(ctx context.Context, delivery jobqueue.Delivery, claim apiserver.AttackLabRunClaim, token string) error {
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	var cancelRequested atomic.Bool
	var leaseLost atomic.Bool
	heartbeatDone := make(chan struct{})
	go processor.keepLease(workCtx, delivery, claim.Run.ID, token, &cancelRequested, &leaseLost, cancelWork, heartbeatDone)
	stopHeartbeat := func() {
		cancelWork()
		<-heartbeatDone
	}
	request := attackLabSandboxRequest{Scope: delivery.Job.Scope, Run: claim.Run, Preflight: claim.Preflight, InputDigest: claim.InputDigest}
	sandbox := attackLabSandbox{Reference: claim.SandboxReference}
	if claim.Disposition == "cleanup" {
		sandbox.Reference = claim.Checkpoint.SandboxReference
		return processor.resumeCleanup(ctx, delivery, claim, token, sandbox, leaseLost.Load, stopHeartbeat)
	}
	if claim.Disposition == "claimed" {
		if claim.Run.CancelRequested {
			return processor.finishWithoutSandbox(ctx, delivery, claim, token, "retryable", stopHeartbeat)
		}
		created, createErr := callAttackLabCreate(processor.config.Provider, workCtx, request)
		if createErr != nil {
			if leaseLost.Load() {
				stopHeartbeat()
				return errWorkerExecution
			}
			return processor.handleCreateFailure(ctx, delivery, claim, token, createErr, cancelRequested.Load(), stopHeartbeat)
		}
		sandbox = created
		finalizeCtx, cancelFinalize := processor.finalizeContext(ctx)
		running, markErr := processor.config.Authority.MarkAttackLabRunning(finalizeCtx, delivery.Job.Scope, apiserver.AttackLabRunningInput{RunID: claim.Run.ID, Controller: processor.config.WorkerID, LeaseToken: token, InputDigest: claim.InputDigest, SandboxReference: sandbox.Reference})
		cancelFinalize()
		if markErr != nil || running.Run.Status != "running" {
			stopHeartbeat()
			return errWorkerExecution
		}
		request.Run = running.Run
	}
	result, collectErr := callAttackLabCollect(processor.config.Provider, workCtx, request, sandbox)
	if leaseLost.Load() {
		stopHeartbeat()
		return errWorkerExecution
	}
	if cancelRequested.Load() || request.Run.CancelRequested {
		result = cancelledAttackLabResult()
	} else if collectErr != nil {
		result = failedAttackLabResult(collectErr)
	}
	if !validAttackLabSandboxResult(result) {
		stopHeartbeat()
		return errWorkerExecution
	}
	finalizeCtx, cancelFinalize := processor.finalizeContext(ctx)
	artifact, writeErr := processor.config.Evidence.Write(finalizeCtx, request, sandbox, result)
	cancelFinalize()
	if writeErr == nil && !validAttackLabEvidenceArtifact(delivery.Job.Scope, claim.Run.ID, claim.Run.Attempt, artifact) {
		stopHeartbeat()
		return errWorkerExecution
	}
	cleanupInput := apiserver.AttackLabCleanupInput{RunID: claim.Run.ID, Controller: processor.config.WorkerID, LeaseToken: token, InputDigest: claim.InputDigest, Attempt: claim.Run.Attempt, SandboxReference: sandbox.Reference}
	if writeErr != nil {
		cleanupInput.Verdict = "inconclusive"
		cleanupInput.ErrorCode = "outcome_unknown"
		if result.ErrorCode == "cancelled" {
			cleanupInput.ErrorCode = "cancelled"
		}
	} else {
		cleanupInput.Verdict = result.Verdict
		cleanupInput.CriterionObserved = result.CriterionObserved
		cleanupInput.CanaryTouched = result.CanaryTouched
		cleanupInput.ErrorCode = result.ErrorCode
		cleanupInput.Evidence = append([]string(nil), result.Evidence...)
		cleanupInput.EvidenceReference = artifact.Reference
		cleanupInput.EvidenceKey = artifact.Key
		cleanupInput.EvidenceVersionID = artifact.VersionID
		cleanupInput.EvidenceChecksum = append([]byte(nil), artifact.Checksum...)
		cleanupInput.EvidenceSizeBytes = artifact.SizeBytes
	}
	finalizeCtx, cancelFinalize = processor.finalizeContext(ctx)
	cleanup, beginErr := processor.config.Authority.BeginAttackLabCleanup(finalizeCtx, delivery.Job.Scope, cleanupInput)
	cancelFinalize()
	if beginErr != nil || cleanup.Run.Status != "cleanup" {
		stopHeartbeat()
		return errWorkerExecution
	}
	return processor.destroyAndFinish(ctx, delivery, claim, token, sandbox, stopHeartbeat)
}

func (processor *attackLabProcessor) resumeCleanup(ctx context.Context, delivery jobqueue.Delivery, claim apiserver.AttackLabRunClaim, token string, sandbox attackLabSandbox, leaseLost func() bool, stopHeartbeat func()) error {
	if leaseLost() {
		stopHeartbeat()
		return errWorkerExecution
	}
	return processor.destroyAndFinish(ctx, delivery, claim, token, sandbox, stopHeartbeat)
}

func (processor *attackLabProcessor) destroyAndFinish(ctx context.Context, delivery jobqueue.Delivery, claim apiserver.AttackLabRunClaim, token string, sandbox attackLabSandbox, stopHeartbeat func()) error {
	finalizeCtx, cancelFinalize := processor.finalizeContext(ctx)
	destroyErr := callAttackLabDestroy(processor.config.Provider, finalizeCtx, sandbox)
	if destroyErr != nil {
		cancelFinalize()
		stopHeartbeat()
		return errWorkerExecution
	}
	finished, finishErr := processor.config.Authority.FinishAttackLabCleanup(finalizeCtx, delivery.Job.Scope, claim.Run.ID, processor.config.WorkerID, token, claim.InputDigest)
	cancelFinalize()
	stopHeartbeat()
	if finishErr != nil || !stringInWorker(finished.Run.Status, "complete", "cancelled") || finished.Run.CleanupState != "complete" {
		return errWorkerExecution
	}
	return processor.acknowledge(context.WithoutCancel(ctx), delivery.Receipt)
}

func (processor *attackLabProcessor) handleCreateFailure(ctx context.Context, delivery jobqueue.Delivery, claim apiserver.AttackLabRunClaim, token string, providerErr error, cancelled bool, stopHeartbeat func()) error {
	code, retryAfter := "", 30*time.Second
	var failure *attackLabProviderFailure
	if errors.As(providerErr, &failure) {
		code, retryAfter = failure.code, failure.retryAfter
	}
	if cancelled {
		code = "retryable"
	}
	if !stringInWorker(code, "retryable", "denied", "malformed") {
		stopHeartbeat()
		return errWorkerExecution
	}
	finalizeCtx, cancelFinalize := processor.finalizeContext(ctx)
	transition, err := processor.config.Authority.RetryAttackLabRun(finalizeCtx, delivery.Job.Scope, claim.Run.ID, processor.config.WorkerID, token, claim.InputDigest, code, processor.config.Now().Add(retryAfter))
	cancelFinalize()
	stopHeartbeat()
	if err != nil {
		return errWorkerExecution
	}
	if stringInWorker(transition.Run.Status, "failed", "cancelled") {
		return processor.acknowledge(context.WithoutCancel(ctx), delivery.Receipt)
	}
	if transition.Run.Status != "retryable" {
		return errWorkerExecution
	}
	return nil
}

func (processor *attackLabProcessor) finishWithoutSandbox(ctx context.Context, delivery jobqueue.Delivery, claim apiserver.AttackLabRunClaim, token, code string, stopHeartbeat func()) error {
	return processor.handleCreateFailure(ctx, delivery, claim, token, &attackLabProviderFailure{code: code, retryAfter: time.Second}, true, stopHeartbeat)
}

func (processor *attackLabProcessor) keepLease(ctx context.Context, delivery jobqueue.Delivery, runID, token string, cancelRequested, leaseLost *atomic.Bool, cancel context.CancelFunc, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewCtx, renewCancel := context.WithTimeout(ctx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
			heartbeat, err := processor.config.Authority.HeartbeatAttackLabRun(renewCtx, delivery.Job.Scope, runID, processor.config.WorkerID, token, processor.config.LeaseSeconds)
			visibilityErr := error(nil)
			if err == nil && heartbeat.Renewed {
				visibilityErr = processor.config.Queue.(jobqueue.VisibilityExtender).ExtendVisibility(renewCtx, []jobqueue.Receipt{delivery.Receipt}, time.Duration(processor.config.LeaseSeconds)*time.Second)
			}
			renewCancel()
			if err != nil || !heartbeat.Renewed || visibilityErr != nil {
				leaseLost.Store(true)
				cancel()
				return
			}
			if heartbeat.CancelRequested {
				cancelRequested.Store(true)
				cancel()
				return
			}
		}
	}
}

func (processor *attackLabProcessor) finalizeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
}

func (processor *attackLabProcessor) acknowledge(ctx context.Context, receipt jobqueue.Receipt) error {
	ackCtx, cancel := context.WithTimeout(ctx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancel()
	if processor.config.Queue.AcknowledgeBatch(ackCtx, []jobqueue.Receipt{receipt}) != nil {
		return errWorkerExecution
	}
	return nil
}

func validAttackLabDelivery(delivery jobqueue.Delivery) (attackLabDeliveryPayload, bool) {
	if delivery.Job.Scope.Validate() != nil || delivery.Job.JobID.IsZero() || delivery.Job.Kind != "attack-lab" || delivery.Job.AuthorityDigest == [sha256.Size]byte{} {
		return attackLabDeliveryPayload{}, false
	}
	var payload attackLabDeliveryPayload
	if decodeStrictWorkerJSON(delivery.Job.Payload, &payload) != nil || payload.OrganizationID != delivery.Job.Scope.OrganizationID().String() || payload.WorkspaceID != delivery.Job.Scope.WorkspaceID().String() || payload.EnvironmentID != delivery.Job.Scope.EnvironmentID().String() || payload.RunID != delivery.Job.JobID.String() || payload.SourceRunID == payload.RunID || payload.DefinitionVersion < 1 || payload.DefinitionVersion > 1_000_000 || !stringInWorker(payload.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || hex.EncodeToString(delivery.Job.AuthorityDigest[:]) != payload.InputDigest {
		return attackLabDeliveryPayload{}, false
	}
	return payload, true
}

func attackLabClaimMatchesDelivery(delivery jobqueue.Delivery, payload attackLabDeliveryPayload, claim apiserver.AttackLabRunClaim) bool {
	return claim.Run.ID == payload.RunID && claim.Run.SourceRunID == payload.SourceRunID && claim.Run.DefinitionID == payload.DefinitionID && claim.Run.DefinitionVersion == payload.DefinitionVersion && claim.Run.TargetID == payload.TargetID && claim.Run.TargetKind == payload.TargetKind && subtle.ConstantTimeCompare(claim.InputDigest[:], delivery.Job.AuthorityDigest[:]) == 1
}

func validAttackLabSandboxResult(result attackLabSandboxResult) bool {
	if !stringInWorker(result.Verdict, "verified", "not_reproduced", "inconclusive") || result.Verdict == "verified" && (!result.CriterionObserved || !result.CanaryTouched) || result.Verdict == "not_reproduced" && (result.CriterionObserved || result.CanaryTouched) || result.Verdict != "inconclusive" && result.ErrorCode != "" || result.Verdict == "inconclusive" && !stringInWorker(result.ErrorCode, "denied", "malformed", "outcome_unknown", "exhausted", "cancelled") || len(result.Evidence) != 5 {
		return false
	}
	prefixes := [...]string{"semantic:", "gateway:", "egress:", "kubernetes:", "cloud:"}
	for index, item := range result.Evidence {
		if len(item) <= len(prefixes[index]) || len(item) > 512 || !strings.HasPrefix(item, prefixes[index]) || strings.TrimSpace(item) != item || strings.ContainsAny(item, "\x00\r\n") {
			return false
		}
	}
	return true
}

func validAttackLabEvidenceArtifact(scope domain.Scope, runID string, attempt int, artifact attackLabEvidenceArtifact) bool {
	_, expectedKey, err := attackLabEvidenceIdentity(scope, runID, attempt)
	if err != nil || !runtimeS3ReferencePattern.MatchString(artifact.Reference) {
		return false
	}
	objectAuthority := strings.TrimPrefix(artifact.Reference, "s3://")
	separator := strings.IndexByte(objectAuthority, '/')
	return separator > 0 && objectAuthority[separator+1:] == artifact.Key && artifact.Key == expectedKey && len(artifact.VersionID) >= 1 && len(artifact.VersionID) <= 512 && !strings.ContainsAny(artifact.VersionID, " \t\r\n\x00") && len(artifact.Checksum) == sha256.Size && subtle.ConstantTimeCompare(artifact.Checksum, make([]byte, sha256.Size)) != 1 && artifact.SizeBytes >= 1 && artifact.SizeBytes <= 64<<20
}

func cancelledAttackLabResult() attackLabSandboxResult {
	return attackLabSandboxResult{Verdict: "inconclusive", ErrorCode: "cancelled", Evidence: []string{"semantic:cancelled before verdict", "gateway:cancelled", "egress:no undeclared egress", "kubernetes:cleanup requested", "cloud:no verified canary touch"}}
}

func failedAttackLabResult(err error) attackLabSandboxResult {
	code := "outcome_unknown"
	var failure *attackLabProviderFailure
	if errors.As(err, &failure) && stringInWorker(failure.code, "denied", "malformed", "outcome_unknown", "exhausted") {
		code = failure.code
	}
	return attackLabSandboxResult{Verdict: "inconclusive", ErrorCode: code, Evidence: []string{"semantic:criterion unavailable", "gateway:execution unavailable", "egress:no undeclared egress observed", "kubernetes:execution incomplete", "cloud:canary outcome unavailable"}}
}

func callAttackLabCreate(provider attackLabSandboxProvider, ctx context.Context, request attackLabSandboxRequest) (sandbox attackLabSandbox, resultErr error) {
	defer func() {
		if recover() != nil {
			sandbox, resultErr = attackLabSandbox{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
	}()
	return provider.Create(ctx, request)
}

func callAttackLabCollect(provider attackLabSandboxProvider, ctx context.Context, request attackLabSandboxRequest, sandbox attackLabSandbox) (result attackLabSandboxResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result, resultErr = attackLabSandboxResult{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
	}()
	return provider.Collect(ctx, request, sandbox)
}

func callAttackLabDestroy(provider attackLabSandboxProvider, ctx context.Context, sandbox attackLabSandbox) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	return provider.Destroy(ctx, sandbox)
}

var _ workerProcessor = (*attackLabProcessor)(nil)
