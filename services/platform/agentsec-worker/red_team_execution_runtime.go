package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type redTeamExecutionAuthority interface {
	Ready(context.Context) error
	ClaimRedTeamRun(context.Context, domain.Scope, string, string, string, int) (apiserver.RedTeamRunClaim, error)
	HeartbeatRedTeamRun(context.Context, domain.Scope, string, string, string, int) (apiserver.RedTeamRunHeartbeat, error)
	FinishRedTeamRun(context.Context, domain.Scope, apiserver.RedTeamRunCompletion) (apiserver.RedTeamRun, error)
	RetryRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte, string, time.Time) (apiserver.RedTeamRun, error)
	CancelClaimedRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte) (apiserver.RedTeamRun, error)
}

type redTeamRunner interface {
	Run(context.Context, redTeamExecutionRequest) (redTeamExecutionResult, error)
}

type redTeamExecutionRequest struct {
	LeaseToken  string
	Scope       domain.Scope
	Run         apiserver.RedTeamRun
	Definition  apiserver.RedTeamDefinition
	InputDigest [sha256.Size]byte
}

type redTeamExecutionResult struct {
	Verdict                                           string
	Objective, Behavior, ErrorCode                    string
	Evidence                                          []string
	EvidenceReference, EvidenceKey, EvidenceVersionID string
	EvidenceChecksum                                  []byte
	EvidenceSizeBytes                                 int64
}

type redTeamExecutionFailure struct {
	code       string
	retryAfter time.Duration
}

func (failure *redTeamExecutionFailure) Error() string { return "red team execution failed" }

type redTeamProcessorConfig struct {
	Authority         redTeamExecutionAuthority
	Queue             discoveryQueue
	Runner            redTeamRunner
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
}

type redTeamProcessor struct{ config redTeamProcessorConfig }

func newRedTeamProcessor(config redTeamProcessorConfig) (*redTeamProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	_, extendsVisibility := config.Queue.(jobqueue.VisibilityExtender)
	if config.Authority == nil || config.Queue == nil || !extendsVisibility || config.Runner == nil || config.Now == nil || config.NewLeaseToken == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 30 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 {
		return nil, errWorkerExecution
	}
	return &redTeamProcessor{config: config}, nil
}

func (processor *redTeamProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Authority.Ready(ctx) != nil {
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

func (processor *redTeamProcessor) process(ctx context.Context, delivery jobqueue.Delivery) error {
	payload, ok := validRedTeamDelivery(delivery)
	if !ok {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	runID := delivery.Job.JobID.String()
	claim, err := processor.config.Authority.ClaimRedTeamRun(ctx, delivery.Job.Scope, runID, processor.config.WorkerID, token, processor.config.LeaseSeconds)
	if err != nil {
		return errWorkerExecution
	}
	switch claim.Disposition {
	case "retry_later":
		return nil
	case "ack_terminal":
		return processor.acknowledge(ctx, delivery.Receipt)
	case "claimed":
	default:
		return errWorkerExecution
	}
	if payload.DefinitionID != claim.Definition.ID || payload.DefinitionVersion != claim.Definition.Version || claim.Run.ID != runID || claim.Run.DefinitionID != payload.DefinitionID || claim.Run.DefinitionVersion != payload.DefinitionVersion || claim.InputDigest != delivery.Job.AuthorityDigest {
		return errWorkerExecution
	}
	request := redTeamExecutionRequest{Scope: delivery.Job.Scope, Run: claim.Run, Definition: claim.Definition, InputDigest: claim.InputDigest, LeaseToken: token}
	return processor.runLeased(ctx, delivery, request, token)
}

func (processor *redTeamProcessor) runLeased(ctx context.Context, delivery jobqueue.Delivery, request redTeamExecutionRequest, token string) error {
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	var cancelRequested atomic.Bool
	var leaseLost atomic.Bool
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(processor.config.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(workCtx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
				heartbeat, err := processor.config.Authority.HeartbeatRedTeamRun(renewCtx, delivery.Job.Scope, request.Run.ID, processor.config.WorkerID, token, processor.config.LeaseSeconds)
				visibilityErr := error(nil)
				if err == nil && heartbeat.Renewed {
					visibilityErr = processor.config.Queue.(jobqueue.VisibilityExtender).ExtendVisibility(renewCtx, []jobqueue.Receipt{delivery.Receipt}, time.Duration(processor.config.LeaseSeconds)*time.Second)
				}
				renewCancel()
				if err != nil || !heartbeat.Renewed || visibilityErr != nil {
					leaseLost.Store(true)
					cancelWork()
					return
				}
				if heartbeat.CancelRequested {
					cancelRequested.Store(true)
					cancelWork()
					return
				}
			}
		}
	}()
	result, runErr := callRedTeamRunner(processor.config.Runner, workCtx, request)
	if leaseLost.Load() {
		cancelWork()
		<-heartbeatDone
		return errWorkerExecution
	}
	finalizeCtx, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancelFinalize()
	if cancelRequested.Load() {
		cancelWork()
		<-heartbeatDone
		cancelled, err := processor.config.Authority.CancelClaimedRedTeamRun(finalizeCtx, delivery.Job.Scope, request.Run.ID, processor.config.WorkerID, token, request.InputDigest)
		if err != nil || cancelled.Status != "cancelled" {
			return errWorkerExecution
		}
		return processor.acknowledge(finalizeCtx, delivery.Receipt)
	}
	if runErr != nil {
		code, retryAfter := "outcome_unknown", 30*time.Second
		var failure *redTeamExecutionFailure
		if errors.As(runErr, &failure) {
			code = failure.code
			if failure.retryAfter > 0 {
				retryAfter = failure.retryAfter
			}
		}
		retried, err := processor.config.Authority.RetryRedTeamRun(finalizeCtx, delivery.Job.Scope, request.Run.ID, processor.config.WorkerID, token, request.InputDigest, code, processor.config.Now().Add(retryAfter))
		cancelWork()
		<-heartbeatDone
		if err != nil {
			return errWorkerExecution
		}
		if retried.Status == "failed" {
			return processor.acknowledge(finalizeCtx, delivery.Receipt)
		}
		if retried.Status != "retryable" {
			return errWorkerExecution
		}
		return nil
	}
	completion := apiserver.RedTeamRunCompletion{RunID: request.Run.ID, Worker: processor.config.WorkerID, LeaseToken: token, InputDigest: request.InputDigest, Verdict: result.Verdict, Objective: result.Objective, Behavior: result.Behavior, ErrorCode: result.ErrorCode, Evidence: append([]string(nil), result.Evidence...), EvidenceReference: result.EvidenceReference, EvidenceKey: result.EvidenceKey, EvidenceVersionID: result.EvidenceVersionID, EvidenceChecksum: append([]byte(nil), result.EvidenceChecksum...), EvidenceSizeBytes: result.EvidenceSizeBytes}
	finished, err := processor.config.Authority.FinishRedTeamRun(finalizeCtx, delivery.Job.Scope, completion)
	cancelWork()
	<-heartbeatDone
	if err != nil || finished.Status != "complete" || finished.ID != request.Run.ID {
		return errWorkerExecution
	}
	return processor.acknowledge(finalizeCtx, delivery.Receipt)
}

func validRedTeamDelivery(delivery jobqueue.Delivery) (redTeamOutboxPayload, bool) {
	if delivery.Job.Scope.Validate() != nil || delivery.Job.JobID.IsZero() || delivery.Job.Kind != "red-team" || delivery.Job.AuthorityDigest == [sha256.Size]byte{} {
		return redTeamOutboxPayload{}, false
	}
	var payload redTeamOutboxPayload
	if decodeStrictWorkerJSON(delivery.Job.Payload, &payload) != nil || payload.OrganizationID != delivery.Job.Scope.OrganizationID().String() || payload.WorkspaceID != delivery.Job.Scope.WorkspaceID().String() || payload.EnvironmentID != delivery.Job.Scope.EnvironmentID().String() || payload.RunID != delivery.Job.JobID.String() || !discoveryRequestDigestPattern.MatchString(payload.InputDigest) || hex.EncodeToString(delivery.Job.AuthorityDigest[:]) != payload.InputDigest {
		return redTeamOutboxPayload{}, false
	}
	return payload, true
}

func callRedTeamRunner(runner redTeamRunner, ctx context.Context, request redTeamExecutionRequest) (result redTeamExecutionResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result, resultErr = redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
	}()
	return runner.Run(ctx, request)
}

func decodeStrictWorkerJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errWorkerExecution
	}
	return nil
}

func (processor *redTeamProcessor) acknowledge(ctx context.Context, receipt jobqueue.Receipt) error {
	if processor.config.Queue.AcknowledgeBatch(ctx, []jobqueue.Receipt{receipt}) != nil {
		return errWorkerExecution
	}
	return nil
}

var _ workerProcessor = (*redTeamProcessor)(nil)
