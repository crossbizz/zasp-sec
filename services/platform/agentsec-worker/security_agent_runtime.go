package main

import (
	"context"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type securityAgentProcessorConfig struct {
	Authority         apiserver.SecurityAgentWorkerAuthority
	Planner           securityAgentPlanner
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
	NewProductID      func() (string, error)
}

type securityAgentProcessor struct {
	config           securityAgentProcessorConfig
	plannerAuthority apiserver.SecurityAgentPlannerAuthority
}

func newSecurityAgentProcessor(config securityAgentProcessorConfig) (*securityAgentProcessor, error) {
	leaseDuration := time.Duration(config.LeaseSeconds) * time.Second
	plannerAuthority, ok := config.Authority.(apiserver.SecurityAgentPlannerAuthority)
	if config.Authority == nil || !ok || !plannerAuthority.SecurityAgentPlannerAvailable() || config.Planner == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 30 || config.LeaseSeconds > 300 || config.BatchSize < 1 || config.BatchSize > 25 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > leaseDuration/2 || config.Now == nil || config.NewLeaseToken == nil || config.NewProductID == nil || config.Now().IsZero() || config.Now().Location() != time.UTC {
		return nil, errWorkerConfiguration
	}
	return &securityAgentProcessor{config: config, plannerAuthority: plannerAuthority}, nil
}

func (processor *securityAgentProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	if _, err := processor.config.Authority.ExpireSecurityAgentApprovals(ctx, processor.config.WorkerID, processor.config.BatchSize); err != nil {
		return errWorkerExecution
	}
	if _, err := processor.config.Authority.ScheduleSecurityAgentTriggers(ctx, processor.config.WorkerID, processor.config.BatchSize); err != nil {
		return errWorkerExecution
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || len(leaseToken) < 16 || len(leaseToken) > 128 {
		return errWorkerExecution
	}
	claims, err := processor.config.Authority.ClaimSecurityAgentRuns(ctx, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	for _, claim := range claims {
		if ctx.Err() != nil {
			return nil
		}
		if err := processor.process(ctx, claim, leaseToken); err != nil {
			return errWorkerExecution
		}
	}
	return nil
}

func (processor *securityAgentProcessor) process(ctx context.Context, claim apiserver.SecurityAgentRunClaim, leaseToken string) error {
	workCtx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	var once sync.Once
	stop := func() { once.Do(cancel) }
	go func() {
		ticker := time.NewTicker(processor.config.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				heartbeatDone <- nil
				return
			case <-ticker.C:
				if err := processor.config.Authority.HeartbeatSecurityAgentRun(workCtx, claim, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds); err != nil {
					heartbeatDone <- err
					stop()
					return
				}
			}
		}
	}()

	operationErr := processor.processClaim(workCtx, claim, leaseToken)
	stop()
	heartbeatErr := <-heartbeatDone
	if ctx.Err() != nil {
		return nil
	}
	if operationErr != nil || heartbeatErr != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *securityAgentProcessor) processClaim(ctx context.Context, claim apiserver.SecurityAgentRunClaim, leaseToken string) error {
	if claim.Prepared {
		ids, err := processor.newProductIDs(2)
		if err != nil {
			return err
		}
		_, err = processor.config.Authority.ExecuteSecurityAgentRun(ctx, claim, processor.config.WorkerID, leaseToken, ids[0], ids[1])
		return err
	}
	contextAuthority, err := processor.plannerAuthority.LoadSecurityAgentPlannerContext(ctx, claim, processor.config.WorkerID, leaseToken)
	if err != nil {
		return err
	}
	plannerContext := securityAgentPlannerContext{
		OrganizationID: contextAuthority.OrganizationID, WorkspaceID: contextAuthority.WorkspaceID, EnvironmentID: contextAuthority.EnvironmentID, RunID: contextAuthority.RunID, DefinitionID: contextAuthority.DefinitionID,
		Purpose: contextAuthority.Purpose, OperatorGoal: contextAuthority.OperatorGoal, CatalogVersion: contextAuthority.CatalogVersion, MaximumSteps: contextAuthority.MaximumSteps,
		AllowedActions: append([]string(nil), contextAuthority.AllowedActions...), AllowedTargets: append([]string(nil), contextAuthority.AllowedTargets...),
	}
	plannerContext.Evidence = make([]securityAgentPlannerEvidence, len(contextAuthority.Evidence))
	for index, evidence := range contextAuthority.Evidence {
		plannerContext.Evidence[index] = securityAgentPlannerEvidence{ID: evidence.ID, Kind: evidence.Kind, Version: evidence.Version, Summary: evidence.Summary}
	}
	plannerResult := processor.config.Planner.Plan(ctx, plannerContext)
	if plannerResult.Failure != "" {
		ids, idErr := processor.newProductIDs(2)
		if idErr != nil {
			return idErr
		}
		_, failErr := processor.plannerAuthority.FailSecurityAgentPlanner(ctx, claim, processor.config.WorkerID, leaseToken, apiserver.SecurityAgentPlannerFailure{InputDigest: contextAuthority.InputDigest, OutputDigest: plannerResult.OutputDigest, Model: plannerResult.Model, PolicyVersion: plannerResult.PolicyVersion, ErrorCode: string(plannerResult.Failure)}, ids[0], ids[1])
		return failErr
	}
	if len(plannerResult.Candidate.Steps) != 1 {
		return errWorkerExecution
	}
	ids, err := processor.newProductIDs(3)
	if err != nil {
		return err
	}
	expiresAt := processor.config.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
	step := plannerResult.Candidate.Steps[0]
	_, err = processor.plannerAuthority.AcceptSecurityAgentPlannerCandidate(ctx, claim, processor.config.WorkerID, leaseToken, apiserver.SecurityAgentPlannerSubmission{InputDigest: contextAuthority.InputDigest, OutputDigest: plannerResult.OutputDigest, Model: plannerResult.Model, PolicyVersion: plannerResult.PolicyVersion, Summary: plannerResult.Candidate.Summary, Action: step.Action, TargetID: step.TargetID}, ids[0], expiresAt, ids[1], ids[2])
	return err
}

func (processor *securityAgentProcessor) newProductIDs(count int) ([]string, error) {
	values := make([]string, count)
	seen := make(map[string]struct{}, count)
	for index := range values {
		value, err := processor.config.NewProductID()
		if err != nil {
			return nil, errWorkerExecution
		}
		if _, err := domain.ParseProductID(value); err != nil {
			return nil, errWorkerExecution
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errWorkerExecution
		}
		seen[value] = struct{}{}
		values[index] = value
	}
	return values, nil
}
