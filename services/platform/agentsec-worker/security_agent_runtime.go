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
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
	NewProductID      func() (string, error)
}

type securityAgentProcessor struct{ config securityAgentProcessorConfig }

func newSecurityAgentProcessor(config securityAgentProcessorConfig) (*securityAgentProcessor, error) {
	leaseDuration := time.Duration(config.LeaseSeconds) * time.Second
	if config.Authority == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 30 || config.LeaseSeconds > 300 || config.BatchSize < 1 || config.BatchSize > 25 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > leaseDuration/2 || config.Now == nil || config.NewLeaseToken == nil || config.NewProductID == nil || config.Now().IsZero() || config.Now().Location() != time.UTC {
		return nil, errWorkerConfiguration
	}
	return &securityAgentProcessor{config: config}, nil
}

func (processor *securityAgentProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
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
	ids, err := processor.newProductIDs(3)
	if err != nil {
		return err
	}
	expiresAt := processor.config.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
	_, err = processor.config.Authority.PrepareSecurityAgentRun(ctx, claim, processor.config.WorkerID, leaseToken, ids[0], expiresAt, ids[1], ids[2])
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
