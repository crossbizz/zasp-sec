package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeStagePassesExplicitExecutionCapability(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	capability := runtimeStageExecution{lease: lease, workerID: "correlator-01", leaseToken: strings.Repeat("a", 32)}
	executor := &authorizedRuntimeStageStub{}
	if _, err := callAuthorizedRuntimeStageExecutor(executor, context.Background(), capability); err != nil {
		t.Fatal(err)
	}
	if executor.legacyCalls != 0 || executor.authorizedCalls != 1 || executor.execution != capability {
		t.Fatal("authorized executor did not receive the exact private lease capability")
	}
}

func TestRuntimeStageRejectsInvalidExecutionCapabilityBeforeEffects(t *testing.T) {
	valid := runtimeStageExecution{lease: runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate), workerID: "correlator-01", leaseToken: strings.Repeat("a", 32)}
	for name, mutate := range map[string]func(*runtimeStageExecution){
		"missing worker": func(value *runtimeStageExecution) { value.workerID = "" },
		"invalid worker": func(value *runtimeStageExecution) { value.workerID = "INVALID" },
		"missing token":  func(value *runtimeStageExecution) { value.leaseToken = "" },
		"invalid token":  func(value *runtimeStageExecution) { value.leaseToken = "short" },
		"missing lease":  func(value *runtimeStageExecution) { value.lease = runtimeevent.StageLease{} },
		"expired lease":  func(value *runtimeStageExecution) { value.lease.LeaseExpiresAt = time.Now().Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			executor := &authorizedRuntimeStageStub{}
			if _, err := callAuthorizedRuntimeStageExecutor(executor, context.Background(), value); err == nil || executor.legacyCalls != 0 || executor.authorizedCalls != 0 {
				t.Fatal("invalid authority reached executor effects")
			}
		})
	}
}

func TestRuntimeStageExecutionCapabilityCannotMarshalCredentials(t *testing.T) {
	value := runtimeStageExecution{lease: runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate), workerID: "correlator-01", leaseToken: strings.Repeat("a", 32)}
	body, err := json.Marshal(value)
	if err != nil || string(body) != "{}" {
		t.Fatal("private capability was serializable")
	}
}

func TestRuntimeStageExecutionCapabilityFormattingRedactsCredentials(t *testing.T) {
	value := runtimeStageExecution{lease: runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate), workerID: "correlator-01", leaseToken: strings.Repeat("a", 32)}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, input := range []any{value, &value} {
			formatted := fmt.Sprintf(format, input)
			if strings.Contains(formatted, value.workerID) || strings.Contains(formatted, value.leaseToken) || strings.Contains(formatted, value.lease.BatchID.String()) {
				t.Fatal("execution capability leaked through formatting")
			}
		}
	}
}

func TestRuntimeStageProcessorUsesAuthorizedExecutor(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	executor := &authorizedRuntimeStageStub{}
	authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{lease}}
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: lease.Stage, ImplementationVersion: lease.ImplementationVersion, WorkerID: "correlator-01", LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if executor.authorizedCalls != 1 || executor.legacyCalls != 0 || executor.execution.workerID != "correlator-01" || executor.execution.leaseToken != strings.Repeat("a", 32) || executor.execution.lease != lease || len(authority.finishes) != 1 {
		t.Fatal("processor bypassed the authorized executor")
	}
}

type authorizedRuntimeStageStub struct {
	legacyCalls     int
	authorizedCalls int
	execution       runtimeStageExecution
}

func (executor *authorizedRuntimeStageStub) Execute(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
	executor.legacyCalls++
	return runtimeStageEffect{}, nil
}

func (executor *authorizedRuntimeStageStub) ExecuteAuthorized(_ context.Context, execution runtimeStageExecution) (runtimeStageEffect, error) {
	executor.authorizedCalls++
	executor.execution = execution
	return runtimeStageEffect{}, nil
}
