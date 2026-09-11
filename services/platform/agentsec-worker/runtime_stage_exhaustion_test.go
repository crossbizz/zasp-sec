package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"testing"
)

func TestRuntimeStageFinishAcceptsOnlyExactTerminalExhaustion(t *testing.T) {
	for _, outcome := range []runtimeevent.StageOutcome{runtimeevent.StageOutcomeRetryable, runtimeevent.StageOutcomeFailed} {
		lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
		lease.Attempt = 100
		request := runtimeevent.StageFinishRequest{Lease: lease, Outcome: outcome, ErrorClass: "denied"}
		if outcome == runtimeevent.StageOutcomeRetryable {
			request.ErrorClass = "retryable"
		}
		result := runtimeevent.StageFinishResult{BatchID: lease.BatchID, Generation: lease.Generation, Stage: lease.Stage, State: runtimeevent.StageOutcomeFailed, Attempt: 100, InputDigest: lease.InputDigest, ImplementationVersion: lease.ImplementationVersion, ErrorClass: "exhausted"}
		if !exactRuntimeStageFinish(result, request) {
			t.Errorf("terminal exhaustion rejected for %s", outcome)
		}
		result.ErrorClass = request.ErrorClass
		if exactRuntimeStageFinish(result, request) {
			t.Errorf("wrong terminal error accepted for %s", outcome)
		}
		result.ErrorClass = "exhausted"
		request.Lease.Attempt, result.Attempt = 99, 99
		if exactRuntimeStageFinish(result, request) {
			t.Errorf("premature exhaustion accepted for %s", outcome)
		}
	}
}
