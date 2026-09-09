package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type missingSessionProjectionDatabase struct{ readyWorkerDatabase }

func (database missingSessionProjectionDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if strings.Contains(statement, "zasp_production_runtime_sessions_readiness") {
		return nil, errors.New("release absent")
	}
	return database.readyWorkerDatabase.QueryJSON(ctx, statement, args...)
}

func TestRuntimeCompleteCompositionRejectsMissingSessionProjectionBeforeExecution(t *testing.T) {
	called := false
	dependencies, err := composeRuntimeStageWorkerRuntime(validRuntimeCompleteConfig(), missingSessionProjectionDatabase{}, &productionRuntimeStageDependencies{
		Stage: runtimeevent.RuntimeStageComplete,
		Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
			called = true
			return runtimeStageEffect{}, nil
		}),
		ready: func(context.Context) error { return nil }, close: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if dependencies.Ready(context.Background()) == nil || dependencies.Processor.RunOnce(context.Background()) == nil || called {
		t.Fatal("completion admitted missing session storage")
	}
}

func TestRuntimeCompletionCarriesExactVerifiedProjectionIntoAtomicFinish(t *testing.T) {
	lease, artifacts, _ := runtimeCompleteFixture(t)
	wanted := string(artifacts.input.Body)
	executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil || effect.ProjectionReceipt != wanted {
		t.Fatal("completion omitted or changed the verified projection receipt")
	}
	processor := &runtimeStageProcessor{config: runtimeStageProcessorConfig{WorkerID: "runtime-complete-01"}}
	finish := processor.finishRequest(lease, "0123456789abcdef", effect, nil)
	if finish.Outcome != runtimeevent.StageOutcomeSucceeded || finish.ProjectionReceipt != wanted {
		t.Fatal("atomic finish omitted the verified projection receipt")
	}
	failed := processor.finishRequest(lease, "0123456789abcdef", effect, errRuntimeStageMalformed)
	if failed.ProjectionReceipt != "" {
		t.Fatal("failed completion carried a projection mutation")
	}
}
