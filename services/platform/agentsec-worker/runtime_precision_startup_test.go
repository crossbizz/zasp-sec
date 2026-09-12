package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type precisionStartupDatabase struct {
	readyWorkerDatabase
	healthy bool
	claims  []string
	checks  int
}

func (database *precisionStartupDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	if strings.Contains(statement, "zasp_production_runtime_precision_readiness") {
		database.checks++
		if strings.Contains(statement, "to_jsonb") {
			if database.healthy {
				return json.RawMessage(`true`), nil
			}
			return json.RawMessage(`false`), nil
		}
		if database.healthy {
			return json.RawMessage(`{"ready":true}`), nil
		}
		return json.RawMessage(`{"ready":false}`), nil
	}
	if strings.Contains(statement, "zasp_runtime_claim_") {
		database.claims = append(database.claims, statement)
		return json.RawMessage(`[]`), nil
	}
	if strings.Contains(statement, "zasp_runtime_precise_search_claim") {
		database.claims = append(database.claims, statement)
		return json.RawMessage(`null`), nil
	}
	return json.RawMessage(`{"ready":true}`), nil
}

func TestPrecisionStartupRequiresRelease51ForEachStage(t *testing.T) {
	for _, test := range []struct {
		config         workerRuntimeConfig
		version, claim string
		stage          runtimeevent.RuntimeStage
	}{
		{validRuntimeArchiveConfig(), "runtime-archive-v2", "zasp_runtime_claim_archive_v2", runtimeevent.RuntimeStageArchive},
		{validRuntimeIndexConfig(), "runtime-index-v2", "zasp_runtime_claim_index_v2", runtimeevent.RuntimeStageIndex},
		{validRuntimeCorrelationConfig(), "runtime-correlation-v4", "zasp_runtime_claim_correlation_v4", runtimeevent.RuntimeStageCorrelate},
		{validRuntimeProjectionConfig(), "runtime-projection-v3", "zasp_runtime_claim_projection_v3", runtimeevent.RuntimeStageProject},
		{validRuntimeCompleteConfig(), "runtime-complete-v3", "zasp_runtime_claim_completion_v3", runtimeevent.RuntimeStageComplete},
	} {
		for _, healthy := range []bool{false, true} {
			t.Run(test.version+map[bool]string{false: "/unready", true: "/ready"}[healthy], func(t *testing.T) {
				config := test.config
				config.RuntimeStageVersion = test.version
				if test.stage == runtimeevent.RuntimeStageIndex {
					config.RuntimeSessionIndex = "zasp-runtime-sessions-v2"
				}
				database := &precisionStartupDatabase{healthy: healthy}
				stage := &productionRuntimeStageDependencies{Stage: test.stage, Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
					t.Fatal("empty queue executed")
					return runtimeStageEffect{}, nil
				}), ready: func(context.Context) error { return nil }, close: func() error { return nil }}
				if test.stage == runtimeevent.RuntimeStageIndex {
					stage.Sessions = sessionSearchExecuteFunc(func(context.Context, runtimeSessionSearchLease) ([]string, error) {
						t.Fatal("empty search queue executed")
						return nil, nil
					})
					stage.SessionReady = func(context.Context) error { return nil }
				}
				dependencies, err := composeRuntimeStageWorkerRuntime(config, database, stage)
				if err != nil {
					t.Fatal("precise composition rejected", err)
				}
				if err := dependencies.Ready(context.Background()); (err == nil) != healthy {
					t.Fatal("startup readiness bypass", err)
				}
				err = dependencies.Processor.RunOnce(context.Background())
				if healthy {
					if err != nil || len(database.claims) == 0 || !strings.Contains(database.claims[0], test.claim) {
						t.Fatal("wrong stage claim", err, database.claims)
					}
					if test.stage == runtimeevent.RuntimeStageIndex && (len(database.claims) != 2 || !strings.Contains(database.claims[1], "zasp_runtime_precise_search_claim")) {
						t.Fatal("wrong search authority", database.claims)
					}
				} else if err == nil || len(database.claims) != 0 {
					t.Fatal("unready worker claimed work", err, database.claims)
				}
				if database.checks == 0 {
					t.Fatal("precision readiness never checked")
				}
			})
		}
	}
}
