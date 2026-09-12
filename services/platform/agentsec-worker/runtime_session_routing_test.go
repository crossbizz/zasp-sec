package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"reflect"
	"strings"
	"testing"
)

func TestSandboxSessionWorkerCompositionSelectsV2Claims(t *testing.T) {
	for _, stage := range []runtimeevent.RuntimeStage{runtimeevent.RuntimeStageProject, runtimeevent.RuntimeStageComplete} {
		t.Run(string(stage), func(t *testing.T) {
			config := validRuntimeProjectionConfig()
			config.RuntimeStageVersion = "runtime-projection-v2"
			want := `SELECT zasp_runtime_claim_projection_v2($1,$2,$3,$4)`
			if stage == runtimeevent.RuntimeStageComplete {
				config = validRuntimeCompleteConfig()
				config.RuntimeStageVersion = "runtime-complete-v2"
				want = `SELECT zasp_runtime_claim_completion_v2($1,$2,$3,$4)`
			}
			database := &sessionWorkerRoutingDatabase{authority: config.DatabaseAuthority, wantClaim: want}
			executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
				t.Fatal("empty claim reached executor")
				return runtimeStageEffect{}, nil
			})
			dependencies, err := composeRuntimeStageWorkerRuntime(config, database, &productionRuntimeStageDependencies{Stage: stage, Executor: executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
			if err != nil {
				t.Fatal("v2 worker configuration rejected", err)
			}
			if err := dependencies.Ready(context.Background()); err != nil {
				t.Fatal("v2 readiness", err)
			}
			if err := dependencies.Processor.RunOnce(context.Background()); err != nil {
				t.Fatal("v2 poll", err)
			}
			if database.claims != 1 || database.checks < 2 {
				t.Fatal("worker skipped claim-time pinned capability", database.claims, database.checks)
			}
			database.unavailable = true
			if err := dependencies.Processor.RunOnce(context.Background()); err == nil || database.claims != 1 {
				t.Fatal("cached readiness bypassed current authority", err, database.claims)
			}
			invalid := config
			invalid.RuntimeStageVersion = strings.TrimSuffix(config.RuntimeStageVersion, "2") + "4"
			if validWorkerRuntimeConfig(invalid) {
				t.Fatal("unknown worker version accepted")
			}
		})
	}
}

type sessionWorkerRoutingDatabase struct {
	readyWorkerDatabase
	authority, wantClaim string
	claims, checks       int
	unavailable          bool
}

func (database *sessionWorkerRoutingDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if statement == `SELECT jsonb_build_object('ready',zasp_production_runtime_sandbox_binding_readiness($1,$2) AND zasp_runtime_principal_ready($3))` {
		database.checks++
		if !reflect.DeepEqual(args, []any{migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint(), database.authority}) {
			return nil, errors.New("wrong sandbox pins")
		}
		if database.unavailable {
			return json.RawMessage(`{"ready":false}`), nil
		}
		return json.RawMessage(`{"ready":true}`), nil
	}
	if statement == database.wantClaim {
		database.claims++
		return json.RawMessage(`[]`), nil
	}
	if strings.Contains(statement, "zasp_production_runtime_sessions_readiness") {
		return database.readyWorkerDatabase.QueryJSON(ctx, statement, args...)
	}
	return nil, errors.New("unexpected session worker operation")
}
