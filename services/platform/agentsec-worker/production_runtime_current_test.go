package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type currentCompositionDatabase struct {
	readyWorkerDatabase
	roles  []string
	legacy int
	fail   bool
}

func (d *currentCompositionDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	if !strings.Contains(query, "zasp_authorization80_runtime.ready($1,$2)") || len(args) != 2 || args[0] != migrations.AuthorizationRuntimeProfileChecksum() {
		d.legacy++
		return nil, errors.New("historical query refused")
	}
	role, ok := args[1].(string)
	if !ok {
		return nil, errors.New("invalid current role")
	}
	d.roles = append(d.roles, role)
	if d.fail {
		return nil, errors.New("current profile unavailable")
	}
	if strings.Contains(query, "jsonb_build_object") {
		return json.RawMessage(`{"ready":true}`), nil
	}
	return json.RawMessage(`true`), nil
}

func currentCompositionConfig(c workerRuntimeConfig) workerRuntimeConfig {
	c.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "owned", TaskQueue: "owned-agent", DiscoveryTaskQueue: "owned-discovery", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/fixture/token", Timeout: time.Second}
	return c
}

func TestCurrentRuntimeCompositionSelectsProfileIndependentOfVersion(t *testing.T) {
	configs := []workerRuntimeConfig{validRuntimeCoordinatorConfig(), validRuntimeArchiveConfig(), validRuntimeIndexConfig(), validRuntimeCorrelationConfig(), validRuntimeProjectionConfig(), validRuntimeCompleteConfig()}
	outbox := validSchedulerRuntimeConfig()
	outbox.Mode, outbox.DatabaseAuthority, outbox.WorkerID = workerModeRuntimeOutbox, "zasp_outbox_worker", "runtime-outbox-01"
	outbox.RuntimeQueueURL, outbox.AWSRegion = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", "us-west-2"
	outbox.OutboxRoleARN, outbox.OutboxTokenFile = "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	configs = append(configs, outbox)
	for _, base := range configs {
		for _, sqlOnly := range []bool{false, true} {
			for _, fail := range []bool{false, true} {
				t.Run(string(base.Mode)+map[bool]string{false: "/services", true: "/sql-only"}[sqlOnly]+map[bool]string{false: "/ready", true: "/closed"}[fail], func(t *testing.T) {
					config := currentCompositionConfig(base)
					if sqlOnly {
						config.RuntimeServices = runtimeservices.Config{}
						config.RuntimeDatabaseProfile = migrations.AuthorizationRuntimeProfileName
					}
					db := &currentCompositionDatabase{fail: fail}
					var dep workerRuntimeDependencies
					var err error
					switch config.Mode {
					case workerModeRuntimeCoordinator:
						queue, _, _ := runtimeCoordinatorQueue(t, &runtimeCoordinatorSteps{})
						dep, err = composeRuntimeCoordinatorWorkerRuntime(config, db, &productionRuntimeQueueDependencies{Queue: queue, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
					case workerModeRuntimeOutbox:
						dep, err = composeOutboxWorkerRuntime(config, db, &recordingOutboxPublisher{}, readyOutboxDependency)
					default:
						stage, _, _ := runtimeStageBinding(config.Mode)
						d := &productionRuntimeStageDependencies{Stage: stage, Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
							return runtimeStageEffect{}, errRuntimeStageRetryable
						}), ready: func(context.Context) error { return nil }, close: func() error { return nil }}
						if stage == runtimeevent.RuntimeStageIndex {
							d.Sessions = sessionSearchExecuteFunc(func(context.Context, runtimeSessionSearchLease) ([]string, error) {
								return nil, errRuntimeStageRetryable
							})
							d.SessionReady = func(context.Context) error { return nil }
						}
						dep, err = composeRuntimeStageWorkerRuntime(config, db, d)
					}
					if err != nil {
						if fail && config.Mode == workerModeRuntimeOutbox && db.legacy == 0 && len(db.roles) == 1 && db.roles[0] == config.DatabaseAuthority {
							return // The retained outbox constructor checks readiness eagerly.
						}
						t.Fatalf("composition: %v", err)
					}
					if config.Mode == workerModeRuntimeCoordinator {
						gate, ok := dep.Processor.(readinessGatedWorkerProcessor)
						if !ok {
							t.Fatal("missing coordinator readiness gate")
						}
						coordinator, ok := gate.delegate.(*runtimeCoordinator)
						if !ok || !coordinator.precision {
							t.Fatal("current profile cannot consume precise backlog")
						}
					}
					err = dep.Ready(context.Background())
					if (err != nil) != fail || db.legacy != 0 || len(db.roles) == 0 {
						t.Fatalf("ready error=%v current=%d historical=%d", err, len(db.roles), db.legacy)
					}
					for _, role := range db.roles {
						if role != config.DatabaseAuthority {
							t.Fatalf("wrong principal %q", role)
						}
					}
				})
			}
		}
	}
}
