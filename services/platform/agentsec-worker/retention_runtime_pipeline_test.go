package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func TestRetentionRuntimePipelineExplicitConfigAndStartup(t *testing.T) {
	base := map[string]string{
		"ZASP_WORKER_MODE": "runtime-coordinator", "ZASP_POSTGRES_DSN": "postgres://runtime_coordinator@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_runtime_coordinator", "ZASP_WORKER_ID": "runtime-coordinator-01", "ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_RUNTIME_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events", "ZASP_AWS_REGION": "us-west-2", "ZASP_RUNTIME_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-runtime-coordinator", "ZASP_RUNTIME_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_RUNTIME_DATABASE_PROFILE": migrations.AuthorizationRuntimeProfileName, "ZASP_RETENTION_PROFILE_CHECKSUM": migrations.RetentionAuditProfileChecksum(),
	}
	cfg, err := loadWorkerRuntimeConfig(mapLookup(base))
	if err != nil || !workerUsesRetentionRuntimeProfile(cfg) {
		t.Fatal("explicit successor not mounted", err)
	}
	for _, ready := range []bool{false, true} {
		db := &runtimeProfileQuery{value: ready}
		err := retentionPipelineStartupReady(context.Background(), db, cfg)
		if (err == nil) != ready || len(db.queries) != 1 || len(db.args[0]) != 4 || db.args[0][1] != "zasp_runtime_coordinator" || db.args[0][2] != "runtime-coordinator" || db.args[0][3] != cfg.RetentionProfileChecksum {
			t.Fatal("startup lost original principal or exact successor pin", err)
		}
	}
	for name, mutate := range map[string]func(map[string]string){
		"parent-only":              func(q map[string]string) { q["ZASP_RUNTIME_DATABASE_PROFILE"] = "" },
		"schedule-queue-on-writer": func(q map[string]string) { q["ZASP_RETENTION_TASK_QUEUE"] = "retention-expiry" },
		"uncompiled-pin":           func(q map[string]string) { q["ZASP_RETENTION_PROFILE_CHECKSUM"] = "uncompiled" },
		"unmounted-mode":           func(q map[string]string) { q["ZASP_WORKER_MODE"] = "runtime-archive" },
	} {
		t.Run(name, func(t *testing.T) {
			q := cloneStringMap(base)
			mutate(q)
			if _, err := loadWorkerRuntimeConfig(mapLookup(q)); err == nil {
				t.Fatal("unapproved successor composition accepted")
			}
		})
	}
}

type retentionCleanupLifecycleFixture struct {
	blocked bool
	passes  int
}

func (f *retentionCleanupLifecycleFixture) Ready(context.Context) error {
	if f.blocked {
		return errRuntimeUnavailable
	}
	return nil
}
func (f *retentionCleanupLifecycleFixture) RunOnce(context.Context) error { f.passes++; return nil }
func (f *retentionCleanupLifecycleFixture) Close() error {
	if f.blocked {
		return errRuntimeUnavailable
	}
	return nil
}
func TestRetentionIndexCleanupCloseRetainsSDKAndOriginalPoolUntilJoin(t *testing.T) {
	cleanup := &retentionCleanupLifecycleFixture{blocked: true}
	sdkClosed, dbClosed := 0, 0
	stage := &productionRuntimeStageDependencies{retentionCleanup: cleanup, ready: func(context.Context) error { return nil }, close: func() error { sdkClosed++; return nil }}
	closeAll := closeWorkerRuntimeDatabase(workerModeRuntimeIndex, stage.Close, func() error { dbClosed++; return nil })
	if stage.Ready(context.Background()) == nil || closeAll() == nil || sdkClosed != 0 || dbClosed != 0 {
		t.Fatal("unjoined cleanup lost originalclients")
	}
	cleanup.blocked = false
	if err := closeAll(); err != nil || sdkClosed != 1 || dbClosed != 1 {
		t.Fatal("cleanup join retry failed", err)
	}
	if stage.Close() != nil || sdkClosed != 1 {
		t.Fatal("SDK close repeated")
	}
}

func TestRetentionRuntimeIndexRequiresMatchingPrecisePhysicalTarget(t *testing.T) {
	base := workerRuntimeConfig{Mode: workerModeRuntimeIndex, RuntimeDatabaseProfile: migrations.AuthorizationRuntimeProfileName, RetentionProfileChecksum: migrations.RetentionAuditProfileChecksum(), RuntimeStageVersion: "runtime-index-v2", RuntimeSessionIndex: "zasp-runtime-sessions-v2"}
	if !workerUsesRetentionRuntimeProfile(base) {
		t.Fatal("matching precise index route rejected")
	}
	for _, shape := range [][2]string{{"runtime-index-v1", "zasp-runtime-sessions-v2"}, {"runtime-index-v2", ""}, {"runtime-index-v2", "zasp-runtime-sessions-v1"}} {
		candidate := base
		candidate.RuntimeStageVersion, candidate.RuntimeSessionIndex = shape[0], shape[1]
		if workerUsesRetentionRuntimeProfile(candidate) {
			t.Fatal("precise DB lease could target legacy index/executor")
		}
	}
}
