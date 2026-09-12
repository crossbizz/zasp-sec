package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimePrecisionHistoryRollbackRefusesLiveSandboxLeaseWithoutRewritingSnapshots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	old := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v2", nil)
	sandbox := seedRuntimeCandidateBatchVersion(t, ctx, admin, 2, sandboxSemantic, "otlp", 2, 1, "runtime-correlation-v3", nil)
	oldBefore := freezeSandboxFixture(t, ctx, worker, old)
	sandboxBefore := freezeSandboxFixture(t, ctx, worker, sandbox)
	runner := installRuntimePrecision(t, ctx, admin)
	// Frozen does not mean completed: the sandbox correlate stage is still
	// leased and schema50's deployment cannot drain it. The rollback guard
	// applies regardless of which migration originally created that work.
	for _, phase := range []string{"installed", "rollback-refused"} {
		if phase == "rollback-refused" {
			if err := runner.DownProductionRuntimePrecision(ctx); !errors.Is(err, migrations.ErrDatabase) {
				t.Fatal("rollback accepted unfinished sandbox work", err)
			}
			if version, err := runner.Version(ctx); err != nil || version != 51 {
				t.Fatal("refused rollback changed release", version, err)
			}
		}
		oldAfter := freezeSandboxFixture(t, ctx, worker, old)
		sandboxAfter := freezeSandboxFixture(t, ctx, worker, sandbox)
		if !oldAfter.Replayed() || !sandboxAfter.Replayed() || !bytes.Equal(oldBefore.Bytes(), oldAfter.Bytes()) || !bytes.Equal(sandboxBefore.Bytes(), sandboxAfter.Bytes()) {
			t.Fatal("historical bytes changed", phase)
		}
	}
}

func TestRuntimePrecisionHistoryRegisteredFreezeAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	semantic := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxSemantic, "otlp", 1, 1, "runtime-correlation-v3", nil)
	freezeSandboxFixture(t, ctx, worker, semantic)
	contract := candidateFixtureWire{schema: "runtime-event-v2", archive: "runtime-archive-v2", index: "runtime-index-v2", prepare: preparePreciseCandidateArchive}
	args := seedRuntimeCandidateBatchInput(t, ctx, admin, 2, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v4", nil, true, contract)
	var result, replay []byte
	if err := worker.QueryRow(ctx, preciseFreezeSQL, args...).Scan(&result); err != nil {
		t.Fatal("registered precise freeze", err)
	}
	if err := worker.QueryRow(ctx, preciseFreezeSQL, args...).Scan(&replay); err != nil {
		t.Fatal("registered precise replay", err)
	}
	var first, second struct {
		Snapshot json.RawMessage `json:"snapshot"`
		Replayed bool            `json:"replayed"`
	}
	if err := json.Unmarshal(result, &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay, &second); err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || !bytes.Equal(first.Snapshot, second.Snapshot) {
		t.Fatal("precise frozen replay changed", string(result), string(replay))
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_candidate_snapshots WHERE convert_from(snapshot_body,'UTF8')::jsonb->>'schema'='runtime-candidate-snapshot-v3'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("registered snapshot codec", count, err)
	}
}

func TestRuntimePrecisionHistoryOldFinishersKeepTheirSearchQueues(t *testing.T) {
	for _, sandbox := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "sandbox"}[sandbox], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, sandbox)
			installRuntimePrecision(t, ctx, admin)
			worker := sandboxSessionCoordinator(t, ctx, admin)
			query := sessionProjectionFinishSQL
			if sandbox {
				query = sandboxSessionFinishSQL
			}
			var result, replay []byte
			if err := worker.QueryRow(ctx, query, args...).Scan(&result); err != nil {
				t.Fatal("historical finisher", err)
			}
			if err := worker.QueryRow(ctx, query, args...).Scan(&replay); err != nil || !bytes.Equal(result, replay) {
				t.Fatal("historical completion replay", err)
			}
			var legacy, newQueue int
			if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_session_search_outbox),(SELECT count(*) FROM zasp_runtime_sandbox_search_outbox)`).Scan(&legacy, &newQueue); err != nil || newQueue != 1 || legacy != map[bool]int{false: 1, true: 0}[sandbox] {
				t.Fatal("historical target checkpoints", legacy, newQueue, err)
			}
		})
	}
}
