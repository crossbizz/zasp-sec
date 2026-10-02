package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestP7WorkerOrdered68TargetLineage(t *testing.T) {
	runWorkerOrdered68PlanningFixture(t, "target-lineage")
}

// The installed native target resolver, not a guessed inventory summary,
// defines the evidence lineage that subsequent effect authority must capture.
// Only its identifiers and digest leave the owned fixture query.
func assertOrdered68TargetLineage(t *testing.T, ctx context.Context, owner, executor *pgx.Conn, start json.RawMessage) {
	t.Helper()
	var identity map[string]any
	if json.Unmarshal(start, &identity) != nil {
		t.Fatal("actual admitted identity")
	}
	delete(identity, "input_digest")
	request, _ := json.Marshal(identity)
	var expectedRaw json.RawMessage
	if err := owner.QueryRow(ctx, `WITH native AS MATERIALIZED (
 SELECT zasp_temporal68.test_target(a.organization_id,a.workspace_id,a.environment_id,a.target_id,d.target_kind,a.test_id,a.test_version) AS resolution
 FROM zasp_authorization80_worker.ordered_associations a
 JOIN public.zasp_red_team_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(a.organization_id,a.workspace_id,a.environment_id,a.test_id,a.test_version)
 WHERE(a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)
) SELECT jsonb_build_object('target_digest',encode(digest(convert_to(resolution::text,'UTF8'),'sha256'),'hex'),
 'snapshot_id',resolution#>>'{provenance,snapshot_id}','evidence_id',resolution#>>'{provenance,evidence_id}',
 'integration_id',resolution#>>'{provenance,integration_id}','source',resolution#>>'{provenance,source}',
 'credential_binding_id',resolution#>>'{comparison,credential_binding_id}') FROM native`, identity["organization_id"], identity["workspace_id"], identity["environment_id"], identity["run_id"]).Scan(&expectedRaw); err != nil {
		t.Fatal("actual native target prerequisite", err)
	}
	var expected map[string]string
	if json.Unmarshal(expectedRaw, &expected) != nil || len(expected) != 6 {
		t.Fatal("native target metadata malformed")
	}
	for _, name := range []string{"target_digest", "snapshot_id", "evidence_id", "integration_id", "source", "credential_binding_id"} {
		if expected[name] == "" {
			t.Fatal("native target prerequisite absent", name)
		}
	}
	var capturedRaw json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning68_source('state',$1::jsonb)`, request).Scan(&capturedRaw); err != nil {
		t.Fatal("actual registered metadata reader", err)
	}
	var captured map[string]json.RawMessage
	if json.Unmarshal(capturedRaw, &captured) != nil {
		t.Fatal("captured target metadata malformed")
	}
	for name, want := range expected {
		var got string
		if json.Unmarshal(captured[name], &got) != nil || got != want {
			t.Error("ordered capture does not bind actual native target lineage", name)
		}
	}
	if t.Failed() {
		return
	}
	// Rollback-only fixture corruption exercises the registered consumer. The
	// compensation reader must retain original metadata even when the native
	// forward resolver can no longer resolve the winning observation.
	controls := []struct{ name, statement string }{
		{"unchanged", `UPDATE zasp_inventory_evidence SET checksum=checksum WHERE id=$1 AND snapshot_id=$2`},
		{"evidence", `UPDATE zasp_inventory_evidence SET checksum=decode(repeat('cd',32),'hex') WHERE id=$1 AND snapshot_id=$2`},
		{"snapshot", `UPDATE zasp_discovery_snapshots SET candidate_digest=decode(repeat('cd',32),'hex') WHERE id=$2 AND EXISTS(SELECT 1 FROM zasp_inventory_evidence WHERE id=$1 AND snapshot_id=$2)`},
		{"observation", `UPDATE zasp_inventory_source_observations SET attributes='{"changed":true}' WHERE evidence_id=$1 AND snapshot_id=$2`},
		{"removed-observation", `UPDATE zasp_inventory_source_observations SET source_state='removed',removed_at=clock_timestamp() WHERE evidence_id=$1 AND snapshot_id=$2`},
	}
	for _, control := range controls {
		for _, compensation := range []bool{false, true} {
			func() {
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					if err := tx.Rollback(rollbackCtx); err != nil {
						t.Error("target control rollback", err)
					}
				}()
				tag, err := tx.Exec(ctx, control.statement+` AND (organization_id,workspace_id,environment_id)=($3,$4,$5)`, expected["evidence_id"], expected["snapshot_id"], identity["organization_id"], identity["workspace_id"], identity["environment_id"])
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("target control prerequisite", control.name, err)
				}
				var current, ready bool
				if err := tx.QueryRow(ctx, `SELECT target_current,zasp_authorization80_worker.catalog_ready() FROM zasp_authorization80_worker.ordered_state WHERE run_id=$1`, identity["run_id"]).Scan(&current, &ready); err != nil || !ready || current != (control.name == "unchanged") {
					t.Fatal("target invalidation control", control.name, err)
				}
				phase, principal, q := "state", "temporal_executor_test_login", request
				if compensation {
					phase, principal = "recovery", "temporal_compensation_test_login"
					copy := make(map[string]any, len(identity)+1)
					for k, v := range identity {
						copy[k] = v
					}
					copy["operation"] = "recovery"
					q, _ = json.Marshal(copy)
				}
				if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{principal}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				var raw json.RawMessage
				err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning68_source($1,$2::jsonb)`, phase, q).Scan(&raw)
				if !compensation && control.name != "unchanged" {
					var native *pgconn.PgError
					if !errors.As(err, &native) || native.Code != "40001" && native.Code != "42501" {
						t.Fatal("changed target accepted", control.name, err)
					}
					return
				}
				if err != nil {
					t.Fatal("captured target consumer", control.name, compensation, err)
				}
				var captured map[string]json.RawMessage
				if json.Unmarshal(raw, &captured) != nil {
					t.Fatal("target control metadata")
				}
				for name, want := range expected {
					var got string
					if json.Unmarshal(captured[name], &got) != nil || got != want {
						t.Fatal("captured target changed", control.name, name)
					}
				}
			}()
		}
		t.Log("native target lineage control", control.name)
	}
}
