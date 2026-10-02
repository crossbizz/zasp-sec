package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func assertOrderedPostAdapterRunner(t *testing.T, ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, start orchestration.StartRequest, store artifactstore.ObjectReferencingArtifactStore, driver *orderedCheckpointArtifacts, phase string, productErr error, engineCalls int) {
	t.Helper()
	if engineCalls != 1 || errors.Is(productErr, context.Canceled) || errors.Is(productErr, context.DeadlineExceeded) || errors.Is(productErr, authorization.ErrUnavailable) {
		t.Fatal("post-adapter producer did not complete its single bounded engine call", productErr, engineCalls)
	}
	if productErr != nil && !errors.Is(productErr, orchestration.ErrInvalid) && !errors.Is(productErr, authorization.ErrDenied) && !errors.Is(productErr, authorization.ErrConflict) && !errors.Is(productErr, authorization.ErrPending) {
		t.Fatal("unexpected post-adapter product failure", productErr)
	}
	var child, step string
	var nativeInput, manifest json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT test_run_id,step_id,body,manifest FROM zasp_temporal68.test_inputs WHERE run_id=$1`, start.Ref.RunID).Scan(&child, &step, &nativeInput, &manifest); err != nil {
		t.Fatal("actual dispatched input absent", err)
	}
	var journalCorrect bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(j.attempt=1 AND j.started_at IS NOT NULL AND
 CASE WHEN $2='test-response-revoked' THEN j.state='completed' AND j.completed_at IS NOT NULL AND j.http_status=200 AND j.protected AND j.response_digest IS NOT NULL AND j.credential_version_digest IS NOT NULL
 ELSE j.state='started' AND j.completed_at IS NULL AND j.http_status IS NULL AND j.protected IS NULL AND j.response_digest IS NULL AND j.credential_version_digest IS NULL END)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts a WHERE a.run_id=$3)
 FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1 AND f.action_key='run_test'`, start.Ref.RunID, phase, child).Scan(&journalCorrect); err != nil || !journalCorrect {
		t.Fatal("post-send journal was lost or fabricated settlement appeared", err)
	}
	if len(driver.writes) < 1 || len(driver.writes) > 2 {
		t.Fatal("unexpected actual artifact writes", len(driver.writes))
	}
	var output *artifactstore.DriverObject
	for index := range driver.writes {
		written := driver.writes[index]
		object, err := store.Get(ctx, artifactstore.Locator{Scope: written.Scope, Reference: written.Reference, VersionID: written.VersionID})
		if err != nil || !bytes.Equal(object.Body, written.Body) || object.SHA256 != written.SHA256 {
			t.Fatal("real post-adapter artifact not retained", err)
		}
		if written.Reference.ArtifactID().String() == child {
			copy := written
			output = &copy
		} else if !bytes.Equal(written.Body, nativeInput) {
			t.Fatal("prepared input artifact changed")
		}
	}
	if phase == "test-disconnected" {
		// A real engine may persist a failure bundle. It is evidence, never a
		// successful settlement, and must not be replaced by a fabricated one.
		if output != nil {
			var bundle existingTestEvidenceBundle
			if json.Unmarshal(output.Body, &bundle) != nil || bundle.Summary.Verdict != "engine_error" {
				t.Fatal("disconnect output claims completed evaluation")
			}
		}
		t.Log("actual customer disconnect retained one started journal and real artifacts without settlement")
		return
	}
	if phase != "test-response-revoked" || output == nil || len(driver.writes) != 2 || productErr == nil {
		t.Fatal("revoked response did not retain output and refuse first settlement", productErr)
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(
 ($2::jsonb#>'{native_artifact,native_output,results,results,0,response,linked_observation}')=jsonb_build_object('schema_version','red-team-linked-observation-v1','run_id',j.test_run_id,'category',j.category,'credential_version_digest',encode(j.credential_version_digest,'hex'),'target_comparison',j.target_resolution->'comparison','observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected)))
 AND EXISTS(SELECT 1 FROM public.zasp_security_agent_runs r JOIN public.zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(r.organization_id,r.requested_by) WHERE r.run_id=$1 AND NOT m.active)
 FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1`, start.Ref.RunID, output.Body).Scan(&bound); err != nil || !bound {
		t.Fatal("captured completed response/comparison or actual revocation absent", err)
	}
	// Wait for the real background projector after the product attempt returns.
	// A pending revision is not accepted as the required authority refusal.
	wait, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	for {
		var equal bool
		if err := owner.QueryRow(wait, `SELECT desired=applied FROM zasp_authorization79.organizations WHERE organization_id=$1`, start.Ref.OrganizationID).Scan(&equal); err != nil {
			t.Fatal("post-response revision convergence", err)
		}
		if equal {
			break
		}
		select {
		case <-wait.Done():
			t.Fatal("post-response real projection did not converge")
		case <-time.After(50 * time.Millisecond):
		}
	}
	snapshot := func() []byte {
		var result []byte
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(r) FROM public.zasp_security_agent_runs r WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM public.zasp_security_agent_steps s WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id) FROM zasp_temporal68.effects f WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY step_id) FROM zasp_temporal68.test_inputs i WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(j) ORDER BY category) FROM zasp_temporal68.invocations j WHERE test_run_id=$2))`, start.Ref.RunID, child).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	objectRef, err := store.ObjectReference(artifactstore.Locator{Scope: output.Scope, Reference: output.Reference, VersionID: output.VersionID})
	if err != nil {
		t.Fatal(err)
	}
	outputManifest := apiserver.RedTeamArtifactReference{Reference: objectRef, VersionID: output.VersionID, SHA256: hex.EncodeToString(output.SHA256[:]), SizeBytes: int64(len(output.Body))}
	request, _ := json.Marshal(map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "run_id": start.Ref.RunID, "step_id": step, "generation": 1, "operation": "complete", "payload": map[string]any{"output_manifest": outputManifest, "output_body": base64.StdEncoding.EncodeToString(output.Body)}})
	repository, err := apiserver.NewSecurityAgentTemporalExecutorRepository(product.orderedTestDatabase(start))
	if err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = repository.TemporalTestSettle(bounded, request, store)
	cancel()
	if !errors.Is(err, authorization.ErrDenied) && !errors.Is(err, authorization.ErrConflict) {
		t.Fatal("first forward settlement after real revocation did not produce authority refusal", err)
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("denied first settlement changed captured evidence")
	}
	var noSettlement bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)`, start.Ref.RunID).Scan(&noSettlement); err != nil || !noSettlement {
		t.Fatal("revoked first settlement persisted a receipt", err)
	}
	t.Log("captured Complete retained actual response and artifacts; first forward settlement denied after real revision convergence")
}

func assertOrderedPostRecoveryRetry(t *testing.T, ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, start orchestration.StartRequest) {
	t.Helper()
	var terminal bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal69.stops WHERE run_id=$1)
 AND EXISTS(SELECT 1 FROM zasp_temporal68.test_stops WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)`, start.Ref.RunID).Scan(&terminal); err != nil || !terminal {
		t.Fatal("captured recovery did not precede actual product retry", err)
	}
	snapshot := func() []byte {
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id) FROM zasp_temporal68.effects f WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(j) ORDER BY category) FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1),
 (SELECT to_jsonb(s) FROM zasp_temporal68.test_stops s WHERE run_id=$1),
 (SELECT to_jsonb(s) FROM zasp_temporal69.stops s WHERE run_id=$1))`, start.Ref.RunID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := snapshot()
	// No runner is installed: terminal product routing must never reach it.
	// An incorrect branch fails, it cannot silently issue another request.
	if product.runner != nil {
		t.Fatal("retry unexpectedly has a runner")
	}
	if err := product.Test(ctx, start); err != nil {
		t.Fatal("actual captured recovery Test retry", err)
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("actual recovery retry altered send/stop evidence")
	}
	t.Log("actual product Test retry after captured69 recovery performed no send and preserved native evidence")
}
