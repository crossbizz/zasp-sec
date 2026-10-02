package apiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// A registered executor without machine proof must not reserve a real child
// or disclose its linked target. The native plan was admitted normally first.
func assertWorkerTest74UnsignedEffect(t *testing.T, ctx context.Context, owner *pgx.Conn, pool *pgxpool.Pool, o, w, e, run string) {
	t.Helper()
	var step, child string
	if err := owner.QueryRow(ctx, `SELECT step_id,test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&step, &child); err != nil {
		t.Fatal(err)
	}
	q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(q)
	var result json.RawMessage
	err = tx.QueryRow(ctx, `SELECT zasp_temporal74.effect($1::jsonb)`, raw).Scan(&result)
	var refusal *pgconn.PgError
	if err == nil {
		t.Error("unproved registered executor reserved actual74 child/effect")
		q["operation"] = "read"
		raw, _ = json.Marshal(q)
		err = tx.QueryRow(ctx, `SELECT zasp_temporal74.linked($1::jsonb)`, raw).Scan(&result)
		if err == nil {
			t.Error("unproved registered executor read actual74 linked target")
		} else if !errors.As(err, &refusal) || refusal.Code != "42501" {
			t.Error("native74 linked refusal class", err)
		}
	} else if !errors.As(err, &refusal) || refusal.Code != "42501" {
		t.Error("native74 reserve refusal class", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var unchanged bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs WHERE run_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_outbox WHERE payload->>'run_id'=$2) AND EXISTS(SELECT 1 FROM zasp_security_agent_steps WHERE run_id=$1 AND state='authorized')`, run, child).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("rolled-back74 attempt left child/outbox/effect residue", err)
	}
}

// An always-denying fence cannot pass: reserve a real child, persist its actual
// artifact, dispatch once, then read only captured state after grantor revoke.
func assertWorkerTest74SignedEffect(t *testing.T, ctx context.Context, owner *pgx.Conn, pool, compensationPool *pgxpool.Pool, forward *authorization.WorkerExecutor, o, w, e, run string, exerciseProofs bool, reconcile func(), afterDispatch func(map[string]any) bool, afterRevocation func(*authorization.WorkerExecutor), afterReserve ...func()) {
	t.Helper()
	var step, child string
	if err := owner.QueryRow(ctx, `SELECT step_id,test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&step, &child); err != nil {
		t.Fatal(err)
	}
	request := func(op string, payload any) json.RawMessage {
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": op, "payload": payload})
		return q
	}
	call := func(executor *authorization.WorkerExecutor, phase, op string, payload any) map[string]any {
		t.Helper()
		decision, err := executor.Authorize(ctx, authorization.WorkerOperation("test74."+phase), request(op, payload))
		if err != nil {
			t.Fatal("authorize actual74 effect", phase, err)
		}
		raw, err := executor.Execute(ctx, decision)
		if err != nil {
			t.Fatal("execute actual74 effect", phase, err)
		}
		var result map[string]any
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal("actual74 effect response")
		}
		return result
	}
	reconcile()
	if exerciseProofs {
		assertWorkerTest74EffectCatalog(t, ctx, owner)
		forwardKey, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		revision, err := forward.Revision(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		assertWorkerTest74EffectBindings(t, ctx, pool, forwardKey, revision, request("reserve", map[string]any{}), false)
	}
	var privateResult json.RawMessage
	privateErr := pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_effect($1::jsonb)`, request("reserve", map[string]any{})).Scan(&privateResult)
	var privateRefusal *pgconn.PgError
	if !errors.As(privateErr, &privateRefusal) || privateRefusal.Code != "42501" {
		t.Fatal("saved native sibling effect exposed to executor", privateErr)
	}
	if result := call(forward, "effect.reserve", "reserve", map[string]any{}); result["state"] != "reserved" || result["send_permit"] != false {
		t.Fatal("actual child reservation")
	}
	if len(afterReserve) > 0 {
		afterReserve[0]()
		return
	}
	if _, err := forward.Authorize(ctx, "test74.linked.read", request("read", map[string]any{})); !errors.Is(err, authorization.ErrPending) {
		t.Fatal("reserve transition did not hold projection pending", err)
	}
	reconcile()
	// Once the effect exists, unsigned linked reads must still refuse. This is
	// independent of the earlier unsigned-reserve transaction's first error.
	for _, statement := range []string{`SELECT zasp_temporal74.linked($1::jsonb)`, `SELECT zasp_temporal74.test_state($1::jsonb)`} {
		var raw json.RawMessage
		err := pool.QueryRow(ctx, statement, request("read", map[string]any{})).Scan(&raw)
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "42501" {
			t.Fatal("unsigned existing effect reader did not refuse", err)
		}
	}
	linked := call(forward, "linked.read", "read", map[string]any{})
	if linked["test_run_id"] != child || linked["target_resolution"] == nil {
		t.Fatal("signed exact linked target read")
	}
	var body []byte
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('schema_version','red-team-runner-input-v2','organization_id',l.organization_id,'workspace_id',l.workspace_id,'environment_id',l.environment_id,'run_id',c.run_id,'definition_id',l.test_definition_id,'definition_version',l.test_definition_version,'target_id',l.target_id,'target_kind',l.target_kind,'categories',l.test_categories,'input_digest',encode(c.input_digest,'hex'),'runner_image_digest','sha256:'||repeat('a',64)) FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE c.run_id=$1`, child).Scan(&body); err != nil {
		t.Fatal(err)
	}
	org, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	scope, _ := domain.NewScope(org, workspace, environment)
	store, err := artifactstore.New(&orderedTestArtifactDriver{objects: make(map[artifactstore.DriverLocator]artifactstore.DriverObject)}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", run+"\x1f"+step)
	ref, _ := domain.ParseEvidenceRef(id)
	artifact, err := store.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := store.ObjectReference(artifact.Locator)
	manifest := RedTeamArtifactReference{Reference: reference, VersionID: artifact.VersionID, SHA256: hex.EncodeToString(artifact.SHA256[:]), SizeBytes: artifact.Size}
	call(forward, "linked.input", "input", map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(body)})
	if result := call(forward, "linked.dispatch", "dispatch", map[string]any{}); result["send_permit"] != true {
		t.Fatal("first signed actual74 dispatch")
	}
	if result := call(forward, "linked.dispatch", "dispatch", map[string]any{}); result["send_permit"] != false {
		t.Fatal("duplicate signed actual74 dispatch")
	}
	if afterDispatch != nil {
		if afterDispatch(linked) {
			return
		}
	}
	key, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), key.Version(), key.Verifier()); err != nil {
		t.Fatal(err)
	}
	compensation, err := authorization.NewWorkerExecutor(compensationPool, nil, "", "", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compensation.Authorize(ctx, "test74.effect.reserve", request("reserve", map[string]any{})); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("compensation selected new effect reserve", err)
	}
	if _, err := forward.Authorize(ctx, "test74.state", request("read", map[string]any{})); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("executor selected captured state purpose", err)
	}
	// Installing the compensation verifier advances the org revision even
	// though the preceding effect/input/dispatch transitions are unchanged.
	if _, err := forward.Authorize(ctx, "test74.linked.read", request("read", map[string]any{})); !errors.Is(err, authorization.ErrPending) {
		t.Fatal("new verifier did not hold forward projection pending", err)
	}
	reconcile()
	beforeRevoke, err := forward.Authorize(ctx, "test74.linked.read", request("read", map[string]any{}))
	if err != nil {
		t.Fatal("current proof before source revoke", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=(SELECT grantor_id FROM zasp_authorization80_worker.test_associations WHERE run_id=$2)`, o, run); err != nil {
		t.Fatal(err)
	}
	if _, err := forward.Execute(ctx, beforeRevoke); !errors.Is(err, authorization.ErrConflict) {
		t.Fatal("source revocation between Check and native effect", err)
	}
	if _, err := forward.Authorize(ctx, "test74.linked.read", request("read", map[string]any{})); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("revoked forward target disclosure", err)
	}
	if afterRevocation != nil {
		afterRevocation(compensation)
	}
	assertWorkerTest74EffectBindings(t, ctx, compensationPool, key, authorization.Revision{}, request("read", map[string]any{}), true)
	var wrong map[string]any
	_ = json.Unmarshal(request("read", map[string]any{}), &wrong)
	wrong["step_id"] = child
	wrongRequest, _ := json.Marshal(wrong)
	if _, err := compensation.Authorize(ctx, "test74.effect.read", wrongRequest); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("captured effect accepted another native step", err)
	}
	for _, phase := range []string{"state", "effect.read"} {
		result := call(compensation, phase, "read", map[string]any{})
		if len(result) != 6 || result["state"] != "started" || result["run_id"] != run || result["step_id"] != step || result["effect_key"] != linked["effect_key"] {
			t.Fatal("captured exact bounded state", phase)
		}
		allowed := " run_id step_id effect_key generation state send_permit "
		if phase == "state" {
			allowed = " run_id step_id action_key test_run_id effect_key state "
		}
		for name := range result {
			if !strings.Contains(allowed, " "+name+" ") {
				t.Fatal("captured receipt disclosed an unclassified field", phase)
			}
		}
	}
	var exact bool
	invocations := 0
	if afterDispatch != nil {
		invocations = 1
	}
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal74.effects WHERE run_id=$1 AND state='started') AND (SELECT count(*)=1 FROM zasp_temporal74.test_inputs WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_red_team_runs WHERE run_id=$2) AND (SELECT count(*)=1 FROM zasp_red_team_outbox WHERE payload->>'run_id'=$2) AND (SELECT count(*)=$3 FROM zasp_temporal74.invocations WHERE test_run_id=$2)`, run, child, invocations).Scan(&exact); err != nil || !exact {
		t.Fatal("actual74 effect/input/child/outbox cardinality", err)
	}
}
