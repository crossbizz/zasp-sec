package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Missing product wiring, an unbound send, or a duplicate send on retry each
// fails this consumer. Only the remote provider and artifact storage are owned
// fixture endpoints; the product, shared planner, database and FGA are real.
func assertWorkerTest74ProductPlanning(t *testing.T, ctx context.Context, dsn string, config runtimeservices.Config, writer authorization.TupleWriter, product *temporalSecurityAgentProduct, start orchestration.StartRequest, mode string, fgaTransport *workerNativeFGATransport) {
	t.Helper()
	mode, timezone := configureWorkerPlannerTimezone(t, ctx, dsn, product, start, mode, workerPlanningTest74)
	owner, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("owned74 observer unavailable")
	}
	defer owner.Close()
	var fault atomic.Bool
	revoke := func(callCtx context.Context) error {
		_, err := owner.Exec(callCtx, `UPDATE zasp_identity_memberships m SET active=false FROM zasp_security_agent_runs r WHERE r.run_id=$1 AND m.principal_id=r.requested_by AND m.organization_id=r.organization_id`, start.Ref.RunID)
		if err == nil {
			fault.Store(true)
		}
		return err
	}
	var selection securityAgentMultistepPricingBinding
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_WORKER_SELECTION")), &selection) != nil || selection.OrganizationID != start.Ref.OrganizationID {
		t.Fatal("owned74 pricing selection unavailable")
	}
	var action, testID, outbox string
	if err := owner.QueryRow(ctx, `SELECT x.action_key,a.test_id FROM zasp_temporal74.run_owners x JOIN zasp_authorization80_worker.test_associations a USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, start.Ref.RunID).Scan(&action, &testID); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	projectionConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("owned74 projection configuration")
	}
	projectionConfig.ConnConfig.User = outbox
	projectionPool, err := pgxpool.NewWithConfig(ctx, projectionConfig)
	if err != nil {
		t.Fatal("owned74 projection pool")
	}
	defer projectionPool.Close()
	projection, err := authorization.NewPostgresProjectionRepository(projectionPool)
	if err != nil {
		t.Fatal(err)
	}
	projectionCtx, stop := context.WithCancel(ctx)
	joined := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			_, err := authorization.Reconcile(projectionCtx, projection, writer, start.Ref.OrganizationID, config.StoreID, config.ModelID)
			if err != nil && !errors.Is(err, authorization.ErrConflict) && projectionCtx.Err() == nil {
				joined <- err
				return
			}
			select {
			case <-projectionCtx.Done():
				joined <- nil
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() {
		stop()
		if err := <-joined; err != nil {
			t.Error("owned74 projection loop", err)
		}
	}()
	var calls atomic.Int32
	var terminalBefore atomic.Value
	var lateResponse atomic.Value
	const terminalHashSQL = `SELECT encode(digest(convert_to(to_jsonb(a)::text,'UTF8'),'sha256'),'hex') FROM zasp_security_agent_audit a WHERE a.run_id=$1 AND a.event_kind='temporal_planning_terminal'`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		var bound bool
		if err != nil || owner.QueryRow(ctx, `SELECT j.state='started' AND j.input_version IS NOT NULL AND j.request_body=$2 AND j.lookup_request->>'credential_digest'=$3 AND p.reservation_id=j.reservation_id AND p.settled_at IS NULL AND p.released_at IS NULL FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal74.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, start.Ref.RunID, string(body), orderedPlanningDigest([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))).Scan(&bound) != nil || !bound {
			t.Error("actual74 provider send lacked persisted start/request/credential/reservation")
			w.WriteHeader(500)
			return
		}
		if mode == "planning-sent-revoke" || mode == "planning-sent-late" {
			if err := revoke(ctx); err != nil {
				t.Error("owned74 post-start revoke", err)
				w.WriteHeader(500)
				return
			}
		}
		if mode == "planning-sent-late" {
			q := temporalStartFields(start)
			delete(q, "input_digest")
			q["operation"] = "reconcile"
			q["payload"] = map[string]any{}
			encoded, _ := json.Marshal(q)
			terminalExecutor := workerPlannerTerminalExecutor(product, timezone)
			decision, err := terminalExecutor.Authorize(ctx, "test74.planning.reconcile", encoded)
			if err == nil {
				_, err = terminalExecutor.Execute(ctx, decision)
			}
			var prior string
			if err == nil {
				err = owner.QueryRow(ctx, terminalHashSQL, start.Ref.RunID).Scan(&prior)
			}
			if err != nil {
				t.Error("actual74 captured in-flight terminalization", err)
				w.WriteHeader(500)
				return
			}
			terminalBefore.Store(prior)
		}
		if mode == "planning-sent-fga" {
			fgaTransport.unavailable.Store(true)
			fault.Store(true)
		}
		candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Run pinned test", "steps": []any{map[string]any{"index": 0, "action": action, "target_id": testID}}})
		var response map[string]json.RawMessage
		_ = json.Unmarshal(openRouterPlannerResponse(string(candidate)), &response)
		response["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
		encoded, _ := json.Marshal(response)
		encoded = append(encoded, '\n')
		if mode == "planning-sent-late" {
			lateResponse.Store(encoded)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	httpClient := server.Client()
	defer httpClient.CloseIdleConnections()
	product.planner = orderedRequestBindingPlanner(t, &release61TLSTransport{base: httpClient.Transport, target: target})
	if mode == "planning-sent-late" {
		product.planner.client.Timeout = 10 * time.Second
	}
	driver := &workerTest74ArtifactObserver{singleTestArtifactDriver: &singleTestArtifactDriver{temporalPlannerArtifactDriver: temporalPlannerArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}}}
	if mode == "planning-prepared-revoke" {
		driver.beforeGet = func(callCtx context.Context) error {
			if fault.Load() {
				return nil
			}
			var prepared bool
			if err := owner.QueryRow(callCtx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE run_id=$1 AND state='prepared')`, start.Ref.RunID).Scan(&prepared); err != nil {
				return err
			}
			if prepared {
				return revoke(callCtx)
			}
			return nil
		}
	}
	product.store, err = artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	product.bindings = []securityAgentMultistepPricingBinding{selection}
	timezone.diagnose(ctx, owner, product, "before_plan", calls.Load(), fault.Load())
	for {
		err = product.SingleTestProduct().Plan(ctx, start)
		if err == nil {
			break
		}
		if !errors.Is(err, authorization.ErrPending) && !errors.Is(err, authorization.ErrConflict) {
			t.Fatal("actual74 shared product planning", err, "provider_calls", calls.Load())
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual74 planning deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	timezone.diagnose(ctx, owner, product, "after_plan", calls.Load(), fault.Load())
	if err := product.SingleTestProduct().Plan(ctx, start); err != nil {
		t.Fatal("actual74 admitted retry", err)
	}
	if mode == "planning-sent-late" {
		body, ok := lateResponse.Load().([]byte)
		if !ok {
			t.Fatal("owned74 late response missing")
		}
		identity := temporalStartFields(start)
		delete(identity, "input_digest")
		encoded, _ := json.Marshal(identity)
		database := &workerFindingPlanningDatabase{base: product.executor, forward: product.workerForward, compensation: product.workerCompensation, start: start, family: workerPlanningTest74}
		for n := 0; n < 2; n++ {
			if err := database.RecoverCapturedPlanning(ctx, encoded, body); err != nil {
				t.Fatal("exact74 late recovery replay", err)
			}
		}
	}
	getsBeforeReplay := driver.gets
	timezone.assertReplay(ctx, owner, product, mode, lateResponse.Load())
	if driver.gets != getsBeforeReplay {
		t.Fatal("captured timezone replay read provider artifacts")
	}
	var exact bool
	if mode != "planning" {
		if !fault.Load() {
			t.Fatal("owned74 recovery fault not reached")
		}
		if err := owner.QueryRow(ctx, `SELECT j.state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans p WHERE p.run_id=j.run_id) AND (SELECT count(*)=1 FROM zasp_security_agent_audit a WHERE a.run_id=j.run_id AND a.event_kind='temporal_planning_terminal') AND EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations p WHERE p.run_id=j.run_id AND CASE WHEN $2 THEN p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.total_tokens IS NULL ELSE p.settled_at IS NOT NULL AND p.total_tokens=30 AND p.cost_nano_credits=30000 END) FROM zasp_temporal74.planning_jobs j WHERE j.run_id=$1`, start.Ref.RunID, mode == "planning-prepared-revoke").Scan(&exact); err != nil || !exact {
			t.Fatal("actual74 recovery did not settle captured debt without admission", err)
		}
		want := int32(1)
		if mode == "planning-prepared-revoke" {
			want = 0
		}
		if calls.Load() != want || driver.puts != 1 {
			t.Fatal("actual74 recovery fresh send/artifact", calls.Load(), driver.puts)
		}
		if mode == "planning-sent-late" {
			var after string
			var entries int
			if err := owner.QueryRow(ctx, terminalHashSQL, start.Ref.RunID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal74.planning_late_usage WHERE run_id=$1`, start.Ref.RunID).Scan(&entries); err != nil {
				t.Fatal(err)
			}
			before, ok := terminalBefore.Load().(string)
			if !ok || before == "" || before != after || entries != 1 {
				t.Fatal("actual74 late charge duplicated or original terminal audit changed", entries)
			}
		}
		return
	}
	if err := owner.QueryRow(ctx, `SELECT j.state='admitted' AND (SELECT count(*)=1 FROM zasp_security_agent_plans p WHERE p.run_id=j.run_id) AND (SELECT count(*)=1 AND bool_and(step_index=0 AND action_key=$2) FROM zasp_security_agent_steps s WHERE s.run_id=j.run_id) AND EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations p WHERE p.run_id=j.run_id AND p.settled_at IS NOT NULL AND p.total_tokens=30 AND p.cost_nano_credits=30000) AND NOT zasp_authorization80_worker.runtime_ready() FROM zasp_temporal74.planning_jobs j WHERE j.run_id=$1`, start.Ref.RunID, action).Scan(&exact); err != nil || !exact {
		t.Fatal("actual74 shared planner admission/accounting", err)
	}
	if calls.Load() != 1 || driver.puts != 2 {
		t.Fatal("actual74 shared planner send/artifact cardinality", calls.Load(), driver.puts)
	}
	if err := product.SingleTestProduct().Test(ctx, start); err == nil {
		t.Fatal("unimplemented74 test used legacy forward path")
	}
}

type workerTest74ArtifactObserver struct {
	*singleTestArtifactDriver
	beforeGet func(context.Context) error
	gets      int
}

func (d *workerTest74ArtifactObserver) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	d.gets++
	if d.beforeGet != nil {
		if err := d.beforeGet(ctx); err != nil {
			return artifactstore.DriverObject{}, err
		}
	}
	return d.singleTestArtifactDriver.Get(ctx, v)
}
