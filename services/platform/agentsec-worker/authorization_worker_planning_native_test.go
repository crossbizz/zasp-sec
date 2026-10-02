package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

type workerPlanningArtifactObserver struct {
	*findingArtifactDriver
	beforeGet func(context.Context) error
	gets      int
}

func (d *workerPlanningArtifactObserver) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	d.gets++
	if d.beforeGet != nil {
		if err := d.beforeGet(ctx); err != nil {
			return artifactstore.DriverObject{}, err
		}
	}
	return d.findingArtifactDriver.Get(ctx, v)
}

func assertWorkerFindingProductPlanning(t *testing.T, ctx context.Context, dsn string, config runtimeservices.Config, writer authorization.TupleWriter, product *temporalSecurityAgentProduct, start orchestration.StartRequest, mode string, fgaTransport *workerNativeFGATransport) {
	t.Helper()
	mode, timezone := configureWorkerPlannerTimezone(t, ctx, dsn, product, start, mode, workerPlanningFinding)
	owner, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("owned planner observer unavailable")
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
	var raw json.RawMessage
	var finding, actor, outbox string
	if err := owner.QueryRow(ctx, `SELECT j.lookup_request FROM zasp_temporal78.planning_jobs j JOIN zasp_temporal78.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE x.definition_id=(SELECT definition_id FROM zasp_temporal78.run_owners WHERE run_id=$1) AND j.state='admitted'`, start.Ref.RunID).Scan(&raw); err != nil || json.Unmarshal(raw, &selection) != nil {
		t.Fatal("owned pricing selection unavailable", err)
	}
	if err := owner.QueryRow(ctx, `SELECT x.trigger_id,r.requested_by FROM zasp_temporal78.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, start.Ref.RunID).Scan(&finding, &actor); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	projectionConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("owned projection configuration")
	}
	projectionConfig.ConnConfig.User = outbox
	projectionPool, err := pgxpool.NewWithConfig(ctx, projectionConfig)
	if err != nil {
		t.Fatal("owned projection pool")
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
			t.Error("owned projection loop", err)
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
		if err != nil || owner.QueryRow(ctx, `SELECT j.state='started' AND j.input_version IS NOT NULL AND j.request_body=$2 AND j.lookup_request->>'credential_digest'=$3 AND p.reservation_id=j.reservation_id AND p.settled_at IS NULL AND p.released_at IS NULL FROM zasp_temporal78.planning_jobs j JOIN zasp_temporal78.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, start.Ref.RunID, string(body), orderedPlanningDigest([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))).Scan(&bound) != nil || !bound {
			t.Error("actual provider send lacked exact persisted start/request/credential/reservation")
			w.WriteHeader(500)
			return
		}
		if mode == "planning-sent-revoke" || mode == "planning-sent-late" {
			if err := revoke(ctx); err != nil {
				t.Error("owned post-start revoke", err)
				w.WriteHeader(500)
				return
			}
		}
		if mode == "planning-sent-late" {
			// A real compensation call records an unknown terminal outcome
			// while the one admitted provider request is still in flight.
			q := temporalStartFields(start)
			delete(q, "input_digest")
			q["operation"] = "reconcile"
			q["payload"] = map[string]any{}
			encoded, _ := json.Marshal(q)
			terminalExecutor := workerPlannerTerminalExecutor(product, timezone)
			decision, err := terminalExecutor.Authorize(ctx, "finding.planning.reconcile", encoded)
			if err == nil {
				_, err = terminalExecutor.Execute(ctx, decision)
			}
			var prior string
			if err == nil {
				err = owner.QueryRow(ctx, terminalHashSQL, start.Ref.RunID).Scan(&prior)
			}
			if err != nil {
				t.Error("captured in-flight terminalization", err)
				w.WriteHeader(500)
				return
			}
			terminalBefore.Store(prior)
		}
		if mode == "planning-sent-fga" {
			fgaTransport.unavailable.Store(true)
			fault.Store(true)
		}
		candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": actor, "status": "investigating", "note": "Investigate the credential exposure"}}})
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
	driver := &workerPlanningArtifactObserver{findingArtifactDriver: &findingArtifactDriver{temporalPlannerArtifactDriver: temporalPlannerArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}}}
	if mode == "planning-prepared-revoke" {
		driver.beforeGet = func(callCtx context.Context) error {
			if fault.Load() {
				return nil
			}
			var prepared bool
			if err := owner.QueryRow(callCtx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal78.planning_jobs WHERE run_id=$1 AND state='prepared')`, start.Ref.RunID).Scan(&prepared); err != nil {
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
		err = product.FindingResponseProduct().Plan(ctx, start)
		if err == nil {
			break
		}
		if !errors.Is(err, authorization.ErrPending) && !errors.Is(err, authorization.ErrConflict) {
			t.Log("planning failure after owned fault", mode, fault.Load(), "provider_calls", calls.Load())
			t.Fatal("actual finding product planning", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual planning deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	timezone.diagnose(ctx, owner, product, "after_plan", calls.Load(), fault.Load())
	if err := product.FindingResponseProduct().Plan(ctx, start); err != nil {
		t.Fatal("actual planning admitted retry", err)
	}
	if mode == "planning-sent-late" {
		body, ok := lateResponse.Load().([]byte)
		if !ok {
			t.Fatal("owned late response not delivered")
		}
		identity := temporalStartFields(start)
		delete(identity, "input_digest")
		encoded, _ := json.Marshal(identity)
		database := &workerFindingPlanningDatabase{base: product.executor, forward: product.workerForward, compensation: product.workerCompensation, start: start}
		for n := 0; n < 2; n++ {
			if err := database.RecoverCapturedPlanning(ctx, encoded, body); err != nil {
				t.Fatal("exact late response recovery replay", err)
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
			t.Fatal("owned recovery fault was not reached")
		}
		if err := owner.QueryRow(ctx, `SELECT j.state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans p WHERE p.run_id=j.run_id) AND (SELECT count(*)=1 FROM zasp_security_agent_audit a WHERE a.run_id=j.run_id AND a.event_kind='temporal_planning_terminal') AND EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations p WHERE p.run_id=j.run_id AND CASE WHEN $2 THEN p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.total_tokens IS NULL ELSE p.settled_at IS NOT NULL AND p.total_tokens=30 AND p.cost_nano_credits=30000 END) FROM zasp_temporal78.planning_jobs j WHERE j.run_id=$1`, start.Ref.RunID, mode == "planning-prepared-revoke").Scan(&exact); err != nil || !exact {
			t.Fatal("actual planner did not settle captured debt without new admission", err)
		}
		want := int32(1)
		if mode == "planning-prepared-revoke" {
			want = 0
		}
		if calls.Load() != want || driver.puts != 1 {
			t.Fatal("captured recovery made fresh send/artifact effect", calls.Load(), driver.puts)
		}
		if mode == "planning-sent-late" {
			var after string
			var entries int
			if err := owner.QueryRow(ctx, terminalHashSQL, start.Ref.RunID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal78.planning_late_usage WHERE run_id=$1`, start.Ref.RunID).Scan(&entries); err != nil {
				t.Fatal(err)
			}
			before, ok := terminalBefore.Load().(string)
			if !ok || before == "" || after != before || entries != 1 {
				t.Fatal("late settlement changed original terminal audit or duplicated charge", entries)
			}
		}
		return
	}
	if err := owner.QueryRow(ctx, `SELECT j.state='admitted' AND (SELECT count(*) FROM zasp_security_agent_plans p WHERE p.run_id=j.run_id)=1 AND EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations p WHERE p.run_id=j.run_id AND p.settled_at IS NOT NULL AND p.total_tokens=30 AND p.cost_nano_credits=30000) FROM zasp_temporal78.planning_jobs j WHERE j.run_id=$1`, start.Ref.RunID).Scan(&exact); err != nil || !exact {
		t.Fatal("actual shared planner did not admit exact settled plan", err)
	}
	if calls.Load() != 1 || driver.puts != 2 {
		t.Fatal("actual shared planner send/artifact cardinality", calls.Load(), driver.puts)
	}
}
