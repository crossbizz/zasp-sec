package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestTemporalSingleTestPlannerPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_TEST74_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned74 database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, fallback := range cfg.Fallbacks {
		if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	cfg = cfg.Copy()
	cfg.User = "temporal_test_executor_login"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	db := &singleTestPlannerTrace{JSONDatabase: &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, t: t}}
	var selection securityAgentMultistepPricingBinding
	if decodeStrictWorkerJSON([]byte(os.Getenv("ZASP_TEST74_BINDING")), &selection) != nil {
		t.Fatal("binding")
	}
	run, testID := os.Getenv("ZASP_TEST74_PARENT"), os.Getenv("ZASP_TEST74_TEST")
	version, err := strconv.ParseInt(os.Getenv("ZASP_TEST74_VERSION"), 10, 64)
	if err != nil || version < 1 {
		t.Fatal("definition version")
	}
	providerDB, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer providerDB.Close(ctx)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		var bound bool
		var action string
		if err != nil || providerDB.QueryRow(ctx, `SELECT j.state='started' AND j.input_version IS NOT NULL AND j.lookup_request->>'credential_digest'=$2 AND p.reservation_id=j.reservation_id AND p.settled_at IS NULL AND (x.source_kind<>'automatic73' OR EXISTS(SELECT 1 FROM zasp_identity_memberships m JOIN zasp_temporal74.service_grants g ON(g.organization_id,g.grantor_id)=(m.organization_id,m.principal_id) WHERE (g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) AND (NOT m.active OR $3::boolean))),x.action_key FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal74.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE j.request_body=$1`, string(body), orderedPlanningDigest([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))), os.Getenv("ZASP_TEST77_LIVE") == "true").Scan(&bound, &action) != nil || !bound {
			t.Error("provider before exact74 request/credential/reservation")
			w.WriteHeader(500)
			return
		}
		if os.Getenv("ZASP_TEST77_LIVE") == "true" {
			var automatic bool
			if err := providerDB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal77.occurrences a USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version) WHERE j.request_body=$1 AND a.disposition='admitted' AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.grant_revocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.definition_version)=(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)))`, string(body)).Scan(&automatic); err != nil || !automatic {
				t.Error("provider without configured automatic occurrence/current grant", automatic, err)
				w.WriteHeader(500)
				return
			}
		}
		candidate := `{"version":1,"summary":"Run pinned test","steps":[{"index":0,"action":"` + action + `","target_id":"` + testID + `"}]}`
		if os.Getenv("ZASP_TEST76_LIVE") == "true" {
			var human bool
			if err := providerDB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal74.run_owners x ON(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(j.organization_id,j.workspace_id,j.environment_id,j.run_id) JOIN zasp_security_agent_runs r ON(r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) JOIN zasp_temporal76.admissions a ON(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,a.input_digest,a.source_kind,a.requester_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_id,x.definition_version,x.input_digest,'resource65',r.requested_by) JOIN zasp_temporal65.commands c ON(c.organization_id,c.workspace_id,c.environment_id,c.event_id,c.run_id,c.kind,c.execution_owner)=(a.organization_id,a.workspace_id,a.environment_id,a.event_id,a.run_id,'start','legacy') JOIN zasp_security_agent_request_receipts q ON(q.organization_id,q.workspace_id,q.environment_id,q.receipt_id,q.principal_id)=(a.organization_id,a.workspace_id,a.environment_id,a.event_id,a.requester_id) JOIN zasp_identity_memberships m ON(m.organization_id,m.principal_id,m.active)=(a.organization_id,a.requester_id,true) JOIN zasp_authorized_scopes s ON(s.organization_id,s.workspace_id,s.environment_id,s.principal_id)=(a.organization_id,a.workspace_id,a.environment_id,a.requester_id) WHERE j.request_body=$1 AND x.source_kind='resource65' AND s.permissions?&ARRAY['view','manage_workflows','run_tests'] AND public.zasp_effective_scope_permissions(s.permissions,m.role)?&ARRAY['view','manage_workflows','run_tests'] AND EXISTS(SELECT 1 FROM zasp_temporal74.grant_revocations g WHERE(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version)))`, string(body)).Scan(&human); err != nil || !human {
				t.Error("provider without exact76 human provenance/current actor and revoked service grant", human, err)
				w.WriteHeader(500)
				return
			}
		}
		var fields map[string]json.RawMessage
		json.Unmarshal(openRouterPlannerResponse(candidate), &fields)
		fields["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
		response, _ := json.Marshal(fields)
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	httpClient := server.Client()
	defer httpClient.CloseIdleConnections()
	planner := orderedRequestBindingPlanner(t, &release61TLSTransport{base: httpClient.Transport, target: target})
	defer planner.Close()
	driver := &singleTestArtifactDriver{temporalPlannerArtifactDriver: temporalPlannerArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_TEST76_LIVE") == "true" {
		runHumanAdmissionLiveRuntime(t, ctx, owner, selection, planner, store, run, &calls)
		return
	}
	if os.Getenv("ZASP_TEST77_LIVE") == "true" {
		runAutomaticSourceLiveRuntime(t, ctx, owner, selection, planner, store, run, &calls)
		return
	}
	if os.Getenv("ZASP_TEST75_LIVE") == "true" {
		runTestSelectorLiveRuntime(t, ctx, owner, selection, planner, store, run, &calls)
		return
	}
	if os.Getenv("ZASP_TEST74_LIVE") == "true" {
		runSingleTestLiveRuntime(t, ctx, owner, selection, planner, store, run, version, &calls)
		return
	}
	actual, ok := any(planner).(interface {
		RunSingleTestPlanning(context.Context, apiserver.JSONDatabase, artifactstore.ArtifactStore, securityAgentMultistepPricingBinding, string, int64) (json.RawMessage, error)
	})
	if !ok {
		t.Fatal("specialized74 actual planner operation missing")
	}
	receipt, err := actual.RunSingleTestPlanning(ctx, db, store, selection, run, version)
	if err != nil || !bytes.Contains(receipt, []byte(`"admitted"`)) || calls.Load() != 1 || driver.puts != 2 {
		t.Logf("controlled planner boundary query=%s database_error=%v result=%s", db.statement, db.err, db.result)
		t.Fatal("actual74 provider/artifacts/admission", string(receipt), err, calls.Load(), driver.puts)
	}
	again, err := actual.RunSingleTestPlanning(ctx, db, store, selection, run, version)
	if err != nil || !bytes.Equal(receipt, again) || calls.Load() != 1 || driver.puts != 2 {
		t.Fatal("retry resent provider or rewrote artifacts", string(again), err, calls.Load(), driver.puts)
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND p.settled_at IS NOT NULL AND p.cost_nano_credits=30000 AND (SELECT count(*)=1 AND bool_and(step_index=0 AND action_key='run_test') FROM zasp_security_agent_steps WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_temporal74.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&bound); err != nil || !bound {
		t.Fatal("actual74 one-step accounting/lease boundary", bound, err)
	}
	t.Log("actual74 HTTPS planner sent once, exact artifact Put/Get, usage settled and canonical step0 admitted; replay sent nothing")
	ids := make([]domain.ProductID, 3)
	for i, id := range []string{selection.OrganizationID, selection.WorkspaceID, selection.EnvironmentID} {
		ids[i], err = domain.ParseProductID(id)
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", run+"\x1f0")
	t.Setenv("ZASP_TEST74_NATIVE", "true")
	t.Setenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN", dsn)
	t.Setenv("ZASP_ORDERED_ORG", selection.OrganizationID)
	t.Setenv("ZASP_ORDERED_WORKSPACE", selection.WorkspaceID)
	t.Setenv("ZASP_ORDERED_ENVIRONMENT", selection.EnvironmentID)
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	native, ok := any(runner).(interface {
		RunSingleTest(context.Context, apiserver.JSONDatabase, domain.Scope, string, string, string) error
		SettleSingleTest(context.Context, apiserver.JSONDatabase, domain.Scope, string, string, string) error
	})
	if !ok {
		t.Fatal("actual74 native executor/parent settlement missing")
	}
	if err := native.RunSingleTest(ctx, db, scope, run, step, "run_test"); err != nil {
		t.Fatal("actual74 child", err)
	}
	if err := owner.QueryRow(ctx, `SELECT r.state='running' AND EXISTS(SELECT 1 FROM zasp_temporal74.child_receipts WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) FROM zasp_security_agent_runs r WHERE run_id=$1`, run).Scan(&bound); err != nil || !bound {
		t.Fatal("child completed parent prematurely", bound, err)
	}
	if err := native.RunSingleTest(ctx, db, scope, run, step, "run_test"); err != nil || runnerCalls.Load() != 1 {
		t.Fatal("child replay reran provider", err, runnerCalls.Load())
	}
	assertSingleTestActualDelivery(t, ctx, owner, db, scope, run, version, false)
	if err := native.SettleSingleTest(ctx, db, scope, run, step, "run_test"); err != nil {
		t.Fatal("actual74 parent", err)
	}
	if err := native.SettleSingleTest(ctx, db, scope, run, step, "run_test"); err != nil || runnerCalls.Load() != 1 {
		t.Fatal("parent replay reran child", err, runnerCalls.Load())
	}
	if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.last_error_code='test_baseline_unavailable' AND EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) FROM zasp_security_agent_runs r WHERE run_id=$1`, run).Scan(&bound); err != nil || !bound {
		t.Fatal("actual baseline distinction", bound, err)
	}
	cfg = cfg.Copy()
	cfg.User = "temporal_test_compensation_login"
	comp, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(ctx)
	compDB := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: comp}, t: t}
	product := &temporalSecurityAgentProduct{executor: db, compensation: compDB, planner: planner, runner: runner, store: store, bindings: []securityAgentMultistepPricingBinding{selection}}
	factory, ok := any(product).(interface {
		SingleTestProduct() orchestration.SingleTestProduct
	})
	if !ok {
		t.Fatal("actual specialized product composition missing")
	}
	var digest string
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: selection.OrganizationID, WorkspaceID: selection.WorkspaceID, EnvironmentID: selection.EnvironmentID, RunID: run}, DefinitionVersion: version, InputDigest: digest}
	specialized := factory.SingleTestProduct()
	if state, err := specialized.Observe(ctx, start); err != nil || state.Phase != "terminal" {
		t.Fatal("actual product terminal proof", state, err)
	}
	if err := specialized.Cleanup(ctx, orchestration.CleanupRequest{Start: start, Reason: "terminal"}); err != nil {
		t.Fatal("verified actual product cleanup", err)
	}
	if err := specialized.Cleanup(ctx, orchestration.CleanupRequest{Start: start, Reason: "terminal"}); err != nil {
		t.Fatal("cleanup replay", err)
	}
	assertSingleTestActualDelivery(t, ctx, owner, db, scope, run, version, true)
	start.InputDigest = strings.Repeat("f", 64)
	if _, err := specialized.Observe(ctx, start); err == nil {
		t.Fatal("product accepted foreign immutable start")
	}
}

type singleTestArtifactDriver struct{ temporalPlannerArtifactDriver }

func (d *singleTestArtifactDriver) ObjectReference(v artifactstore.DriverLocator) (string, error) {
	return "s3://zasp-test74-component/" + v.Key, nil
}
func (d *singleTestArtifactDriver) PlannedObjectReference(v artifactstore.DriverLocator) (string, error) {
	return d.ObjectReference(v)
}

type singleTestPlannerTrace struct {
	apiserver.JSONDatabase
	statement string
	result    json.RawMessage
	err       error
}

func (d *singleTestPlannerTrace) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	d.statement = statement
	d.result, d.err = d.JSONDatabase.QueryJSON(ctx, statement, args...)
	return d.result, d.err
}
