package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

// The borrowed store blocks only the second parent's committed prepared input.
// Releasing it resumes the real planner's fresh authority check before HTTP.
type selectorRevocationBarrier struct {
	artifactstore.ObjectReferencingArtifactStore
	probe            *pgx.Conn
	parent           string
	reached, release chan struct{}
	once             sync.Once
}

func (b *selectorRevocationBarrier) Get(ctx context.Context, l artifactstore.Locator) (artifactstore.Artifact, error) {
	if l.VersionID != "" {
		var prepared bool
		if err := b.probe.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE run_id=$1 AND state='prepared' AND input_version=$2)`, b.parent, l.VersionID).Scan(&prepared); err != nil {
			return artifactstore.Artifact{}, err
		}
		if prepared {
			b.once.Do(func() { close(b.reached) })
			select {
			case <-b.release:
			case <-ctx.Done():
				return artifactstore.Artifact{}, ctx.Err()
			}
		}
	}
	return b.ObjectReferencingArtifactStore.Get(ctx, l)
}

func runTestSelectorLiveRuntime(t *testing.T, ctx context.Context, owner *pgx.Conn, binding securityAgentMultistepPricingBinding, planner *productionSecurityAgentPlanner, store artifactstore.ObjectReferencingArtifactStore, parent string, providerCalls *atomic.Int32) {
	t.Helper()
	t.Setenv("ZASP_TEST74_NATIVE", "true")
	t.Setenv("ZASP_TEST74_UNSAFE", "true")
	t.Setenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN", owner.Config().ConnString())
	t.Setenv("ZASP_ORDERED_ORG", binding.OrganizationID)
	t.Setenv("ZASP_ORDERED_WORKSPACE", binding.WorkspaceID)
	t.Setenv("ZASP_ORDERED_ENVIRONMENT", binding.EnvironmentID)
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	var secondParent string
	if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id(d.organization_id,d.workspace_id,d.environment_id,'security_agent_run',concat_ws(chr(31),d.definition_id,d.version,d.body->>'trigger_kind',f.id,f.version+1)) FROM zasp_security_agent_definitions d JOIN zasp_risk_findings f ON(f.organization_id,f.workspace_id,f.environment_id,f.rule,f.status)=(d.organization_id,d.workspace_id,d.environment_id,d.body->>'trigger_source','open') WHERE d.definition_id=$1 ORDER BY f.id,f.version DESC LIMIT 1`, os.Getenv("ZASP_TEST75_DEFINITION")).Scan(&secondParent); err != nil {
		t.Fatal(err)
	}
	probe, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(context.Background())
	barrier := &selectorRevocationBarrier{ObjectReferencingArtifactStore: store, probe: probe, parent: secondParent, reached: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-barrier.release:
		default:
			close(barrier.release)
		}
	}()
	namespace := fmt.Sprintf("test-selector75-%d", time.Now().UnixNano())
	nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal(err)
	}
	err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
	nc.Close()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cfg := validSecurityAgentRuntimeConfig()
	dsn := func(user string) string {
		v := owner.Config()
		return (&url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(v.Host, strconv.Itoa(int(v.Port))), Path: "/" + v.Database, RawQuery: "sslmode=disable"}).String()
	}
	cfg.PostgresDSN = dsn("security_agent_v33_worker_login")
	cfg.TemporalExecutorDSN = dsn("temporal_test_executor_login")
	cfg.TemporalCompensationDSN = dsn("temporal_test_compensation_login")
	root := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(root, name)
		if os.WriteFile(p, b, 0400) != nil {
			t.Fatal("fixture file")
		}
		return p
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.GatewaySigningKeyID = "selector75-key"
	cfg.GatewaySigningPrivateFile = write("key", []byte(base64.RawURLEncoding.EncodeToString(key)))
	pricing, _ := json.Marshal([]securityAgentMultistepPricingBinding{binding})
	cfg.TemporalPricingBindingsFile = write("pricing", pricing)
	fga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controlled-fga-token" || r.URL.Path != "/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models/01ARZ3NDEKTSV4RRFFQ69G5FAW" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer fga.Close()
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: namespace, TaskQueue: namespace + "-tests", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: write("token", []byte("controlled-fga-token")), Timeout: 10 * time.Second}
	ref := orchestration.TestSelectorRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, DefinitionID: os.Getenv("ZASP_TEST75_DEFINITION")}
	assertSelectorSourceSerialization(t, ctx, owner, cfg.TemporalExecutorDSN, ref)
	external := workerExternalIO{planner: func(workerRuntimeConfig) (*productionSecurityAgentPlanner, error) {
		planner.mu.RLock()
		transport := planner.client.Transport
		planner.mu.RUnlock()
		return newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: cfg.SecurityAgentPlannerEndpoint, Model: cfg.SecurityAgentPlannerModel, Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: cfg.SecurityAgentPlannerPolicy, Transport: transport})
	}, temporal: func(workerRuntimeConfig) (temporalExecutionIO, error) {
		return temporalExecutionIO{runner: runner, store: barrier, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error { return nil }}, nil
	}}
	deps, err := buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("actual75 worker composition", err)
	}
	defer func() {
		started := time.Now()
		if err := deps.Close(); err != nil {
			t.Error("worker close", err)
		}
		t.Log("first worker Close elapsed", time.Since(started))
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("actual75 readiness", err)
	}
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("actual75 configuration reconciliation", err)
	}
	id, err := orchestration.TestSelectorID(ref)
	if err != nil {
		t.Fatal(err)
	}
	handle := c.ScheduleClient().GetHandle(ctx, id)
	defer handle.Delete(context.Background())
	description, err := handle.Describe(ctx)
	if err != nil {
		t.Fatal("production selector Schedule absent", err)
	}
	if len(description.Schedule.Spec.Intervals) != 1 || description.Schedule.Spec.Intervals[0].Every != time.Second {
		t.Fatal("shipped selector cadence", description.Schedule.Spec)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var admitted bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal73.admissions WHERE run_id=$1)`, parent).Scan(&admitted); err != nil {
			t.Fatal(err)
		}
		if admitted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual scheduled source admission absent")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Selector disable is a future-admission fence, not run cancellation.
	if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":3,"cadence_seconds":1,"enabled":false}')`); err != nil {
		t.Fatal(err)
	}
	// A pass may correctly skip an organization held by a Schedule admission.
	// Drive the actual production processor until its durable acceptance exists.
	deadline = time.Now().Add(45 * time.Second)
	for passes := 1; ; passes++ {
		if err := deps.Processor.RunOnce(ctx); err != nil {
			t.Fatal("actual75 start delivery", err)
		}
		var accepted bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries WHERE run_id=$1 AND accepted_at IS NOT NULL)`, parent).Scan(&accepted); err != nil {
			t.Fatal(err)
		}
		if accepted {
			t.Log("actual delivery accepted after processor passes", passes)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("durable start delivery remained pending")
		}
		time.Sleep(100 * time.Millisecond)
	}
	workflowID, _ := orchestration.SingleTestWorkflowID(orchestration.RunRef{OrganizationID: ref.OrganizationID, WorkspaceID: ref.WorkspaceID, EnvironmentID: ref.EnvironmentID, RunID: parent})
	if err := c.GetWorkflow(ctx, workflowID, "").Get(ctx, nil); err != nil {
		var diagnostic []byte
		diagnosticErr := owner.QueryRow(ctx, `SELECT jsonb_build_object('state',r.state,'version',r.version,'attempt',r.attempt,'lease_owner',r.lease_owner,'admission',(SELECT to_jsonb(a) FROM zasp_temporal73.admissions a WHERE a.run_id=$1),'owner',(SELECT to_jsonb(x) FROM zasp_temporal74.run_owners x WHERE x.run_id=$1),'delivery',(SELECT to_jsonb(d) FROM zasp_temporal74.start_deliveries d WHERE d.run_id=$1),'organization_free',pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||r.organization_id,0))) FROM zasp_security_agent_runs r WHERE r.run_id=$1`, parent).Scan(&diagnostic)
		t.Logf("start boundary diagnostic=%s query_error=%v", diagnostic, diagnosticErr)
		t.Fatal("scheduled74 execution", err)
	}
	var proof bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts p JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1 AND x.source_kind='automatic73' AND r.lease_owner IS NULL AND r.lease_token IS NULL)`, parent).Scan(&proof); err != nil || !proof || providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		t.Fatal("scheduled canonical parent receipt", proof, err, providerCalls.Load(), runnerCalls.Load())
	}
	t.Log("actual Schedule ->75 current service admission ->73 canonical start ->74 child/parent execution", namespace, parent)
	description, err = handle.Describe(ctx)
	if err != nil || !description.Schedule.State.Paused {
		t.Fatal("disabled desired configuration was not applied", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3);SELECT zasp_temporal75.configure('{"revision":4,"cadence_seconds":1,"enabled":true}')`, pgx.QueryExecModeSimpleProtocol, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(45 * time.Second)
	for {
		if err := deps.Processor.RunOnce(ctx); err != nil {
			t.Fatal("second actual configuration/start pass", err)
		}
		select {
		case <-barrier.reached:
			goto prepared
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("second scheduled parent did not reach prepared barrier")
		}
		time.Sleep(100 * time.Millisecond)
	}
prepared:
	if providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		t.Fatal("second provider/native IO crossed preparation barrier")
	}
	// Controlled administration changes the real current grant row; no planner
	// or SQL authorization is stubbed. The original creator is still inactive.
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal74.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) SELECT organization_id,workspace_id,environment_id,definition_id,definition_version,grantor_id,'pid_f0750000-0000-4000-8000-000000000091' FROM zasp_temporal74.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, ref.DefinitionID); err != nil {
		t.Fatal(err)
	}
	close(barrier.release)
	secondWorkflow, _ := orchestration.SingleTestWorkflowID(orchestration.RunRef{OrganizationID: ref.OrganizationID, WorkspaceID: ref.WorkspaceID, EnvironmentID: ref.EnvironmentID, RunID: secondParent})
	err = c.GetWorkflow(ctx, secondWorkflow, "").Get(ctx, nil)
	t.Log("revoked admitted workflow result", err)
	if providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		t.Fatal("revoked grant allowed fresh provider/native IO", providerCalls.Load(), runnerCalls.Load())
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3)`, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID); err != nil {
		t.Fatal(err)
	}
	wake, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: "selector-revoked-authority-proof", TaskQueue: cfg.RuntimeServices.TaskQueue}, orchestration.TestSelectorWorkflow, orchestration.TestSelectorStart{Ref: ref, Revision: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := wake.Get(ctx, nil); err == nil {
		t.Fatal("revoked grant accepted subsequent actual selector Activity")
	}
	var count int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal75.admissions WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3)`, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID).Scan(&count); err != nil || count != 2 {
		t.Fatal("revoked later source consumed admission", count, err)
	}
	t.Log("selector disable preserved admitted execution; current grant revoke blocked prepared fresh IO and later source admission")
}

func assertSelectorSourceSerialization(t *testing.T, ctx context.Context, owner *pgx.Conn, dsn string, ref orchestration.TestSelectorRef) {
	t.Helper()
	id, _ := orchestration.TestSelectorID(ref)
	if _, err := owner.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, id); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			owner.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1,0))`, id)
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	source := &temporalTestSelectorSource{session: temporalDiscoveryScheduleSource{dsn: dsn, timeout: 10 * time.Second}, automatic: true}
	type outcome struct {
		desired orchestration.TestSelectorDesired
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		var value orchestration.TestSelectorDesired
		err := source.WithCurrentSelector(bounded, ref, func(d orchestration.TestSelectorDesired) error { value = d; return nil })
		done <- outcome{value, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND pid<>pg_backend_pid())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("registered reconciliation did not serialize")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":2,"cadence_seconds":1,"enabled":true}');SELECT pg_advisory_unlock(hashtextextended($1,0))`, pgx.QueryExecModeSimpleProtocol, id); err != nil {
		t.Fatal(err)
	}
	locked = false
	got := <-done
	if got.err != nil || got.desired.Revision != 2 {
		t.Fatal("registered source read stale desired configuration before serialization", got.desired, got.err)
	}
	t.Log("registered source joined after lock and read current desired revision2")
}
