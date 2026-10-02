package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/types/known/durationpb"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Block only the real immutable input read after SQL committed prepared. The
// production worker must cancel/join this borrowed IO, then recover on restart.
type singleTestPreparedBarrier struct {
	artifactstore.ObjectReferencingArtifactStore
	probe        *pgx.Conn
	parent       string
	organization string
	reached      chan struct{}
	joined       chan struct{}
	once         sync.Once
	released     atomic.Bool
}

func (s *singleTestPreparedBarrier) Get(ctx context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	if !s.released.Load() && locator.VersionID != "" && locator.Scope.OrganizationID().String() == s.organization {
		var prepared bool
		if err := s.probe.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE run_id=$1 AND state='prepared' AND input_version=$2)`, s.parent, locator.VersionID).Scan(&prepared); err != nil {
			return artifactstore.Artifact{}, err
		}
		if prepared {
			s.once.Do(func() { close(s.reached) })
			<-ctx.Done()
			close(s.joined)
			return artifactstore.Artifact{}, ctx.Err()
		}
	}
	return s.ObjectReferencingArtifactStore.Get(ctx, locator)
}

func runSingleTestLiveRuntime(t *testing.T, ctx context.Context, owner *pgx.Conn, binding securityAgentMultistepPricingBinding, planner *productionSecurityAgentPlanner, store artifactstore.ObjectReferencingArtifactStore, parent string, version int64, providerCalls *atomic.Int32) {
	t.Helper()
	t.Setenv("ZASP_TEST74_NATIVE", "true")
	t.Setenv("ZASP_TEST74_UNSAFE", "true")
	t.Setenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN", owner.Config().ConnString())
	t.Setenv("ZASP_ORDERED_ORG", binding.OrganizationID)
	t.Setenv("ZASP_ORDERED_WORKSPACE", binding.WorkspaceID)
	t.Setenv("ZASP_ORDERED_ENVIRONMENT", binding.EnvironmentID)
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	probe, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(ctx)
	barrier := &singleTestPreparedBarrier{ObjectReferencingArtifactStore: store, probe: probe, parent: parent, organization: binding.OrganizationID, reached: make(chan struct{}), joined: make(chan struct{})}
	var second securityAgentMultistepPricingBinding
	if decodeStrictWorkerJSON([]byte(os.Getenv("ZASP_TEST74_SECOND_BINDING")), &second) != nil {
		t.Fatal("tenant B binding")
	}
	secondParent := os.Getenv("ZASP_TEST74_SECOND_PARENT")
	probeB, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer probeB.Close(ctx)
	barrierB := &singleTestPreparedBarrier{ObjectReferencingArtifactStore: barrier, probe: probeB, parent: secondParent, organization: second.OrganizationID, reached: make(chan struct{}), joined: make(chan struct{})}
	namespace := fmt.Sprintf("p4c-test74-%d", time.Now().UnixNano())
	nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal(err)
	}
	err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: "owned P4C specialized test execution", WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
	nc.Close()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, err := c.WorkflowService().GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("owned local Temporal", info.ServerVersion, "namespace", namespace)
	cfg := validSecurityAgentRuntimeConfig()
	dsn := func(user string) string {
		v := owner.Config()
		return (&url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(v.Host, strconv.Itoa(int(v.Port))), Path: "/" + v.Database, RawQuery: "sslmode=disable"}).String()
	}
	cfg.PostgresDSN = dsn("security_agent_v33_worker_login")
	cfg.TemporalExecutorDSN = dsn("temporal_test_executor_login")
	cfg.TemporalCompensationDSN = dsn("temporal_test_compensation_login")
	root := t.TempDir()
	write := func(name string, body []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, body, 0400); err != nil {
			t.Fatal(err)
		}
		return path
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.GatewaySigningKeyID = "test74-current-key"
	cfg.GatewaySigningPrivateFile = write("signing", []byte(base64.RawURLEncoding.EncodeToString(private)))
	pricing, _ := json.Marshal([]securityAgentMultistepPricingBinding{binding, second})
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
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: namespace, TaskQueue: namespace + "-test", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: write("fga-token", []byte("controlled-fga-token")), Timeout: 10 * time.Second}
	var clientCloses atomic.Int32
	external := workerExternalIO{planner: func(workerRuntimeConfig) (*productionSecurityAgentPlanner, error) {
		planner.mu.RLock()
		transport := planner.client.Transport
		planner.mu.RUnlock()
		return newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: cfg.SecurityAgentPlannerEndpoint, Model: cfg.SecurityAgentPlannerModel, Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: cfg.SecurityAgentPlannerPolicy, Transport: transport})
	}, temporal: func(workerRuntimeConfig) (temporalExecutionIO, error) {
		return temporalExecutionIO{runner: runner, store: barrierB, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error {
			for _, b := range []*singleTestPreparedBarrier{barrier, barrierB} {
				select {
				case <-b.joined:
				default:
					t.Error("product client closed before borrowed IO returned")
				}
			}
			clientCloses.Add(1)
			return nil
		}}, nil
	}}
	deps, err := buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("actual installed74 production startup", err)
	}
	defer func() {
		if err := deps.Close(); err != nil {
			t.Error("actual74 worker drain", err)
		}
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("actual74 production readiness", err)
	}
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("actual74 production first poll", err)
	}
	select {
	case <-barrier.reached:
	case <-ctx.Done():
		t.Fatal("durable preparation barrier", ctx.Err())
	}
	select {
	case <-barrierB.reached:
	case <-ctx.Done():
		t.Fatal("tenant B preparation barrier", ctx.Err())
	}
	revoke, err := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv("ZASP_TEST74_REVOKE_URL"), nil)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := http.DefaultClient.Do(revoke)
	if err != nil {
		t.Fatal("actual tenant B config revoke", err)
	}
	revoked.Body.Close()
	if revoked.StatusCode != http.StatusNoContent {
		t.Fatal("actual tenant B config revoke", revoked.StatusCode)
	}
	if providerCalls.Load() != 0 || runnerCalls.Load() != 0 {
		t.Fatal("IO before durable prepared restart")
	}
	if err := deps.Close(); err != nil {
		t.Log("prepared worker first close reached drain deadline; clients remain owned until IO returns", err)
	}
	select {
	case <-barrier.joined:
	case <-ctx.Done():
		t.Fatal("prepared IO failed to join", ctx.Err())
	}
	select {
	case <-barrierB.joined:
	case <-ctx.Done():
		t.Fatal("tenant B prepared IO join", ctx.Err())
	}
	if err := deps.Close(); err != nil {
		t.Fatal("prepared worker retry close after IO joined", err)
	}
	if clientCloses.Load() != 1 {
		t.Fatal("prepared clients not closed exactly once after join", clientCloses.Load())
	}
	if deps.Ready(ctx) == nil {
		t.Fatal("closed prepared worker ready")
	}
	barrier.released.Store(true)
	barrierB.released.Store(true)
	deps, err = buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("prepared worker restart", err)
	}
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("restarted worker readiness", err)
	}
	t.Log("actual production worker joined and restarted after committed prepared request, before provider IO")
	var digest string
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, parent).Scan(&digest); err != nil {
		t.Fatal("production did not transfer untouched manual owner", err)
	}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, RunID: parent}, DefinitionVersion: version, InputDigest: digest}
	id, _ := orchestration.SingleTestWorkflowID(start.Ref)
	engine, err := orchestration.NewTemporalEngine(c, cfg.RuntimeServices.TaskQueue, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.StartSingleTest(ctx, start); err != nil {
		t.Fatal("repeat exact logical start", err)
	}
	if err := c.GetWorkflow(ctx, id, "").Get(ctx, nil); err != nil {
		t.Fatal("actual74 Temporal completion", err)
	}
	secondRef := orchestration.RunRef{OrganizationID: second.OrganizationID, WorkspaceID: second.WorkspaceID, EnvironmentID: second.EnvironmentID, RunID: secondParent}
	secondID, _ := orchestration.SingleTestWorkflowID(secondRef)
	if err := c.GetWorkflow(ctx, secondID, "").Get(ctx, nil); err == nil {
		t.Fatal("revoked tenant B workflow claimed execution success")
	}
	var revokedProof bool
	if err := owner.QueryRow(ctx, `SELECT j.state='needs_human' AND r.last_error_code='planner_not_sent' AND p.released_at IS NOT NULL AND p.settled_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_temporal74.grant_revocations g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(j.organization_id,j.workspace_id,j.environment_id,r.definition_id,4)) FROM zasp_temporal74.planning_jobs j JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, secondParent).Scan(&revokedProof); err != nil || !revokedProof {
		t.Fatal("tenant B revoke/pre-IO release proof", revokedProof, err)
	}
	if err := engine.StartSingleTest(ctx, start); err != nil {
		t.Fatal("repeat closed exact logical start", err)
	}
	var proof bool
	// The lease-free planner fixes its accounting generation at attempt1.
	// No retained lease or public invocation may be manufactured alongside it.
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts p JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1 AND r.state='needs_human' AND r.last_error_code='test_condition_persists' AND r.attempt=1 AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL) AND EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries WHERE run_id=$1 AND accepted_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations j JOIN zasp_temporal74.run_owners x ON (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id) WHERE x.run_id=$1)`, parent).Scan(&proof); err != nil || !proof || providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		var detail []byte
		diagnosticErr := owner.QueryRow(ctx, `SELECT jsonb_build_object('state',r.state,'reason',r.last_error_code,'attempt',r.attempt,'lease_owner',r.lease_owner,'lease_token',r.lease_token,'lease_expires_at',r.lease_expires_at,'parent_receipt',(SELECT receipt FROM zasp_temporal74.parent_receipts WHERE run_id=$1),'start_delivery',(SELECT to_jsonb(d) FROM zasp_temporal74.start_deliveries d WHERE run_id=$1),'stops',(SELECT to_jsonb(s) FROM zasp_temporal74.stops s WHERE run_id=$1)) FROM zasp_security_agent_runs r WHERE run_id=$1`, parent).Scan(&detail)
		t.Logf("actual workflow proof detail %s diagnostic_error=%v", detail, diagnosticErr)
		t.Fatal("actual workflow proof or no-resend", proof, err, providerCalls.Load(), runnerCalls.Load())
	}
	// This uses the production red-team builder, actual worker identity and
	// actual Temporal client. Only queue transport and unused native IO are external.
	var message []byte
	if err := owner.QueryRow(ctx, `SELECT b.payload FROM zasp_red_team_outbox b JOIN zasp_temporal74.run_owners x ON(b.organization_id,b.workspace_id,b.environment_id,b.payload->>'run_id')=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id) WHERE x.run_id=$1`, parent).Scan(&message); err != nil {
		t.Fatal(err)
	}
	var payload redTeamOutboxPayload
	if decodeStrictWorkerJSON(message, &payload) != nil {
		t.Fatal("live outbox payload")
	}
	scope, err := temporalScope(start)
	if err != nil {
		t.Fatal(err)
	}
	child, err := domain.ParseProductID(payload.RunID)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes, err := hex.DecodeString(payload.InputDigest)
	if err != nil || len(digestBytes) != 32 {
		t.Fatal("live child digest")
	}
	var digestValue [32]byte
	copy(digestValue[:], digestBytes)
	steps := []string{}
	delivery := jobqueue.Delivery{Job: jobqueue.Job{Scope: scope, JobID: child, Kind: "red-team", Payload: message, AuthorityDigest: digestValue}}
	queue := &recordingDiscoveryQueue{steps: &steps, deliveries: []jobqueue.Delivery{delivery, delivery}}
	redConfig := validRedTeamRuntimeConfig()
	redConfig.PostgresDSN, redConfig.RuntimeServices = dsn("ordered_test_red_worker"), cfg.RuntimeServices
	redExternal := external
	redExternal.redTeam = func(workerRuntimeConfig) (*productionRedTeamDependencies, error) {
		return &productionRedTeamDependencies{Queue: queue, Runner: &recordingRedTeamRunner{steps: &steps}, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error { return nil }}, nil
	}
	redDeps, err := buildWorkerRuntimeWithIO(ctx, redConfig, redExternal)
	if err != nil {
		t.Fatal("actual red-team Temporal composition", err)
	}
	defer redDeps.Close()
	if err := redDeps.Ready(ctx); err != nil {
		t.Fatal("actual red-team74 readiness", err)
	}
	if err := redDeps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("actual terminal duplicate transport", err)
	}
	if strings.Join(steps, ",") != "consume,ack,ack" || providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		t.Fatal("terminal delivery used retained/provider execution", steps, providerCalls.Load(), runnerCalls.Load())
	}
	var deliveryCount int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal74.delivery_receipts WHERE run_id=$1`, parent).Scan(&deliveryCount); err != nil || deliveryCount != 1 {
		t.Fatal("actual delivery receipt", deliveryCount, err)
	}
	t.Setenv("ZASP_TEST74_UNSAFE", "false")
	automaticRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv("ZASP_TEST74_RERUN_URL"), nil)
	if err != nil {
		t.Fatal(err)
	}
	automaticResponse, err := http.DefaultClient.Do(automaticRequest)
	if err != nil {
		t.Fatal("actual automatic rerun configuration", err)
	}
	var automatic struct {
		RunID   string `json:"run_id"`
		Version int64  `json:"definition_version"`
	}
	decodeErr := json.NewDecoder(automaticResponse.Body).Decode(&automatic)
	automaticResponse.Body.Close()
	if automaticResponse.StatusCode != http.StatusOK || decodeErr != nil || automatic.Version != 3 {
		t.Fatal("automatic rerun response", automatic, decodeErr)
	}
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("production automatic rerun relay", err)
	}
	autoRef := start.Ref
	autoRef.RunID = automatic.RunID
	autoID, _ := orchestration.SingleTestWorkflowID(autoRef)
	approvalWait, cancelApproval := context.WithTimeout(ctx, 45*time.Second)
	defer cancelApproval()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := owner.QueryRow(approvalWait, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1 AND r.state='waiting_approval' AND a.state='pending')`, automatic.RunID).Scan(&waiting); err != nil {
			t.Fatal("live approval wait", err)
		}
		if waiting {
			break
		}
		select {
		case <-ticker.C:
		case <-approvalWait.Done():
			t.Fatal("live approval not reached", approvalWait.Err())
		}
	}
	var noChild bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs c JOIN zasp_temporal74.run_owners x ON x.test_run_id=c.run_id WHERE x.run_id=$1)`, automatic.RunID).Scan(&noChild); err != nil || !noChild || runnerCalls.Load() != 1 || providerCalls.Load() != 2 {
		t.Fatal("live preapproval effect", noChild, err, runnerCalls.Load(), providerCalls.Load())
	}
	beforeApproval, err := c.DescribeWorkflowExecution(ctx, autoID, "")
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv("ZASP_TEST74_APPROVAL_URL"), nil)
	approvalResponse, err := http.DefaultClient.Do(approvalRequest)
	if err != nil {
		t.Fatal("actual automatic approval", err)
	}
	approvalResponse.Body.Close()
	if approvalResponse.StatusCode != http.StatusNoContent {
		t.Fatal("actual automatic approval", approvalResponse.StatusCode)
	}
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, automatic.RunID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	autoStart := orchestration.StartRequest{Ref: autoRef, DefinitionVersion: automatic.Version, InputDigest: digest}
	if err := engine.StartSingleTest(ctx, autoStart); err != nil {
		t.Fatal("approval duplicate same start", err)
	}
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("actual approval decision outbox relay", err)
	}
	var deliveredControl bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_temporal74.control_intents i JOIN zasp_temporal74.control_receipts r USING(organization_id,workspace_id,environment_id,control_id) WHERE i.run_id=$1 AND i.kind='approval'`, automatic.RunID).Scan(&deliveredControl); err != nil || !deliveredControl {
		t.Fatal("actual approval durable control receipt", deliveredControl, err)
	}
	autoWait, cancelAuto := context.WithTimeout(ctx, 45*time.Second)
	defer cancelAuto()
	if err := c.GetWorkflow(autoWait, autoID, "").Get(autoWait, nil); err != nil {
		var diagnostic []byte
		readErr := owner.QueryRow(ctx, `SELECT jsonb_build_object('owner',to_jsonb(x),'parent',to_jsonb(r),'planning',(SELECT to_jsonb(j) - ARRAY['request_body','raw_response','context','output_body'] FROM zasp_temporal74.planning_jobs j WHERE j.run_id=x.run_id),'effect',(SELECT jsonb_build_object('state',f.state,'started_at',f.started_at) FROM zasp_temporal74.effects f WHERE f.run_id=x.run_id),'stops',(SELECT to_jsonb(s) FROM zasp_temporal74.stops s WHERE s.run_id=x.run_id)) FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, automatic.RunID).Scan(&diagnostic)
		t.Logf("automatic phase diagnostic namespace=%s read=%v state=%s", namespace, readErr, diagnostic)
		if described, describeErr := c.DescribeWorkflowExecution(ctx, autoID, ""); describeErr == nil {
			t.Logf("automatic activities=%v workflow=%v", described.PendingActivities, described.WorkflowExecutionInfo.Status)
		}
		t.Fatal("actual automatic rerun completion", err)
	}
	var comparison bool
	afterApproval, err := c.DescribeWorkflowExecution(ctx, autoID, "")
	if err != nil || afterApproval.WorkflowExecutionInfo.Execution.RunId != beforeApproval.WorkflowExecutionInfo.Execution.RunId {
		t.Fatal("approval created new workflow execution", err)
	}
	if err := owner.QueryRow(ctx, `SELECT x.source_kind='automatic73' AND x.action_key='rerun_test' AND r.state='remediated' AND p.receipt->>'outcome'='remediated' AND p.snapshot->'before'->>'run_id'=(SELECT test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$2) AND NOT m.active AND EXISTS(SELECT 1 FROM zasp_temporal73.admissions a WHERE a.run_id=x.run_id AND a.execution_owner='retained_single_action') AND EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries d WHERE d.run_id=x.run_id AND d.accepted_at IS NOT NULL) FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.parent_receipts p USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) JOIN zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(g.organization_id,g.grantor_id) WHERE x.run_id=$1`, automatic.RunID, parent).Scan(&comparison); err != nil || !comparison || providerCalls.Load() != 2 || runnerCalls.Load() != 2 {
		t.Fatal("actual fail-to-pass rerun/service principal proof", comparison, err, providerCalls.Load(), runnerCalls.Load())
	}
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, automatic.RunID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if err := engine.StartSingleTest(ctx, autoStart); err != nil {
		t.Fatal("automatic repeat logical start", err)
	}
	t.Log("actual automatic73 rerun used version-bound service grant with inactive creator, pinned actual failed baseline and passed after artifact -> remediated; original73 owner untouched")
	assertSingleTestLiveAPICancel(t, ctx, owner, c, deps.Processor, autoRef, providerCalls, runnerCalls)
	if _, err := orchestration.SingleTestWorkflowID(orchestration.RunRef{OrganizationID: strings.Repeat("x", 8)}); err == nil {
		t.Fatal("invalid identity")
	}
	t.Log("actual production composition: API admission ->74 takeover/start -> local Temporal planner/native test -> verified child/parent, same logical start repeated; controlled HTTPS/storage/FGA transports")
}

func assertSingleTestLiveAPICancel(t *testing.T, ctx context.Context, owner *pgx.Conn, c client.Client, processor workerProcessor, ref orchestration.RunRef, providers, runners *atomic.Int32) {
	t.Helper()
	post := func(key string, target any) {
		t.Helper()
		q, err := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv(key), nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.DefaultClient.Do(q)
		if err != nil {
			t.Fatal(key, err)
		}
		defer r.Body.Close()
		if target == nil {
			if r.StatusCode != http.StatusNoContent {
				t.Fatal(key, r.StatusCode)
			}
			return
		}
		if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(target) != nil {
			t.Fatal(key, r.StatusCode)
		}
	}
	var admitted struct {
		RunID   string `json:"run_id"`
		Version int64  `json:"definition_version"`
	}
	post("ZASP_TEST74_CANCEL_ADMIT_URL", &admitted)
	if !validRecoveryProductID(admitted.RunID) || admitted.Version != 3 {
		t.Fatal("cancel admission identity", admitted)
	}
	ref.RunID = admitted.RunID
	id, _ := orchestration.SingleTestWorkflowID(ref)
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal("cancel run actual start relay", err)
	}
	wait, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := owner.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='waiting_approval')`, ref.RunID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ticker.C:
		case <-wait.Done():
			t.Fatal("cancel run approval wait", wait.Err())
		}
	}
	before, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil {
		t.Fatal(err)
	}
	post("ZASP_TEST74_CANCEL_URL", nil)
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal("actual cancellation control relay", err)
	}
	if err := c.GetWorkflow(wait, id, "").Get(wait, nil); err == nil || !temporal.IsCanceledError(err) {
		t.Fatal("actual workflow cancellation", err)
	}
	after, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil || after.WorkflowExecutionInfo.Execution.RunId != before.WorkflowExecutionInfo.Execution.RunId {
		t.Fatal("cancel started new execution", err)
	}
	var proved bool
	if err := owner.QueryRow(ctx, `SELECT r.state='cancelled' AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND s.proof->>'kind'='admitted' AND s.proof->>'effect_state'='absent' AND NOT zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects f WHERE f.run_id=x.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs child WHERE child.run_id=x.test_run_id) AND (SELECT count(*) FROM zasp_temporal74.control_intents i JOIN zasp_temporal74.control_receipts a USING(organization_id,workspace_id,environment_id,control_id) WHERE i.run_id=x.run_id AND i.kind='cancel')=1 FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.stops s USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, ref.RunID).Scan(&proved); err != nil || !proved || providers.Load() != 3 || runners.Load() != 2 {
		t.Fatal("actual cancelled cleanup/control proof", proved, err, providers.Load(), runners.Load())
	}
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal("cancel delivered replay", err)
	}
	t.Log("actual typed API cancellation -> committed74 control -> production relay -> same Temporal execution cancelled with verified absent-child cleanup; no native provider call")
}
