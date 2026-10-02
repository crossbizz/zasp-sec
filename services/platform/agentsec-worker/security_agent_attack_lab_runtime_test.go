package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabrunner"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAttackLabLinkedRuntimeOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_ATTACK_LAB_TASK2_DSN")
	if dsn == "" {
		t.Skip("owned parent fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	database := func(user string) apiserver.JSONDatabase {
		c, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		c.ConnConfig.User = user
		pool, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		var session, current string
		if err := pool.QueryRow(ctx, `SELECT session_user,current_user`).Scan(&session, &current); err != nil || session != user || current != user {
			pool.Close()
			t.Fatalf("registered fixture identity: wanted%s got%s/%s: %v", user, session, current, err)
		}
		db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
		if err != nil {
			pool.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	controllerDB := database("attack_lab_controller_login")
	for _, q := range []string{`SELECT to_jsonb(session_user::text)`, `SELECT to_jsonb(zasp_attack_lab_principal_ready('zasp_attack_lab_controller'))`} {
		raw, err := controllerDB.QueryJSON(ctx, q)
		t.Logf("registered controller diagnostic %s: %s %v", q, raw, err)
	}
	controller, err := apiserver.NewAttackLabExecutionRepository(controllerDB, apiserver.AttackLabExecutionAuthorityController)
	if err != nil {
		t.Fatal(err)
	}
	proxyRepo, err := apiserver.NewAttackLabExecutionRepository(database("attack_lab_proxy_login"), apiserver.AttackLabExecutionAuthorityProxy)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := domain.ParseProductID(os.Getenv("ZASP_ATTACK_LAB_TASK2_ORG"))
	w, _ := domain.ParseProductID(os.Getenv("ZASP_ATTACK_LAB_TASK2_WORKSPACE"))
	e, _ := domain.ParseProductID(os.Getenv("ZASP_ATTACK_LAB_TASK2_ENVIRONMENT"))
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	var parent, step, execution string
	if err := owner.QueryRow(ctx, `SELECT run_id,step_id,execution_id FROM zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o.String(), w.String(), e.String()).Scan(&parent, &step, &execution); err != nil {
		t.Fatal(err)
	}
	mode := os.Getenv("ZASP_ATTACK_LAB_TASK2_MODE")
	key := []byte("test-only-attack-lab-signing-key-32")
	target := &task2CanaryForwarder{verdict: mode != "lost_running"}
	handler, err := attacklabproxy.NewHandler(attacklabproxy.Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return time.Now().UTC() }}, proxyRepo, target)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	httpClient := server.Client()
	httpClient.Transport = combinedE2EOpenRouterTransport{target: proxyURL, inner: httpClient.Transport}
	kube := &task2KubernetesTransport{t: t, uid: "123e4567-e89b-12d3-a456-426614174000", mode: mode, blockCreate: mode == "lost_create", verdict: target.verdict, client: httpClient}
	api := timeoutTestKubernetesAPI(t, kube)
	api.runnerTestRoleARN = attackLabIdentityTestRole
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{Cluster: api, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner", RunnerTestRoleARN: attackLabIdentityTestRole, RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", SigningKey: key, OperationTimeout: time.Second, Now: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	authority := &task2ControllerFault{attackLabExecutionAuthority: controller, kube: kube, provider: provider, loseRunning: mode != "lost_create" && mode != "cleanup_reply"}
	artifactDriver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(artifactDriver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	writer, _ := newProductionAttackLabEvidenceWriter(artifacts)
	queueDriver := &combinedE2ERecoveryQueueDriver{}
	queue, err := jobqueue.New(queueDriver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1 << 20, MaximumBatchBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	outboxConfig := validAttackLabOutboxRuntimeConfig()
	outboxConfig.BatchSize = 1
	outbox, err := composeAttackLabOutboxWorkerRuntime(outboxConfig, database("attack_lab_outbox_login"), queue, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	if err := outbox.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("registered outbox: %v", err)
	}
	runOnce := func() error {
		processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: writer, WorkerID: "task-two-controller", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("7", 32), nil }})
		if err != nil {
			return err
		}
		return processor.RunOnce(ctx)
	}
	if mode == "create_denied" {
		if err := runOnce(); err != nil {
			t.Fatalf("definite Create denial: %v", err)
		}
		var state, cleanup string
		var started bool
		if err := owner.QueryRow(ctx, `SELECT state,cleanup_state,started_at IS NOT NULL FROM zasp_attack_lab_runs WHERE run_id=$1`, execution).Scan(&state, &cleanup, &started); err != nil || state != "failed" || cleanup != "complete" || !started || target.calls.Load() != 0 || kube.created {
			t.Fatalf("definite denied identity=%s/%s started=%v calls=%d: %v", state, cleanup, started, target.calls.Load(), err)
		}
		deniedClient, _ := newAttackLabLinkClient(database("attack_lab_settlement_login"), "task-two-reconciler", func() time.Time { return time.Now().UTC() })
		if err := deniedClient.ReconcileOne(ctx, scope, artifacts); err != nil {
			t.Fatalf("definite denial client: %v", err)
		}
		var outcome string
		if err := owner.QueryRow(ctx, `SELECT COALESCE(settlement_result->>'outcome','pending') FROM zasp_sa_attack_lab_links WHERE run_id=$1`, parent).Scan(&outcome); err != nil || outcome != "failed" {
			t.Fatalf("definite denial remained %s instead of failed: %v", outcome, err)
		}
		t.Log("LOCAL controlled Create403: no Job, no proxy execution, existing controller terminal cleanup, actual client Failed settlement")
		return
	}
	if err := runOnce(); err == nil {
		t.Fatal("fault did not interrupt controller")
	}
	var state, cleanup, reference string
	var attempt int
	read := func() {
		t.Helper()
		if err := owner.QueryRow(ctx, `SELECT state,cleanup_state,COALESCE(sandbox_reference,''),attempt FROM zasp_attack_lab_runs WHERE run_id=$1`, execution).Scan(&state, &cleanup, &reference, &attempt); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if mode == "lost_create" {
		if state != "leased" || target.calls.Load() != 0 || attempt != 1 {
			t.Fatalf("pre-running external execution: %s attempt%d calls%d", state, attempt, target.calls.Load())
		}
	} else if mode == "cleanup_reply" {
		if state != "cleanup" || cleanup != "in_progress" || target.calls.Load() != 1 {
			t.Fatalf("lost cleanup obligation %s/%s calls%d", state, cleanup, target.calls.Load())
		}
	} else if state != "running" || !strings.HasSuffix(reference, "@"+kube.uid) || attempt != 1 || target.calls.Load() != 1 {
		t.Fatalf("lost durable running identity %s %s attempt%d calls%d", state, reference, attempt, target.calls.Load())
	}
	clientDB := database("attack_lab_settlement_login")
	client, _ := newAttackLabLinkClient(&task2DiagnosticQuery{t: t, db: clientDB}, "task-two-reconciler", func() time.Time { return time.Now().UTC() })
	if err := client.ReconcileOne(ctx, scope, artifacts); err != nil {
		t.Fatalf("pending actual client: %v", err)
	}
	var pending bool
	if err := owner.QueryRow(ctx, `SELECT settled_at IS NULL FROM zasp_sa_attack_lab_links WHERE run_id=$1`, parent).Scan(&pending); err != nil || !pending {
		t.Fatalf("running/cleanup settled early: %v %v", pending, err)
	}
	stopped := stringInWorker(mode, "cancel_cleanup", "action_stopped", "environment_stopped", "global_stopped", "duration_expired", "budget_stopped")
	if stopped {
		stopSQL := `UPDATE zasp_security_agent_runs SET state='cancelled' WHERE run_id=$1`
		switch mode {
		case "action_stopped":
			stopSQL = `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE action_key='start_attack_lab' AND organization_id=(SELECT organization_id FROM zasp_security_agent_runs WHERE run_id=$1)`
		case "duration_expired":
			stopSQL = `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`
		case "budget_stopped":
			stopSQL = `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_steps_exceeded' WHERE run_id=$1`
		}
		if stringInWorker(mode, "action_stopped", "environment_stopped") {
			action, kind := "start_attack_lab", "action"
			if mode == "environment_stopped" {
				action, kind = "*", "environment"
			}
			var version int64
			var actor string
			if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,$4)`, o.String(), w.String(), e.String(), action).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `SELECT approver_id FROM zasp_sa_attack_lab_links WHERE run_id=$1`, parent).Scan(&actor); err != nil {
				t.Fatal(err)
			}
			if _, err := database("security_agent_v33_api_login").QueryJSON(ctx, `SELECT zasp_production_security_agent_existing_tests_set_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, o.String(), w.String(), e.String(), actor, "task-two-control-stop", kind, action, false, version, time.Now().UTC().Add(4*time.Minute), "pid_8ea10000-0000-4000-8000-000000000001", "pid_8ea20000-0000-4000-8000-000000000002", "pid_8ea30000-0000-4000-8000-000000000003", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()); err != nil {
				t.Fatalf("registered API stop: %v", err)
			}
		} else if mode == "global_stopped" {
			var raw json.RawMessage
			var control struct {
				Version int64 `json:"version"`
			}
			if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_global_read($1,$2)`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &control); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_global_set($1,$2,$3,$4,$5,$6)`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint(), false, control.Version, "pid_8ea40000-0000-4000-8000-000000000004", "task-two-global-stop").Scan(&raw); err != nil {
				t.Fatalf("registered operator stop: %v", err)
			}
		} else if _, err := owner.Exec(ctx, stopSQL, parent); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_sa_attack_lab_links SET available_at=clock_timestamp() WHERE run_id=$1`, parent); err != nil {
			t.Fatal(err)
		}
		if err := client.ReconcileOne(ctx, scope, artifacts); err != nil {
			t.Fatal(err)
		}
		var requested bool
		if err := owner.QueryRow(ctx, `SELECT cancel_requested FROM zasp_attack_lab_runs WHERE run_id=$1`, execution).Scan(&requested); err != nil || !requested {
			t.Fatalf("stop discarded cancellation obligation: %v", err)
		}
	}
	kube.mu.Lock()
	kube.blockCreate = false
	kube.blockDelete = false
	if mode == "missing_job" {
		kube.missing = true
	}
	kube.mu.Unlock()
	if _, err := owner.Exec(ctx, `UPDATE zasp_attack_lab_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, execution); err != nil {
		t.Fatal(err)
	}
	queueDriver.mu.Lock()
	queueDriver.delivered = false
	queueDriver.mu.Unlock()
	if err := runOnce(); err != nil {
		t.Fatalf("restarted production controller: %v", err)
	}
	read()
	if cleanup != "complete" || !stringInWorker(state, "complete", "cancelled") || attempt != 1 || target.calls.Load() != 1 {
		t.Fatalf("recovery changed execution %s/%s attempt%d calls%d", state, cleanup, attempt, target.calls.Load())
	}
	kube.mu.Lock()
	posts := kube.posts
	deletes := kube.deletes
	kube.mu.Unlock()
	if mode != "lost_create" && posts != 1 {
		t.Fatalf("running recovery created again: %d POSTs", posts)
	}
	if mode == "artifact_drift" {
		artifactDriver.mu.Lock()
		for k, v := range artifactDriver.objects {
			v.Body = []byte(`{"schema_version":"foreign"}`)
			v.Size = int64(len(v.Body))
			v.SHA256 = sha256.Sum256(v.Body)
			artifactDriver.objects[k] = v
		}
		artifactDriver.mu.Unlock()
	}
	if mode == "source_drift" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_attempts SET evidence_checksum=digest('drift','sha256') WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o.String(), w.String(), e.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_sa_attack_lab_links SET available_at=clock_timestamp() WHERE run_id=$1`, parent); err != nil {
		t.Fatal(err)
	}
	lost := &task2LostSettlement{db: clientDB}
	restarted, _ := newAttackLabLinkClient(lost, "task-two-reconciler", func() time.Time { return time.Now().UTC() })
	if err := restarted.ReconcileOne(ctx, scope, artifacts); err != nil {
		t.Fatalf("actual artifact settlement: %v", err)
	}
	var outcome, reason string
	var proof []byte
	if err := owner.QueryRow(ctx, `SELECT settlement_result->>'outcome',settlement_result->>'reason',settlement_proof FROM zasp_sa_attack_lab_links WHERE run_id=$1 AND settled_at IS NOT NULL`, parent).Scan(&outcome, &reason, &proof); err != nil {
		t.Fatal(err)
	}
	want := "needs_human"
	if stringInWorker(mode, "missing_job", "expired_job", "artifact_drift", "source_drift") {
		want = "inconclusive"
	}
	if stopped {
		want = "cancelled"
	}
	if outcome != want || len(proof) == 0 || !lost.lost || lost.calls != 2 {
		t.Fatalf("settlement=%s/%s wanted%s calls%d", outcome, reason, want, lost.calls)
	}
	if err := restarted.ReconcileOne(ctx, scope, artifacts); err != nil {
		t.Fatal(err)
	}
	t.Logf("LOCAL controlled %s: durable attempt%d; authorized external requests%d; Job POSTs%d; UID-fenced DELETEs%d; %s/%s; exact lost settlement reply retried", mode, attempt, target.calls.Load(), posts, deletes, outcome, reason)
}

type task2DiagnosticQuery struct {
	t  *testing.T
	db existingTestQuery
}

func (q *task2DiagnosticQuery) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	raw, err := q.db.QueryJSON(ctx, sql, args...)
	q.t.Logf("reconcile boundary %s: %s %v", sql, raw, err)
	return raw, err
}

type task2LostSettlement struct {
	db    existingTestQuery
	lost  bool
	calls int
	first string
}

func (q *task2LostSettlement) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	if strings.Contains(sql, "reconcile_settle") {
		q.calls++
		encoded, _ := json.Marshal(args)
		if q.first != "" && q.first != string(encoded) {
			return nil, errors.New("settlement retry changed bytes")
		}
		q.first = string(encoded)
		raw, err := q.db.QueryJSON(ctx, sql, args...)
		if err == nil && !q.lost {
			q.lost = true
			return nil, errors.New("reply lost after commit")
		}
		return raw, err
	}
	return q.db.QueryJSON(ctx, sql, args...)
}

type task2ControllerFault struct {
	attackLabExecutionAuthority
	claim       apiserver.AttackLabRunClaim
	kube        *task2KubernetesTransport
	provider    *productionAttackLabKubernetesProvider
	loseRunning bool
}

func (a *task2ControllerFault) ClaimAttackLabRun(ctx context.Context, s domain.Scope, r, w, l string, seconds int) (apiserver.AttackLabRunClaim, error) {
	v, err := a.attackLabExecutionAuthority.ClaimAttackLabRun(ctx, s, r, w, l, seconds)
	a.claim = v
	return v, err
}
func (a *task2ControllerFault) BeginAttackLabProvisioning(ctx context.Context, s domain.Scope, input apiserver.AttackLabProvisioningInput) (apiserver.AttackLabRunTransition, error) {
	v, err := a.attackLabExecutionAuthority.BeginAttackLabProvisioning(ctx, s, input)
	if err != nil {
		return v, err
	}
	job, err := a.provider.jobForRequest(attackLabSandboxRequest{Scope: s, Run: v.Run, Preflight: a.claim.Preflight, InputDigest: input.InputDigest})
	if err != nil {
		return v, err
	}
	a.kube.mu.Lock()
	a.kube.job = job
	a.kube.mu.Unlock()
	return v, nil
}
func (a *task2ControllerFault) MarkAttackLabRunning(ctx context.Context, s domain.Scope, input apiserver.AttackLabRunningInput) (apiserver.AttackLabRunTransition, error) {
	v, err := a.attackLabExecutionAuthority.MarkAttackLabRunning(ctx, s, input)
	if err != nil {
		return v, err
	}
	if err := a.kube.invoke(ctx, true); err != nil {
		return v, err
	}
	if a.loseRunning {
		a.loseRunning = false
		return v, errors.New("running reply lost after commit")
	}
	return v, nil
}

type task2CanaryForwarder struct {
	calls   atomic.Int32
	verdict bool
}

func (f *task2CanaryForwarder) Forward(_ context.Context, r attacklabproxy.ForwardRequest) (attacklabproxy.ForwardResult, error) {
	if r.Method != "POST" || r.Path != "/v1/attack-lab/canary" || !strings.HasPrefix(r.CredentialReference, "ref:red-team/") {
		return attacklabproxy.ForwardResult{}, errors.New("authority mismatch")
	}
	var b map[string]any
	if json.Unmarshal(r.Body, &b) != nil {
		return attacklabproxy.ForwardResult{}, errors.New("bad body")
	}
	f.calls.Add(1)
	out, _ := json.Marshal(map[string]any{"schema_version": "attack-lab-canary-v1", "organization_id": b["organization_id"], "workspace_id": b["workspace_id"], "environment_id": b["environment_id"], "run_id": r.RunID, "input_digest": b["input_digest"], "criterion_observed": f.verdict, "canary_touched": f.verdict, "evidence": "owned controlled canary"})
	return attacklabproxy.ForwardResult{StatusCode: 200, ContentType: "application/json", Body: out}, nil
}

type task2KubernetesTransport struct {
	t                                                   *testing.T
	mu                                                  sync.Mutex
	job                                                 attackLabKubernetesJob
	uid, mode                                           string
	created, missing, blockCreate, blockDelete, verdict bool
	posts, deletes                                      int
	client                                              *http.Client
}

func (k *task2KubernetesTransport) invoke(ctx context.Context, want bool) error {
	j := k.job
	runner, err := attacklabrunner.New(attacklabrunner.Config{OrganizationID: j.OrganizationID, WorkspaceID: j.WorkspaceID, EnvironmentID: j.EnvironmentID, RunID: j.RunID, Destination: j.Destination, SuccessCriterion: j.SuccessCriterion, ExpectedSideEffects: j.ExpectedSideEffects, InputDigest: j.InputDigest, ProxyEndpoint: j.ProxyEndpoint, EgressToken: j.EgressToken, Timeout: time.Second}, k.client)
	if err != nil {
		return err
	}
	_, err = runner.Run(ctx)
	if (err == nil) != want {
		return fmt.Errorf("proxy durable authority accepted=%v wanted=%v: %w", err == nil, want, err)
	}
	return nil
}
func (k *task2KubernetesTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	response := func(status int, body string) (*http.Response, error) {
		return attackLabKubernetesTestResponse(status, body), nil
	}
	p := r.URL.Path
	switch {
	case p == "/version":
		return response(200, `{"major":"1","minor":"30"}`)
	case p == "/api/v1/namespaces/zasp-attack-lab":
		return response(200, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`)
	case strings.Contains(p, "/serviceaccounts/"):
		return response(200, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"},"annotations":{"eks.amazonaws.com/role-arn":"`+attackLabIdentityTestRole+`"}},"automountServiceAccountToken":false,"secrets":[],"imagePullSecrets":[]}`)
	case strings.Contains(p, "/configmaps/"):
		return response(200, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"agentsec-attack-lab-proxy-ca","namespace":"zasp-attack-lab","uid":"423e4567-e89b-12d3-a456-426614174000"},"data":{"proxy-ca.crt":`+strconv.Quote(testDiscoveryCACertificatePEM)+`}}`)
	case strings.Contains(p, "/securitygrouppolicies/"):
		return response(200, `{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-1234abcd"]}}}`)
	case r.Method == "POST" && strings.HasSuffix(p, "/jobs"):
		k.posts++
		body, _ := io.ReadAll(r.Body)
		var manifest attackLabKubernetesJobManifest
		if json.Unmarshal(body, &manifest) != nil || manifest.Metadata.Name != k.job.Name {
			return nil, errors.New("unexpected job intent")
		}
		if k.mode == "create_denied" {
			return response(403, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}`)
		}
		if !k.created {
			k.created = true
			if err := k.invoke(r.Context(), false); err != nil {
				return nil, err
			}
		}
		if k.blockCreate {
			return nil, errors.New("create committed; response lost")
		}
		if k.posts > 1 {
			return response(409, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"AlreadyExists","code":409}`)
		}
		return response(201, attackLabKubernetesExactJobResponse(k.t, k.job, k.uid))
	case r.Method == "DELETE":
		b, _ := io.ReadAll(r.Body)
		var options struct {
			Preconditions     struct{ UID string }
			PropagationPolicy string
		}
		if json.Unmarshal(b, &options) != nil || options.Preconditions.UID != k.uid || options.PropagationPolicy != "Foreground" {
			return nil, errors.New("cleanup lacks UID fence")
		}
		k.deletes++
		k.missing = true
		if k.mode == "cleanup_reply" && k.deletes == 1 {
			k.blockDelete = true
			return nil, errors.New("delete committed; response lost")
		}
		return response(200, `{"apiVersion":"v1","kind":"Status","status":"Success","reason":"Deleted","code":200}`)
	case strings.HasSuffix(p, "/pods"):
		if k.blockDelete {
			return nil, errors.New("cleanup observation unavailable")
		}
		if k.missing {
			return response(200, `{"apiVersion":"v1","kind":"PodList","items":[]}`)
		}
		return response(200, task2PodList(k.t, k.job, k.uid, k.verdict))
	case strings.Contains(p, "/jobs/"):
		if k.blockCreate || k.blockDelete {
			return nil, errors.New("unknown external observation")
		}
		if k.missing {
			return response(404, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}`)
		}
		var object map[string]any
		json.Unmarshal([]byte(attackLabKubernetesExactJobResponse(k.t, k.job, k.uid)), &object)
		status := map[string]any{"succeeded": 1, "failed": 0, "conditions": []any{map[string]string{"type": "Complete", "status": "True"}}}
		if k.mode == "expired_job" {
			status = map[string]any{"failed": 1, "conditions": []any{map[string]string{"type": "Failed", "status": "True", "reason": "DeadlineExceeded"}}}
		}
		object["status"] = status
		b, _ := json.Marshal(object)
		return response(200, string(b))
	}
	return nil, fmt.Errorf("unhandled controlled Kubernetes request %s %s", r.Method, p)
}

func task2PodList(t *testing.T, j attackLabKubernetesJob, uid string, verdict bool) string {
	t.Helper()
	encoded, _ := json.Marshal(attackLabKubernetesExactJobManifest(j, uid).Spec.Template.Spec)
	var spec map[string]any
	json.Unmarshal(encoded, &spec)
	spec["nodeName"] = "fargate-owned-fixture"
	termination, _ := json.Marshal(map[string]any{"schema_version": "attack-lab-outcome-v1", "criterion_observed": verdict, "canary_touched": verdict, "gateway_evidence": "registered proxy authorized one POST", "egress_evidence": "exact approved destination", "cloud_evidence": "controlled canary"})
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": j.Name + "-fixture", "namespace": j.Namespace, "uid": "523e4567-e89b-12d3-a456-426614174000", "labels": map[string]string{"job-name": j.Name, "zasp.io/execution": "attack-lab", "eks.amazonaws.com/fargate-profile": "attack-lab"}, "ownerReferences": []attackLabKubernetesOwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: j.Name, UID: uid, Controller: true}}}, "spec": spec, "status": map[string]any{"phase": "Succeeded", "containerStatuses": []any{map[string]any{"name": "runner", "image": j.Image, "imageID": j.Image, "ready": false, "restartCount": 0, "state": map[string]any{"terminated": map[string]any{"exitCode": 0, "reason": "Completed", "message": string(termination)}}}}}}
	b, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "PodList", "items": []any{pod}})
	return string(b)
}
