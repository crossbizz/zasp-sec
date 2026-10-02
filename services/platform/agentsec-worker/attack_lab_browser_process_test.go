package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/health"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklabproxy"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type attackLabBrowserMessage struct {
	EntryID, OrganizationID, WorkspaceID, EnvironmentID, JobID, Kind string
	Body                                                             []byte
	SHA256                                                           [32]byte
}
type attackLabBrowserState struct {
	Job                                    attackLabKubernetesJob
	Created, Missing, Verdict, LoseRunning bool
	Posts, Deletes, Calls                  int
	Messages                               []attackLabBrowserMessage
	Artifacts                              combinedE2ERecoveryArtifactWire
}

// The process uses registered runtime repositories throughout. Local provider
// state is persisted across process restarts; no product SQL is seeded here.
func TestAttackLabBrowserWorkerProcess(t *testing.T) {
	if os.Getenv("ZASP_ATTACK_LAB_BROWSER_WORKER") != "true" {
		t.Skip("owned browser fixture only")
	}
	dsn, err := url.Parse(os.Getenv("ZASP_ATTACK_LAB_BROWSER_DSN"))
	if err != nil || dsn.Scheme != "postgres" || dsn.Hostname() != "127.0.0.1" || dsn.User.Username() != "zasp_e2e_security_agent_worker" || dsn.Path != "/postgres" || dsn.RawQuery != "sslmode=disable" {
		t.Fatal("owned worker database refused")
	}
	port := os.Getenv("ZASP_ATTACK_LAB_BROWSER_WORKER_PORT")
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || strconv.Itoa(number) != port {
		t.Fatal("owned control port refused")
	}
	statePath := os.Getenv("ZASP_ATTACK_LAB_BROWSER_STATE")
	if !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath || !strings.Contains(statePath, "/zasp-production-e2e-") || filepath.Base(statePath) != "attack-lab-provider.json" {
		t.Fatal("owned provider state path refused")
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_ATTACK_LAB_BROWSER_DEADLINE"))
	if err != nil || time.Until(deadline) < time.Second || time.Until(deadline) > 30*time.Minute {
		t.Fatal("bounded worker deadline required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	database := func(login string) apiserver.JSONDatabase {
		copy := *dsn
		copy.User = url.User(login)
		db := combinedE2ERecoveryDatabase(t, ctx, copy.String())
		return db
	}
	planner, _, closePlanner, err := newCombinedE2EOpenRouterPlanner(false)
	if err != nil {
		t.Fatal(err)
	}
	defer closePlanner()
	c := validSecurityAgentRuntimeConfig()
	c.PostgresDSN = dsn.String()
	c.BatchSize = 1
	agent, err := composeSecurityAgentWorkerRuntime(c, database("zasp_e2e_security_agent_worker"), &budgetFixturePlanner{planner})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	objects := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(objects, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("test-only-attack-lab-signing-key-32")
	target := &task2CanaryForwarder{verdict: true}
	proxyRepo, err := apiserver.NewAttackLabExecutionRepository(database("zasp_e2e_attack_lab_proxy"), apiserver.AttackLabExecutionAuthorityProxy)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler, err := attacklabproxy.NewHandler(attacklabproxy.Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return time.Now().UTC() }}, proxyRepo, target)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyHandler.Close()
	proxy := httptest.NewTLSServer(proxyHandler)
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	proxyClient := proxy.Client()
	proxyClient.Transport = combinedE2EOpenRouterTransport{target: proxyURL, inner: proxyClient.Transport}
	kube := &task2KubernetesTransport{t: t, uid: "123e4567-e89b-12d3-a456-426614174000", verdict: true, client: proxyClient}
	cluster := timeoutTestKubernetesAPI(t, kube)
	cluster.runnerTestRoleARN = attackLabIdentityTestRole
	provider, err := newProductionAttackLabKubernetesProvider(productionAttackLabKubernetesProviderConfig{Cluster: cluster, Namespace: "zasp-attack-lab", ServiceAccount: "agentsec-attack-lab-runner", RunnerTestRoleARN: attackLabIdentityTestRole, RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", SigningKey: key, OperationTimeout: time.Second, Now: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	queueDriver := &combinedE2ERecoveryQueueDriver{}
	queue, err := jobqueue.New(queueDriver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1 << 20, MaximumBatchBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := newProductionAttackLabEvidenceWriter(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	oc := validAttackLabOutboxRuntimeConfig()
	oc.BatchSize = 1
	outbox, err := composeAttackLabOutboxWorkerRuntime(oc, database("zasp_e2e_attack_lab_outbox"), queue, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	cc, err := loadWorkerRuntimeConfig(mapLookup(validAttackLabControllerRuntimeEnvironment()))
	if err != nil { t.Fatal(err) }
	cc.BatchSize = 1
	cc.LeaseDuration = 30 * time.Second
	controller, err := composeAttackLabWorkerRuntime(cc, database("zasp_e2e_attack_lab_controller"), &productionAttackLabDependencies{Queue: queue, Provider: provider, Evidence: writer, ready: provider.Ready, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	processor := controller.Processor.(readinessGatedWorkerProcessor).delegate.(*attackLabProcessor)
	fault := &task2ControllerFault{attackLabExecutionAuthority: processor.config.Authority, kube: kube, provider: provider, loseRunning: true}
	processor.config.Authority = fault
	lost := &task2LostSettlement{db: database("e2e_attack_lab_reconciler")}
	rc := loadAttackLabReconcilerFixture(t)
	reconciler, err := composeAttackLabLinkRuntime(rc, lost, existingTestRuntimeDependencies{Artifacts: artifacts, Ready: func(context.Context) error { return nil }, Close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()
	if raw, readErr := os.ReadFile(statePath); readErr == nil {
		var state attackLabBrowserState
		if decodeStrictWorkerJSON(raw, &state) != nil {
			t.Fatal("provider state rejected")
		}
		kube.job, kube.created, kube.missing, kube.verdict, kube.posts, kube.deletes = state.Job, state.Created, state.Missing, state.Verdict, state.Posts, state.Deletes
		target.verdict = state.Verdict
		target.calls.Store(int32(state.Calls))
		fault.loseRunning = state.LoseRunning
		for _, item := range state.Messages {
			o, _ := domain.ParseProductID(item.OrganizationID)
			w, _ := domain.ParseProductID(item.WorkspaceID)
			e, _ := domain.ParseProductID(item.EnvironmentID)
			s, scopeErr := domain.NewScope(o, w, e)
			id, idErr := domain.ParseProductID(item.JobID)
			if scopeErr != nil || idErr != nil {
				t.Fatal("queue state refused")
			}
			queueDriver.messages = append(queueDriver.messages, jobqueue.DriverMessage{EntryID: item.EntryID, Scope: s, JobID: id, Kind: item.Kind, Body: item.Body, SHA256: item.SHA256})
		}
		for _, item := range state.Artifacts.Objects {
			o, _ := domain.ParseProductID(item.OrganizationID)
			w, _ := domain.ParseProductID(item.WorkspaceID)
			e, _ := domain.ParseProductID(item.EnvironmentID)
			s, scopeErr := domain.NewScope(o, w, e)
			ref, refErr := domain.ParseEvidenceRef(item.Reference)
			if scopeErr != nil || refErr != nil {
				t.Fatal("artifact state refused")
			}
			object := combinedE2ECloneDriverObject(artifactstore.DriverObject{DriverLocator: artifactstore.DriverLocator{Key: item.Key, Scope: s, Reference: ref, VersionID: item.VersionID}, MediaType: item.MediaType, Body: item.Body})
			objects.objects[item.Key+"\x1f"+item.VersionID] = object
		}
		objects.order = state.Artifacts.Order
	} else if !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	save := func() error {
		state := attackLabBrowserState{Job: kube.job, Created: kube.created, Missing: kube.missing, Verdict: kube.verdict, Posts: kube.posts, Deletes: kube.deletes, Calls: int(target.calls.Load()), LoseRunning: fault.loseRunning}
		for _, m := range queueDriver.messages {
			state.Messages = append(state.Messages, attackLabBrowserMessage{m.EntryID, m.Scope.OrganizationID().String(), m.Scope.WorkspaceID().String(), m.Scope.EnvironmentID().String(), m.JobID.String(), m.Kind, m.Body, m.SHA256})
		}
		state.Artifacts.Order = objects.order
		for _, o := range objects.objects {
			state.Artifacts.Objects = append(state.Artifacts.Objects, combinedE2ERecoveryArtifactObjectWire{Key: o.Key, OrganizationID: o.OrganizationID().String(), WorkspaceID: o.WorkspaceID().String(), EnvironmentID: o.EnvironmentID().String(), Reference: o.Reference.String(), VersionID: o.VersionID, MediaType: o.MediaType, Body: o.Body})
		}
		raw, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return os.WriteFile(statePath, raw, 0600)
	}
	source := newAttackLabBrowserSourceRuntime(t, ctx, database, artifacts)
	defer source.Close()
	checks := map[string]func(context.Context) error{"agentsec-security-agent:8081": agent.Ready, "agentsec-attack-lab-outbox:8081": outbox.Ready, "agentsec-attack-lab-controller:8081": controller.Ready, "agentsec-attack-lab-proxy:8081": proxyRepo.Ready, "security-agent-attack-lab-reconciler:8081": reconciler.Ready}
	var mu sync.Mutex
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		work, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" && r.URL.Path == "/readyz" {
			check, ok := checks[r.Host]
			if !ok {
				check = func(ctx context.Context) error {
					for _, ready := range checks {
						if err := ready(ctx); err != nil {
							return err
						}
					}
					return nil
				}
			}
			h, _ := health.New(health.Config{Service: "attack-lab-browser", Version: "local"})
			h.SetReady(check(work) == nil)
			h.ServeHTTP(w, r)
			return
		}
		if r.Method != "POST" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		var operationErr error
		switch r.URL.Path {
		case "/plan":
			operationErr = agent.Processor.RunOnce(work)
		case "/source":
			operationErr = source.Processor.RunOnce(work)
		case "/outbox":
			operationErr = outbox.Processor.RunOnce(work)
		case "/execute":
			operationErr = controller.Processor.RunOnce(work)
		case "/reconcile":
			operationErr = reconciler.Processor.RunOnce(work)
		case "/arm-verified", "/arm-not-reproduced":
			kube.created, kube.missing, kube.blockCreate, kube.blockDelete = false, false, false, false
			kube.job = attackLabKubernetesJob{}
			kube.posts, kube.deletes = 0, 0
			kube.verdict = r.URL.Path == "/arm-verified"
			target.verdict = kube.verdict
			target.calls.Store(0)
			fault.loseRunning = true
			queueDriver.messages = nil
			queueDriver.delivered = false
			queueDriver.acknowledged = false
			lost.lost = false
			lost.calls = 0
			lost.first = ""
		default:
			http.NotFound(w, r)
			return
		}
		if err := save(); err != nil {
			http.Error(w, "provider state persistence failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if operationErr != nil {
			w.WriteHeader(503)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": operationErr == nil, "error": func() string {
			if operationErr == nil {
				return ""
			}
			return operationErr.Error()
		}(), "provider_calls": target.calls.Load(), "job_posts": kube.posts, "job_deletes": kube.deletes, "settlement_calls": lost.calls, "lost_settlement_reply": lost.lost})
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 12 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
		return
	}
	shutdown, closeShutdown := context.WithTimeout(context.Background(), 3*time.Second)
	defer closeShutdown()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		t.Error(err)
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Error(err)
	}
	t.Log("owned Attack Lab worker/reconciler joined")
}

func newAttackLabBrowserSourceRuntime(t *testing.T, ctx context.Context, database func(string) apiserver.JSONDatabase, artifacts *artifactstore.Store) workerRuntimeDependencies {
	t.Helper()
	root := t.TempDir()
	tokenFile := filepath.Join(root, "adapter-token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 64)), 0400); err != nil {
		t.Fatal(err)
	}
	command := redTeamCommandFunc(func(_ context.Context, _ string, args, _ []string, directory string) error {
		if len(args) != 4 {
			return errors.New("controlled source command refused")
		}
		raw, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var input redTeamRunnerInput
		if json.Unmarshal(raw, &input) != nil {
			return errors.New("source input refused")
		}
		output := redTeamRunnerOutput{SchemaVersion: "red-team-evidence-v1", Engine: "promptfoo", EngineVersion: "0.121.19", RunID: input.RunID, InputDigest: input.InputDigest, Objective: "Evaluate curated categories: prompt_injection", Behavior: "0 of 1 curated security checks passed; 1 exposed unsafe behavior.", Verdict: "fail", Evidence: []string{"prompt_injection: unsafe behavior observed"}}
		native := redTeamNativeArtifact{SchemaVersion: "red-team-native-artifact-v1", RedactionPolicy: "red-team-artifact-redaction-v1", RunID: input.RunID, InputDigest: input.InputDigest, NativeOutput: &redTeamNativeOutput{}}
		native.NativeOutput.Metadata.PromptfooVersion = "0.121.19"
		native.NativeOutput.Results.Version = 3
		passed := false
		status := 200
		record := redTeamNativeResult{Success: &passed}
		record.Provider.Label = "zasp-red-team-adapter"
		record.Vars.Category, record.Vars.Prompt = "prompt_injection", redTeamCuratedPrompt("prompt_injection")
		record.TestCase.Metadata.Category = "prompt_injection"
		record.Response.Output, record.Response.Metadata.HTTP.Status = "[REDACTED]", &status
		record.GradingResult.Pass, record.GradingResult.Reason = &passed, "[REDACTED]"
		native.NativeOutput.Results.Results = []redTeamNativeResult{record}
		body, _ := json.Marshal(native)
		if err := os.WriteFile(filepath.Join(directory, "artifact.json"), body, 0600); err != nil {
			return err
		}
		body, _ = json.Marshal(output)
		return os.WriteFile(args[3], body, 0600)
	})
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/zasp/red-team-worker@sha256:" + strings.Repeat("d", 64), Artifacts: artifacts, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", TargetTokenFile: tokenFile, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: time.Minute, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := jobqueue.New(&combinedE2ERecoveryQueueDriver{}, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1 << 20, MaximumBatchBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := composeRedTeamOutboxWorkerRuntime(validRedTeamOutboxRuntimeConfig(), database("zasp_e2e_red_team_outbox"), queue, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c := validRedTeamRuntimeConfig()
	c.BatchSize = 1
	worker, err := composeRedTeamWorkerRuntime(c, database("zasp_e2e_red_team_worker"), &productionRedTeamDependencies{Queue: queue, Runner: runner, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return workerRuntimeDependencies{Processor: attackLabBrowserProcessor(func(ctx context.Context) error {
		if err := outbox.Processor.RunOnce(ctx); err != nil {
			return err
		}
		return worker.Processor.RunOnce(ctx)
	}), Ready: worker.Ready, Close: func() error { _ = outbox.Close(); return worker.Close() }}
}

type attackLabBrowserProcessor func(context.Context) error

func (p attackLabBrowserProcessor) RunOnce(ctx context.Context) error { return p(ctx) }
