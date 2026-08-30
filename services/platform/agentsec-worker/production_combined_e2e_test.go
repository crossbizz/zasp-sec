package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery/neondriver"
)

type combinedE2EOpenRouterTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (transport combinedE2EOpenRouterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	target := *request.URL
	target.Scheme = transport.target.Scheme
	target.Host = transport.target.Host
	clone.URL = &target
	return transport.inner.RoundTrip(clone)
}

func newCombinedE2EOpenRouterPlanner(unavailable bool) (*productionSecurityAgentPlanner, func() int, func(), error) {
	var mu sync.Mutex
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		if unavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(response, `{"error":"unavailable"}`)
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/chat/completions" || request.Header.Get("Authorization") != "Bearer sk-or-v1-production-e2e-token" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("X-Zasp-Data-Policy") != "security-agent-planner-v1" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
		if err != nil || len(body) > 64*1024 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var providerRequest securityAgentOpenRouterRequest
		if json.Unmarshal(body, &providerRequest) != nil || len(providerRequest.Messages) != 2 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var plannerContext struct {
			AllowedActions    []string                       `json:"allowed_actions"`
			AllowedTargets    []string                       `json:"allowed_targets"`
			Scope             map[string]string              `json:"scope"`
			UntrustedEvidence []securityAgentPlannerEvidence `json:"untrusted_evidence"`
		}
		if json.Unmarshal([]byte(providerRequest.Messages[1].Content), &plannerContext) != nil || len(plannerContext.AllowedActions) != 1 || len(plannerContext.UntrustedEvidence) != 1 {
			response.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		action := plannerContext.AllowedActions[0]
		targetID := plannerContext.UntrustedEvidence[0].ID
		if action == "create_temporary_policy" {
			targetID = plannerContext.Scope["environment_id"]
		} else if action == "revoke_integration_connection" {
			for _, candidate := range plannerContext.AllowedTargets {
				if candidate != plannerContext.Scope["environment_id"] && candidate != plannerContext.UntrustedEvidence[0].ID {
					targetID = candidate
					break
				}
			}
		}
		candidate, _ := json.Marshal(securityAgentPlannerCandidate{Version: 1, Summary: "Bounded production E2E response", Steps: []securityAgentPlannerStep{{Index: 0, Action: action, TargetID: targetID}}})
		_, _ = response.Write(openRouterPlannerResponse(string(candidate)))
	}))
	target, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		return nil, nil, nil, err
	}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{
		Endpoint:      "https://openrouter.ai/api/v1/chat/completions",
		Model:         "openai/gpt-5-mini",
		Token:         []byte("sk-or-v1-production-e2e-token"),
		Timeout:       5 * time.Second,
		MaximumTokens: 512,
		PolicyVersion: "security-agent-planner-v1",
		Transport:     combinedE2EOpenRouterTransport{target: target, inner: server.Client().Transport},
	})
	if err != nil {
		server.Close()
		return nil, nil, nil, err
	}
	callCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
	var closeOnce sync.Once
	closeEndpoint := func() { closeOnce.Do(func() { _ = planner.Close(); server.Close() }) }
	return planner, callCount, closeEndpoint, nil
}

func TestCombinedE2EOpenRouterPlannerUsesProductionHTTPBoundary(t *testing.T) {
	planner, callCount, closeEndpoint, err := newCombinedE2EOpenRouterPlanner(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeEndpoint)
	result := planner.Plan(context.Background(), testSecurityAgentPlannerContext())
	if _, ok := any(planner).(*productionSecurityAgentPlanner); !ok || result.Failure != "" || result.Candidate.Version != 1 || callCount() != 1 {
		t.Fatalf("planner=%T result=%+v calls=%d", planner, result, callCount())
	}
}

func TestProductionCombinedE2ESecurityAgentWorker(t *testing.T) {
	dsn := os.Getenv("ZASP_COMBINED_E2E_SECURITY_AGENT_DSN")
	if dsn == "" {
		t.Skip("combined E2E helper")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	config := validSecurityAgentRuntimeConfig()
	config.PostgresDSN = dsn
	config.WorkerID = "production-e2e-security-agent"
	config.PollInterval = 100 * time.Millisecond
	config.LeaseDuration = 30 * time.Second
	config.ShutdownTimeout = time.Second
	planner, plannerCalls, closePlanner, err := newCombinedE2EOpenRouterPlanner(os.Getenv("ZASP_COMBINED_E2E_SECURITY_AGENT_PLANNER") == "unavailable")
	if err != nil {
		t.Fatal(err)
	}
	defer closePlanner()
	dependencies, err := composeSecurityAgentWorkerRuntime(config, database, planner)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_COMBINED_E2E_SECURITY_AGENT_ONCE") == "true" {
		if err := dependencies.Ready(ctx); err != nil {
			t.Fatal(err)
		}
		if err := dependencies.Processor.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if plannerCalls() != 1 {
			t.Fatalf("planner calls=%d", plannerCalls())
		}
		if err := dependencies.Close(); err != nil {
			t.Fatal(err)
		}
		t.Log("composed security agent persisted planner-unavailable without an action")
		return
	}
	if err := serveWorkerRuntime(ctx, os.Stdout, buildVersion, config, dependencies, net.Listen); err != nil {
		t.Fatal(err)
	}
}

func TestProductionCombinedE2EAttackLabWorker(t *testing.T) {
	controllerDSN := os.Getenv("ZASP_COMBINED_E2E_ATTACK_LAB_CONTROLLER_DSN")
	outboxDSN := os.Getenv("ZASP_COMBINED_E2E_ATTACK_LAB_OUTBOX_DSN")
	runID := os.Getenv("ZASP_COMBINED_E2E_ATTACK_LAB_RUN_ID")
	expectCancelled := os.Getenv("ZASP_COMBINED_E2E_ATTACK_LAB_EXPECT_CANCELLED")
	if controllerDSN == "" && outboxDSN == "" && runID == "" {
		t.Skip("combined E2E helper")
	}
	if expectCancelled != "" && expectCancelled != "true" {
		t.Fatal("combined E2E Attack Lab cancellation expectation is invalid")
	}
	if controllerDSN == "" || outboxDSN == "" {
		t.Fatal("combined E2E Attack Lab authority is incomplete")
	}
	if _, err := domain.ParseProductID(runID); err != nil {
		t.Fatal("combined E2E Attack Lab run is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	controllerDatabase := combinedE2ERecoveryDatabase(t, ctx, controllerDSN)
	outboxDatabase := combinedE2ERecoveryDatabase(t, ctx, outboxDSN)
	driver := &combinedE2ERecoveryQueueDriver{}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1 << 20, MaximumBatchBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	outboxConfig := validAttackLabOutboxRuntimeConfig()
	outboxConfig.PostgresDSN = outboxDSN
	outboxConfig.WorkerID = "production-e2e-attack-lab-outbox"
	outboxConfig.LeaseDuration = 30 * time.Second
	outboxConfig.ShutdownTimeout = 3 * time.Second
	outboxConfig.BatchSize = 1
	outbox, err := composeAttackLabOutboxWorkerRuntime(outboxConfig, outboxDatabase, queue, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := outbox.Processor.(*attackLabOutboxProcessor); !ok || outbox.Ready == nil || outbox.Close == nil {
		t.Fatalf("Attack Lab outbox composition=%#v", outbox)
	}
	if err := outbox.Ready(ctx); err != nil {
		t.Fatalf("Attack Lab outbox readiness: %v", err)
	}
	if err := outbox.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("Attack Lab outbox processor: %v", err)
	}
	if err := outbox.Close(); err != nil {
		t.Fatalf("Attack Lab outbox close: %v", err)
	}

	artifactDriver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(artifactDriver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newProductionAttackLabEvidenceWriter(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	provider := &combinedE2EAttackLabProvider{runID: runID}
	controllerConfig, err := loadWorkerRuntimeConfig(mapLookup(validAttackLabControllerRuntimeEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	controllerConfig.PostgresDSN = controllerDSN
	controllerConfig.WorkerID = "production-e2e-attack-lab-controller"
	controllerConfig.LeaseDuration = 30 * time.Second
	controllerConfig.ShutdownTimeout = 3 * time.Second
	controllerConfig.BatchSize = 1
	closed := false
	dependencies, err := composeAttackLabWorkerRuntime(controllerConfig, controllerDatabase, &productionAttackLabDependencies{
		Queue: queue, Provider: provider, Evidence: evidence,
		ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !closed {
			_ = dependencies.Close()
		}
	})
	if _, ok := dependencies.Processor.(readinessGatedWorkerProcessor); !ok || dependencies.Ready == nil || dependencies.Close == nil {
		t.Fatalf("Attack Lab controller composition=%#v", dependencies)
	}
	if err := dependencies.Ready(ctx); err != nil {
		t.Fatalf("Attack Lab controller readiness: %v", err)
	}
	if err := dependencies.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("Attack Lab controller processor: %v", err)
	}
	if expectCancelled == "true" {
		if !driver.acknowledged || provider.created || provider.collected || provider.destroyed || len(artifactDriver.order) != 0 {
			t.Fatalf("cancelled Attack Lab result ack=%t provider=%t/%t/%t artifacts=%v", driver.acknowledged, provider.created, provider.collected, provider.destroyed, artifactDriver.order)
		}
	} else if !driver.acknowledged || !provider.created || !provider.collected || !provider.destroyed || len(artifactDriver.order) != 1 || artifactDriver.order[0] != "application/json" {
		t.Fatalf("Attack Lab result ack=%t provider=%t/%t/%t artifacts=%v", driver.acknowledged, provider.created, provider.collected, provider.destroyed, artifactDriver.order)
	}
	if err := dependencies.Close(); err != nil || !closed {
		t.Fatalf("Attack Lab controller close=%v closed=%t", err, closed)
	}
	if expectCancelled == "true" {
		t.Log("composed Attack Lab outbox and controller acknowledged cancelled run without sandbox side effects")
	} else {
		t.Log("composed Attack Lab outbox and controller completed deterministic isolated sandbox evidence")
	}
}

type combinedE2EAttackLabProvider struct {
	runID                         string
	created, collected, destroyed bool
}

func (*combinedE2EAttackLabProvider) Ready(context.Context) error { return nil }

func (provider *combinedE2EAttackLabProvider) Create(_ context.Context, request attackLabSandboxRequest) (attackLabSandbox, error) {
	if request.Run.ID != provider.runID || request.Run.Status != "leased" || request.Run.Environment == "production" || request.Preflight.Destination != request.Run.Destination || request.Preflight.SuccessCriterion == "" {
		return attackLabSandbox{}, errors.New("Attack Lab local provider authority drift")
	}
	name, ok := attackLabJobName(request.Scope, request.Run.ID)
	if !ok {
		return attackLabSandbox{}, errors.New("Attack Lab local sandbox identity rejected")
	}
	provider.created = true
	return attackLabSandbox{Reference: "k8s://attack-lab/jobs/" + name + "@123e4567-e89b-12d3-a456-426614174000"}, nil
}

func (*combinedE2EAttackLabProvider) Reconcile(context.Context, attackLabSandboxRequest) (attackLabSandbox, bool, error) {
	return attackLabSandbox{}, false, errors.New("Attack Lab local reconcile was not expected")
}

func (provider *combinedE2EAttackLabProvider) Collect(_ context.Context, request attackLabSandboxRequest, sandbox attackLabSandbox) (attackLabSandboxResult, error) {
	if !provider.created || request.Run.ID != provider.runID || request.Run.Status != "running" || !attackLabWorkerSandboxReferencePattern.MatchString(sandbox.Reference) {
		return attackLabSandboxResult{}, errors.New("Attack Lab local collection authority drift")
	}
	provider.collected = true
	return attackLabSandboxResult{Verdict: "verified", CriterionObserved: true, CanaryTouched: true, Evidence: []string{
		"semantic:success criterion observed", "gateway:exact destination allowed", "egress:no undeclared egress", "kubernetes:isolated job completed", "cloud:bounded canary touched",
	}}, nil
}

func (provider *combinedE2EAttackLabProvider) Destroy(_ context.Context, sandbox attackLabSandbox) error {
	if !provider.collected || !attackLabWorkerSandboxReferencePattern.MatchString(sandbox.Reference) {
		return errors.New("Attack Lab local cleanup authority drift")
	}
	provider.destroyed = true
	return nil
}

func TestProductionCombinedE2ERecoveryWorker(t *testing.T) {
	phase := os.Getenv("ZASP_COMBINED_E2E_RECOVERY_PHASE")
	if phase == "" {
		t.Skip("combined E2E helper")
	}
	if phase != "backup" && phase != "restore" {
		t.Fatal("combined E2E recovery phase is invalid")
	}
	workerDSN, outboxDSN := os.Getenv("ZASP_COMBINED_E2E_RECOVERY_WORKER_DSN"), os.Getenv("ZASP_COMBINED_E2E_RECOVERY_OUTBOX_DSN")
	artifactFile := os.Getenv("ZASP_COMBINED_E2E_RECOVERY_ARTIFACT_FILE")
	if workerDSN == "" || outboxDSN == "" || artifactFile == "" || filepath.Clean(artifactFile) != artifactFile {
		t.Fatal("combined E2E recovery authority is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	workerDatabase := &combinedE2ERecoveryDatabaseTrace{database: combinedE2ERecoveryDatabase(t, ctx, workerDSN)}
	outboxDatabase := combinedE2ERecoveryDatabase(t, ctx, outboxDSN)
	authority, err := newPostgresRecoveryOperationAuthority(workerDatabase)
	if err != nil {
		diagnostic, diagnosticErr := workerDatabase.QueryJSON(ctx, `SELECT jsonb_build_object('principal',zasp_recovery_principal_ready('zasp_recovery_worker'),'release',zasp_recovery_execution_readiness($1,$2))`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint())
		t.Fatalf("operation authority: %v diagnostic=%s diagnostic_error=%v", err, diagnostic, diagnosticErr)
	}
	outboxAuthority, err := newPostgresRecoveryOutboxAuthority(outboxDatabase)
	if err != nil {
		t.Fatal(err)
	}
	driver := &combinedE2ERecoveryQueueDriver{}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1 << 20, MaximumBatchBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	topic := recoveryBackupOutboxTopic
	if phase == "restore" {
		topic = recoveryRestoreOutboxTopic
	}
	outboxConfig := validRecoveryOutboxRuntimeConfig()
	outboxConfig.WorkerID = "production-e2e-recovery-outbox"
	outboxConfig.LeaseDuration = 10 * time.Second
	outboxConfig.ShutdownTimeout = 3 * time.Second
	outboxConfig.BatchSize = 1
	outboxConfig.RecoveryOutboxTopic = topic
	if phase == "restore" {
		outboxConfig.RecoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-restore-jobs"
	}
	outbox, err := composeRecoveryOutboxWorkerRuntime(outboxConfig, outboxAuthority, queue, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := outbox.Processor.(readinessGatedWorkerProcessor); !ok || outbox.Ready == nil || outbox.Close == nil || outboxConfig.Mode != workerModeRecoveryOutbox {
		t.Fatalf("recovery outbox composition=%#v mode=%q", outbox, outboxConfig.Mode)
	}
	if err := outbox.Ready(ctx); err != nil {
		t.Fatalf("recovery outbox readiness: %v", err)
	}
	if err := outbox.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("publish recovery outbox: %v", err)
	}
	if err := outbox.Close(); err != nil {
		t.Fatalf("close recovery outbox: %v", err)
	}

	artifactDriver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	if phase == "restore" {
		combinedE2ELoadRecoveryArtifacts(t, artifactFile, artifactDriver)
	}
	artifacts, err := artifactstore.New(artifactDriver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	operationConfig := validRecoveryRuntimeConfig()
	operationConfig.WorkerID = "production-e2e-recovery-" + phase
	operationConfig.LeaseDuration = 10 * time.Second
	operationConfig.ShutdownTimeout = 3 * time.Second
	operationConfig.BatchSize = 1
	if phase == "backup" {
		publisher, publisherErr := newRecoveryArtifactPublisher(recoveryArtifactPublisherConfig{Store: artifacts, Signer: combinedE2ERecoverySigner{}, NeonProjectID: "silent-river-123456", NeonBranchID: "br-falling-sun-123456", PostgresLSN: authority.PostgresLSN, Now: combinedE2EClock})
		if publisherErr != nil {
			t.Fatal(publisherErr)
		}
		closed := false
		dependencies, dependencyErr := composeRecoveryWorkerRuntime(operationConfig, authority, &productionRecoveryDependencies{Queue: queue, Publisher: publisher, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
		if dependencyErr != nil {
			t.Fatal(dependencyErr)
		}
		t.Cleanup(func() {
			if !closed {
				_ = dependencies.Close()
			}
		})
		if _, ok := dependencies.Processor.(readinessGatedWorkerProcessor); !ok || dependencies.Ready == nil || dependencies.Close == nil || operationConfig.Mode != workerModeRecovery || operationConfig.RecoveryOperationKind != "backup" {
			t.Fatalf("recovery backup composition=%#v mode=%q kind=%q", dependencies, operationConfig.Mode, operationConfig.RecoveryOperationKind)
		}
		if readyErr := dependencies.Ready(ctx); readyErr != nil {
			t.Fatalf("backup readiness: %v", readyErr)
		}
		if processorErr := dependencies.Processor.RunOnce(ctx); processorErr != nil {
			t.Fatalf("backup processor: %v acknowledged=%t artifacts=%v database=%v metrics=%q", processorErr, driver.acknowledged, artifactDriver.order, workerDatabase.snapshot(), dependencies.Metrics())
		}
		if !driver.acknowledged || len(artifactDriver.order) != 4 || !strings.Contains(artifactDriver.order[3], "recovery-manifest") {
			t.Fatalf("backup queue/artifact order ack=%v order=%v", driver.acknowledged, artifactDriver.order)
		}
		if closeErr := dependencies.Close(); closeErr != nil || !closed {
			t.Fatalf("backup close=%v closed=%t", closeErr, closed)
		}
		combinedE2ESaveRecoveryArtifacts(t, artifactFile, artifactDriver)
		t.Log("signed recovery manifest published last")
		return
	}

	loader, err := newRecoveryArtifactManifestLoader(recoveryManifestLoaderConfig{Store: artifacts, Verifier: combinedE2ERecoveryVerifier{}, Now: combinedE2EClock})
	if err != nil {
		t.Fatal(err)
	}
	loaderTrace := &combinedE2ERecoveryManifestLoaderTrace{delegate: loader}
	neon := newCombinedE2ERecoveryNeonTLS(t)
	kubernetes := &combinedE2ERecoveryKubernetes{uid: "18111111-2222-4333-8444-555555555555", database: workerDatabase, targetRoot: t.TempDir()}
	infrastructure, err := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: "silent-river-123456", ParentBranchID: "br-falling-sun-123456"})
	if err != nil || infrastructure.Ready(ctx) != nil {
		t.Fatalf("local recovery infrastructure: %v", err)
	}
	operationConfig.PostgresDSN = "postgres://recovery@ep-main.us-west-2.aws.neon.tech/zasp?sslmode=verify-full"
	operationConfig.RecoveryOperationKind = "restore"
	operationConfig.RecoveryQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-recovery-restore-jobs"
	operationConfig.RecoveryNeonSecretReference = "ref:neon/project-api-key"
	operationConfig.RecoveryKubernetesURL = "https://kubernetes.default.svc"
	operationConfig.RecoveryKubernetesToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	operationConfig.RecoveryKubernetesCA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	operationConfig.RecoveryRunnerImage = "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64)
	operationConfig.RecoveryRunnerServiceAccount = "agentsec-recovery-runner"
	operationConfig.RecoveryNeonEgressCIDRs = []string{"10.24.8.0/24"}
	closed := false
	dependencies, err := composeRecoveryWorkerRuntime(operationConfig, authority, &productionRecoveryDependencies{Queue: queue, Loader: loaderTrace, Infrastructure: infrastructure, ready: func(context.Context) error { return nil }, close: func() error { closed = true; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !closed {
			_ = dependencies.Close()
		}
	})
	if _, ok := dependencies.Processor.(readinessGatedWorkerProcessor); !ok || dependencies.Ready == nil || dependencies.Close == nil || operationConfig.Mode != workerModeRecovery || operationConfig.RecoveryOperationKind != "restore" {
		t.Fatalf("recovery restore composition=%#v mode=%q kind=%q", dependencies, operationConfig.Mode, operationConfig.RecoveryOperationKind)
	}
	if readyErr := dependencies.Ready(ctx); readyErr != nil {
		t.Fatalf("restore readiness: %v", readyErr)
	}
	if err := dependencies.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("restore processor: %v loader=%v acknowledged=%t artifacts=%v reads=%v database=%v metrics=%q neon=%t/%t kubernetes=%v", err, loaderTrace.failure(), driver.acknowledged, artifactDriver.order, artifactDriver.readSnapshot(), workerDatabase.snapshot(), dependencies.Metrics(), neon.created, neon.deleted, kubernetes.calls)
	}
	if !driver.acknowledged || !neon.created || !neon.deleted || strings.Join(kubernetes.calls, ",") != "provision,validate,rebuild,cleanup-namespace,record-cleanup" {
		t.Fatalf("restore ack=%v neon=%v/%v kubernetes=%v", driver.acknowledged, neon.created, neon.deleted, kubernetes.calls)
	}
	if closeErr := dependencies.Close(); closeErr != nil || !closed {
		t.Fatalf("restore close=%v closed=%t", closeErr, closed)
	}
	t.Log("local TLS Neon fixture, exact projection counts, and temporary resource cleanup completed")
}

func combinedE2ERecoveryDatabase(t *testing.T, ctx context.Context, dsn string) apiserver.JSONDatabase {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns, poolConfig.MinConns = 3, 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

type combinedE2ERecoveryDatabaseTrace struct {
	database recoveryJSONDatabase
	mu       sync.Mutex
	steps    []string
}

type combinedE2ERecoveryManifestLoaderTrace struct {
	delegate recoveryManifestLoader
	mu       sync.Mutex
	err      error
}

func (trace *combinedE2ERecoveryManifestLoaderTrace) Load(ctx context.Context, claim recoveryOperationClaim) (recoveryLoadedManifest, error) {
	loaded, err := trace.delegate.Load(ctx, claim)
	trace.mu.Lock()
	trace.err = err
	trace.mu.Unlock()
	return loaded, err
}

func (trace *combinedE2ERecoveryManifestLoaderTrace) failure() error {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.err
}

func (trace *combinedE2ERecoveryDatabaseTrace) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	payload, err := trace.database.QueryJSON(ctx, statement, arguments...)
	label := map[string]string{
		recoveryWorkerReadySQL: "ready", recoveryClaimDeliverySQL: "claim_delivery", recoveryHeartbeatOperationSQL: "heartbeat",
		recoveryBeginHoldSQL: "begin_hold", recoveryReleaseHoldSQL: "release_hold", recoveryCapturePageSQL: "capture_page",
		recoveryFinishBackupSQL: "finish_backup", recoveryFailOperationSQL: "fail", recoveryCurrentLSNSQL: "lsn",
	}[statement]
	if label == "" {
		label = "other"
	}
	if err != nil {
		label += ":error"
	}
	trace.mu.Lock()
	trace.steps = append(trace.steps, label)
	trace.mu.Unlock()
	return payload, err
}

func (trace *combinedE2ERecoveryDatabaseTrace) snapshot() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]string(nil), trace.steps...)
}

type combinedE2ERecoverySigner struct{}

func (combinedE2ERecoverySigner) Sign(_ context.Context, payload []byte) (string, []byte, error) {
	digest := sha256.Sum256(payload)
	return "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", digest[:], nil
}

type combinedE2ERecoveryVerifier struct{}

func (combinedE2ERecoveryVerifier) Verify(_ context.Context, key string, payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	if key != "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111" || !bytes.Equal(digest[:], signature) {
		return errors.New("recovery signature mismatch")
	}
	return nil
}

type combinedE2ERecoveryQueueDriver struct {
	mu           sync.Mutex
	messages     []jobqueue.DriverMessage
	delivered    bool
	acknowledged bool
}

func (driver *combinedE2ERecoveryQueueDriver) PublishBatch(_ context.Context, messages []jobqueue.DriverMessage) ([]jobqueue.DriverPublished, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.messages = append([]jobqueue.DriverMessage(nil), messages...)
	result := make([]jobqueue.DriverPublished, len(messages))
	for index, message := range messages {
		result[index] = jobqueue.DriverPublished{EntryID: message.EntryID, JobID: message.JobID, MessageID: fmt.Sprintf("recovery-e2e-%d", index+1)}
	}
	return result, nil
}

func (driver *combinedE2ERecoveryQueueDriver) ConsumeBatch(_ context.Context, limit int) ([]jobqueue.DriverDelivery, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.delivered || len(driver.messages) == 0 || limit < len(driver.messages) {
		return []jobqueue.DriverDelivery{}, nil
	}
	driver.delivered = true
	result := make([]jobqueue.DriverDelivery, len(driver.messages))
	for index, message := range driver.messages {
		result[index] = jobqueue.DriverDelivery{Message: message, MessageID: fmt.Sprintf("recovery-e2e-%d", index+1), ReceiptHandle: fmt.Sprintf("recovery-receipt-%d", index+1), ReceiveCount: 1}
	}
	return result, nil
}

func (driver *combinedE2ERecoveryQueueDriver) AcknowledgeBatch(_ context.Context, receipts []jobqueue.DriverReceipt) ([]domain.ProductID, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(receipts) != len(driver.messages) {
		return nil, errors.New("recovery acknowledgement mismatch")
	}
	result := make([]domain.ProductID, len(receipts))
	for index := range receipts {
		result[index] = receipts[index].JobID
	}
	driver.acknowledged = true
	return result, nil
}

func (_ *combinedE2ERecoveryQueueDriver) ExtendVisibility(_ context.Context, receipts []jobqueue.DriverReceipt, _ int32) ([]domain.ProductID, error) {
	result := make([]domain.ProductID, len(receipts))
	for index := range receipts {
		result[index] = receipts[index].JobID
	}
	return result, nil
}

type combinedE2ERecoveryArtifactWire struct {
	Order   []string                                `json:"order"`
	Objects []combinedE2ERecoveryArtifactObjectWire `json:"objects"`
}

type combinedE2ERecoveryArtifactObjectWire struct {
	Key, OrganizationID, WorkspaceID, EnvironmentID, Reference, VersionID, MediaType string
	Body                                                                             []byte
}

func combinedE2ESaveRecoveryArtifacts(t *testing.T, filename string, driver *combinedE2EArtifactDriver) {
	t.Helper()
	driver.mu.Lock()
	defer driver.mu.Unlock()
	wire := combinedE2ERecoveryArtifactWire{Order: append([]string(nil), driver.order...), Objects: make([]combinedE2ERecoveryArtifactObjectWire, 0, len(driver.objects))}
	for _, object := range driver.objects {
		wire.Objects = append(wire.Objects, combinedE2ERecoveryArtifactObjectWire{Key: object.Key, OrganizationID: object.OrganizationID().String(), WorkspaceID: object.WorkspaceID().String(), EnvironmentID: object.EnvironmentID().String(), Reference: object.Reference.String(), VersionID: object.VersionID, MediaType: object.MediaType, Body: bytes.Clone(object.Body)})
	}
	encoded, err := json.Marshal(wire)
	if err != nil || os.WriteFile(filename, encoded, 0o600) != nil {
		t.Fatal("persist recovery artifacts")
	}
}

func combinedE2ELoadRecoveryArtifacts(t *testing.T, filename string, driver *combinedE2EArtifactDriver) {
	t.Helper()
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var wire combinedE2ERecoveryArtifactWire
	if decodeStrictWorkerJSON(body, &wire) != nil || len(wire.Objects) != 4 || len(wire.Order) != 4 {
		t.Fatal("invalid persisted recovery artifacts")
	}
	driver.order = append([]string(nil), wire.Order...)
	for _, item := range wire.Objects {
		organization, organizationErr := domain.ParseProductID(item.OrganizationID)
		workspace, workspaceErr := domain.ParseProductID(item.WorkspaceID)
		environment, environmentErr := domain.ParseProductID(item.EnvironmentID)
		referenceID, referenceErr := domain.ParseProductID(item.Reference)
		scope, scopeErr := domain.NewScope(organization, workspace, environment)
		reference, evidenceErr := domain.NewEvidenceRef(referenceID)
		if organizationErr != nil || workspaceErr != nil || environmentErr != nil || referenceErr != nil || scopeErr != nil || evidenceErr != nil {
			t.Fatal("invalid persisted recovery artifact authority")
		}
		object := combinedE2ECloneDriverObject(artifactstore.DriverObject{DriverLocator: artifactstore.DriverLocator{Key: item.Key, Scope: scope, Reference: reference, VersionID: item.VersionID}, MediaType: item.MediaType, Body: bytes.Clone(item.Body)})
		driver.objects[item.Key+"\x1f"+item.VersionID] = object
	}
}

type combinedE2ERecoveryNeonTLS struct {
	server  *httptest.Server
	created bool
	deleted bool
}

func newCombinedE2ERecoveryNeonTLS(t *testing.T) *combinedE2ERecoveryNeonTLS {
	t.Helper()
	fixture := &combinedE2ERecoveryNeonTLS{}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/br-falling-sun-123456"):
			response.WriteHeader(http.StatusOK)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/branches"):
			body, _ := io.ReadAll(io.LimitReader(request.Body, 8193))
			if len(body) == 0 || len(body) > 8192 {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			fixture.created = true
			response.WriteHeader(http.StatusCreated)
		case request.Method == http.MethodDelete && strings.HasSuffix(request.URL.Path, "/br-recovery-e2e"):
			fixture.deleted = true
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *combinedE2ERecoveryNeonTLS) request(ctx context.Context, method, path string, body io.Reader) (int, error) {
	request, err := http.NewRequestWithContext(ctx, method, fixture.server.URL+path, body)
	if err != nil {
		return 0, err
	}
	response, err := fixture.server.Client().Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
	return response.StatusCode, nil
}

func (fixture *combinedE2ERecoveryNeonTLS) Ready(ctx context.Context) error {
	status, err := fixture.request(ctx, http.MethodGet, "/api/v2/projects/silent-river-123456/branches/br-falling-sun-123456", nil)
	if err != nil || status != http.StatusOK {
		return errors.New("local Neon readiness failed")
	}
	return nil
}

func (fixture *combinedE2ERecoveryNeonTLS) CreateBranch(ctx context.Context, request neondriver.CreateBranchRequest) (neondriver.Branch, error) {
	body, _ := json.Marshal(request)
	status, err := fixture.request(ctx, http.MethodPost, "/api/v2/projects/silent-river-123456/branches", bytes.NewReader(body))
	if err != nil || status != http.StatusCreated {
		return neondriver.Branch{}, errors.New("local Neon create failed")
	}
	return neondriver.Branch{ID: "br-recovery-e2e", ProjectID: "silent-river-123456", ParentID: "br-falling-sun-123456", ParentLSN: request.ParentLSN, Name: request.Name, Endpoints: []neondriver.Endpoint{{ID: "ep-recovery-e2e", BranchID: "br-recovery-e2e", Type: "read_write", Host: "ep-recovery.internal"}}}, nil
}

func (*combinedE2ERecoveryNeonTLS) GetBranchByName(context.Context, string, string) (neondriver.Branch, error) {
	return neondriver.Branch{}, neondriver.ErrNotFound
}

func (fixture *combinedE2ERecoveryNeonTLS) DeleteBranch(ctx context.Context, project, branch string) error {
	if project != "silent-river-123456" || branch != "br-recovery-e2e" {
		return errors.New("local Neon delete authority drift")
	}
	status, err := fixture.request(ctx, http.MethodDelete, "/api/v2/projects/"+project+"/branches/"+branch, nil)
	if err != nil || status != http.StatusNoContent {
		return errors.New("local Neon delete failed")
	}
	return nil
}

type combinedE2ERecoveryKubernetes struct {
	plan       recoveryKubernetesPlan
	uid        string
	calls      []string
	database   recoveryJSONDatabase
	targetRoot string
}

type combinedE2ERecoveryDatabaseFunc func(context.Context, string, ...any) (json.RawMessage, error)

func (function combinedE2ERecoveryDatabaseFunc) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	return function(ctx, statement, arguments...)
}

type combinedE2ERecoveryJobDatabase struct{ database recoveryJSONDatabase }

func (database combinedE2ERecoveryJobDatabase) ValidateScope(ctx context.Context, organization, workspace, environment string) (json.RawMessage, error) {
	if database.database == nil {
		return nil, errWorkerExecution
	}
	return database.database.QueryJSON(ctx, recoveryValidateScopeSQL, organization, workspace, environment)
}

func (database combinedE2ERecoveryJobDatabase) ProjectionPage(ctx context.Context, organization, workspace, environment, snapshotID, section, afterID string, limit int) (apiserver.SnapshotProjectionPage, error) {
	if database.database == nil {
		return apiserver.SnapshotProjectionPage{}, errWorkerExecution
	}
	payload, err := database.database.QueryJSON(ctx, recoveryProjectionPageSQL, organization, workspace, environment, snapshotID, section, nullableRecoveryCursor(afterID), limit)
	if err != nil {
		return apiserver.SnapshotProjectionPage{}, errWorkerExecution
	}
	return decodeRecoveryProjectionPage(payload)
}

func TestCombinedE2ERecoveryKubernetesDerivesValidationFromRestoredDatabase(t *testing.T) {
	projection := json.RawMessage(`[]`)
	digest := sha256.Sum256(projection)
	fixture := &combinedE2ERecoveryKubernetes{
		uid:        "18111111-2222-4333-8444-555555555555",
		targetRoot: t.TempDir(),
		database: combinedE2ERecoveryDatabaseFunc(func(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
			if statement != recoveryValidateScopeSQL {
				return nil, errors.New("unexpected recovery statement")
			}
			return json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":[]}`), nil
		}),
	}
	plan := recoveryKubernetesPlan{
		Scope:                recoveryWorkerScope(t),
		RestoreID:            "pid_71000004-0000-4000-8000-000000000004",
		TargetEnvironment:    "recovery-test",
		ExpectedCounts:       apiserver.RecoveryCounts{Assets: 999, Findings: 999, Policies: 999},
		ProjectionDigest:     digest,
		EvidenceSampleDigest: sha256.Sum256([]byte("[]")),
	}
	fixture.plan = plan
	observed, _, err := fixture.Validate(context.Background(), plan, fixture.uid)
	if err != nil || observed != (apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}) {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	rebuilt, err := fixture.Rebuild(context.Background(), plan, fixture.uid)
	if err != nil || rebuilt != digest {
		t.Fatalf("rebuilt=%x err=%v", rebuilt, err)
	}
}

func (*combinedE2ERecoveryKubernetes) Ready(context.Context) error { return nil }
func (fixture *combinedE2ERecoveryKubernetes) Provision(_ context.Context, plan recoveryKubernetesPlan) (string, error) {
	fixture.calls = append(fixture.calls, "provision")
	fixture.plan = plan
	if len(plan.Jobs) != 3 || plan.NetworkPolicy.Name != "recovery-deny-by-default" {
		return "", errors.New("isolated recovery plan rejected")
	}
	return fixture.uid, nil
}
func (fixture *combinedE2ERecoveryKubernetes) Validate(ctx context.Context, plan recoveryKubernetesPlan, uid string) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error) {
	fixture.calls = append(fixture.calls, "validate")
	if plan.RestoreID != fixture.plan.RestoreID || uid != fixture.uid || fixture.database == nil {
		return apiserver.RecoveryCounts{}, apiserver.RecoveryArtifactLocator{}, errors.New("recovery validation authority drift")
	}
	config := combinedE2ERecoveryJobConfig(plan, recoveryJobModePostgresValidation, "")
	var output bytes.Buffer
	if err := runRecoveryJob(ctx, config, combinedE2ERecoveryJobDatabase{database: fixture.database}, &output); err != nil {
		return apiserver.RecoveryCounts{}, apiserver.RecoveryArtifactLocator{}, err
	}
	var result struct {
		SchemaVersion        string                   `json:"schema_version"`
		Counts               apiserver.RecoveryCounts `json:"counts"`
		EvidenceSampleSHA256 string                   `json:"evidence_sample_sha256"`
	}
	if decodeStrictWorkerJSON(output.Bytes(), &result) != nil || result.SchemaVersion != "recovery_validation_job_v1" || result.EvidenceSampleSHA256 != config.EvidenceSampleSHA256 {
		return apiserver.RecoveryCounts{}, apiserver.RecoveryArtifactLocator{}, errors.New("recovery validation output rejected")
	}
	return result.Counts, recoveryEvidenceLocator(plan.Scope, "pid_71000008-0000-4000-8000-000000000008", "recovery_validation_v1"), nil
}
func (fixture *combinedE2ERecoveryKubernetes) Rebuild(ctx context.Context, plan recoveryKubernetesPlan, uid string) ([sha256.Size]byte, error) {
	fixture.calls = append(fixture.calls, "rebuild")
	if plan.RestoreID != fixture.plan.RestoreID || uid != fixture.uid || fixture.database == nil || fixture.targetRoot == "" {
		return [sha256.Size]byte{}, errors.New("recovery rebuild authority drift")
	}
	var rebuilt [sha256.Size]byte
	for _, mode := range []recoveryJobMode{recoveryJobModeGraphProjection, recoveryJobModeSearchProjection} {
		target := filepath.Join(fixture.targetRoot, string(mode))
		if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return [sha256.Size]byte{}, err
		}
		config := combinedE2ERecoveryJobConfig(plan, mode, target)
		var output bytes.Buffer
		if err := runRecoveryJob(ctx, config, combinedE2ERecoveryJobDatabase{database: fixture.database}, &output); err != nil {
			return [sha256.Size]byte{}, err
		}
		var result struct {
			SchemaVersion        string `json:"schema_version"`
			Kind                 string `json:"kind"`
			ProjectionSHA256     string `json:"projection_sha256"`
			EvidenceSampleSHA256 string `json:"evidence_sample_sha256"`
		}
		if decodeStrictWorkerJSON(output.Bytes(), &result) != nil || result.SchemaVersion != "recovery_projection_job_v1" || result.Kind != strings.TrimSuffix(strings.TrimPrefix(string(mode), "recovery-"), "-projection") || result.EvidenceSampleSHA256 != config.EvidenceSampleSHA256 {
			return [sha256.Size]byte{}, errors.New("recovery rebuild output rejected")
		}
		decoded, err := hex.DecodeString(result.ProjectionSHA256)
		if err != nil || len(decoded) != sha256.Size || rebuilt != ([sha256.Size]byte{}) && !bytes.Equal(rebuilt[:], decoded) {
			return [sha256.Size]byte{}, errors.New("recovery rebuild digest rejected")
		}
		copy(rebuilt[:], decoded)
	}
	return rebuilt, nil
}

func combinedE2ERecoveryJobConfig(plan recoveryKubernetesPlan, mode recoveryJobMode, targetDirectory string) recoveryJobConfig {
	return recoveryJobConfig{
		Mode: mode, PostgresDSN: "postgres://recovery@ep-recovery.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", BranchIP: "10.24.8.7",
		OrganizationID: plan.Scope.OrganizationID().String(), WorkspaceID: plan.Scope.WorkspaceID().String(), EnvironmentID: plan.Scope.EnvironmentID().String(), TargetEnvironment: plan.TargetEnvironment,
		ProjectionSHA256: hex.EncodeToString(plan.ProjectionDigest[:]), EvidenceSampleSHA256: hex.EncodeToString(plan.EvidenceSampleDigest[:]), TargetDirectory: targetDirectory,
	}
}
func (fixture *combinedE2ERecoveryKubernetes) Cleanup(_ context.Context, plan recoveryKubernetesPlan, uid string) (apiserver.RecoveryCleanupEvidence, error) {
	fixture.calls = append(fixture.calls, "cleanup")
	if plan.RestoreID != fixture.plan.RestoreID || uid != fixture.uid {
		return apiserver.RecoveryCleanupEvidence{}, errors.New("recovery cleanup authority drift")
	}
	return apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(plan.Scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}, nil
}

func (fixture *combinedE2ERecoveryKubernetes) CleanupNamespace(_ context.Context, plan recoveryKubernetesCleanupPlan, uid string) (string, error) {
	fixture.calls = append(fixture.calls, "cleanup-namespace")
	if plan.RestoreID != fixture.plan.RestoreID || uid != fixture.uid {
		return uid, errors.New("recovery cleanup authority drift")
	}
	return uid, nil
}

func (fixture *combinedE2ERecoveryKubernetes) RecordCleanup(_ context.Context, plan recoveryKubernetesCleanupPlan, uid, state string) (apiserver.RecoveryCleanupEvidence, error) {
	fixture.calls = append(fixture.calls, "record-cleanup")
	if plan.RestoreID != fixture.plan.RestoreID || uid != fixture.uid || state != "deleted" {
		return apiserver.RecoveryCleanupEvidence{}, errors.New("recovery cleanup evidence drift")
	}
	return apiserver.RecoveryCleanupEvidence{State: state, Evidence: recoveryEvidenceLocator(plan.Scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}, nil
}

func TestProductionCombinedE2EDiscoveryWorker(t *testing.T) {
	workerDSN := os.Getenv("ZASP_COMBINED_E2E_WORKER_DSN")
	if workerDSN == "" {
		t.Skip("combined E2E helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := combinedE2EScope(t)
	jobID := combinedE2EProductID(t, os.Getenv("ZASP_COMBINED_E2E_JOB_ID"))
	parserVersion, toolVersion := os.Getenv("ZASP_COMBINED_E2E_PARSER_VERSION"), os.Getenv("ZASP_COMBINED_E2E_TOOL_VERSION")
	scenario := os.Getenv("ZASP_COMBINED_E2E_SCENARIO")
	if parserVersion == "" || toolVersion == "" || scenario == "" {
		t.Fatal("combined E2E authority is incomplete")
	}

	poolConfig, err := pgxpool.ParseConfig(workerDSN)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns, poolConfig.MinConns = 3, 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	postgresTrace := &combinedE2EPostgresTrace{}
	database, err := apiserver.NewPostgresJSONDatabase(&combinedE2EPostgresDriver{delegate: &workerPostgresDriver{pool: pool}, trace: postgresTrace})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	tracedDatabase := &combinedE2ETracingDatabase{delegate: database}

	factory, err := newCombinedE2ECollectorFactory(scenario, parserVersion, toolVersion)
	if err != nil {
		t.Fatal(err)
	}
	queue := &combinedE2EDiscoveryQueue{delivery: jobqueue.Delivery{Job: jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: []byte(`{}`)}}}
	config := workerRuntimeConfig{
		Mode: workerModeDiscovery, PostgresDSN: workerDSN, DatabaseAuthority: "zasp_discovery_worker", WorkerID: "production-e2e-local-discovery",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 10 * time.Second, BatchSize: 1, ShutdownTimeout: 5 * time.Second,
		DiscoveryQueueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-discovery-jobs", AWSRegion: "us-east-1",
		EvidenceBucket: "zasp-production-e2e-evidence", EvidenceOwner: "123456789012", EvidenceKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		ParserVersion: parserVersion, ToolVersion: toolVersion, DiscoveryRoleARN: "arn:aws:iam::123456789012:role/zasp-production-e2e-discovery", DiscoveryTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", DiscoverySecretPrefix: "zasp-production-e2e/connectors",
		AWSCollectorVersion: "collector_v1", KubernetesCollectorVersion: "collector_v1", GitHubCollectorVersion: "collector_v1", OktaCollectorVersion: "collector_v1", KubernetesEgressCIDRs: []string{"203.0.113.0/24"},
		GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret", ProviderTimeout: time.Second, DiscoveryReadinessTimeout: time.Second,
	}
	dependencies, err := composeDiscoveryWorkerRuntime(config, tracedDatabase, &productionDiscoveryDependencies{Factory: factory, Queue: queue, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dependencies.Processor.RunOnce(ctx); err != nil {
		t.Fatalf("%v; database trace=%s; postgres trace=%s", err, tracedDatabase.Trace(), postgresTrace.String())
	}
	wantAcknowledged := scenario != "partial"
	if queue.acknowledged != wantAcknowledged {
		t.Fatalf("scenario %q acknowledged=%v want %v; database trace=%s; postgres trace=%s", scenario, queue.acknowledged, wantAcknowledged, tracedDatabase.Trace(), postgresTrace.String())
	}
	t.Log("deterministic local provider and artifact authority completed public sync")
}

func TestProductionCombinedE2ETemporaryPolicyActionWorker(t *testing.T) {
	actionDSN := os.Getenv("ZASP_COMBINED_E2E_ACTION_DSN")
	if actionDSN == "" {
		t.Skip("combined E2E helper")
	}
	phase := os.Getenv("ZASP_COMBINED_E2E_ACTION_PHASE")
	if phase != "apply" && phase != "cleanup" && phase != "reconcile" {
		t.Fatal("combined E2E action phase is invalid")
	}
	actionKey := os.Getenv("ZASP_COMBINED_E2E_ACTION_KEY")
	if actionKey == "" {
		actionKey = "create_temporary_policy"
	}
	if actionKey != "create_temporary_policy" && actionKey != "isolate_session" {
		t.Fatal("combined E2E action key is invalid")
	}
	privateKeyBytes, err := base64.RawURLEncoding.DecodeString(os.Getenv("ZASP_COMBINED_E2E_ACTION_PRIVATE_KEY"))
	if err != nil || len(privateKeyBytes) != ed25519.PrivateKeySize {
		t.Fatal("combined E2E action signing authority is invalid")
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	actionPrivateKey := append(ed25519.PrivateKey(nil), privateKey...)
	policyPrivateKey := append(ed25519.PrivateKey(nil), privateKey...)
	defer clear(privateKey)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(actionDSN)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns, poolConfig.MinConns = 3, 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	postgresTrace := &combinedE2EPostgresTrace{}
	database, err := apiserver.NewPostgresJSONDatabase(&combinedE2EPostgresDriver{delegate: &workerPostgresDriver{pool: pool}, trace: postgresTrace})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	tracedDatabase := &combinedE2ETracingDatabase{delegate: database}
	config := workerRuntimeConfig{
		Mode: workerModeSecurityAgentAction, PostgresDSN: actionDSN, DatabaseAuthority: "zasp_security_agent_action_worker", WorkerID: "production-e2e-security-agent-action",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 8, ShutdownTimeout: 20 * time.Second,
		GatewaySigningKeyID: "gateway-key-01", GatewaySigningPrivateFile: "/var/run/secrets/zasp-security-agent-action/gateway-signing-private-key",
	}
	dependencies, err := composeSecurityAgentActionWorkerRuntime(config, tracedDatabase, actionPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dependencies.Close() }()
	if err := dependencies.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if phase == "reconcile" {
		if err := dependencies.Processor.RunOnce(ctx); err != nil {
			t.Fatalf("%v; database trace=%s; postgres trace=%s", err, tracedDatabase.Trace(), postgresTrace.String())
		}
		t.Log("connector revocation reconciled through the production action worker")
		return
	}

	policyDSN := os.Getenv("ZASP_COMBINED_E2E_POLICY_DEPLOYMENT_DSN")
	if policyDSN == "" {
		t.Fatal("combined E2E policy deployment authority is missing")
	}
	policyPoolConfig, err := pgxpool.ParseConfig(policyDSN)
	if err != nil {
		t.Fatal(err)
	}
	policyPoolConfig.MaxConns, policyPoolConfig.MinConns = 3, 1
	policyPool, err := pgxpool.NewWithConfig(ctx, policyPoolConfig)
	if err != nil {
		t.Fatal(err)
	}
	policyDatabase, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: policyPool})
	if err != nil {
		policyPool.Close()
		t.Fatal(err)
	}
	defer func() { _ = policyDatabase.Close() }()
	deployed, err := composePolicyDeploymentWorkerRuntime(workerRuntimeConfig{
		Mode: workerModePolicyDeployment, PostgresDSN: policyDSN, DatabaseAuthority: "zasp_policy_deployment_worker", WorkerID: "production-e2e-policy-deployment",
		PollInterval: 50 * time.Millisecond, LeaseDuration: 60 * time.Second, BatchSize: 8, ShutdownTimeout: 20 * time.Second,
		GatewaySigningKeyID: "gateway-key-01", GatewaySigningPrivateFile: "/var/run/secrets/zasp-policy-deployment/gateway-signing-private-key",
	}, policyDatabase, policyPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := deployed.Ready(ctx); err != nil {
		_ = deployed.Close()
		t.Fatal(err)
	}
	deploymentCtx, stopDeployment := context.WithCancel(ctx)
	deploymentDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if err := deployed.Processor.RunOnce(deploymentCtx); err != nil && deploymentCtx.Err() == nil {
				deploymentDone <- err
				return
			}
			select {
			case <-deploymentCtx.Done():
				deploymentDone <- nil
				return
			case <-ticker.C:
			}
		}
	}()
	actionErr := dependencies.Processor.RunOnce(ctx)
	stopDeployment()
	deploymentErr := <-deploymentDone
	closeErr := deployed.Close()
	if actionErr != nil || deploymentErr != nil || closeErr != nil {
		t.Fatalf("action=%v deployment=%v close=%v; database trace=%s; postgres trace=%s", actionErr, deploymentErr, closeErr, tracedDatabase.Trace(), postgresTrace.String())
	}

	gatewayPool, err := pgxpool.New(ctx, os.Getenv("ZASP_COMBINED_E2E_GATEWAY_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayPool.Close()
	afterSequence, expectedPolicies := int64(0), 3
	expectedRunState := "contained"
	if phase == "cleanup" {
		afterSequence, expectedPolicies, expectedRunState = 1, 1, "remediated"
	}
	if rawSequence := os.Getenv("ZASP_COMBINED_E2E_AFTER_SEQUENCE"); rawSequence != "" {
		parsed, parseErr := strconv.ParseInt(rawSequence, 10, 64)
		if parseErr != nil || parsed < 0 {
			t.Fatal("combined E2E action sequence is invalid")
		}
		afterSequence = parsed
	}
	var raw json.RawMessage
	if err := gatewayPool.QueryRow(ctx, `SELECT zasp_runtime_gateway_policy_bundle($1,$2)`, "pid_79000003-0000-4000-8000-000000000003", afterSequence).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var envelope policy.GatewayPolicyEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-01": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, policy.GatewayPolicyBinding{
		OrganizationID: "pid_10000001-0000-4000-8000-000000000001", WorkspaceID: "pid_10000002-0000-4000-8000-000000000002", EnvironmentID: "pid_10000003-0000-4000-8000-000000000003", DeviceID: "pid_79000001-0000-4000-8000-000000000001",
	}, time.Now().UTC().Truncate(time.Second))
	if err != nil || len(verified.Policies) != expectedPolicies {
		t.Fatalf("gateway bundle=%s policies=%d err=%v", raw, len(verified.Policies), err)
	}
	if actionKey == "isolate_session" && phase == "apply" {
		targetSession, otherSession := os.Getenv("ZASP_COMBINED_E2E_ACTION_SESSION_ID"), os.Getenv("ZASP_COMBINED_E2E_ACTION_OTHER_SESSION_ID")
		if targetSession == "" || otherSession == "" || targetSession == otherSession {
			t.Fatal("combined E2E session authority is invalid")
		}
		sessionPolicies := 0
		for _, compiled := range verified.Policies {
			if !strings.HasPrefix(compiled.ID, "session-isolation-") {
				continue
			}
			sessionPolicies++
			input := map[string]string{"session_id": targetSession}
			if compiled.Trigger == "tool_call" {
				input["tool.name"] = "shell"
			} else {
				input["http.method"] = "POST"
			}
			blocked, blockedErr := policy.Evaluate(ctx, compiled, input)
			input["session_id"] = otherSession
			allowed, allowedErr := policy.Evaluate(ctx, compiled, input)
			if blockedErr != nil || !blocked.Matched || blocked.Action != policy.ActionBlock || allowedErr != nil || allowed.Matched {
				t.Fatalf("session policy=%#v blocked=%#v blocked_err=%v allowed=%#v allowed_err=%v", compiled, blocked, blockedErr, allowed, allowedErr)
			}
		}
		if sessionPolicies != 2 {
			t.Fatalf("session policy count=%d bundle=%s", sessionPolicies, raw)
		}
	}
	var runState string
	if err := gatewayPool.QueryRow(ctx, `SELECT run.state FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) WHERE effect.action_key='create_temporary_policy' ORDER BY effect.updated_at DESC LIMIT 1`).Scan(&runState); err == nil {
		t.Fatal("gateway principal read private Security Agent state")
	}
	if envelope.Sequence != uint64(afterSequence+1) {
		t.Fatalf("phase=%s sequence=%d", phase, envelope.Sequence)
	}
	if actionKey == "isolate_session" {
		t.Logf("central policy deployment signed session isolation gateway policy %s and verified exact target plus unrelated allowance through gateway authority; state=%s", phase, expectedRunState)
	} else {
		t.Logf("central policy deployment signed temporary gateway policy %s and verified through gateway authority; state=%s", phase, expectedRunState)
	}
}

func TestProductionCombinedE2EConnectorRevocationWorker(t *testing.T) {
	connectorDSN := os.Getenv("ZASP_COMBINED_E2E_CONNECTOR_DSN")
	if connectorDSN == "" {
		t.Skip("combined E2E helper")
	}
	integrationID := combinedE2EProductID(t, os.Getenv("ZASP_COMBINED_E2E_CONNECTOR_INTEGRATION_ID"))
	expectedReference := os.Getenv("ZASP_COMBINED_E2E_CONNECTOR_REFERENCE")
	if expectedReference == "" {
		t.Fatal("combined E2E connector reference is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(connectorDSN)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns, poolConfig.MinConns = 4, 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	connectorRepository, err := apiserver.NewConnectorRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	reconciliationRepository := &combinedE2EConnectorRepository{ConnectorRepository: connectorRepository, expectedIntegrationID: integrationID.String(), completed: make(chan apiserver.ConnectorEffectTransition, 1)}
	workflows, err := apiserver.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	provider := &combinedE2ERevocationProvider{revoked: make(chan string, 1)}
	registry, err := apiserver.NewConnectorProviderRegistry(map[string]apiserver.ConnectorOAuthProviderDefinition{
		"github": {Provider: provider, RequestedScopes: []string{"actions:read", "contents:read", "metadata:read"}, CredentialClass: "github_installation_reference"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := apiserver.NewConnectorReconciler(apiserver.ConnectorReconcilerConfig{Repository: reconciliationRepository, Workflows: workflows, Registry: registry, Secrets: combinedE2EConnectorSecrets{}, Owner: "production-e2e-connector-worker", LeaseSeconds: 60, Limit: 10, Interval: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(runCtx) }()
	select {
	case reference := <-provider.revoked:
		if reference != expectedReference {
			stop()
			t.Fatalf("provider reference=%q want %q", reference, expectedReference)
		}
	case <-ctx.Done():
		stop()
		t.Fatal("real connector reconciler did not invoke the provider")
	}
	var transition apiserver.ConnectorEffectTransition
	select {
	case transition = <-reconciliationRepository.completed:
	case <-ctx.Done():
		stop()
		t.Fatal("real connector reconciler did not durably complete the revocation")
	}
	stop()
	if runErr := <-done; runErr != nil && !errors.Is(runErr, context.Canceled) {
		t.Fatal(runErr)
	}
	if transition.Status != "reconciled" {
		t.Fatalf("connector effect status=%q", transition.Status)
	}
	t.Logf("real connector reconciler revoked exact reference %s", expectedReference)
}

type combinedE2EConnectorRepository struct {
	*apiserver.ConnectorRepository
	expectedIntegrationID string
	completed             chan apiserver.ConnectorEffectTransition
}

func (repository *combinedE2EConnectorRepository) CompleteConnectorRevocation(ctx context.Context, lease apiserver.ConnectorEffectLease) (apiserver.ConnectorEffectTransition, error) {
	if lease.IntegrationID != repository.expectedIntegrationID {
		return apiserver.ConnectorEffectTransition{}, errors.New("unexpected connector revocation target")
	}
	transition, err := repository.ConnectorRepository.CompleteConnectorRevocation(ctx, lease)
	if err == nil {
		select {
		case repository.completed <- transition:
		default:
		}
	}
	return transition, err
}

type combinedE2ERevocationProvider struct {
	revoked chan string
}

func (*combinedE2ERevocationProvider) AuthorizationURL(string, string) (string, error) {
	return "", errors.New("not used")
}
func (*combinedE2ERevocationProvider) Complete(context.Context, string, string, []byte) (apiserver.ConnectorOAuthGrant, error) {
	return apiserver.ConnectorOAuthGrant{}, errors.New("not used")
}
func (*combinedE2ERevocationProvider) Recover(context.Context, string) (apiserver.ConnectorOAuthGrant, error) {
	return apiserver.ConnectorOAuthGrant{}, errors.New("not used")
}
func (*combinedE2ERevocationProvider) Discard(context.Context, string, bool) error {
	return errors.New("not used")
}
func (provider *combinedE2ERevocationProvider) Revoke(_ context.Context, reference string) error {
	select {
	case provider.revoked <- reference:
	default:
	}
	return nil
}

type combinedE2EConnectorSecrets struct{}

func (combinedE2EConnectorSecrets) Acquire(context.Context, string, apiserver.OAuthSecretMaterial, time.Time) (apiserver.OAuthSecretMaterial, error) {
	return apiserver.OAuthSecretMaterial{}, errors.New("not used")
}
func (combinedE2EConnectorSecrets) Consume(context.Context, string) ([]byte, error) {
	return nil, errors.New("not used")
}
func (combinedE2EConnectorSecrets) Delete(context.Context, string) error {
	return errors.New("not used")
}

func TestProductionCombinedE2EProviderFixturesAreCanonical(t *testing.T) {
	for _, fixture := range []struct {
		provider  collection.Provider
		subject   collection.SubjectBinding
		class     collection.CredentialClass
		reference string
	}{
		{collection.ProviderAWS, collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, collection.CredentialAWSAssumeRole, "ref:aws/assume-role/e2e-account"},
		{collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "prod.example/cluster-a"}, collection.CredentialKubernetesCluster, "ref:kubernetes/cluster/e2e-a"},
		{collection.ProviderGitHub, collection.SubjectBinding{Kind: "github_installation", ID: "424242"}, collection.CredentialGitHubInstallation, "ref:github/installation/424242"},
		{collection.ProviderOkta, collection.SubjectBinding{Kind: "okta_tenant", ID: "e2e.okta.com"}, collection.CredentialOktaRefresh, "ref:okta/refresh/e2e-tenant"},
	} {
		t.Run(string(fixture.provider), func(t *testing.T) {
			entities, relationships, complete, err := combinedE2EPageValues(fixture.provider, "complete")
			if err != nil {
				t.Fatal(err)
			}
			cursor := collection.Cursor{Provider: fixture.provider, Version: "local_e2e_v1", Value: "complete-1"}
			var pageErr error
			switch fixture.provider {
			case collection.ProviderAWS:
				_, pageErr = awsdiscovery.NewCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			case collection.ProviderKubernetes:
				_, pageErr = kubernetesdiscovery.NewCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			case collection.ProviderGitHub:
				_, pageErr = githubdiscovery.NewCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			case collection.ProviderOkta:
				_, pageErr = idpdiscovery.NewOktaCollectionPage(fixture.subject, cursor, complete, entities, relationships)
			}
			if pageErr != nil {
				t.Fatalf("canonical page: %v", pageErr)
			}
			driver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
			artifacts, artifactErr := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
			if artifactErr != nil {
				t.Fatal(artifactErr)
			}
			api := &combinedE2ECollectionAPI{scenario: "complete"}
			var client collection.ProviderClient
			switch fixture.provider {
			case collection.ProviderAWS:
				client, pageErr = awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			case collection.ProviderKubernetes:
				client, pageErr = kubernetesdiscovery.NewCollectionClient(api, artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			case collection.ProviderGitHub:
				client, pageErr = githubdiscovery.NewCollectionClient(api, artifacts, githubdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			case collection.ProviderOkta:
				client, pageErr = idpdiscovery.NewOktaCollectionClient(api, artifacts, idpdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: combinedE2EClock})
			}
			if pageErr != nil {
				t.Fatalf("client: %v", pageErr)
			}
			request := collection.Request{
				Scope: combinedE2EScope(t), IntegrationID: combinedE2EProductID(t, "pid_77000001-0000-4000-8000-000000000001"), ConnectionID: combinedE2EProductID(t, "pid_77000002-0000-4000-8000-000000000002"), JobID: combinedE2EProductID(t, "pid_77000003-0000-4000-8000-000000000003"),
				Attempt: 1, Provider: fixture.provider, CollectorVersion: "collector_v1", CredentialClass: fixture.class, CredentialReference: fixture.reference, ExpectedSubject: fixture.subject,
				ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: combinedE2EClock(), Bounds: collection.Bounds{MaxPages: 1, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second},
			}
			outcome, collectErr := client.(interface {
				CollectWithCredential(context.Context, collection.Request, []byte) (collection.Outcome, error)
			}).CollectWithCredential(context.Background(), request, []byte("local-e2e-credential-material"))
			if collectErr != nil || outcome == nil {
				t.Fatalf("collect: outcome=%T err=%v", outcome, collectErr)
			}
		})
	}
}

func TestProductionCombinedE2EPartialFixtureProducesDurablePartialOutcome(t *testing.T) {
	scope := workerScope(t)
	input := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	input.Provider = collection.ProviderKubernetes
	input.CredentialClass = collection.CredentialKubernetesCluster
	input.CredentialReference = "ref:kubernetes/cluster/e2e-partial"
	input.SubjectKind = "kubernetes_cluster"
	input.SubjectID = "prod.example/cluster-partial"
	input.ExpectedSubject = collection.SubjectBinding{Kind: input.SubjectKind, ID: input.SubjectID}
	input.CursorProvider, input.CursorVersion, input.CursorValue = nil, nil, nil
	input.ParserVersion, input.ToolVersion = "inventory-parser-2026.08.20", "collector-tool-2026.08.20"
	input.Configuration = json.RawMessage(`{"cluster":"prod.example/cluster-partial"}`)
	factory, err := newCombinedE2ECollectorFactory("partial", input.ParserVersion, input.ToolVersion)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := factory.BuildDiscoveryCollector(context.Background(), discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "production-e2e-local-discovery", LeaseToken: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Destroy()
	request, ok := collectionRequest(scope, input)
	if !ok {
		t.Fatal("partial fixture request was invalid")
	}
	outcome, err := collector.Collect(context.Background(), request)
	if err != nil {
		t.Fatalf("partial fixture returned %T: %v", err, err)
	}
	if _, ok := outcome.(collection.PartialResult); !ok {
		t.Fatalf("partial fixture outcome = %T, want collection.PartialResult", outcome)
	}
}

type combinedE2EPostgresTrace struct {
	mu    sync.Mutex
	value string
}

func (trace *combinedE2EPostgresTrace) set(value string) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.value = value
}

func (trace *combinedE2EPostgresTrace) String() string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.value
}

type combinedE2EPostgresDriver struct {
	delegate apiserver.PostgresDriver
	trace    *combinedE2EPostgresTrace
}

func (driver *combinedE2EPostgresDriver) QueryRow(ctx context.Context, query string, arguments ...any) apiserver.PostgresRow {
	return &combinedE2ETracingRow{delegate: driver.delegate.QueryRow(ctx, query, arguments...), stage: combinedE2EDatabaseStage(query), trace: driver.trace}
}

func (driver *combinedE2EPostgresDriver) Exec(ctx context.Context, query string, arguments ...any) error {
	err := driver.delegate.Exec(ctx, query, arguments...)
	if err != nil {
		driver.trace.set(combinedE2EPostgresError(combinedE2EDatabaseStage(query), err))
	}
	return err
}

func (driver *combinedE2EPostgresDriver) Close() error { return driver.delegate.Close() }

type combinedE2ETracingRow struct {
	delegate apiserver.PostgresRow
	stage    string
	trace    *combinedE2EPostgresTrace
}

func (row *combinedE2ETracingRow) Scan(destinations ...any) error {
	err := row.delegate.Scan(destinations...)
	if err != nil {
		row.trace.set(combinedE2EPostgresError(row.stage, err))
	}
	return err
}

func combinedE2EPostgresError(stage string, err error) string {
	var provider *pgconn.PgError
	if !errors.As(err, &provider) {
		return stage + ":non_provider"
	}
	message := provider.Message
	if len(message) < 1 || len(message) > 128 || strings.IndexFunc(message, func(character rune) bool {
		return character != ' ' && character != '_' && character != '-' && (character < 'a' || character > 'z')
	}) >= 0 {
		message = "redacted"
	}
	return stage + ":" + provider.Code + ":" + message
}

type combinedE2ETracingDatabase struct {
	mu       sync.Mutex
	delegate apiserver.JSONDatabase
	stages   []string
}

func (database *combinedE2ETracingDatabase) SchemaVersion(ctx context.Context) (string, error) {
	value, err := database.delegate.SchemaVersion(ctx)
	database.record("schema_version", err)
	return value, err
}

func (database *combinedE2ETracingDatabase) QueryJSON(ctx context.Context, query string, arguments ...any) (json.RawMessage, error) {
	value, err := database.delegate.QueryJSON(ctx, query, arguments...)
	stage := combinedE2EDatabaseStage(query)
	if err == nil && (stage == "zasp_execution_claim_delivery" || stage == "zasp_execution_finish_job") {
		if stage == "zasp_execution_finish_job" && len(arguments) == 11 {
			stage = fmt.Sprintf("%s:%v:%v", stage, arguments[6], arguments[8])
		}
		var result struct {
			Attempt     int    `json:"attempt"`
			Disposition string `json:"disposition"`
			State       string `json:"state"`
		}
		if json.Unmarshal(value, &result) == nil {
			stage = fmt.Sprintf("%s:%s:%s:%d", stage, result.Disposition, result.State, result.Attempt)
		}
	}
	database.record(stage, err)
	return value, err
}

func (database *combinedE2ETracingDatabase) Exec(ctx context.Context, query string, arguments ...any) error {
	err := database.delegate.Exec(ctx, query, arguments...)
	database.record(combinedE2EDatabaseStage(query), err)
	return err
}

func (database *combinedE2ETracingDatabase) record(stage string, err error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	if err != nil {
		classification := "unavailable"
		for candidate, name := range map[error]string{
			apiserver.ErrRepositoryOperation: "operation", apiserver.ErrRepositoryConflict: "conflict", apiserver.ErrRepositoryNotFound: "not_found",
		} {
			if errors.Is(err, candidate) {
				classification = name
				break
			}
		}
		stage += ":error:" + classification + ":" + fmt.Sprintf("%T", err)
	}
	database.stages = append(database.stages, stage)
}

func (database *combinedE2ETracingDatabase) Trace() string {
	database.mu.Lock()
	defer database.mu.Unlock()
	return strings.Join(database.stages, ",")
}

func combinedE2EDatabaseStage(query string) string {
	for _, stage := range []string{
		"zasp_inventory_readiness", "zasp_execution_principal_ready", "zasp_execution_claim_delivery", "zasp_execution_job_input",
		"zasp_execution_heartbeat_job", "zasp_execution_checkpoint_partial", "zasp_execution_apply_complete_snapshot", "zasp_execution_finish_job",
		"zasp_security_agent_temporary_policy_readiness", "zasp_security_agent_action_principal_ready", "zasp_security_agent_claim_temporary_policy_effects",
		"zasp_security_agent_heartbeat_temporary_policy_effect", "zasp_security_agent_store_temporary_policy_target", "zasp_security_agent_read_temporary_policy_target", "zasp_security_agent_finish_temporary_policy_effect",
	} {
		if strings.Contains(query, stage) {
			return stage
		}
	}
	return "other"
}

type combinedE2EDiscoveryQueue struct {
	mu           sync.Mutex
	delivery     jobqueue.Delivery
	consumed     bool
	acknowledged bool
}

func (queue *combinedE2EDiscoveryQueue) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.consumed {
		return []jobqueue.Delivery{}, nil
	}
	queue.consumed = true
	return []jobqueue.Delivery{queue.delivery}, nil
}

func (queue *combinedE2EDiscoveryQueue) AcknowledgeBatch(context.Context, []jobqueue.Receipt) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.acknowledged = true
	return nil
}

func (*combinedE2EDiscoveryQueue) ExtendVisibility(context.Context, []jobqueue.Receipt, time.Duration) error {
	return nil
}

type combinedE2ECredentialResolver struct{}

func (*combinedE2ECredentialResolver) ResolveDiscoveryCredential(_ context.Context, request discoveryCredentialMaterialRequest) (*collection.CredentialMaterial, error) {
	return collection.NewCredentialMaterial(request.Credential, []byte("local-e2e-credential-material"), time.Now().Add(5*time.Minute))
}

func newCombinedE2ECollectorFactory(scenario, parserVersion, toolVersion string) (discoveryCollectorFactory, error) {
	driver := &combinedE2EArtifactDriver{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		return nil, err
	}
	api := &combinedE2ECollectionAPI{scenario: scenario}
	clients := make(map[collection.Provider]collection.ProviderClient, 4)
	clients[collection.ProviderAWS], err = awsdiscovery.NewCollectionClient(api, artifacts, awsdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	if err == nil {
		clients[collection.ProviderKubernetes], err = kubernetesdiscovery.NewCollectionClient(api, artifacts, kubernetesdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	}
	if err == nil {
		clients[collection.ProviderGitHub], err = githubdiscovery.NewCollectionClient(api, artifacts, githubdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	}
	if err == nil {
		clients[collection.ProviderOkta], err = idpdiscovery.NewOktaCollectionClient(api, artifacts, idpdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: parserVersion, ToolVersion: toolVersion, Clock: combinedE2EClock})
	}
	if err != nil {
		return nil, err
	}
	classes := map[collection.Provider]collection.CredentialClass{
		collection.ProviderAWS: collection.CredentialAWSAssumeRole, collection.ProviderKubernetes: collection.CredentialKubernetesCluster,
		collection.ProviderGitHub: collection.CredentialGitHubInstallation, collection.ProviderOkta: collection.CredentialOktaRefresh,
	}
	registrations := make([]firstPartyProviderClientRegistration, 0, 4)
	for _, provider := range []collection.Provider{collection.ProviderAWS, collection.ProviderKubernetes, collection.ProviderGitHub, collection.ProviderOkta} {
		probe, ok := clients[provider].(collection.ReadinessProbe)
		if !ok {
			return nil, errors.New("local provider readiness unavailable")
		}
		registrations = append(registrations, firstPartyProviderClientRegistration{Provider: provider, CollectorVersion: "collector_v1", CredentialClass: classes[provider], Client: clients[provider], Readiness: probe, ReadinessTimeout: time.Second})
	}
	providers, err := newFirstPartyCollectionFactory(registrations)
	if err != nil {
		return nil, err
	}
	return newProductionDiscoveryCollectorFactory(providers, &combinedE2ECredentialResolver{})
}

func combinedE2EClock() time.Time { return time.Now().UTC().Truncate(time.Second) }

type combinedE2ECollectionAPI struct{ scenario string }

func (*combinedE2ECollectionAPI) CheckCollectionReadiness(context.Context) error { return nil }

func (api *combinedE2ECollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request awsdiscovery.CollectionPageRequest) (awsdiscovery.CollectionPage, error) {
	if ctx == nil || ctx.Err() != nil || len(credential) < 16 {
		return awsdiscovery.CollectionPage{}, collection.ErrContract
	}
	if api.scenario == "failed" {
		failure, _ := collection.NewFailure(collection.FailureMalformed, time.Time{})
		return awsdiscovery.CollectionPage{}, failure
	}
	entities, relationships, complete, err := combinedE2EPageValues(request.Provider, api.scenario)
	if err != nil {
		return awsdiscovery.CollectionPage{}, err
	}
	cursor := collection.Cursor{Provider: request.Provider, Version: "local_e2e_v1", Value: fmt.Sprintf("%s-%d", api.scenario, request.Page)}
	switch request.Provider {
	case collection.ProviderAWS:
		return awsdiscovery.NewCollectionPage(request.Subject, cursor, complete, entities, relationships)
	case collection.ProviderKubernetes:
		return kubernetesdiscovery.NewCollectionPage(request.Subject, cursor, complete, entities, relationships)
	case collection.ProviderGitHub:
		return githubdiscovery.NewCollectionPage(request.Subject, cursor, complete, entities, relationships)
	case collection.ProviderOkta:
		return idpdiscovery.NewOktaCollectionPage(request.Subject, cursor, complete, entities, relationships)
	default:
		return awsdiscovery.CollectionPage{}, collection.ErrContract
	}
}

type combinedE2EEntity struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	DisplayName    string          `json:"display_name"`
	StableFields   json.RawMessage `json:"stable_fields"`
	Attributes     json.RawMessage `json:"attributes"`
}

type combinedE2ERelationship struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
	Attributes     json.RawMessage `json:"attributes"`
}

func combinedE2EPageValues(provider collection.Provider, scenario string) ([]json.RawMessage, []json.RawMessage, bool, error) {
	if scenario == "empty" {
		return []json.RawMessage{}, []json.RawMessage{}, true, nil
	}
	if scenario == "partial" {
		if provider != collection.ProviderKubernetes {
			return nil, nil, false, collection.ErrContract
		}
		entities := make([]json.RawMessage, 1000)
		for index := range entities {
			entities[index] = combinedE2EMarshal(combinedE2EEntity{ID: fmt.Sprintf("pid_%08x-0000-4000-8000-%012x", 0x25000000+index, index+1), Kind: "kubernetes_resource", SourceNativeID: fmt.Sprintf("partial-%04d", index), DisplayName: fmt.Sprintf("Partial resource %04d", index), StableFields: json.RawMessage(fmt.Sprintf(`{"api_group":"core","api_version":"v1","cluster":"prod.example/cluster-a","name":"partial-%04d","namespace":"partial","resource_kind":"ConfigMap"}`, index)), Attributes: json.RawMessage(`{"namespaced":true,"state":"active"}`)})
		}
		return entities, []json.RawMessage{}, false, nil
	}
	var entities []combinedE2EEntity
	var relationships []combinedE2ERelationship
	switch provider {
	case collection.ProviderAWS:
		entities = []combinedE2EEntity{{ID: "pid_24000001-0000-4000-8000-000000000001", Kind: "aws_account", SourceNativeID: "123456789012", DisplayName: "Production AWS account", StableFields: json.RawMessage(`{"account_id":"123456789012"}`), Attributes: json.RawMessage(`{"state":"active"}`)}}
	case collection.ProviderKubernetes:
		entities = []combinedE2EEntity{{ID: "pid_21000001-0000-4000-8000-000000000001", Kind: "kubernetes_agent", SourceNativeID: "support-agent", DisplayName: "Support agent", StableFields: json.RawMessage(`{"api_group":"apps","api_version":"v1","cluster":"prod.example/cluster-a","name":"support-agent","namespace":"zasp","resource_kind":"DaemonSet","service_account":"support-agent"}`), Attributes: json.RawMessage(`{"namespaced":true,"posture":{"cicd_write":false,"credential_active":true,"credential_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","destructive_tool":false,"host_filesystem":false,"human_credential":false,"privileged":false,"production_agent":true,"production_credential":true,"production_secret_reach":false,"production_write":false,"runtime_control":true,"runtime_policy_supported":true,"sensitive_data_reach":false,"shell_execution":false,"unapproved_remote_tool":false,"unrestricted_egress":false,"untrusted_input":false},"state":"active"}`)}}
		if scenario != "shared" {
			entities = append(entities,
				combinedE2EEntity{ID: "pid_21000002-0000-4000-8000-000000000002", Kind: "kubernetes_workload", SourceNativeID: "support-runtime", DisplayName: "Production runtime", StableFields: json.RawMessage(`{"api_group":"apps","api_version":"v1","cluster":"prod.example/cluster-a","name":"support-runtime","namespace":"zasp","resource_kind":"Deployment","service_account":"support-runtime"}`), Attributes: json.RawMessage(`{"namespaced":true,"state":"active"}`)},
				combinedE2EEntity{ID: "pid_21000004-0000-4000-8000-000000000004", Kind: "kubernetes_service_account", SourceNativeID: "zasp/support-agent", DisplayName: "Support agent identity", StableFields: json.RawMessage(`{"api_group":"core","api_version":"v1","cluster":"prod.example/cluster-a","name":"support-agent","namespace":"zasp","resource_kind":"ServiceAccount"}`), Attributes: json.RawMessage(`{"namespaced":true,"state":"active"}`)},
			)
			relationships = []combinedE2ERelationship{{ID: "pid_21000003-0000-4000-8000-000000000003", Kind: "uses_identity", SourceNativeID: "support-agent-identity", FromEntityID: "pid_21000001-0000-4000-8000-000000000001", ToEntityID: "pid_21000004-0000-4000-8000-000000000004", Attributes: json.RawMessage(`{"state":"active","type":"service_account"}`)}}
		}
	case collection.ProviderGitHub:
		entities = []combinedE2EEntity{{ID: "pid_22000001-0000-4000-8000-000000000001", Kind: "github_repository", SourceNativeID: "zasp/security-automation", DisplayName: "Automation repository", StableFields: json.RawMessage(`{"installation_id":424242,"name":"security-automation","owner":"zasp","repository":"security-automation","visibility":"private"}`), Attributes: json.RawMessage(`{"archived":false,"default_branch":"main","state":"active"}`)}}
	case collection.ProviderOkta:
		entities = []combinedE2EEntity{{ID: "pid_23000001-0000-4000-8000-000000000001", Kind: "okta_group", SourceNativeID: "security-operators", DisplayName: "Security operators", StableFields: json.RawMessage(`{"name":"security-operators","object_type":"group","tenant":"e2e.okta.com"}`), Attributes: json.RawMessage(`{"state":"active","status":"ACTIVE"}`)}}
	default:
		return nil, nil, false, collection.ErrContract
	}
	encodedEntities := make([]json.RawMessage, len(entities))
	for index := range entities {
		encodedEntities[index] = combinedE2EMarshal(entities[index])
	}
	encodedRelationships := make([]json.RawMessage, len(relationships))
	for index := range relationships {
		encodedRelationships[index] = combinedE2EMarshal(relationships[index])
	}
	return encodedEntities, encodedRelationships, true, nil
}

func combinedE2EMarshal(value any) json.RawMessage {
	body, _ := json.Marshal(value)
	return body
}

type combinedE2EArtifactDriver struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
	order   []string
	reads   []string
}

func (driver *combinedE2EArtifactDriver) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	version := "version-" + hex.EncodeToString(object.SHA256[:8])
	object.VersionID = version
	key := object.Key + "\x1f" + version
	if current, exists := driver.objects[key]; exists {
		if current.MediaType != object.MediaType || current.SHA256 != object.SHA256 || !bytes.Equal(current.Body, object.Body) {
			return artifactstore.DriverObject{}, errors.New("artifact drift")
		}
		return combinedE2ECloneDriverObject(current), nil
	}
	driver.objects[key] = combinedE2ECloneDriverObject(object)
	driver.order = append(driver.order, object.MediaType)
	return combinedE2ECloneDriverObject(object), nil
}

func (driver *combinedE2EArtifactDriver) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	object, ok := driver.objects[locator.Key+"\x1f"+locator.VersionID]
	if !ok {
		driver.reads = append(driver.reads, "missing:"+locator.Reference.String())
		return artifactstore.DriverObject{}, errors.New("artifact missing")
	}
	driver.reads = append(driver.reads, object.MediaType)
	return combinedE2ECloneDriverObject(object), nil
}

func (driver *combinedE2EArtifactDriver) readSnapshot() []string {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return append([]string(nil), driver.reads...)
}

func (driver *combinedE2EArtifactDriver) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	delete(driver.objects, locator.Key+"\x1f"+locator.VersionID)
	return nil
}

func (*combinedE2EArtifactDriver) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	if locator.Key == "" || locator.VersionID == "" {
		return "", errors.New("artifact reference unavailable")
	}
	return "s3://zasp-production-e2e-evidence/" + locator.Key, nil
}

func combinedE2ECloneDriverObject(object artifactstore.DriverObject) artifactstore.DriverObject {
	object.Body = bytes.Clone(object.Body)
	object.SHA256 = sha256.Sum256(object.Body)
	object.Size = int64(len(object.Body))
	return object
}

func combinedE2EScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		combinedE2EProductID(t, "pid_10000001-0000-4000-8000-000000000001"),
		combinedE2EProductID(t, "pid_10000002-0000-4000-8000-000000000002"),
		combinedE2EProductID(t, "pid_10000003-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func combinedE2EProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
