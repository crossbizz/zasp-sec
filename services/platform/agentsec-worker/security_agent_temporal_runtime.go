package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

type temporalSecurityAgentRuntime struct {
	product             *temporalSecurityAgentProduct
	activities          *orchestration.Activities
	singleActivities    *orchestration.SingleTestActivities
	recoveryActivities  *orchestration.SingleTestRecoveryActivities
	findingActivities   *orchestration.FindingResponseActivities
	automaticActivities *orchestration.AutomaticActivities
	worker              worker.Worker
	ready               func(context.Context) error
	closeClients        func() error
	closing             atomic.Bool
	stopOnce, closeOnce sync.Once
	stopped             chan struct{}
	timeout             time.Duration
	closeErr            error
	selector            *temporalTestSelectorProcessor
	automatic           *temporalAutomaticSourceProcessor
	finding             workerProcessor
}

func newTemporalSecurityAgentWorker(c client.Client, queue string, p *temporalSecurityAgentProduct, ready func(context.Context) error, closeClients func() error, timeout time.Duration, concurrency int) (*temporalSecurityAgentRuntime, error) {
	if c == nil || queue == "" || p == nil || ready == nil || closeClients == nil || timeout < time.Second || timeout > time.Minute || concurrency < 1 || concurrency > 64 {
		return nil, errRuntimeUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ready(ctx) != nil {
		return nil, errRuntimeUnavailable
	}
	activities := &orchestration.Activities{Product: p}
	w := worker.New(c, queue, worker.Options{WorkerStopTimeout: timeout, MaxConcurrentActivityExecutionSize: concurrency, MaxConcurrentWorkflowTaskExecutionSize: concurrency})
	w.RegisterWorkflow(orchestration.SecurityAgentWorkflow)
	w.RegisterWorkflow(orchestration.SecurityAgentCleanupWorkflow)
	for name, handler := range map[string]any{"Observe": activities.Observe, "Plan": activities.Plan, "Apply": activities.Apply, "Advance": activities.Advance, "Test": activities.Test, "Cleanup": activities.Cleanup} {
		w.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
	}
	var single *orchestration.SingleTestActivities
	var recovery *orchestration.SingleTestRecoveryActivities
	installed, err := singleRecoveryRuntimeAvailable(ctx, p.executor)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	if installed {
		if !p.singleTestEnabled {
			return nil, errRuntimeUnavailable
		}
		valid, err := singleRecoveryRuntimeAvailable(ctx, p.compensation)
		if err != nil || !valid {
			return nil, errRuntimeUnavailable
		}
		product, err := p.SingleTestRecoveryProduct()
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		recovery = &orchestration.SingleTestRecoveryActivities{Product: product}
		w.RegisterWorkflow(orchestration.SingleTestOperatorCleanupWorkflow)
		w.RegisterActivityWithOptions(recovery.Step, activity.RegisterOptions{Name: "SingleOperatorCleanup"})
	}
	if p.singleTestEnabled {
		single = &orchestration.SingleTestActivities{Product: p.SingleTestProduct()}
		w.RegisterWorkflow(orchestration.SingleTestWorkflow)
		w.RegisterWorkflow(orchestration.SingleTestCleanupWorkflow)
		for name, handler := range map[string]any{"SingleObserve": single.Observe, "SinglePlan": single.Plan, "SingleTest": single.Test, "SingleSettle": single.Settle, "SingleCleanup": single.Cleanup} {
			w.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
		}
	}
	if p.testSelectorEnabled {
		w.RegisterWorkflow(orchestration.TestSelectorWorkflow)
		w.RegisterActivityWithOptions(p.AdmitTestSelector, activity.RegisterOptions{Name: "AdmitTestSelector"})
	}
	var finding *orchestration.FindingResponseActivities
	if p.findingResponseEnabled {
		finding = &orchestration.FindingResponseActivities{Product: p.FindingResponseProduct()}
		w.RegisterWorkflow(orchestration.FindingResponseWorkflow)
		w.RegisterWorkflow(orchestration.FindingResponseCleanupWorkflow)
		for name, handler := range map[string]any{"FindingObserve": finding.Observe, "FindingPlan": finding.Plan, "FindingApply": finding.Apply, "FindingCleanup": finding.Cleanup} {
			w.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
		}
	}
	var automatic *orchestration.AutomaticActivities
	if p.automaticSourcesEnabled {
		automatic = &orchestration.AutomaticActivities{Product: p}
		w.RegisterWorkflow(orchestration.AutomaticSourceWorkflow)
		w.RegisterWorkflow(orchestration.AutomaticCatchupWorkflow)
		w.RegisterActivityWithOptions(automatic.Source, activity.RegisterOptions{Name: "AutomaticSourcePage"})
		w.RegisterActivityWithOptions(automatic.Catchup, activity.RegisterOptions{Name: "AutomaticCatchupPage"})
	}
	if err := w.Start(); err != nil {
		return nil, errRuntimeUnavailable
	}
	baseReady := ready
	if recovery != nil {
		ready = func(c context.Context) error {
			if err := baseReady(c); err != nil {
				return err
			}
			for _, db := range []apiserver.JSONDatabase{p.executor, p.compensation} {
				if ok, err := singleRecoveryRuntimeAvailable(c, db); err != nil || !ok {
					return errRuntimeUnavailable
				}
			}
			return nil
		}
	}
	return &temporalSecurityAgentRuntime{product: p, activities: activities, singleActivities: single, recoveryActivities: recovery, findingActivities: finding, automaticActivities: automatic, worker: w, ready: ready, closeClients: closeClients, stopped: make(chan struct{}), timeout: timeout}, nil
}
func (r *temporalSecurityAgentRuntime) Ready(ctx context.Context) error {
	if r == nil || r.closing.Load() {
		return errRuntimeUnavailable
	}
	return r.ready(ctx)
}
func (r *temporalSecurityAgentRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closing.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	r.stopOnce.Do(func() { go func() { r.worker.Stop(); close(r.stopped) }() })
	if err := r.activities.Close(ctx); err != nil {
		return errRuntimeUnavailable
	}
	if r.singleActivities != nil {
		if err := r.singleActivities.Close(ctx); err != nil {
			return errRuntimeUnavailable
		}
	}
	if r.recoveryActivities != nil {
		if err := r.recoveryActivities.Close(ctx); err != nil {
			return errRuntimeUnavailable
		}
	}
	if r.automaticActivities != nil {
		if err := r.automaticActivities.Close(ctx); err != nil {
			return errRuntimeUnavailable
		}
	}
	if r.findingActivities != nil {
		if err := r.findingActivities.Close(ctx); err != nil {
			return errRuntimeUnavailable
		}
	}
	select {
	case <-r.stopped:
	case <-ctx.Done():
		return errRuntimeUnavailable
	}
	r.closeOnce.Do(func() { r.closeErr = r.closeClients() })
	return r.closeErr
}

func buildTemporalSecurityAgentRuntime(ctx context.Context, cfg workerRuntimeConfig, c client.Client) (*temporalSecurityAgentRuntime, error) {
	return buildTemporalSecurityAgentRuntimeWithIO(ctx, cfg, c, nil, productionWorkerIO())
}
func buildTemporalSecurityAgentRuntimeWithIO(ctx context.Context, cfg workerRuntimeConfig, c client.Client, fgaClient *fga.OpenFgaClient, external workerExternalIO) (*temporalSecurityAgentRuntime, error) {
	if ctx == nil || c == nil || cfg.TemporalExecutorDSN == "" || cfg.TemporalCompensationDSN == "" || cfg.TemporalExecutorDSN == cfg.TemporalCompensationDSN || cfg.TemporalExecutorDSN == cfg.PostgresDSN || cfg.TemporalCompensationDSN == cfg.PostgresDSN || !filepath.IsAbs(cfg.TemporalPricingBindingsFile) {
		return nil, errRuntimeUnavailable
	}
	if temporalWorkerProductionProfileReady(ctx, cfg.TemporalExecutorDSN) != nil {
		return nil, errRuntimeUnavailable
	}
	// Re-read the mounted signing secret for recovery after trusted-key rotation.
	signing := func() (string, ed25519.PrivateKey, policy.GatewayPolicyKeys, error) {
		key, err := loadSecurityAgentActionPrivateKey(cfg.GatewaySigningPrivateFile)
		if err != nil {
			return "", nil, policy.GatewayPolicyKeys{}, errRuntimeUnavailable
		}
		public, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return "", nil, policy.GatewayPolicyKeys{}, errRuntimeUnavailable
		}
		keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{cfg.GatewaySigningKeyID: public})
		if err != nil {
			return "", nil, policy.GatewayPolicyKeys{}, errRuntimeUnavailable
		}
		return cfg.GatewaySigningKeyID, key, keys, nil
	}
	bindings, err := loadTemporalPricingBindings(cfg.TemporalPricingBindingsFile)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	planner, err := external.planner(cfg)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		key := binding.OrganizationID + "/" + binding.WorkspaceID + "/" + binding.EnvironmentID
		if seen[key] || !release61PlannerAvailable(planner, binding) {
			planner.Close()
			return nil, errRuntimeUnavailable
		}
		seen[key] = true
	}
	execution, err := external.temporal(cfg)
	if err != nil {
		planner.Close()
		return nil, errRuntimeUnavailable
	}
	var databases []apiserver.JSONDatabase
	var pools []*pgxpool.Pool
	var databaseClosers []func() error
	closeClients := func() error {
		var result error
		for _, closeDB := range databaseClosers {
			result = errors.Join(result, closeDB())
		}
		return errors.Join(result, planner.Close(), execution.close())
	}
	fail := func() (*temporalSecurityAgentRuntime, error) { closeClients(); return nil, errRuntimeUnavailable }
	if execution.close == nil {
		planner.Close()
		return nil, errRuntimeUnavailable
	}
	if execution.ready == nil || execution.store == nil || !release61TestRunnerAvailable(execution.runner) {
		return fail()
	}
	for _, dsn := range []string{cfg.TemporalExecutorDSN, cfg.TemporalCompensationDSN} {
		pc, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			return fail()
		}
		pc.MaxConns = int32(cfg.BatchSize + 2)
		pc.MinConns = 1
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			return fail()
		}
		var driver apiserver.PostgresDriver = &workerPostgresDriver{pool: pool}
		if observer := external.temporalDiagnostic; observer != nil && observer.driver != nil {
			driver = observer.driver(driver)
		}
		db, err := apiserver.NewPostgresJSONDatabase(driver)
		if err != nil {
			pool.Close()
			return fail()
		}
		databases = append(databases, db)
		pools = append(pools, pool)
		databaseClosers = append(databaseClosers, db.Close)
	}
	p := &temporalSecurityAgentProduct{executor: databases[0], compensation: databases[1], planner: planner, runner: execution.runner, store: execution.store, bindings: bindings, signing: signing, workerID: cfg.WorkerID}
	var workerChecker authorization.Checker
	if fgaClient != nil {
		checker, err := authorization.NewOpenFGA(fgaClient, cfg.RuntimeServices)
		if err != nil {
			return fail()
		}
		workerChecker = checker
	}
	if bindTemporalWorkerAuthorization(ctx, cfg, workerChecker, p, pools) != nil {
		return fail()
	}
	var signingReady func() error
	if p.workerForward != nil {
		ordered, err := newWorkerOrderedPolicySigning(cfg)
		if err != nil {
			return fail()
		}
		p.orderedPolicyKeyID, p.orderedPolicyKeys, p.orderedPolicySigner = ordered.keyID, ordered.keys, ordered.sign
		p.signing = nil
		signingReady = ordered.ready
	} else {
		// A mounted verifier belongs to the named authorization profile. Do
		// not silently downgrade that configuration to the legacy signer.
		if cfg.GatewayPolicyKeysFile != "" {
			return fail()
		}
		signingReady = func() error {
			_, private, _, err := signing()
			clear(private)
			return err
		}
		if signingReady() != nil {
			return fail()
		}
	}
	if observer := external.temporalDiagnostic; observer != nil {
		if observer.database == nil || observer.singleTest == nil {
			return fail()
		}
		p.executor = observer.database(p.executor)
		if nilWorkerDependency(p.executor) {
			return fail()
		}
		p.singleTestDiagnostic = observer.singleTest
	}
	p.singleTestEnabled, err = singleTestRuntimeAvailable(ctx, databases[0], false)
	if err != nil {
		return fail()
	}
	p.findingResponseEnabled, err = findingResponseRuntimeAvailable(ctx, databases[0])
	if err != nil {
		return fail()
	}
	p.testSelectorEnabled, err = testSelectorAvailable(ctx, databases[0])
	if err != nil {
		return fail()
	}
	p.automaticSourcesEnabled, err = automaticSourcesAvailable(ctx, databases[0])
	if err != nil || p.automaticSourcesEnabled != p.testSelectorEnabled {
		return fail()
	}
	var selector *temporalTestSelectorProcessor
	if p.testSelectorEnabled {
		if !p.singleTestEnabled {
			return fail()
		}
		source := &temporalTestSelectorSource{session: temporalDiscoveryScheduleSource{dsn: cfg.TemporalExecutorDSN, timeout: cfg.RuntimeServices.Timeout}, automatic: p.automaticSourcesEnabled}
		if source.Ready(ctx) != nil {
			return fail()
		}
		reconciler, err := orchestration.NewTestSelectorReconciler(c.ScheduleClient(), source, cfg.RuntimeServices.TaskQueue, cfg.RuntimeServices.Timeout)
		if err != nil {
			return fail()
		}
		selector = &temporalTestSelectorProcessor{source: source, reconciler: reconciler}
	}
	ready := func(ctx context.Context) error {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if p.workerForward != nil && (p.workerForward.Ready(bounded) != nil || p.workerCompensation.Ready(bounded) != nil) {
			return errRuntimeUnavailable
		}
		for i, db := range databases {
			authority := []string{"zasp_temporal_executor", "zasp_temporal_compensation"}[i]
			raw, err := db.QueryJSON(bounded, `SELECT to_jsonb(zasp_temporal69.ready($1,$2) AND zasp_temporal69.principal_ready($3))`, migrations.ProductionTemporalWorkflow().Checksum(), migrations.TemporalWorkflowFingerprint(), authority)
			if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
				return errRuntimeUnavailable
			}
			if p.singleTestEnabled {
				if installed, err := singleTestRuntimeAvailable(bounded, db, false); err != nil || !installed {
					return errRuntimeUnavailable
				}
			}
			if p.findingResponseEnabled {
				if installed, err := findingResponseRuntimeAvailable(bounded, db); err != nil || !installed {
					return errRuntimeUnavailable
				}
			}
		}
		if signingReady() != nil {
			return errRuntimeUnavailable
		}
		if !release61TestRunnerAvailable(execution.runner) || execution.ready(bounded) != nil {
			return errRuntimeUnavailable
		}
		if selector != nil && selector.source.Ready(bounded) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	runtime, err := newTemporalSecurityAgentWorker(c, cfg.RuntimeServices.TaskQueue, p, ready, closeClients, cfg.ShutdownTimeout, cfg.BatchSize)
	if err != nil {
		return fail()
	}
	runtime.selector = selector
	if p.findingResponseEnabled {
		starter, err := orchestration.NewFindingResponseStarter(c, cfg.RuntimeServices.TaskQueue, cfg.RuntimeServices.Timeout)
		if err != nil {
			runtime.Close()
			return nil, errRuntimeUnavailable
		}
		runtime.finding = temporalOutboxProcessor{relay: p.findingResponseRelay(starter.Start), legacy: p.findingResponseControlRelay(func(ctx context.Context, kind string, q orchestration.StartRequest) error {
			if kind == "approval" {
				return starter.Wake(ctx, q)
			}
			return starter.Cancel(ctx, q)
		})}
	}
	if p.automaticSourcesEnabled {
		starter, err := orchestration.NewAutomaticSourceStarter(c, cfg.RuntimeServices.TaskQueue, cfg.RuntimeServices.Timeout)
		if err != nil {
			runtime.Close()
			return nil, errRuntimeUnavailable
		}
		relay := &orchestration.AutomaticSourceRelay{Store: orchestration.AutomaticSourceSQLStore{Database: databases[0], Timeout: cfg.RuntimeServices.Timeout}, Starter: starter}
		runtime.automatic = &temporalAutomaticSourceProcessor{database: databases[0], relay: relay}
	}
	return runtime, nil
}

func loadTemporalPricingBindings(path string) ([]securityAgentMultistepPricingBinding, error) {
	if !filepath.IsAbs(path) {
		return nil, errRuntimeUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 65537))
	file.Close()
	var bindings []securityAgentMultistepPricingBinding
	if readErr != nil || len(raw) > 65536 || decodeStrictWorkerJSON(raw, &bindings) != nil || len(bindings) == 0 || len(bindings) > 100 {
		return nil, errRuntimeUnavailable
	}
	seen := map[string]bool{}
	for _, b := range bindings {
		key := b.OrganizationID + "/" + b.WorkspaceID + "/" + b.EnvironmentID
		if seen[key] {
			return nil, errRuntimeUnavailable
		}
		seen[key] = true
	}
	return bindings, nil
}

type temporalExecutionIO struct {
	runner *productionRedTeamRunner
	store  artifactstore.ArtifactStore
	ready  func(context.Context) error
	close  func() error
}

func newTemporalExecutionIO(cfg workerRuntimeConfig) (temporalExecutionIO, error) {
	cloudCfg := temporalSecurityAgentCloudConfig(cfg)
	artifactCfg := productionDiscoveryArtifactConfig{Bucket: cfg.EvidenceBucket, ExpectedBucketOwner: cfg.EvidenceOwner, KMSKeyARN: cfg.EvidenceKMSKeyARN, OperationTimeout: 10 * time.Second, MaximumBytes: 1 << 20}
	cloud, err := newProductionDiscoveryCloudAuthority(cloudCfg)
	if err != nil {
		return temporalExecutionIO{}, errRuntimeUnavailable
	}
	artifacts, err := newProductionDiscoveryArtifactAuthority(cloud.s3, artifactCfg)
	if err != nil {
		cloud.Close()
		return temporalExecutionIO{}, errRuntimeUnavailable
	}
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: cfg.RedTeamRunnerImage, Artifacts: artifacts, Command: productionRedTeamCommand{}, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: cfg.RedTeamTargetEndpoint, TargetTokenFile: cfg.RedTeamTargetTokenFile, TargetCAFile: cfg.RedTeamTargetCAFile, TempRoot: "/tmp", Timeout: cfg.RedTeamRunnerTimeout, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil || !release61TestRunnerAvailable(runner) {
		cloud.Close()
		return temporalExecutionIO{}, errRuntimeUnavailable
	}
	ready := func(ctx context.Context) error {
		if readyProductionDiscoveryRole(ctx, cloud.assumeRole, cloudCfg, artifactCfg) != nil || readyProductionDiscoveryArtifactAuthority(ctx, cloud.s3, cloud.kms, cloudCfg, artifactCfg) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	return temporalExecutionIO{runner, artifacts, ready, cloud.Close}, nil
}

func temporalSecurityAgentCloudConfig(cfg workerRuntimeConfig) productionDiscoveryCloudConfig {
	return productionDiscoveryCloudConfig{Region: cfg.AWSRegion, RoleARN: cfg.RedTeamRoleARN, TokenFile: cfg.RedTeamTokenFile, SecretRoot: "zasp/red-team", Timeout: 10 * time.Second, Clock: func() time.Time { return time.Now().UTC() }, Session: "zasp-red-team-worker"}
}

// A late decision for a validated terminal product run has an explicit retained
// outcome. It does not assert compensation succeeded or create fresh effects.
type retainedTemporalEngine struct {
	engine  orchestration.Engine
	product *temporalSecurityAgentProduct
}

func (e retainedTemporalEngine) Start(ctx context.Context, q orchestration.StartRequest) error {
	v, err := e.product.inspect(ctx, q, e.product.executor)
	if err != nil {
		return err
	}
	if v.Terminal && !v.CleanupRequired {
		return nil
	}
	return e.engine.Start(ctx, q)
}
func (e retainedTemporalEngine) Notify(ctx context.Context, m orchestration.Message) error {
	q := map[string]any{"organization_id": m.Ref.OrganizationID, "workspace_id": m.Ref.WorkspaceID, "environment_id": m.Ref.EnvironmentID, "run_id": m.Ref.RunID, "event_id": m.EventID, "decision_id": m.DecisionID, "kind": m.Kind}
	raw, err := e.product.lifecycleQuery(ctx, e.product.executor, `SELECT zasp_temporal69.inspect_message($1::jsonb)`, m.Ref, q)
	if err != nil {
		return err
	}
	var v temporalProductState
	if json.Unmarshal(raw, &v) != nil {
		return orchestration.ErrConflict
	}
	start := orchestration.StartRequest{Ref: m.Ref, DefinitionVersion: v.Start.DefinitionVersion, InputDigest: v.Start.InputDigest}
	checked, err := e.product.inspect(ctx, start, e.product.executor)
	if err != nil {
		return err
	}
	if checked.Terminal {
		return nil
	}
	return e.engine.Notify(ctx, m)
}
