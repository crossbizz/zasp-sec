package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Removing the named product route, sending before the journal commit, or
// accepting an artifact without native settlement must break this consumer.
func TestP7OrderedActualRunnerNative(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_ORDERED_OWNER_DSN")
	if dsn == "" {
		t.Skip("actual checked Test approval parent required")
	}
	checkpoint := os.Getenv("ZASP_P7_ORDERED_CHECKPOINT")
	postAdapter := os.Getenv("ZASP_P7_ORDERED_POST_ADAPTER")
	capacity := os.Getenv("ZASP_P7_ORDERED_POLICY_CAPACITY")
	prefix, prefixErr := orderedCapacityPrefixMode(os.Getenv("ZASP_P7_ORDERED_POLICY_PREFIX"), capacity)
	if prefixErr != nil {
		t.Fatal("invalid capacity prefix mode")
	}
	if capacity != "" && (capacity != "100" || checkpoint != "" || postAdapter != "" || os.Getenv("ZASP_P7_ORDERED_POST_RECOVERY_RETRY") != "") {
		t.Fatal("invalid policy capacity mode")
	}
	if postAdapter != "" && postAdapter != "test-response-revoked" && postAdapter != "test-disconnected" || postAdapter != "" && checkpoint != "" {
		t.Fatal("unknown post-adapter phase")
	}
	if checkpoint != "" && checkpoint != "test-reserved" && checkpoint != "test-started" {
		t.Fatal("unknown producer checkpoint")
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	observerBudget := 4 * time.Minute
	if capacity == "100" && !prefix {
		observerBudget = 62 * time.Minute
	}
	ctx, cancel := context.WithTimeout(signalCtx, observerBudget)
	defer cancel()
	var config runtimeservices.Config
	var identity struct {
		Organization string `json:"organization_id"`
		Workspace    string `json:"workspace_id"`
		Environment  string `json:"environment_id"`
		Run          string `json:"run_id"`
		Version      int64  `json:"definition_version"`
		Digest       string `json:"input_digest"`
	}
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_ORDERED_CONFIG")), &config) != nil || config.FGAURL != "http://127.0.0.1:8088" || json.Unmarshal([]byte(os.Getenv("ZASP_P7_ORDERED_START")), &identity) != nil {
		t.Fatal("owned runner coordinates required")
	}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: identity.Organization, WorkspaceID: identity.Workspace, EnvironmentID: identity.Environment, RunID: identity.Run}, DefinitionVersion: identity.Version, InputDigest: identity.Digest}
	if _, err := orchestration.WorkflowID(start.Ref); err != nil {
		t.Fatal(err)
	}
	capacityTrace := &orderedCapacityTrace{t: t}
	poolFor := func(login string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil || net.ParseIP(cfg.ConnConfig.Host) == nil || !net.ParseIP(cfg.ConnConfig.Host).IsLoopback() {
			t.Fatal("owned loopback database required")
		}
		for _, fallback := range cfg.ConnConfig.Fallbacks {
			if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
				t.Fatal("foreign database fallback")
			}
		}
		if login != "" {
			cfg.ConnConfig.User = login
		}
		cfg.MaxConns = 2
		cfg.ConnConfig.Tracer = orderedTestNativeTrace{t: t}
		if capacity == "100" {
			capacityTrace.next = cfg.ConnConfig.Tracer
			cfg.ConnConfig.Tracer = capacityTrace
		}
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	owner, forwardPool, compPool := poolFor(""), poolFor(os.Getenv("ZASP_P7_ORDERED_EXECUTOR")), poolFor("temporal_compensation_test_login")
	if os.Getenv("ZASP_P7_ORDERED_EXECUTOR") == "" {
		t.Fatal("registered executor required")
	}
	database := func(pool *pgxpool.Pool) apiserver.JSONDatabase {
		d, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("owned FGA unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("owned FGA identity")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("owned FGA credential unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: config.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, config)
	if err != nil {
		t.Fatal(err)
	}
	var projector string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&projector); err != nil {
		t.Fatal(err)
	}
	projection, err := authorization.NewPostgresProjectionRepository(poolFor(projector))
	if err != nil {
		t.Fatal(err)
	}
	projectCtx, stopProjector := context.WithCancel(ctx)
	projectDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-projectCtx.Done():
				projectDone <- nil
				return
			case <-ticker.C:
				var pending bool
				if err := owner.QueryRow(projectCtx, `SELECT desired<>applied FROM zasp_authorization79.organizations WHERE organization_id=$1`, identity.Organization).Scan(&pending); err != nil {
					if projectCtx.Err() != nil {
						projectDone <- nil
					} else {
						projectDone <- err
					}
					return
				}
				if pending {
					if _, err := authorization.Reconcile(projectCtx, projection, writer, identity.Organization, config.StoreID, config.ModelID); err != nil && projectCtx.Err() == nil && !errors.Is(err, authorization.ErrConflict) && !errors.Is(err, authorization.ErrPending) {
						projectDone <- err
						return
					}
				}
			}
		}
	}()
	defer func() {
		stopProjector()
		if err := <-projectDone; err != nil {
			t.Error("real background projection failed", err)
		}
	}()
	keys := t.TempDir()
	writeKey := func(name string, seed byte) string {
		path := filepath.Join(keys, name)
		if err := os.WriteFile(path, bytes.Repeat([]byte{seed}, 32), 0400); err != nil {
			t.Fatal(err)
		}
		return path
	}
	product := &temporalSecurityAgentProduct{executor: database(forwardPool), compensation: database(compPool)}
	workerConfig := workerRuntimeConfig{RuntimeServices: config, WorkerAuthorizationKeyFile: writeKey("forward", 91), CompensationAuthorizationKeyFile: writeKey("compensation", 92)}
	if err := bindTemporalWorkerAuthorization(ctx, workerConfig, checker, product, []*pgxpool.Pool{forwardPool, compPool}); err != nil {
		t.Fatal("actual product worker binding", err)
	}
	if capacity == "100" {
		if prefix {
			assertOrderedMaximumProductPolicy(t, ctx, owner, product, start, capacityTrace, func(step string, calls func() int32) {
				assertOrderedCapacityPrefix(t, ctx, owner, product, start, step, calls, capacityTrace, workerConfig, checker, os.Getenv("ZASP_P7_ORDERED_EXECUTOR"))
			})
			return
		}
		assertOrderedMaximumProductPolicy(t, ctx, owner, product, start, capacityTrace)
		return
	}
	if retry := os.Getenv("ZASP_P7_ORDERED_POST_RECOVERY_RETRY"); retry != "" {
		if retry != "1" || postAdapter == "" || checkpoint != "" {
			t.Fatal("invalid post-recovery retry")
		}
		assertOrderedPostRecoveryRetry(t, ctx, owner, product, start)
		return
	}
	adapterBinary := os.Getenv("ZASP_P7_ORDERED_ADAPTER_BINARY")
	if !filepath.IsAbs(adapterBinary) {
		t.Fatal("compiled adapter fixture required")
	}
	credentialsDirectory := t.TempDir()
	child := exec.CommandContext(ctx, adapterBinary, "-test.run=^TestP7OrderedRunnerAdapterServer$", "-test.v", "-test.timeout=5m")
	child.WaitDelay = 5 * time.Second
	child.Env = []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=" + os.Getenv("TMPDIR"), "ZASP_P7_ORDERED_OWNER_DSN=" + dsn, "ZASP_P7_ORDERED_CONFIG=" + os.Getenv("ZASP_P7_ORDERED_CONFIG"), "ZASP_P7_ORDERED_PARENT=" + identity.Run, "ZASP_P7_ORDERED_ADAPTER_DIRECTORY=" + credentialsDirectory}
	child.Env = append(child.Env, "ZASP_P7_ORDERED_POST_ADAPTER="+postAdapter)
	var adapterOutput bytes.Buffer
	child.Stdout, child.Stderr = &adapterOutput, &adapterOutput
	if err := child.Start(); err != nil {
		t.Fatal("actual adapter child", err)
	}
	adapterDone := make(chan error, 1)
	go func() { adapterDone <- child.Wait() }()
	joined := false
	defer func() {
		if joined {
			return
		}
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-adapterDone:
			if err != nil {
				t.Error("adapter child failed", err, "stage", orderedAdapterStartupDiagnostic(adapterOutput.Bytes()), "diagnostic_bytes", adapterOutput.Len())
			}
		case <-time.After(10 * time.Second):
			_ = child.Process.Kill()
			<-adapterDone
			t.Error("adapter child needed forced termination")
		}
	}()
	var ready struct {
		Port int `json:"port"`
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for ready.Port == 0 {
		select {
		case err := <-adapterDone:
			joined = true
			t.Fatal("adapter exited before readiness", err, "stage", orderedAdapterStartupDiagnostic(adapterOutput.Bytes()), "diagnostic_bytes", adapterOutput.Len())
		case <-readyCtx.Done():
			t.Fatal("adapter readiness timed out")
		case <-ticker.C:
			if raw, err := os.ReadFile(filepath.Join(credentialsDirectory, "ready.json")); err == nil {
				_ = json.Unmarshal(raw, &ready)
			}
		}
	}
	artifactDirectory := os.Getenv("ZASP_P7_ORDERED_ARTIFACT_DIRECTORY")
	if !filepath.IsAbs(artifactDirectory) {
		t.Fatal("parent-owned artifact directory required")
	}
	driver := &orderedCheckpointArtifacts{release61ArtifactDriver: &release61ArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: artifactDirectory, t: t}}, phase: checkpoint}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	module, err := filepath.Abs("../../../workers/redteam-node/runner.mjs")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := filepath.Abs("../../../workers/redteam-node/ordered-native-relay.fixture.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := &orderedNativeEngine{t: t, credentials: credentialsDirectory, module: module, relay: relay, port: ready.Port}
	engineCommand := redTeamCommandFunc(func(c context.Context, executable string, args, env []string, dir string) error {
		if checkpoint == "test-started" {
			crashOrderedCheckpoint(t, checkpoint, command.calls)
		}
		return command.Run(c, executable, args, env, dir)
	})
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "owned/runner@" + orderedNativeEngineImage, Artifacts: store, Command: engineCommand, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp-system.svc.cluster.local/v1/evaluate", TargetTokenFile: filepath.Join(credentialsDirectory, "token"), TargetCAFile: filepath.Join(credentialsDirectory, "ca.pem"), TempRoot: t.TempDir(), Timeout: 30 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal("actual runner constructor", err)
	}
	product.runner, product.store = runner, store
	for attempt := 0; attempt < 8; attempt++ {
		err = product.Test(ctx, start)
		if checkpoint == "test-reserved" && driver.fired {
			if err == nil {
				t.Fatal("input Put refusal was swallowed")
			}
			crashOrderedCheckpoint(t, checkpoint, command.calls)
		}
		if postAdapter != "" && command.calls > 0 {
			break
		}
		if !errors.Is(err, authorization.ErrPending) && !errors.Is(err, authorization.ErrConflict) {
			break
		}
		// Only the workflow's existing pending/conflict retry classes are
		// retried. Started effects still take the real no-resend stop branch.
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if checkpoint != "" {
		t.Fatal("actual Test did not reach requested producer checkpoint", checkpoint, err)
	}
	if postAdapter != "" {
		assertOrderedPostAdapterRunner(t, ctx, owner, product, start, store, driver, postAdapter, err, command.calls)
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-adapterDone:
			joined = true
			if err != nil || !strings.Contains(adapterOutput.String(), "--- PASS: TestP7OrderedRunnerAdapterServer") {
				t.Fatal("post-adapter actual server did not join", err, "diagnostic_bytes", adapterOutput.Len())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("post-adapter server join timeout")
		}
		return
	}
	if err != nil {
		orderedTestFailureCheckpoints(t, ctx, owner, identity.Run, command.calls, len(driver.writes))
		t.Fatal("actual product Test", err)
	}
	var exact bool
	var evidence json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*)=1 FROM zasp_temporal68.test_inputs WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(state IN('verified','completed')) FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test')
 AND (SELECT count(*)=1 AND bool_and(j.state='completed' AND j.attempt=1 AND j.http_status=200 AND j.protected AND encode(j.input_digest,'hex')=(convert_from(i.body,'UTF8')::jsonb->>'input_digest') AND j.target_resolution=f.snapshot->'targets'->'resolution') FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) JOIN zasp_temporal68.test_inputs i ON (i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id,i.test_run_id)=(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,j.test_run_id) WHERE f.run_id=$1 AND f.action_key='run_test')
 AND (SELECT count(*)=1 FROM public.zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_test_settled')
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_stops WHERE run_id=$1),
 (SELECT to_jsonb(s) FROM zasp_temporal68.test_settlements s WHERE run_id=$1)`, identity.Run).Scan(&exact, &evidence); err != nil || !exact || command.calls != 1 {
		t.Fatal("native Test settlement or one-send cardinality", err, "engine_calls", command.calls)
	}
	scope, err := temporalScope(start)
	if err != nil {
		t.Fatal(err)
	}
	var manifests [2]json.RawMessage
	var bodies [2][]byte
	if err := owner.QueryRow(ctx, `SELECT i.manifest,i.body,s.output_manifest,s.output_body FROM zasp_temporal68.test_inputs i JOIN zasp_temporal68.test_settlements s USING(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id) WHERE i.run_id=$1`, identity.Run).Scan(&manifests[0], &bodies[0], &manifests[1], &bodies[1]); err != nil {
		t.Fatal("native input/output artifacts", err)
	}
	var prepared redTeamRunnerInput
	if json.Unmarshal(bodies[0], &prepared) != nil {
		t.Fatal("prepared artifact identity")
	}
	step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", identity.Run+"\x1f1")
	inputArtifact, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", identity.Run+"\x1f"+step)
	for index := range manifests {
		var manifest apiserver.RedTeamArtifactReference
		if json.Unmarshal(manifests[index], &manifest) != nil {
			t.Fatal("native artifact manifest shape")
		}
		id := inputArtifact
		if index == 1 {
			id = prepared.RunID
		}
		pid, err := domain.ParseProductID(id)
		if err != nil {
			t.Fatal("native artifact ID", err)
		}
		reference, err := domain.NewEvidenceRef(pid)
		if err != nil {
			t.Fatal("native artifact reference", err)
		}
		object, err := store.Get(ctx, artifactstore.Locator{Scope: scope, Reference: reference, VersionID: manifest.VersionID})
		objectReference, referenceErr := store.ObjectReference(object.Locator)
		digest := sha256.Sum256(bodies[index])
		if err != nil || referenceErr != nil || objectReference != manifest.Reference || !bytes.Equal(object.Body, bodies[index]) || manifest.SizeBytes != int64(len(object.Body)) || manifest.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("settlement did not bind the actual durable artifact", index, err)
		}
	}
	var observationBound bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(
 jsonb_array_length(convert_from(s.output_body,'UTF8')::jsonb#>'{native_artifact,native_output,results,results}')=1
 AND (convert_from(s.output_body,'UTF8')::jsonb#>'{native_artifact,native_output,results,results,0,response,linked_observation}')=jsonb_build_object(
 'schema_version','red-team-linked-observation-v1','run_id',j.test_run_id,'category',j.category,
 'credential_version_digest',encode(j.credential_version_digest,'hex'),'target_comparison',j.target_resolution->'comparison',
 'observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected))
 AND c.state='complete' AND c.attempt=1 AND c.evidence_checksum=digest(s.output_body,'sha256')
 AND a.attempt=1 AND a.evidence_checksum=c.evidence_checksum
 AND l.reconcile_state='settled' AND l.reconcile_settlement=s.response)
 FROM zasp_temporal68.test_settlements s JOIN zasp_temporal68.invocations j USING(effect_key,test_run_id)
 JOIN public.zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(s.organization_id,s.workspace_id,s.environment_id,s.test_run_id)
 JOIN public.zasp_red_team_attempts a ON(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,1)
 JOIN public.zasp_security_agent_test_links l ON(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.test_run_id)=(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id,s.test_run_id)
 WHERE s.run_id=$1`, identity.Run).Scan(&observationBound); err != nil || !observationBound {
		t.Fatal("real engine comparison/observation differs from native journal or settled child", err)
	}
	if err := product.Test(ctx, start); err != nil {
		t.Fatal("actual product settled retry", err)
	}
	var stable bool
	if err := owner.QueryRow(ctx, `SELECT to_jsonb(s)=$2::jsonb FROM zasp_temporal68.test_settlements s WHERE run_id=$1`, identity.Run, evidence).Scan(&stable); err != nil || !stable || command.calls != 1 {
		t.Fatal("settled retry changed receipt or resent", err)
	}
	_ = child.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-adapterDone:
		joined = true
		if err != nil || !strings.Contains(adapterOutput.String(), "--- PASS: TestP7OrderedRunnerAdapterServer") {
			t.Fatal("actual adapter did not join", err, "diagnostic_bytes", adapterOutput.Len())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("actual adapter join timeout")
	}
	t.Log("actual product Test, pinned engine, TLS handler/journal, persisted input/output, native settlement and no-send settled retry passed; controlled customer response only")
}
