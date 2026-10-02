package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

type recoveryNativeForbiddenIO struct{ calls atomic.Int32 }

func (f *recoveryNativeForbiddenIO) Check(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
	f.calls.Add(1)
	return authorization.Decision{}, authorization.ErrUnavailable
}
func (f *recoveryNativeForbiddenIO) ResolveTarget(context.Context, redteamadapter.TargetResolution) (redteamadapter.TargetBinding, error) {
	f.calls.Add(1)
	return redteamadapter.TargetBinding{}, redteamadapter.ErrAdapter
}
func (f *recoveryNativeForbiddenIO) ResolveTargetCredential(context.Context, string) (*redteamadapter.Credential, error) {
	f.calls.Add(1)
	return nil, redteamadapter.ErrAdapter
}

type recoveryNativeArtifacts struct {
	mu      sync.Mutex
	objects map[artifactstore.DriverLocator]artifactstore.DriverObject
	bucket  string
	puts    int
}

func (d *recoveryNativeArtifacts) Get(_ context.Context, l artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.objects[l]
	if !ok {
		return v, artifactstore.ErrGet
	}
	return v, nil
}
func (d *recoveryNativeArtifacts) Put(_ context.Context, v artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v.VersionID = "recovered-product-v1"
	if prior, ok := d.objects[v.DriverLocator]; ok {
		if !bytes.Equal(prior.Body, v.Body) {
			return v, artifactstore.ErrPut
		}
		return prior, nil
	}
	d.puts++
	d.objects[v.DriverLocator] = v
	return v, nil
}
func (d *recoveryNativeArtifacts) Delete(context.Context, artifactstore.DriverLocator) error {
	return artifactstore.ErrDelete
}
func (d *recoveryNativeArtifacts) ObjectReference(l artifactstore.DriverLocator) (string, error) {
	return d.bucket + l.Key, nil
}

// The only fixture transport change is one exact cluster URL to the owned TLS
// listener. Node still verifies its certificate, sends the production bytes,
// and runs the production recovery command and response decoder.
type recoveryNativeNode struct {
	mu                     sync.Mutex
	t                      *testing.T
	module, node, endpoint string
	calls                  int
}

func (c *recoveryNativeNode) Run(ctx context.Context, _ string, args, env []string, dir string) error {
	if len(args) != 4 || args[1] != "recover-completed" {
		return errors.New("unexpected recovery command")
	}
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	const script = `import {pathToFileURL} from 'node:url';import https from 'node:https';const [module,input,output,endpoint]=process.argv.slice(2);const r=await import(pathToFileURL(module));const transport=(url,options,body)=>new Promise((resolve,reject)=>{if(url!=='https://agentsec-red-team-adapter.zasp-system.svc.cluster.local/v1/effects/completed-receipt')return reject(new Error('foreign fixture URL'));const req=https.request(endpoint+'/v1/effects/completed-receipt',options,res=>{let chunks=[];let size=0;res.on('data',b=>{size+=b.length;if(size>8192){req.destroy();reject(new Error('oversize'));}else chunks.push(b)});res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString('utf8')}))});req.on('error',reject);req.setTimeout(10000,()=>req.destroy(new Error('timeout')));req.end(body)});await r.runCompletedRecovery(input,output,process.env,transport);`
	cmd := exec.CommandContext(ctx, c.node, "--input-type=module", "-e", script, "owned-fixture", c.module, args[2], args[3], c.endpoint)
	cmd.Env = env
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		c.t.Log("actual recovery command failed", err, "diagnostic bytes", len(output), "class", recoveryNodeFailureClass(output), "runner frames", regexp.MustCompile(`runner\.mjs:[0-9]+:[0-9]+`).FindAllString(string(output), 8), "context", ctx.Err())
		return err
	}
	return nil
}

// Only fixed labels and source line numbers cross the diagnostic boundary.
// Child stderr can contain paths or connection details and is never printed.
func recoveryNodeFailureClass(output []byte) string {
	for _, entry := range []struct{ match, class string }{
		{"red team runner input rejected", "runner_rejected"},
		{"Error: timeout", "transport_timeout"},
		{"CERT_HAS_EXPIRED", "tls_expired"},
		{"ERR_TLS_CERT_ALTNAME_INVALID", "tls_name"},
		{"ECONNREFUSED", "connection_refused"},
		{"ERR_MODULE_NOT_FOUND", "module_missing"},
	} {
		if bytes.Contains(output, []byte(entry.match)) {
			return entry.class
		}
	}
	return "unclassified"
}

type recoveryStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *recoveryStatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recoveryStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func TestP7WorkerSingleTestRecoveredProductNative(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_WORKER_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned completed-invocation fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil || net.ParseIP(pc.ConnConfig.Host) == nil || !net.ParseIP(pc.ConnConfig.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	owner, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	poolFor := func(login string) *pgxpool.Pool {
		c := pc.Copy()
		c.ConnConfig.User = login
		c.ConnConfig.Tracer = workerLifecycleTracer(t, c.ConnConfig.Tracer)
		c.MaxConns = 2
		p, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	parent := os.Getenv("ZASP_P7_WORKER_PARENT")
	var start orchestration.StartRequest
	var step, child, action string
	var inputBody []byte
	var manifest apiserver.RedTeamArtifactReference
	var manifestRaw json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT x.organization_id,x.workspace_id,x.environment_id,x.definition_version,x.input_digest,x.step_id,x.test_run_id,x.action_key,i.body,i.manifest FROM zasp_temporal74.run_owners x JOIN zasp_temporal74.test_inputs i USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE x.run_id=$1`, parent).Scan(&start.Ref.OrganizationID, &start.Ref.WorkspaceID, &start.Ref.EnvironmentID, &start.DefinitionVersion, &start.InputDigest, &step, &child, &action, &inputBody, &manifestRaw); err != nil {
		t.Fatal("captured native input", err)
	}
	start.Ref.RunID = parent
	if json.Unmarshal(manifestRaw, &manifest) != nil {
		t.Fatal("captured manifest")
	}
	product, journal, driver, forbidden, command, receiptCalls := newRecoveryNativeComposition(t, ctx, poolFor("worker_test_executor"), poolFor("worker_test_compensation"), poolFor("ordered_test_red_adapter"), start, inputBody, manifest)
	if err := journal.Ready(ctx); err != nil {
		t.Fatal("fresh captured journal readiness", err)
	}
	scope, err := temporalScope(start)
	if err != nil {
		t.Fatal(err)
	}
	var input redTeamRunnerInput
	if json.Unmarshal(inputBody, &input) != nil {
		t.Fatal("captured input")
	}
	forward, comp := product.workerForward, product.workerCompensation
	var original json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY category) FROM zasp_temporal74.invocations j WHERE test_run_id=$1`, child).Scan(&original); err != nil {
		t.Fatal(err)
	}
	assertWorkerRecoveryStatus(t, ctx, owner, product, start, child)
	if err := product.SingleTestProduct().Cleanup(ctx, orchestration.CleanupRequest{Start: start, Reason: "workflow_failed"}); err != nil {
		t.Fatal("actual revoked Cleanup completed recovery and parent settlement", err)
	}
	if err := product.SingleTestProduct().Test(ctx, start); err != nil {
		t.Fatal("actual recovered child retry", err)
	}
	x, err := singleTestExecutionFor(&workerSingleTestDatabase{base: product.executor, forward: forward, compensation: comp, start: start}, scope, parent, step, action)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.query(ctx, `SELECT zasp_temporal74.test_settle($1::jsonb)`, "complete", map[string]any{"snapshot_digest": strings.Repeat("0", 64), "proof_body": "e30="}); !errors.Is(err, authorization.ErrConflict) {
		t.Fatal("changed settlement snapshot accepted", err)
	}
	if err := product.SingleTestProduct().Settle(ctx, start); err != nil {
		t.Fatal("actual captured parent settlement", err)
	}
	if err := product.SingleTestProduct().Settle(ctx, start); err != nil {
		t.Fatal("actual captured parent retry", err)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal74.child_receipts WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='test_reconciled') AND (SELECT count(*)=1 AND bool_and(state='verified') FROM zasp_temporal74.effects WHERE run_id=$1) AND (SELECT jsonb_agg(to_jsonb(j) ORDER BY category)=$3::jsonb FROM zasp_temporal74.invocations j WHERE test_run_id=$2)`, parent, child, original).Scan(&exact); err != nil || !exact {
		t.Fatal("captured product cardinality/journal", err)
	}
	if forbidden.calls.Load() != 0 || receiptCalls.Load() != int32(len(input.Categories)) || command.calls != 1 || driver.puts != 1 {
		t.Fatal("captured product attempted extra IO", forbidden.calls.Load(), receiptCalls.Load(), command.calls, driver.puts)
	}
	for _, statement := range []string{
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_settle_native(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test_comparison_binding(v jsonb) RETURNS text LANGUAGE sql AS $$SELECT repeat('a',64)$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_redact_snapshot(v jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT v$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_settle_native(jsonb) TO zasp_temporal_compensation`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_settle(jsonb) TO zasp_temporal_executor`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
		var refused bool
		err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready()`).Scan(&refused)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err != nil || !refused {
			t.Fatal("settlement private catalog drift accepted", err)
		}
	}
	t.Log("actual product, Node HTTPS recovery, artifact store, child and parent settlement; no new target IO; deployed DNS and service authentication not tested")
}

// Shared with the cheap smoke test; Ready and all native effects remain in the
// database-backed consumer. The constructor path itself performs no database IO.
func newRecoveryNativeComposition(t *testing.T, ctx context.Context, forwardPool, compPool, adapterPool *pgxpool.Pool, start orchestration.StartRequest, inputBody []byte, manifest apiserver.RedTeamArtifactReference) (*temporalSecurityAgentProduct, *redteamadapter.TemporalPostgresJournal, *recoveryNativeArtifacts, *recoveryNativeForbiddenIO, *recoveryNativeNode, *atomic.Int32) {
	t.Helper()
	scope, err := temporalScope(start)
	if err != nil {
		t.Fatal(err)
	}
	var input redTeamRunnerInput
	if json.Unmarshal(inputBody, &input) != nil {
		t.Fatal("original input")
	}
	loc, err := existingTestArtifactLocator(scope, manifest, 65536)
	if err != nil {
		t.Fatal(err)
	}
	driverLoc := artifactstore.DriverLocator{Scope: scope, Reference: loc.Reference, VersionID: loc.VersionID, Key: release61ArtifactKey(scope, loc.Reference.String())}
	driver := &recoveryNativeArtifacts{objects: map[artifactstore.DriverLocator]artifactstore.DriverObject{}, bucket: strings.TrimSuffix(manifest.Reference, driverLoc.Key)}
	driver.objects[driverLoc] = artifactstore.DriverObject{DriverLocator: driverLoc, MediaType: "application/json", Body: inputBody, Size: int64(len(inputBody)), SHA256: sha256.Sum256(inputBody)}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	forbidden := &recoveryNativeForbiddenIO{}
	forwardKey, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
	compKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	forward, err := authorization.NewWorkerExecutor(forwardPool, forbidden, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", forwardKey)
	if err != nil {
		t.Fatal(err)
	}
	comp, err := authorization.NewWorkerExecutor(compPool, nil, "", "", compKey)
	if err != nil {
		t.Fatal(err)
	}
	adapterForward, err := authorization.NewWorkerAdapter(adapterPool, forbidden, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", forwardKey)
	if err != nil {
		t.Fatal(err)
	}
	database := func(p *pgxpool.Pool) apiserver.JSONDatabase {
		d, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: p})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	journal, err := redteamadapter.NewWorkerSingleTestPostgresJournal(database(adapterPool), migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), adapterForward, comp)
	if err != nil {
		t.Fatal("fresh captured journal", err)
	}
	invoker, err := redteamadapter.NewProductionHTTPSInvoker([]string{"93.184.216.0/24"}, time.Second, forbidden)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := redteamadapter.NewWorkerEffectJournaledHandler(redteamadapter.Config{WorkerToken: []byte(strings.Repeat("a", 64)), MaximumRequestBytes: 4096}, forbidden, invoker, journal, journal)
	if err != nil {
		t.Fatal(err)
	}
	receiptCalls := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/effects/completed-receipt" {
			t.Error("recovery attempted nonreceipt HTTP")
			w.WriteHeader(400)
			return
		}
		receiptCalls.Add(1)
		started := time.Now()
		status := &recoveryStatusWriter{ResponseWriter: w}
		handler.ServeHTTP(status, r)
		t.Log("owned completed-receipt HTTP", "status", status.status, "elapsed", time.Since(started), "request context", r.Context().Err())
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	tokenFile, caFile := filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem")
	if os.WriteFile(tokenFile, []byte(strings.Repeat("a", 64)), 0400) != nil || os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400) != nil {
		t.Fatal("owned TLS input")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	module, err := filepath.Abs("../../../workers/redteam-node/runner.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := &recoveryNativeNode{t: t, node: node, module: module, endpoint: server.URL}
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "owned/runner@" + input.RunnerImageDigest, Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp-system.svc.cluster.local/v1/evaluate", TargetTokenFile: tokenFile, TargetCAFile: caFile, TempRoot: dir, Timeout: 30 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	product := &temporalSecurityAgentProduct{executor: database(forwardPool), compensation: database(compPool), workerForward: forward, workerCompensation: comp, runner: runner, store: store}
	return product, journal, driver, forbidden, command, receiptCalls
}
