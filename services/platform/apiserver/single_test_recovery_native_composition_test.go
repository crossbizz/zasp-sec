package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

// These are deliberately unaccepted. A separate reviewed source/capture
// successor must bind the complete migration input tree and these two files.
// Environment variables cannot supply or override the approval pins/paths.
const singleRecoveryApprovedWorkerTree = ""
const singleRecoveryApprovedRecoverySource = ""
const singleRecoveryApprovedCaptureManifest = ""
const singleRecoveryApprovedContextProof = ""
const singleRecoveryApprovedRunnerSource = ""
const singleRecoveryCaptureManifestPath = ""
const singleRecoveryContextProofPath = ""

const singleRecoveryNodePath = "/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node"
const singleRecoveryNodeSHA256 = "2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d"
const singleRecoveryTemporalPath = "/private/tmp/zasp-temporal-cli-1.9.1.iKlp9x/temporal"
const singleRecoveryTemporalSHA256 = "33c298d41f6eefebf01a28a3511f444480e939e21d3518cb0c12a4abad467c4b"
const singleRecoveryGoRoot = "/Users/manishmaheshwari/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.13.darwin-arm64"
const singleRecoveryModuleCache = "/Users/manishmaheshwari/go/pkg/mod"
const singleRecoveryCompileCache = "/private/tmp/zasp-recovery-worker-compile.Kjyi21/home/go-build"

const singleRecoveryOriginalRun = "pid_f0807400-0000-4000-8000-000000000001"
const singleRecoveryForwardRun = "pid_f0807400-0000-4000-8000-000000000011"
const singleRecoveryBrowser = "controlled-single-recovery-browser-session"
const singleRecoveryBrowserSessionID = "session-controlled-single-recovery"

func singleRecoveryDriverDigest(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}
func singleRecoveryNativeSourcePreflight() error {
	want := singleRecoveryDriverPrerequisites{Mode: "1", WorkerSource: singleRecoveryApprovedWorkerTree, RecoverySource: singleRecoveryApprovedRecoverySource, CaptureManifest: singleRecoveryApprovedCaptureManifest, ContextProof: singleRecoveryApprovedContextProof, RunnerSource: singleRecoveryApprovedRunnerSource}
	// Check acceptance before filesystem discovery, compilation or service start.
	if err := singleRecoveryDriverPreflight(want, want); err != nil {
		return err
	}
	got := want
	got.Mode = os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_DRIVER")
	var tree bytes.Buffer
	err := filepath.WalkDir("../migrations", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("source symlink rejected")
		}
		if strings.HasSuffix(path, "_test.go") || !(strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".sql")) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		tree.WriteString(filepath.ToSlash(path))
		tree.WriteByte(0)
		tree.WriteString(singleRecoveryDriverDigest(b))
		tree.WriteByte('\n')
		return nil
	})
	if err != nil {
		return errors.New("source tree binding unavailable")
	}
	got.WorkerSource = singleRecoveryDriverDigest(tree.Bytes())
	source, _ := migrations.ProductionTemporalSingleRecoverySource()
	got.RecoverySource = singleRecoveryDriverDigest([]byte(source))
	for _, file := range []struct {
		path string
		dest *string
	}{{singleRecoveryCaptureManifestPath, &got.CaptureManifest}, {singleRecoveryContextProofPath, &got.ContextProof}, {"../../../workers/redteam-node/runner.mjs", &got.RunnerSource}} {
		info, err := os.Lstat(file.path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return errors.New("reviewed source/capture file unavailable")
		}
		b, err := os.ReadFile(file.path)
		if err != nil {
			return errors.New("reviewed file read failed")
		}
		*file.dest = singleRecoveryDriverDigest(b)
	}
	return singleRecoveryDriverPreflight(got, want)
}

func singleRecoverySubtest(t *testing.T, name string, call func(*testing.T)) (bool, error) {
	completed := false
	ok := t.Run(name, func(t *testing.T) {
		call(t)
		if !t.Failed() && !t.Skipped() {
			completed = true
		}
	})
	if !ok {
		return false, errors.New("native application phase failed")
	}
	return completed, nil
}

// Local controlled delivery only. SQL Stage/Acknowledge and all current
// revision/attestation checks remain real. This is not live OpenFGA evidence.
type singleRecoveryControlledTuples struct{}

func (singleRecoveryControlledTuples) Replace(ctx context.Context, _ authorization.Revision, _, _ []fga.ClientTupleKey) error {
	return ctx.Err()
}

func TestSingleTestRecoveryNativeDriver(t *testing.T) {
	if os.Getenv("ZASP_SINGLE_RECOVERY_NATIVE_DRIVER") == "" {
		t.Skip("explicit source-bound owned native acceptance required")
	}
	if err := singleRecoveryNativeSourcePreflight(); err != nil {
		t.Fatal("native prerequisite refused", err)
	}
	if runtime.GOOS != "darwin" || runtime.GOROOT() != singleRecoveryGoRoot || os.DevNull != "/dev/null" {
		t.Fatal("reviewed macOS toolchain required")
	}
	for _, tool := range []struct{ path, digest string }{{singleRecoveryNodePath, singleRecoveryNodeSHA256}, {singleRecoveryTemporalPath, singleRecoveryTemporalSHA256}} {
		body, err := os.ReadFile(tool.path)
		if err != nil || singleRecoveryDriverDigest(body) != tool.digest {
			t.Fatal("reviewed native tool bytes changed")
		}
	}
	for _, name := range []string{"initdb", "postgres", "pg_ctl"} {
		if path, err := exec.LookPath(name); err != nil || path != "/opt/homebrew/bin/"+name {
			t.Fatal("required native executable missing", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	ctx, owned := newAuditHTTPFixtureOwner(t, ctx, "", nil)
	home := filepath.Join(owned.root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal("owned empty home")
	}
	singleRecoveryIsolateParent(t, home)
	// The reused starter registers every acquired resource before initialization.
	runTemporalTestGrantFixtureWithConcurrency(t, func(_ context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		var endpoint, namespace, binary string
		var temporalClient client.Client
		var runner *migrations.Runner
		var selection map[string]any
		var setupDone bool
		apiInput := singleRecoveryAPIInput{DSN: owner.Config().ConnString(), Run: singleRecoveryOriginalRun, ForwardRun: singleRecoveryForwardRun, BrowserSession: singleRecoveryBrowser}
		apiInput.Reconcile = func(call context.Context) error {
			var login string
			if err := owner.QueryRow(call, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&login); err != nil {
				return err
			}
			cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
			if err != nil {
				return err
			}
			cfg.ConnConfig.User = login
			cfg.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(call, cfg)
			if err != nil {
				return err
			}
			defer pool.Close()
			projection, err := authorization.NewPostgresProjectionRepository(pool)
			if err != nil {
				return err
			}
			_, err = authorization.Reconcile(call, projection, singleRecoveryControlledTuples{}, o, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW")
			return err
		}
		err := runSingleRecoveryNativePhases(ctx, singleRecoveryDriverSteps{
			Preflight: singleRecoveryNativeSourcePreflight,
			Start: func(ctx context.Context) (func(context.Context) error, error) {
				var close func(context.Context) error
				var err error
				endpoint, namespace, temporalClient, close, err = singleRecoveryStartTemporal(ctx, owned)
				if err != nil {
					return close, err
				}
				binary = filepath.Join(owned.root, "recovery-worker.test")
				cmd, err := singleRecoveryWorkerCompileCommand(filepath.Join(owned.root, "home"), binary)
				if err != nil {
					return close, err
				}
				compileCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
				defer stop()
				if _, err = testprocess.Run(compileCtx, cmd); err != nil {
					return close, singleRecoveryCompileFailure(compileCtx, err)
				}
				apiInput.Observer, err = orchestration.NewSingleTestOriginalObserver(temporalClient, 5*time.Second)
				return close, err
			},
			Install: func(context.Context) (bool, error) {
				return singleRecoverySubtest(t, "install-replay-drift", func(t *testing.T) {
					runner, selection = singleRecoveryInstall(t, ctx, owner, api, o, w, e, testID, actor)
					setupDone = runner != nil
				})
			},
			Fixtures: func(context.Context) (bool, error) {
				return singleRecoverySubtest(t, "actual-distinct-originals", func(t *testing.T) {
					if !setupDone {
						t.Fatal("installation did not finish")
					}
					singleRecoveryPrepareOriginals(t, ctx, owner, o, w, e, testID, selection)
				})
			},
			Admit: func(context.Context) (bool, error) {
				return singleRecoverySubtest(t, "api-admit", func(t *testing.T) { apiInput.Phase = "admit"; runSingleTestRecoveryConnectedPostgres(t, apiInput) })
			},
			Worker: func(ctx context.Context) (bool, error) {
				cmd := exec.Command(binary, "-test.run=^TestSingleTestRecoveryConnectedTemporal$", "-test.v", "-test.count=1", "-test.timeout=4m")
				cmd.Dir = "../agentsec-worker"
				cmd.Env = singleRecoveryChildEnvironment(filepath.Join(owned.root, "home"), map[string]string{"ZASP_SINGLE_RECOVERY_NATIVE_OWNER_DSN": apiInput.DSN, "ZASP_SINGLE_RECOVERY_NATIVE_RUN": apiInput.Run, "ZASP_SINGLE_RECOVERY_NATIVE_TEMPORAL": endpoint, "ZASP_SINGLE_RECOVERY_NATIVE_NAMESPACE": namespace})
				call, stop := context.WithTimeout(ctx, 4*time.Minute)
				defer stop()
				output, err := testprocess.Run(call, cmd)
				if err != nil {
					return false, singleRecoveryWorkerFailure(call, output, err)
				}
				// Exit zero also includes a skipped test. Require the exact real entry pass.
				return strings.Contains(string(output), "--- PASS: TestSingleTestRecoveryConnectedTemporal (") && !strings.Contains(string(output), "--- SKIP:"), nil
			},
			Readback: func(context.Context) (bool, error) {
				return singleRecoverySubtest(t, "api-readback", func(t *testing.T) { apiInput.Phase = "readback"; runSingleTestRecoveryConnectedPostgres(t, apiInput) })
			},
		})
		if err != nil {
			t.Fatal("native recovery composition failed", err)
		}
		t.Log("controlled local identity/Check/projection/planner/artifact fixture; actual PostgreSQL fences and owned Temporal application workflow; not live Stytch/OpenFGA/provider evidence")
	}, []int{2}, func(t *testing.T) string {
		return auditHTTPSizeStartPostgres(t, ctx, owned, "zasp_test", auditHTTPPostgresIsolation{environment: singleRecoveryChildEnvironment(home, nil), dsn: singleRecoveryOwnedDSN})
	})
}

func singleRecoveryChildEnvironment(home string, extra map[string]string) []string {
	env := []string{"PATH=" + filepath.Dir(singleRecoveryNodePath) + ":" + filepath.Join(singleRecoveryGoRoot, "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "GOMODCACHE=" + singleRecoveryModuleCache, "GOCACHE=" + filepath.Join(home, "go-build"), "LC_ALL=C", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOMAXPROCS=2",
		"PGPASSFILE=/dev/null", "PGSERVICEFILE=/dev/null", "PGSERVICE=", "PGPASSWORD=", "PGSSLMODE=disable", "PGSSLCERT=/dev/null", "PGSSLKEY=/dev/null", "PGSSLROOTCERT=/dev/null"}
	// Only fixed driver-owned names can cross the consumer boundary.
	for _, name := range []string{"ZASP_SINGLE_RECOVERY_NATIVE_OWNER_DSN", "ZASP_SINGLE_RECOVERY_NATIVE_RUN", "ZASP_SINGLE_RECOVERY_NATIVE_TEMPORAL", "ZASP_SINGLE_RECOVERY_NATIVE_NAMESPACE"} {
		if value, ok := extra[name]; ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

func singleRecoveryWorkerCompileCommand(home, binary string) (*exec.Cmd, error) {
	if err := singleRecoveryCompileCacheAvailable(singleRecoveryCompileCache); err != nil {
		return nil, err
	}
	return singleRecoveryWorkerCompileCommandForCache(home, binary, singleRecoveryCompileCache)
}

func singleRecoveryCompileCacheAvailable(cache string) error {
	info, err := os.Lstat(cache)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("controlled worker compile cache unavailable")
	}
	return nil
}

func singleRecoveryWorkerCompileCommandForCache(home, binary, cache string) (*exec.Cmd, error) {
	env := singleRecoveryChildEnvironment(home, nil)
	original := "GOCACHE=" + filepath.Join(home, "go-build")
	replaced := 0
	for i, entry := range env {
		if entry == original {
			env[i] = "GOCACHE=" + cache
			replaced++
		}
	}
	if replaced != 1 {
		return nil, errors.New("controlled worker compile environment refused")
	}
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "test", "-mod=readonly", "-p=1", "-c", "-o", binary, "./agentsec-worker")
	cmd.Dir = ".."
	cmd.Env = env
	return cmd, nil
}

func singleRecoveryCompileFailure(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return errors.New("worker test compilation deadline")
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return errors.New("worker test compilation canceled")
	}
	return errors.New("worker test compilation failed")
}

// URL parsing here has no filesystem side effects. Explicit empty TLS fields
// are required: pgx ignores empty environment values, and reads root CA content
// before its sslmode switch. Do this before the starter's first readiness parse.
func singleRecoveryOwnedDSN(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Path != "/postgres" || u.Fragment != "" || u.User == nil || u.User.Username() != "zasp_test" {
		return "", errors.New("owned PostgreSQL identity required")
	}
	if _, present := u.User.Password(); present {
		return "", errors.New("fixture must not supply credentials")
	}
	if err = singleRecoveryOwnedEndpoint(u.Host); err != nil {
		return "", err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) != 1 || len(q["sslmode"]) != 1 || q.Get("sslmode") != "disable" {
		return "", errors.New("unexpected fixture DSN settings")
	}
	for _, key := range []string{"sslrootcert", "sslcert", "sslkey", "password"} {
		q.Set(key, "")
	}
	q.Set("passfile", "/dev/null")
	q.Set("servicefile", "/dev/null")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func singleRecoveryIsolateParent(t *testing.T, home string) {
	t.Helper()
	// Clear all pgx5.10 environment inputs before applying this fixture's values.
	for _, name := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGCHANNELBINDING", "PGREQUIREAUTH"} {
		t.Setenv(name, "")
	}
	for _, entry := range singleRecoveryChildEnvironment(home, nil) {
		name, value, _ := strings.Cut(entry, "=")
		if name == "HOME" || strings.HasPrefix(name, "XDG_") || strings.HasPrefix(name, "PG") {
			t.Setenv(name, value)
		}
	}
}

func singleRecoveryStartTemporal(ctx context.Context, owned *auditHTTPFixtureOwner) (string, string, client.Client, func(context.Context) error, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", "", nil, nil, err
	}
	endpoint := listener.Addr().String()
	if err = listener.Close(); err != nil {
		return "", "", nil, nil, err
	}
	if err = singleRecoveryOwnedEndpoint(endpoint); err != nil {
		return "", "", nil, nil, err
	}
	_, port, _ := net.SplitHostPort(endpoint)
	namespace := "zasp-single-recovery-" + filepath.Base(owned.root)[len("zasp-http-fixture-"):]
	command := exec.Command(singleRecoveryTemporalPath, "server", "start-dev", "--ip", "127.0.0.1", "--port", port, "--headless", "--db-filename", filepath.Join(owned.root, "temporal.sqlite"), "--namespace", namespace)
	command.Env = singleRecoveryChildEnvironment(filepath.Join(owned.root, "home"), nil)
	serverCtx, stop := context.WithCancel(context.Background())
	result := make(chan error, 1)
	var temporalClient client.Client
	var closed bool
	var closeErr error
	close := func(cleanup context.Context) error {
		if closed {
			return closeErr
		}
		closed = true
		if temporalClient != nil {
			temporalClient.Close()
		}
		stop()
		select {
		case err := <-result:
			if !singleRecoveryJoinedCancellation(err) {
				closeErr = errors.New("Temporal termination/join uncertain")
			}
		case <-cleanup.Done():
			closeErr = errors.New("Temporal bounded join failed")
		}
		if closeErr != nil {
			owned.retained = errors.Join(owned.retained, closeErr)
		}
		return closeErr
	}
	owned.processes = append(owned.processes, auditHTTPFixtureClose{"owned recovery Temporal", close})
	go func() { _, err := testprocess.Run(serverCtx, command); result <- err }()
	ready, readyCancel := context.WithTimeout(ctx, 20*time.Second)
	defer readyCancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ready.Done():
			return endpoint, namespace, nil, close, errors.New("owned Temporal readiness timeout")
		case err := <-result:
			result <- err
			return endpoint, namespace, nil, close, errors.New("owned Temporal exited before readiness")
		case <-ticker.C:
			attempt, cancel := context.WithTimeout(ready, time.Second)
			c, err := client.DialContext(attempt, client.Options{HostPort: endpoint, Namespace: namespace})
			if err == nil {
				_, err = c.WorkflowService().DescribeNamespace(attempt, &workflowservice.DescribeNamespaceRequest{Namespace: namespace})
				if err == nil {
					cancel()
					temporalClient = c
					return endpoint, namespace, c, close, nil
				}
				c.Close()
			}
			cancel()
		}
	}
}
func singleRecoveryJoinedCancellation(err error) bool {
	if err == nil {
		return true
	}
	if group, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range group.Unwrap() {
			if !singleRecoveryJoinedCancellation(e) {
				return false
			}
		}
		return true
	}
	if err == context.Canceled {
		return true
	}
	if e, ok := err.(*exec.ExitError); ok {
		if e.ProcessState == nil {
			return false
		}
		status, ok := e.ProcessState.Sys().(syscall.WaitStatus)
		return ok && status.Signaled() && (status.Signal() == syscall.SIGTERM || status.Signal() == syscall.SIGKILL)
	}
	// testprocess wraps the exit result; other ownership failures remain refusal.
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return singleRecoveryJoinedCancellation(one.Unwrap())
	}
	return false
}

func singleRecoveryInstall(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) (*migrations.Runner, map[string]any) {
	t.Helper()
	installAutomaticSourceFixture(t, ctx, owner)
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: owner})
	if err != nil {
		t.Fatal("migration runner")
	}
	if err = runner.UpProductionTemporalFindingResponse(ctx); err != nil {
		t.Fatal("finding predecessor")
	}
	if _, err = owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN; CREATE ROLE worker_test_compensation LOGIN;
SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation');
UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;
UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
		t.Fatal("registered fixture principals")
	}
	seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
	cfg := owner.Config().Copy()
	cfg.User = "worker_test_executor"
	executor, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("executor")
	}
	defer executor.Close(ctx)
	authority, identity := orderedResourceGo(t, api, o, w, e, actor)
	manualSource, ok := authority.repository.database.(*PostgresJSONDatabase)
	if !ok {
		t.Fatal("manual admission diagnostic source")
	}
	manualDatabase, manualDiagnostic := wrapSingleRecoveryManualAdmissionDatabase(manualSource)
	repository := &PostgresRepository{database: manualDatabase, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
	for i, run := range []string{singleRecoveryOriginalRun, singleRecoveryForwardRun} {
		suffix := i * 10
		request := SecurityAgentRunRequest{DefinitionID: temporalTestLegacyProved, ExpectedVersion: 4, IdempotencyKey: fmt.Sprintf("recovery-native-original-%d", i), RunID: run, TriggerKind: "manual", AuditID: fmt.Sprintf("pid_f0807400-0000-4000-8000-%012d", suffix+2), CorrelationID: fmt.Sprintf("pid_f0807400-0000-4000-8000-%012d", suffix+3), ReceiptID: fmt.Sprintf("pid_f0807400-0000-4000-8000-%012d", suffix+4)}
		receipt, err := repository.runSecurityAgentManual(ctx, identity, request)
		if err != nil || receipt.ID != run {
			t.Fatal("actual distinct manual admission", manualDiagnostic.summary(err, err == nil && receipt.ID == run))
		}
		var takeover json.RawMessage
		if err = executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run).Scan(&takeover); err != nil || string(takeover) == "null" {
			t.Fatal("actual takeover")
		}
	}
	adminCfg := owner.Config().Copy()
	adminCfg.User = "security_agent_v33_discovery_api_login"
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal("pricing API")
	}
	defer admin.Close(ctx)
	policy := orderedPricingAdminRequest(o, w, e, actor)
	bindTemporalTestPlannerPricing(policy)
	pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
	if err != nil {
		t.Fatal("planner pricing")
	}
	selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
	for _, up := range []func(context.Context) error{runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile, runner.UpProductionTemporalSingleRecovery, runner.UpProductionTemporalSingleRecovery} {
		if err = up(ctx); err != nil {
			t.Fatal("real profile installation/replay")
		}
	}
	singleRecoveryInstallationDrift(t, ctx, owner, runner)
	human := authorizationFixtureAttestor(t)
	if _, err = owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, human.Version(), human.Verifier()); err != nil {
		t.Fatal("actual human verifier registration")
	}
	if _, err = owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest($1,'sha256'),$2,$3,$4,$5,$6,'[]',repeat('r',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, singleRecoveryBrowser, singleRecoveryBrowserSessionID, actor, o, w, e); err != nil {
		t.Fatal("controlled current browser identity")
	}
	return runner, selection
}

type singleRecoveryNestedMigrationDB struct{ tx pgx.Tx }

func (d *singleRecoveryNestedMigrationDB) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	return d.tx.QueryRow(ctx, q, args...)
}
func (d *singleRecoveryNestedMigrationDB) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &integrationMigrationTransaction{transaction: tx}, nil
}
func singleRecoveryInstallationDrift(t *testing.T, ctx context.Context, owner *pgx.Conn, runner *migrations.Runner) {
	for _, mutation := range []string{`ALTER FUNCTION zasp_temporal_single_recovery.ready(text) SET search_path TO pg_catalog`, `GRANT EXECUTE ON FUNCTION zasp_temporal_single_recovery.value(text,text,text,text) TO PUBLIC`} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal("drift transaction")
		}
		func() {
			defer func() {
				rollback, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := tx.Rollback(rollback); err != nil {
					t.Error("drift rollback failed")
				}
			}()
			if _, err = tx.Exec(ctx, mutation); err != nil {
				t.Fatal("fixed drift setup")
			}
			nested, _ := migrations.NewRunner(&singleRecoveryNestedMigrationDB{tx})
			if err = nested.UpProductionTemporalSingleRecovery(ctx); err == nil {
				t.Fatal("drift accepted")
			}
		}()
		if err = runner.UpProductionTemporalSingleRecovery(ctx); err != nil {
			t.Fatal("drift rollback/replay")
		}
	}
}

func singleRecoveryPrepareOriginals(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, testID string, selection map[string]any) {
	for _, run := range []string{singleRecoveryOriginalRun, singleRecoveryForwardRun} {
		checker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
			return authorization.Decision{Allowed: q.OrganizationID == o && q.WorkspaceID == w && q.EnvironmentID == e, ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}, nil
		})
		seam := &singleRecoveryPlanningSeam{checker: checker, writer: singleRecoveryControlledTuples{}}
		seam.afterAdmission = func(forward *authorization.WorkerExecutor, poolFor func(string) *pgxpool.Pool, reconcile func()) {
			compKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
			if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), compKey.Version(), compKey.Verifier()); err != nil {
				t.Fatal("compensation verifier")
			}
			if run == singleRecoveryForwardRun {
				assertWorkerTest74SignedEffect(t, ctx, owner, poolFor("worker_test_executor"), poolFor("worker_test_compensation"), forward, o, w, e, run, false, reconcile, nil, nil, reconcile)
				return
			}
			assertWorkerTest74SignedEffect(t, ctx, owner, poolFor("worker_test_executor"), poolFor("worker_test_compensation"), forward, o, w, e, run, false, reconcile, func(linked map[string]any) bool {
				key, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
				assertWorkerTest74UnsignedAdapter(t, ctx, owner, o, w, e, run, linked, func() *authorization.WorkerExecutor {
					machine, err := authorization.NewWorkerAdapter(poolFor("ordered_test_red_adapter"), checker, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", key)
					if err != nil {
						t.Fatal("adapter machine")
					}
					return machine
				})
				compensation, err := authorization.NewWorkerExecutor(poolFor("worker_test_compensation"), nil, "", "", compKey)
				if err != nil {
					t.Fatal("captured compensation")
				}
				var q json.RawMessage
				if err = owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest,'reason','workflow_cancelled') FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&q); err != nil {
					t.Fatal("actual cleanup identity")
				}
				decision, err := compensation.Authorize(ctx, "test74.lifecycle.cleanup", q)
				if err != nil {
					t.Fatal("captured stop authorization")
				}
				if _, err = compensation.Execute(ctx, decision); err != nil {
					t.Fatal("captured stopped unknown transition")
				}
				return true
			}, nil)
		}
		copied := make(map[string]any, len(selection))
		for k, v := range selection {
			copied[k] = v
		}
		assertWorkerTest74PlanningLoadWith(t, ctx, owner, o, w, e, run, testID, copied, "recovery-driver", seam)
	}
	var exact bool
	err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.stops WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1 AND state IN('started','unknown')) AND EXISTS(SELECT 1 FROM zasp_temporal74.invocations i JOIN zasp_temporal74.effects f USING(effect_key) WHERE f.run_id=$1 AND i.state='started') AND EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$2 AND state='reserved') AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.invocations i JOIN zasp_temporal74.effects f USING(effect_key) WHERE f.run_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.commands WHERE run_id IN($1,$2)) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE run_id IN($1,$2)) AND (SELECT count(*)=2 AND bool_and(concurrency_limit=2) FROM zasp_security_agent_run_budgets WHERE run_id IN($1,$2))`, singleRecoveryOriginalRun, singleRecoveryForwardRun).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("distinct stopped-debt/reserved-original invariants")
	}
}
