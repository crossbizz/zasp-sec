package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func assertDaemonReplayContainer(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getegid() != 65532 {
		t.Fatal("requires root fixture with isolated consumer group")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	for _, path := range []string{"/tmp", "/var/run/secrets/kubernetes.io/serviceaccount"} {
		var state syscall.Statfs_t
		if syscall.Statfs(path, &state) != nil || state.Type != 0x01021994 {
			t.Fatal("requires private tmpfs", path)
		}
	}
	if entries, err := os.ReadDir("/var/run/secrets/kubernetes.io/serviceaccount"); err != nil || len(entries) != 0 {
		t.Fatal("fixture credential mount isn't empty", err)
	}
	for _, path := range []string{"/proof/apiserver.test", "/proof/sensor-agent.test", "/proof/sensor-agent"} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatal("missing fixture binary", path)
		}
	}
}

func startDaemonReplayPostgres(t *testing.T, ctx context.Context, ownership *daemonReplayOwnership) string {
	t.Helper()
	account, err := user.Lookup("postgres")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatal("invalid PostgreSQL OS identity")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	identity := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	root := ownership.root(t)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "pgdata")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(data, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	initCtx, stopInit := context.WithTimeout(ctx, 20*time.Second)
	defer stopInit()
	init := exec.CommandContext(initCtx, "/usr/lib/postgresql/18/bin/initdb", "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data)
	init.SysProcAttr, init.WaitDelay = identity, time.Second
	if output, err := init.CombinedOutput(); err != nil {
		t.Fatalf("isolated initdb: %v %s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	log, err := os.Create(filepath.Join(root, "postgres.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/lib/postgresql/18/bin/postgres", "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.SysProcAttr, command.Stdout, command.Stderr = identity, log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	t.Cleanup(func() {
		defer log.Close()
		select {
		case <-done:
			t.Error("PostgreSQL exited before owned shutdown", waitErr)
			return
		default:
		}
		stopCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		stop := exec.CommandContext(stopCtx, "/usr/lib/postgresql/18/bin/pg_ctl", "-D", data, "-m", "fast", "-w", "stop")
		stop.SysProcAttr, stop.WaitDelay = identity, time.Second
		if err := stop.Run(); err != nil {
			t.Error("bounded PostgreSQL shutdown failed", err)
			command.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("PostgreSQL required forced cleanup")
			command.Process.Kill()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("PostgreSQL wasn't joined")
			}
		}
		select {
		case <-done:
			if waitErr != nil {
				t.Error("PostgreSQL exited unsuccessfully", waitErr)
			}
		default:
			// The earlier failure also prevents owned-root deletion.
		}
	})
	dsn := fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
	waitDaemonReplay(t, initCtx, "private PostgreSQL readiness", func() bool {
		select {
		case <-done:
			t.Fatal("PostgreSQL exited before readiness")
		default:
		}
		attempt, cancel := context.WithTimeout(initCtx, time.Second)
		defer cancel()
		connection, err := pgx.Connect(attempt, dsn)
		if err != nil {
			return false
		}
		connection.Close(attempt)
		return true
	})
	return dsn
}

func migrateDaemonReplayDatabase(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	runner := migrateToTypedInventoryCutover(t, ctx, admin)
	for _, up := range []func(context.Context) error{
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution, runner.UpProductionRecovery,
		runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility,
		runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook,
		runner.UpProductionRuntimeQueueReplay, runner.UpProductionRedTeamSafety, runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts,
		runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery,
		runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan,
		runner.UpProductionRuntimeCandidateAuthority, runner.UpProductionRuntimeAcceptance,
	} {
		if err := up(ctx); err != nil {
			t.Fatal("actual release migration", err)
		}
	}
	if version, err := runner.Version(ctx); err != nil || version != 48 {
		t.Fatal("wrong release schema", version, err)
	}
	names := []string{"runtime_http_api", "runtime_http_discovery", "runtime_http_ingest", "runtime_http_worker", "runtime_http_outbox", "runtime_http_gateway"}
	for _, name := range names {
		if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			t.Fatal(err)
		}
	}
	var registered bool
	if err := admin.QueryRow(ctx, `SELECT zasp_discovery_register_principals(session_user,$1,$2,$3,$4,$5,$6)`, names[0], names[1], names[2], names[3], names[4], names[5]).Scan(&registered); err != nil || !registered {
		t.Fatal("register exact fixture principals", err)
	}
}

func invokeDaemonReplayProducerFixture(t *testing.T, ctx context.Context, root string, config installedChunkChildConfig, action string) installedChunkChildResult {
	t.Helper()
	config.Action = action
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "fixture.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, "/proof/sensor-agent.test", "-test.run=^TestInstalledLineageConsumerProcess$", "-test.count=1")
	command.Env = []string{"PATH=/usr/bin:/bin", "ZASP_LINEAGE_CONSUMER_FIXTURE=" + path, "GOMEMLIMIT=128MiB"}
	command.WaitDelay = time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("producer fixture %s: %v %s", action, err, output)
	}
	raw, err = os.ReadFile(config.ResultPath)
	var result installedChunkChildResult
	if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid producer fixture result", err)
	}
	return result
}

type replayDaemonProcess struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
	log     *os.File
	joined  bool
}

func startReplayDaemon(t *testing.T, ctx context.Context, root string, config installedChunkChildConfig, name string) *replayDaemonProcess {
	t.Helper()
	command := exec.CommandContext(ctx, "/proof/sensor-agent")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	command.Env = []string{"PATH=/usr/bin:/bin", "GOMEMLIMIT=96MiB", "SSL_CERT_FILE=" + config.CAPath,
		"ZASP_SENSOR_ROLE=lineage-consumer", "ZASP_SENSOR_TOKEN_SOURCE=owned-file", "ZASP_SENSOR_ENROLLMENT_BINDING=" + config.Source.EnrollmentBinding,
		"ZASP_SENSOR_CONTROL_PLANE_URL=" + config.Endpoint, "ZASP_SENSOR_TOKEN_FILE=" + config.TokenPath,
		"ZASP_LINEAGE_SPOOL_DIRECTORY=" + config.SpoolPath, "ZASP_LINEAGE_ACK_DIRECTORY=" + config.AckPath, "ZASP_LINEAGE_STATE_DIRECTORY=" + filepath.Dir(config.CursorPath),
		"ZASP_SENSOR_NAMESPACE=agentsec", "ZASP_SENSOR_POD_NAME=sensor-agent-a", "ZASP_SENSOR_NODE_NAME=" + config.Source.NodeName,
		"ZASP_SENSOR_KERNEL_FILE=" + filepath.Join(root, "kernel", "value"), "ZASP_SENSOR_BTF_FILE=" + filepath.Join(root, "btf", "value"),
		"ZASP_TETRAGON_METRICS_URL=http://127.0.0.1:2112/metrics", "ZASP_SENSOR_BATCH_SIZE=100", "ZASP_SENSOR_MAX_PROCESSES=10000",
		"ZASP_SENSOR_POLL_INTERVAL=100ms", "ZASP_SENSOR_OPERATION_TIMEOUT=2s", "ZASP_SENSOR_SHUTDOWN_TIMEOUT=5s", "ZASP_SENSOR_LEASE_DURATION=15s", "ZASP_SENSOR_REPORT_TTL=30s",
		"KUBERNETES_SERVICE_HOST=127.0.0.1", "KUBERNETES_SERVICE_PORT=443"}
	log, err := os.Create(filepath.Join(root, name+"-daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout, command.Stderr, command.WaitDelay = log, log, time.Second
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	process := &replayDaemonProcess{command: command, done: make(chan struct{}), log: log}
	go func() { process.err = command.Wait(); close(process.done) }()
	t.Cleanup(func() { process.stop(t) })
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", command.Process.Pid))
	if err != nil || !bytes.Contains(status, []byte("Uid:\t65532\t65532\t65532\t65532")) || !bytes.Contains(status, []byte("Gid:\t65532\t65532\t65532\t65532")) || !bytes.Contains(status, []byte("CapEff:\t0000000000000000")) {
		t.Fatal("daemon identity/capabilities not isolated", err)
	}
	return process
}

func (process *replayDaemonProcess) stop(t *testing.T) {
	t.Helper()
	if process.joined {
		return
	}
	process.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-process.done:
	case <-time.After(7 * time.Second):
		process.command.Process.Kill()
		select {
		case <-process.done:
		case <-time.After(2 * time.Second):
			t.Error("daemon wasn't joined after KILL")
			return
		}
	}
	process.joined = true
	process.log.Close()
	if process.err != nil {
		t.Error("actual daemon exited unsuccessfully", process.err)
	}
}

func waitDaemonReplay(t *testing.T, ctx context.Context, label string, ready func() bool) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("deadline waiting for " + label)
		case <-ticker.C:
		}
	}
}

func daemonReplaySourceSnapshot(t *testing.T, path string) string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot strings.Builder
	for _, entry := range entries {
		name := filepath.Join(path, entry.Name())
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			t.Fatal("invalid bounded source file", err)
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		fmt.Fprintf(&snapshot, "%s:%o:%d:%d:%x\n", entry.Name(), info.Mode(), stat.Dev, stat.Ino, sha256.Sum256(raw))
	}
	return snapshot.String()
}

// Unlike t.TempDir, this owner preserves state after any failed assertion or
// unconfirmed process join. Successful cleanup validates the original root.
type daemonReplayOwnedRoot struct {
	path     string
	identity os.FileInfo
}

type daemonReplayOwnership struct{ roots []daemonReplayOwnedRoot }

func (ownership *daemonReplayOwnership) root(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "zasp-daemon-replay-")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	ownership.roots = append(ownership.roots, daemonReplayOwnedRoot{path: root, identity: info})
	return root
}

type daemonReplayCleanupReport interface {
	Helper()
	Failed() bool
	Log(...any)
	Error(...any)
}

func (ownership *daemonReplayOwnership) cleanup(t daemonReplayCleanupReport) {
	t.Helper()
	if t.Failed() {
		for _, root := range ownership.roots {
			t.Log("preserved failed fixture state within the isolated container", root.path)
		}
		return
	}
	for _, root := range ownership.roots {
		current, err := os.Lstat(root.path)
		if err != nil || !current.IsDir() || !os.SameFile(root.identity, current) || filepath.Dir(root.path) != "/tmp" || !strings.HasPrefix(filepath.Base(root.path), "zasp-daemon-replay-") {
			t.Error("owned fixture root changed; refusing cleanup", err)
			return
		}
	}
	for _, root := range ownership.roots {
		if err := os.RemoveAll(root.path); err != nil {
			t.Error("owned fixture cleanup", err)
			return
		}
	}
}
