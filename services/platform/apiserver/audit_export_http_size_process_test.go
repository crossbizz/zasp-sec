//go:build darwin || linux

package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

func TestAuditHTTPSizeProcessInputs(t *testing.T) {
	good := "postgres://invocation_discovery_api@127.0.0.1:15432/zasp?sslmode=disable"
	for _, tc := range []struct{ dsn, address, control string }{
		{strings.Replace(good, "127.0.0.1", "203.0.113.1", 1), "127.0.0.1:14443", ""},
		{good + "&host=127.0.0.1,203.0.113.1", "127.0.0.1:14443", ""},
		{strings.Replace(good, "invocation_discovery_api", "postgres", 1), "127.0.0.1:14443", ""},
		{good, "localhost:14443", ""}, {good, "127.0.0.1:014443", ""}, {good, "127.0.0.1:14443", "worker-retain"},
	} {
		if auditHTTPSizeAPIInputs(tc.dsn, tc.address, tc.control) == nil {
			t.Error("unsafe child input accepted")
		}
	}
	if err := auditHTTPSizeAPIInputs(good, "127.0.0.1:14443", ""); err != nil {
		t.Fatal(err)
	}
}

func TestAuditHTTPSizeProcessProtocol(t *testing.T) {
	for _, raw := range []string{"", `{"pid":1}`, "{\"pid\":1,\"url\":\"http://203.0.113.1:80\",\"mode\":\"api\"}\n", "{\"pid\":1,\"url\":\"http://127.0.0.1:80\",\"mode\":\"api\",\"extra\":true}\n", strings.Repeat("x", 4097)} {
		if _, err := auditHTTPSizeReadRecord(strings.NewReader(raw), "api", false); err == nil {
			t.Error("malformed or early EOF readiness accepted")
		}
	}
	valid := "{\"pid\":123,\"url\":\"http://127.0.0.1:14443\",\"mode\":\"api\"}\n"
	if _, err := auditHTTPSizeReadRecord(strings.NewReader(valid), "api", false); err != nil {
		t.Fatal(err)
	}
	if _, err := auditHTTPSizeReadRecord(strings.NewReader("{\"pid\":123,\"url\":\"cleanup-complete\",\"mode\":\"api\"}\n"), "api", true); err != nil {
		t.Fatal(err)
	}
}

func TestAuditHTTPSizeProcessTerminalTail(t *testing.T) {
	terminal := "{\"pid\":123,\"url\":\"cleanup-complete\",\"mode\":\"api\"}\n"
	for _, tail := range []string{"x", terminal, "\n"} {
		if _, err := auditHTTPSizeReadTerminal(strings.NewReader(terminal+tail), "api"); err == nil {
			t.Error("buffered trailing terminal data accepted")
		}
	}
	if _, err := auditHTTPSizeReadTerminal(strings.NewReader(terminal), "api"); err != nil {
		t.Fatal(err)
	}
}

func auditHTTPSizeReadTerminal(r io.Reader, mode string) (auditHTTPSizeRecord, error) {
	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(r, 4096)
	}
	record, err := auditHTTPSizeReadRecord(reader, mode, true)
	if err != nil {
		return record, err
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return record, errors.New("trailing terminal protocol data")
	}
	return record, nil
}

func TestAuditHTTPSizeProcessPrivateFiles(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.pem")
	if err := os.WriteFile(valid, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := auditHTTPSizePrivateFile(valid, 16); err != nil || string(raw) != "owned" {
		t.Fatal("private input rejected", err)
	}
	for _, name := range []string{"empty", "oversize", "public", "symlink", "missing"} {
		path := filepath.Join(root, name)
		switch name {
		case "empty":
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
		case "oversize":
			if err := os.WriteFile(path, []byte(strings.Repeat("x", 17)), 0600); err != nil {
				t.Fatal(err)
			}
		case "public":
			if err := os.WriteFile(path, []byte("ca"), 0644); err != nil {
				t.Fatal(err)
			}
		case "symlink":
			if err := os.Symlink(valid, path); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := auditHTTPSizePrivateFile(path, 16); err == nil {
			t.Fatal("unsafe private input accepted", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, cleanup, err := auditHTTPSizeAPIFactory(ctx, "postgres://invocation_discovery_api@127.0.0.1:1/zasp?sslmode=disable", "127.0.0.1:14443", valid, []byte(strings.Repeat("h", 32)))
	if err == nil || err.Error() != "invalid owned CA" {
		t.Fatal("malformed CA reached database construction", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditHTTPSizeProcessEnvironment(t *testing.T) {
	for _, key := range []string{"ZASP_OLD_FAULT", "PGHOST", "AWS_PROFILE", "HTTPS_PROXY", "http_proxy", "GODEBUG", "GORACE", "GOGC", "GOMEMLIMIT", "GOMAXPROCS"} {
		t.Setenv(key, "ambient-fixture")
	}
	for _, entry := range auditHTTPSizeEnvironment() {
		if strings.HasSuffix(entry, "=ambient-fixture") {
			t.Fatal("ambient process authority survived")
		}
	}
}

func TestAuditHTTPSizeProcessStartFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	started := time.Now()
	c, err := startAuditHTTPSizeAPI(ctx, filepath.Join(t.TempDir(), "absent-binary"), "postgres://invocation_discovery_api@127.0.0.1:1/zasp?sslmode=disable", "127.0.0.1:14443", "/absent-ca", "")
	if c != nil {
		cleanup, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		_, _ = c.Stop(cleanup)
	}
	if err == nil || c == nil || c.result == nil || time.Since(started) > 5*time.Second {
		t.Fatal("early runner failure did not close/join protocol readers", err)
	}
}

// A runner boundary can return an error while its sole background owner still
// waits. No numeric process control is introduced by this deterministic control.
func TestAuditHTTPSizeProcessBackgroundOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	backgroundDone, release := make(chan struct{}), make(chan struct{})
	go func() { <-release; close(backgroundDone) }()
	defer func() { close(release); <-backgroundDone }()
	run := func(context.Context, *exec.Cmd) ([]byte, error) {
		return nil, errors.New("owned worker direct child reap incomplete")
	}
	child, err := startAuditHTTPSizeAPIWithRunner(ctx, "unused-binary", "postgres://invocation_discovery_api@127.0.0.1:1/zasp?sslmode=disable", "127.0.0.1:14443", "/unused-ca", "", run)
	if err == nil || child == nil {
		t.Fatal("background ownership control unavailable")
	}
	cleanup, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	_, err = child.Stop(cleanup)
	if err == nil || child.result == nil || child.joined {
		t.Fatal("nonnil error result counted as proven join")
	}
	select {
	case <-backgroundDone:
		t.Fatal("control background owner already exited")
	default:
	}
	closed := false
	o := &auditHTTPFixtureOwner{processes: []auditHTTPFixtureClose{{"error-result child", func(context.Context) error {
		if !child.joined {
			return errors.New("unproven child")
		}
		return nil
	}}}, resources: []auditHTTPFixtureClose{{"borrowed SQL", func(context.Context) error { closed = true; return nil }}}}
	if o.Close(cleanup) == nil || closed {
		t.Fatal("startup error destroyed resources still borrowed by background owner")
	}
}

// The observation stays attached to its fixture owner after a caller timeout.
// Only Run owns process observation, signaling and Wait. Callers only receive
// its one buffered result; repeated observation never starts another process.
type auditHTTPSizeStopObservation struct {
	owner   *auditHTTPFixtureOwner
	command *exec.Cmd
	after   func()
	done    chan auditHTTPSizeRunResult
	result  *auditHTTPSizeRunResult
}

func (o *auditHTTPSizeStopObservation) Observe(ctx context.Context) (*auditHTTPSizeRunResult, error) {
	if o.result != nil {
		return o.result, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.done == nil {
		o.done = make(chan auditHTTPSizeRunResult, 1)
		go func() {
			output, err := testprocess.Run(ctx, o.command)
			if o.after != nil {
				o.after()
			}
			o.done <- auditHTTPSizeRunResult{output, err}
		}()
	}
	select {
	case r := <-o.done:
		o.result = &r
		return o.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestAuditHTTPSizePostgresStopLateBudget(t *testing.T) {
	t.Run("expired-admission", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		o := &auditHTTPSizeStopObservation{command: exec.Command("/bin/sh", "-c", "exit 0")}
		if _, err := o.Observe(ctx); err == nil || o.done != nil {
			t.Fatal("expired cleanup admitted a stop runner")
		}
	})
	t.Run("late-owned-result", func(t *testing.T) {
		root, err := os.MkdirTemp("", "zasp-http-late-stop-control-")
		if err != nil {
			t.Fatal(err)
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			_ = os.RemoveAll(root)
			t.Fatal(err)
		}
		ready := make(chan error, 1)
		go func() {
			var b [6]byte
			_, err := io.ReadFull(reader, b[:])
			if err == nil && string(b[:]) != "ready\n" {
				err = errors.New("unexpected shell readiness")
			}
			ready <- err
		}()
		command := exec.Command("/bin/sh", "-c", "trap '' TERM; printf 'ready\\n' >&3; while :; do :; done")
		command.ExtraFiles = []*os.File{writer}
		owner := &auditHTTPFixtureOwner{root: root}
		observation := &auditHTTPSizeStopObservation{owner: owner, command: command, after: func() { _ = writer.Close() }}
		owner.resources = []auditHTTPFixtureClose{
			{"control root", func(context.Context) error { return os.RemoveAll(root) }},
			{"stop runner", func(ctx context.Context) error {
				r, err := observation.Observe(ctx)
				if err != nil {
					return err
				}
				return r.err
			}},
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		started := time.Now()
		err = owner.Close(cleanup)
		elapsed := time.Since(started)
		cancel()
		if err == nil || elapsed > 180*time.Millisecond {
			t.Errorf("stop caller overran 100ms aggregate budget: elapsed=%s error=%v", elapsed, err)
		}
		if observation.result != nil {
			t.Error("caller waited for the late stop result")
		}
		if _, err := os.Stat(root); err != nil || observation.owner != owner {
			t.Error("late stop lost exact owner/root", err)
		}
		late, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		r, err := observation.Observe(late)
		if err != nil {
			_ = reader.Close()
			<-ready
			t.Fatalf("control result uncertain; retaining root=%s and sole runner: %v", root, err)
		}
		if err := <-ready; err != nil {
			t.Error("TERM-ignore shell was not ready", err)
		}
		_ = reader.Close()
		// Test-owned cancellation only: the exact two-leaf error is the shared
		// runner's final joined return, not an unclassified background error.
		joined := false
		if multi, ok := r.err.(interface{ Unwrap() []error }); ok {
			leaves := multi.Unwrap()
			if len(leaves) == 2 && leaves[0] == context.DeadlineExceeded {
				if exit, ok := leaves[1].(*exec.ExitError); ok {
					if status, ok := exit.Sys().(syscall.WaitStatus); ok {
						joined = status.Signaled() && status.Signal() == syscall.SIGKILL
					}
				}
			}
		}
		if !joined {
			t.Fatalf("control join uncertain; retaining root=%s: %v", root, r.err)
		}
		if again, err := observation.Observe(late); err != nil || again != r {
			t.Fatal("late result did not remain owned without another runner", err)
		}
		if _, err := os.Stat(root); err != nil || owner.Close(late) == nil {
			t.Fatal("late result incorrectly promoted refused fixture cleanup", err)
		}
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
		t.Logf("late stop: caller=%s result=%s; exact canceled/KILL control joined; refused owner retained root until explicit control disposal", elapsed, time.Since(started))
	})
}

type auditHTTPPostgresIsolation struct {
	environment []string
	dsn         func(string) (string, error)
}

func auditHTTPSizeStartPostgres(t *testing.T, ctx context.Context, owner *auditHTTPFixtureOwner, username string, isolation ...auditHTTPPostgresIsolation) string {
	t.Helper()
	if len(isolation) > 1 {
		t.Fatal("one PostgreSQL isolation setting required")
	}
	var isolated auditHTTPPostgresIsolation
	if len(isolation) == 1 {
		isolated = isolation[0]
		if len(isolated.environment) == 0 || isolated.dsn == nil {
			t.Fatal("complete PostgreSQL isolation required")
		}
	}
	initdb, e1 := exec.LookPath("initdb")
	postgres, e2 := exec.LookPath("postgres")
	pgCtl, e3 := exec.LookPath("pg_ctl")
	if e1 != nil || e2 != nil || e3 != nil {
		t.Fatal("required owned PostgreSQL executable missing")
	}
	data := filepath.Join(owner.root, "postgres-data")
	var command *exec.Cmd
	var result chan auditHTTPSizeRunResult
	var serverCancel context.CancelFunc
	stopObservation := &auditHTTPSizeStopObservation{owner: owner, command: exec.Command(pgCtl, "-D", data, "-m", "fast", "-w", "-t", "5", "stop")}
	stopObservation.command.Env = isolated.environment
	// Registered before initdb, listen reservation or server startup can fail.
	owner.resources = append(owner.resources, auditHTTPFixtureClose{"PostgreSQL stop/join", func(cleanup context.Context) error {
		if command == nil {
			return nil
		}
		stopCtx, stop := context.WithTimeout(cleanup, 5*time.Second)
		stopResult, stopErr := stopObservation.Observe(stopCtx)
		stop()
		if stopErr == nil {
			stopErr = stopResult.err
		}
		if stopErr != nil {
			return fmt.Errorf("owned PostgreSQL stop refused: %w", stopErr)
		}
		select {
		case r := <-result:
			if r.err != nil {
				return r.err
			}
			serverCancel()
			t.Logf("joined owned PostgreSQL pid=%d root=%s", command.Process.Pid, owner.root)
			return nil
		case <-cleanup.Done():
			return errors.New("PostgreSQL runner join uncertain")
		}
	}})
	buildCtx, stop, err := auditHTTPSizePhase(ctx, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	initialize := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username="+username, "-D", data)
	initialize.Env = isolated.environment
	_, err = testprocess.Run(buildCtx, initialize)
	stop()
	if err != nil {
		owner.retained = errors.New("initdb process ownership not proven")
		t.Fatal("bounded initdb", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Env = isolated.environment
	// Deliberately independent of fixture cancellation. Unknown borrowers retain
	// the live server, data and sole Run owner until explicit operator cleanup.
	serverCtx, cancel := context.WithCancel(context.Background())
	serverCancel = cancel
	result = make(chan auditHTTPSizeRunResult, 1)
	go func() {
		output, err := testprocess.Run(serverCtx, command)
		result <- auditHTTPSizeRunResult{output, err}
	}()
	dsn := fmt.Sprintf("postgres://%s@127.0.0.1:%d/postgres?sslmode=disable", username, port)
	if isolated.dsn != nil {
		dsn, err = isolated.dsn(dsn)
		if err != nil {
			t.Fatal("owned PostgreSQL DSN isolation")
		}
	}
	readyCtx, done, err := auditHTTPSizePhase(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		probeCtx, stop := context.WithTimeout(readyCtx, 250*time.Millisecond)
		conn, e := pgx.Connect(probeCtx, dsn)
		stop()
		if e == nil {
			closeCtx, closeStop := context.WithTimeout(readyCtx, time.Second)
			e = conn.Close(closeCtx)
			closeStop()
			if e != nil {
				owner.retained = errors.New("readiness connection close failed")
				t.Fatal(e)
			}
			t.Logf("owned PostgreSQL ready: root=%s", owner.root)
			return dsn
		}
		select {
		case r := <-result:
			result <- r
			if r.err != nil {
				owner.retained = errors.New("PostgreSQL startup result has unproven ownership")
			}
			t.Fatal("PostgreSQL exited before readiness", r.err)
		case <-readyCtx.Done():
			t.Fatal("bounded PostgreSQL readiness", readyCtx.Err())
		case <-tick.C:
		}
	}
}

func TestAuditHTTPFixtureLifetimeDefaultAndOwnedPostgres(t *testing.T) {
	for _, name := range []string{"initdb", "postgres", "pg_ctl"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("required PostgreSQL executable", name)
		}
	}
	var defaultRoot string
	t.Run("ordinary-default", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_test"))
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&defaultRoot); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Stat(defaultRoot); !os.IsNotExist(err) {
		t.Fatal("ordinary default fixture cleanup changed")
	}
	var ownedRoot string
	t.Run("owner-before-child-failure", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		ctx, owner := newAuditHTTPFixtureOwner(t, ctx, "", nil)
		owner.startPostgres = func(t *testing.T, ctx context.Context, user string) string {
			return auditHTTPSizeStartPostgres(t, ctx, owner, user)
		}
		dsn := startDisposablePostgresAs(t, "zasp_test", ctx)
		ownedRoot = owner.root
		cancel()
		// Simulate operation failure before API/worker startup. Canceling fixture
		// work must not kill the PG server before the owner closes its resources.
		probe, stop := context.WithTimeout(context.Background(), time.Second)
		conn, err := pgx.Connect(probe, dsn)
		if err != nil {
			stop()
			t.Fatal("fixture cancellation killed retained server", err)
		}
		if err := conn.Close(probe); err != nil {
			t.Fatal(err)
		}
		stop()
	})
	if _, err := os.Stat(ownedRoot); !os.IsNotExist(err) {
		t.Fatal("owner failed pre-child PostgreSQL/root cleanup")
	}
}

func TestAuditHTTPFixtureLifetimeRetainsLivePostgres(t *testing.T) {
	for _, name := range []string{"initdb", "postgres", "pg_ctl"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("required PostgreSQL executable", name)
		}
	}
	root, err := os.MkdirTemp("", "zasp-http-live-retention-control-")
	if err != nil {
		t.Fatal(err)
	}
	owner := &auditHTTPFixtureOwner{root: root, resources: []auditHTTPFixtureClose{{"root", func(context.Context) error { return os.RemoveAll(root) }}}}
	// This control expects refusal. Its separate test cleanup acts only after
	// both controlled borrowers have joined; it does not change owner's result.
	releaseBorrowers := func() {}
	t.Cleanup(func() {
		releaseBorrowers()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for i := len(owner.resources) - 1; i >= 0; i-- {
			if err := owner.resources[i].close(ctx); err != nil {
				t.Error(err)
				return
			}
		}
		t.Log("released control borrowers, then explicitly cleaned retained PG/root")
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, auditHTTPFixtureContextKey{}, owner)
	dsn := auditHTTPSizeStartPostgres(t, ctx, owner, "zasp_test")
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	auditHTTPFixtureOwnConnection(ctx, "held ACK connection", conn)
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	lifetime := newAuditHTTPHandlerLifetime(context.Background())
	go func() {
		defer close(joined)
		lifetime.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://127.0.0.1/ack", nil))
	}()
	<-entered
	releaseBorrowers = func() { close(release); <-joined }
	owner.processes = append(owner.processes, auditHTTPFixtureClose{"unproven background runner", func(context.Context) error { return errors.New("background owner still active") }})
	owner.handlers = append(owner.handlers, auditHTTPFixtureClose{"held ACK handler", lifetime.Close})
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = owner.Close(cleanup)
	stop()
	if err == nil {
		t.Fatal("unjoined borrowers accepted")
	}
	if conn.IsClosed() {
		t.Fatal("held ACK connection closed")
	}
	if _, err := os.Stat(filepath.Join(root, "postgres-data")); err != nil {
		t.Fatal("retained PostgreSQL root lost", err)
	}
	probe, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := conn.Ping(probe); err != nil {
		t.Fatal("fixture cancellation/uncertain join killed PostgreSQL", err)
	}
	t.Logf("refused cleanup retained live PG, borrowed connection, and data root=%s", root)
}

type auditHTTPSizeRecord struct {
	PID           int    `json:"pid"`
	URL           string `json:"url"`
	Mode          string `json:"mode"`
	RetainedBytes int64  `json:"retained_bytes,omitempty"`
	SelfRSSBytes  int64  `json:"self_rss_bytes,omitempty"`
}

func auditHTTPSizeAPIInputs(dsn, address, control string) error {
	c, err := pgx.ParseConfig(dsn)
	local := func(s string) bool {
		ip := net.ParseIP(s)
		return s == "localhost" || filepath.IsAbs(s) || ip != nil && ip.IsLoopback()
	}
	if err != nil || dsn == "" || c.User != "invocation_discovery_api" || !local(c.Host) || control != "" && control != "api-retain" && control != "diagnostics" {
		return errors.New("invalid API fixture inputs")
	}
	for _, f := range c.Fallbacks {
		if !local(f.Host) {
			return errors.New("nonlocal API fallback")
		}
	}
	return auditHTTPSizeAddress(address)
}
func auditHTTPSizeAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || net.JoinHostPort(ip.String(), port) != address {
		return errors.New("invalid loopback address")
	}
	return nil
}
func auditHTTPSizeReadRecord(r io.Reader, mode string, terminal bool) (auditHTTPSizeRecord, error) {
	var record auditHTTPSizeRecord
	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(r, 4096)
	}
	raw, err := reader.ReadSlice('\n')
	if err != nil || len(raw) > 4096 {
		return record, errors.New("invalid framed record")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(&struct{}{}) != io.EOF || record.PID < 1 || record.Mode != mode {
		return record, errors.New("invalid record identity")
	}
	// Reject duplicate/missing fields as well as unknown fields.
	var fields map[string]json.RawMessage
	canonical, _ := json.Marshal(record)
	if json.Unmarshal(raw, &fields) != nil || record.RetainedBytes < 0 || record.SelfRSSBytes < 0 || !terminal && (record.RetainedBytes != 0 || record.SelfRSSBytes != 0) || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return record, errors.New("noncanonical record")
	}
	if terminal {
		if record.URL != "cleanup-complete" {
			return record, errors.New("missing cleanup")
		}
	} else {
		u, e := url.Parse(record.URL)
		if e != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || auditHTTPSizeAddress(u.Host) != nil {
			return record, errors.New("invalid ready URL")
		}
	}
	return record, nil
}

func auditHTTPSizePrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("invalid private fixture file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if int64(len(b)) > maximum {
		return nil, errors.New("oversize private file")
	}
	return b, err
}

func auditHTTPSizeEnvironment() []string {
	var result []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "ZASP_") || strings.HasPrefix(upper, "PG") || strings.HasPrefix(upper, "AWS_") || strings.Contains(upper, "PROXY") || upper == "GOGC" || upper == "GOMEMLIMIT" || upper == "GOMAXPROCS" || upper == "GODEBUG" || upper == "GORACE" {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "GOGC=100", "GOMEMLIMIT=off", "GOMAXPROCS=2")
}

// The returned cleanup owns the borrowed factory's connection and transport.
func auditHTTPSizeAPIFactory(ctx context.Context, dsn, address, caPath string, key []byte) (http.Handler, func() error, error) {
	var conn *pgx.Conn
	var transport *http.Transport
	cleanup := func() error {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		if conn != nil {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return conn.Close(c)
		}
		return nil
	}
	if err := auditHTTPSizeAPIInputs(dsn, address, ""); err != nil {
		return nil, cleanup, err
	}
	ca, err := auditHTTPSizePrivateFile(caPath, 16384)
	if err != nil {
		return nil, cleanup, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, cleanup, errors.New("invalid owned CA")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, cleanup, err
	}
	conn, err = pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, cleanup, err
	}
	auditHTTPFixtureOwnConnection(ctx, "partial API factory", conn)
	transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		if network != "tcp" || destination != auditExportTestPolicy().Bucket+".s3.us-east-1.amazonaws.com:443" {
			return nil, errors.New("unexpected API provider destination")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirect refused") }}
	sdk := s3.New(s3.Options{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return auditHTTPSizeCredentials("reader"), nil }), HTTPClient: client, RetryMaxAttempts: 1})
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: conn})
	if err != nil {
		return nil, cleanup, err
	}
	identity, err := NewPostgresRepository(db)
	if err != nil {
		return nil, cleanup, err
	}
	handler, err := NewAuditExportProductionHandler(ctx, db, AuditExportHandlerConfiguration{Storage: []AuditExportStorageConfiguration{{Policy: auditExportTestPolicy(), Client: sdk}}, CursorSigningKey: key, ProviderTimeout: 3 * time.Second})
	if err != nil {
		return nil, cleanup, err
	}
	router, err := NewCompositionWithAuditExports(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")}, handler)
	if err != nil {
		return nil, cleanup, err
	}
	secured, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://audit-export.invalid", MaximumBodyBytes: 1024, Authenticate: identity.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
	return secured, cleanup, err
}

func TestAuditHTTPSizeAPIProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_HTTP_SIZE_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned API process")
	}
	address := os.Getenv("ZASP_AUDIT_HTTP_SIZE_ADDRESS")
	if err := auditHTTPSizeAPIInputs(dsn, address, os.Getenv("ZASP_AUDIT_HTTP_SIZE_CONTROL")); err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, os.Getenv("ZASP_AUDIT_HTTP_SIZE_DEADLINE"))
	if err != nil || time.Until(deadline) <= 20*time.Second || time.Until(deadline) > 12*time.Minute {
		t.Fatal("invalid owned child deadline")
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline.Add(-20*time.Second))
	defer cancel()
	status, control := os.NewFile(3, "status"), os.NewFile(4, "control")
	defer status.Close()
	defer control.Close()
	handler, cleanup, err := auditHTTPSizeAPIFactory(ctx, dsn, address, os.Getenv("ZASP_AUDIT_HTTP_SIZE_CA"), []byte(strings.Repeat("h", 32)))
	if err != nil {
		closeErr := cleanup()
		t.Fatal("API factory", err, closeErr)
	}
	retained := new(auditHTTPSizeRetained)
	if os.Getenv("ZASP_AUDIT_HTTP_SIZE_CONTROL") == "api-retain" {
		handler = retained.Wrap(handler)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err, cleanup())
	}
	lifetime := newAuditHTTPHandlerLifetime(ctx)
	server := &http.Server{Handler: lifetime.Wrap(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	stopped := make(chan error, 1)
	go func() {
		raw := make([]byte, 5)
		_, e := io.ReadFull(control, raw)
		if e == nil && string(raw) != "stop\n" {
			e = errors.New("invalid control record")
		}
		stopped <- e
	}()
	writeErr := json.NewEncoder(status).Encode(auditHTTPSizeRecord{PID: os.Getpid(), URL: "http://" + listener.Addr().String(), Mode: "api"})
	var stopErr error
	readJoined := false
	if writeErr == nil {
		select {
		case stopErr = <-stopped:
			readJoined = true
		case <-ctx.Done():
			stopErr = ctx.Err()
		}
	} else {
		stopErr = writeErr
	}
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownErr := server.Shutdown(shutdownCtx)
	done()
	if shutdownErr != nil {
		_ = server.Close()
	}
	cancel()
	_ = control.Close()
	joinCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	select {
	case e := <-served:
		if !errors.Is(e, http.ErrServerClosed) {
			stopErr = errors.Join(stopErr, e)
		}
	case <-joinCtx.Done():
		stopErr = errors.Join(stopErr, joinCtx.Err())
	}
	if !readJoined {
		select {
		case <-stopped:
		case <-joinCtx.Done():
			stopErr = errors.Join(stopErr, joinCtx.Err())
		}
	}
	closeErr := auditHTTPSizeCloseAfterHandlers(joinCtx, lifetime, cleanup)
	done()
	if err := errors.Join(stopErr, shutdownErr, closeErr); err != nil {
		t.Fatal("API cleanup refused", err)
	}
	record := auditHTTPSizeRecord{PID: os.Getpid(), URL: "cleanup-complete", Mode: "api", RetainedBytes: retained.Bytes()}
	if os.Getenv("ZASP_AUDIT_HTTP_SIZE_CONTROL") == "diagnostics" {
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		record.SelfRSSBytes, err = auditHTTPSizeNormalizeRSS(runtime.GOOS, usage.Maxrss)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := json.NewEncoder(status).Encode(record); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(retained)
}

type auditHTTPSizeChildResult struct {
	Joined        bool
	PID           int
	Mode          string
	Output        []byte
	PeakRSSBytes  int64
	RetainedBytes int64
	SelfRSSBytes  int64
}
type auditHTTPSizeRunResult struct {
	output []byte
	err    error
}
type auditHTTPSizeAPIChild struct {
	joined          bool
	command         *exec.Cmd
	status, control *os.File
	reader          *bufio.Reader
	run             chan auditHTTPSizeRunResult
	ready           auditHTTPSizeRecord
	result          *auditHTTPSizeRunResult
	cancel          context.CancelFunc
	stopped         bool
}

func (c *auditHTTPSizeAPIChild) URL() string { return c.ready.URL }
func startAuditHTTPSizeAPI(ctx context.Context, binary, dsn, address, ca, control string) (*auditHTTPSizeAPIChild, error) {
	return startAuditHTTPSizeAPIWithRunner(ctx, binary, dsn, address, ca, control, testprocess.Run)
}

func startAuditHTTPSizeAPIWithRunner(ctx context.Context, binary, dsn, address, ca, control string, run func(context.Context, *exec.Cmd) ([]byte, error)) (*auditHTTPSizeAPIChild, error) {
	if err := auditHTTPSizeAPIInputs(dsn, address, control); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < 35*time.Second {
		return nil, errors.New("API deadline admission")
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	controlR, controlW, err := os.Pipe()
	if err != nil {
		statusR.Close()
		statusW.Close()
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.Command(binary, "-test.run=^TestAuditHTTPSizeAPIProcess$", "-test.v", "-test.count=1", "-test.timeout=12m")
	cmd.Env = append(auditHTTPSizeEnvironment(), "ZASP_AUDIT_HTTP_SIZE_DSN="+dsn, "ZASP_AUDIT_HTTP_SIZE_ADDRESS="+address, "ZASP_AUDIT_HTTP_SIZE_CA="+ca, "ZASP_AUDIT_HTTP_SIZE_CONTROL="+control, "ZASP_AUDIT_HTTP_SIZE_DEADLINE="+deadline.Format(time.RFC3339Nano))
	cmd.ExtraFiles = []*os.File{statusW, controlR}
	c := &auditHTTPSizeAPIChild{command: cmd, status: statusR, control: controlW, reader: bufio.NewReaderSize(statusR, 4096), run: make(chan auditHTTPSizeRunResult, 1), cancel: cancel}
	go func() {
		out, e := run(runCtx, cmd)
		e = errors.Join(e, statusW.Close(), controlR.Close())
		c.run <- auditHTTPSizeRunResult{out, e}
	}()
	type recordResult struct {
		record auditHTTPSizeRecord
		err    error
	}
	records := make(chan recordResult, 1)
	go func() { r, e := auditHTTPSizeReadRecord(c.reader, "api", false); records <- recordResult{r, e} }()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	var readyErr error
	readerJoined := false
	select {
	case r := <-records:
		c.ready = r.record
		readyErr = r.err
		readerJoined = true
	case result := <-c.run:
		c.result = &result
		readyErr = errors.New("API runner exited before readiness")
	case <-timer.C:
		readyErr = errors.New("API readiness timeout")
	case <-ctx.Done():
		readyErr = ctx.Err()
	}
	if readyErr == nil {
		return c, nil
	}
	_ = c.status.Close()
	if !readerJoined {
		<-records
	}
	// The already-installed fixture owner must classify/stop this child. A
	// nonnil error result can still have a background process owner.
	return c, readyErr
}
func (c *auditHTTPSizeAPIChild) Stop(ctx context.Context) (auditHTTPSizeChildResult, error) {
	if c.stopped {
		return auditHTTPSizeChildResult{}, errors.New("API already stopped")
	}
	c.stopped = true
	defer c.status.Close()
	_, writeErr := io.WriteString(c.control, "stop\n")
	_ = c.control.Close()
	if c.result == nil {
		cooperative := time.NewTimer(10 * time.Second)
		defer cooperative.Stop()
		select {
		case result := <-c.run:
			c.result = &result
		case <-cooperative.C:
			c.cancel()
			select {
			case result := <-c.run:
				c.result = &result
			case <-ctx.Done():
				return auditHTTPSizeChildResult{}, errors.New("API runner join uncertain")
			}
		case <-ctx.Done():
			c.cancel()
			return auditHTTPSizeChildResult{}, errors.New("API cleanup deadline before runner join")
		}
	}
	c.cancel()
	// On runner error it may have retained background exit ownership. Do not
	// touch mutable exec.Cmd state or claim a joined/normal terminal process.
	if c.result.err != nil {
		return auditHTTPSizeChildResult{Mode: "api", Output: c.result.output}, errors.Join(writeErr, c.result.err)
	}
	c.joined = true
	terminal, recordErr := auditHTTPSizeReadTerminal(c.reader, "api")
	result := auditHTTPSizeChildResult{Mode: "api", Output: c.result.output, Joined: true}
	if c.command.Process != nil {
		result.PID = c.command.Process.Pid
	}
	err := errors.Join(writeErr, c.result.err, recordErr)
	if terminal.PID != result.PID || c.ready.PID != result.PID || bytes.Contains(result.Output, []byte("--- SKIP:")) || c.command.ProcessState == nil || !c.command.ProcessState.Success() {
		err = errors.Join(err, fmt.Errorf("API terminal identity/exit/protocol refused: %s", result.Output))
	}
	if err == nil {
		result.PeakRSSBytes, err = auditHTTPSizePeak(c.command.ProcessState)
		result.RetainedBytes, result.SelfRSSBytes = terminal.RetainedBytes, terminal.SelfRSSBytes
		if result.SelfRSSBytes > result.PeakRSSBytes {
			err = errors.New("self RSS exceeds final kernel peak")
		}
	}
	return result, err
}
