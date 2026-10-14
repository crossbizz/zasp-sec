package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// A persistent, disposable official server is necessary: restarting the owned
// server withdraws its old preshared key without losing the actual model/tuples.
// No proxy, injected decision, raw activation or caller-provided witness is used.
type connectorLifecycleFGA struct {
	binary, dsn, endpoint, oldFile, newFile, oldToken, newToken string
	port, grpcPort                                              int
	command                                                     *exec.Cmd
	executable                                                  *os.File
	executableInfo                                              os.FileInfo
	executableHash                                              string
}

func newConnectorLifecycleFGA(t *testing.T) *connectorLifecycleFGA {
	t.Helper()
	binary := os.Getenv("ZASP_CONNECTOR_LIFECYCLE_OPENFGA_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("owned official OpenFGA binary prerequisite absent")
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatal("owned official OpenFGA executable unavailable")
	}
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned FGA PostgreSQL unavailable")
	}
	if _, err := conn.Exec(ctx, `CREATE DATABASE connector_lifecycle_fga`); err != nil {
		conn.Close(ctx)
		t.Fatal("owned FGA database creation refused")
	}
	conn.Close(ctx)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("owned FGA database address invalid")
	}
	parsed.Path = "/connector_lifecycle_fga"
	fd, err := syscall.Open(binary, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal("official executable custody unavailable")
	}
	held := os.NewFile(uintptr(fd), binary)
	heldInfo, err := held.Stat()
	if err != nil {
		held.Close()
		t.Fatal("official held executable metadata unavailable")
	}
	expectedHash := os.Getenv("ZASP_CONNECTOR_LIFECYCLE_OPENFGA_SHA256")
	decoded, err := hex.DecodeString(expectedHash)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != expectedHash {
		held.Close()
		t.Fatal("official archive verified member checksum prerequisite absent")
	}
	f := &connectorLifecycleFGA{binary: binary, dsn: parsed.String(), executable: held, executableInfo: heldInfo, executableHash: expectedHash}
	t.Cleanup(func() { f.verifyExecutable(t); held.Close() })
	f.verifyExecutable(t)
	for _, slot := range []*int{&f.port, &f.grpcPort} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("owned FGA port unavailable")
		}
		*slot = l.Addr().(*net.TCPAddr).Port
		l.Close()
	}
	f.endpoint = "http://127.0.0.1:" + strconv.Itoa(f.port)
	root := t.TempDir()
	os.Chmod(root, 0700)
	for _, entry := range []struct {
		token, path *string
		name        string
	}{{&f.oldToken, &f.oldFile, "old-token"}, {&f.newToken, &f.newFile, "new-token"}} {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("owned credential entropy unavailable")
		}
		*entry.token = hex.EncodeToString(key[:])
		*entry.path = filepath.Join(root, entry.name)
		if os.WriteFile(*entry.path, []byte(*entry.token), 0600) != nil {
			t.Fatal("owned credential file unavailable")
		}
	}
	f.verifyExecutable(t)
	migrate := exec.CommandContext(ctx, "/proc/self/fd/3", "migrate")
	migrate.ExtraFiles = []*os.File{f.executable}
	migrate.Env = f.environment("")
	if migrate.Run() != nil {
		t.Fatal("official FGA datastore migration refused")
	}
	f.verifyExecutable(t)
	f.start(t, f.oldToken+","+f.newToken)
	t.Cleanup(func() { f.stop(t) })
	t.Setenv("ZASP_P6_NATIVE_OPENFGA_URL", f.endpoint)
	t.Setenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE", f.newFile)
	return f
}
func (f *connectorLifecycleFGA) environment(tokens string) []string {
	return append(os.Environ(), "OPENFGA_DATASTORE_ENGINE=postgres", "OPENFGA_DATASTORE_URI="+f.dsn, "OPENFGA_HTTP_ADDR=127.0.0.1:"+strconv.Itoa(f.port), "OPENFGA_GRPC_ADDR=127.0.0.1:"+strconv.Itoa(f.grpcPort), "OPENFGA_AUTHN_METHOD=preshared", "OPENFGA_AUTHN_PRESHARED_KEYS="+tokens, "OPENFGA_PLAYGROUND_ENABLED=false", "OPENFGA_METRICS_ENABLED=false", "OPENFGA_LOG_LEVEL=warn")
}
func (f *connectorLifecycleFGA) start(t *testing.T, tokens string) {
	t.Helper()
	f.verifyExecutable(t)
	f.command = exec.Command("/proc/self/fd/3", "run")
	f.command.ExtraFiles = []*os.File{f.executable}
	f.command.Env = f.environment(tokens)
	if f.command.Start() != nil {
		t.Fatal("official FGA owned process refused")
	}
	actual, err := os.Stat("/proc/" + strconv.Itoa(f.command.Process.Pid) + "/exe")
	if err != nil || !os.SameFile(actual, f.executableInfo) {
		f.stop(t)
		t.Fatal("official FGA running executable custody mismatch")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(f.endpoint + "/healthz")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.stop(t)
	t.Fatal("official FGA owned health deadline")
}
func (f *connectorLifecycleFGA) stop(t *testing.T) {
	t.Helper()
	if f.command == nil {
		return
	}
	command := f.command
	f.command = nil
	if command.Process.Signal(syscall.SIGTERM) != nil {
		t.Error("owned FGA normal stop refused")
		return
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Error("owned FGA did not exit normally")
		}
		f.verifyExecutable(t)
	case <-time.After(5 * time.Second):
		t.Error("owned FGA did not join after normal stop")
	}
}
func (f *connectorLifecycleFGA) withdrawOld(t *testing.T) {
	f.stop(t)
	if t.Failed() {
		t.Fatal("owned credential withdrawal requires a joined old server")
	}
	f.start(t, f.newToken)
}

// The old writer is an actual original projection process with its own official
// credential. Its precise PID is observed, then its stdin closes and Wait joins
// it normally. This is a local component observation, never a fleet attestation.
func startConnectorLifecycleWriter(t *testing.T, dsn, endpoint, tokenFile, org, store, model string) (int, func()) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned writer executable unavailable")
	}
	command := exec.Command(executable, "-test.run=^TestConnectorMaintenanceLifecycleWriterProcess$", "-test.timeout=2m")
	command.Env = append(os.Environ(), "ZASP_CONNECTOR_LIFECYCLE_WRITER=1", "ZASP_CONNECTOR_LIFECYCLE_DSN="+dsn, "ZASP_CONNECTOR_LIFECYCLE_ENDPOINT="+endpoint, "ZASP_CONNECTOR_LIFECYCLE_TOKEN_FILE="+tokenFile, "ZASP_CONNECTOR_LIFECYCLE_ORG="+org, "ZASP_CONNECTOR_LIFECYCLE_STORE="+store, "ZASP_CONNECTOR_LIFECYCLE_MODEL="+model)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal("owned writer input unavailable")
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal("owned writer readiness unavailable")
	}
	if command.Start() != nil {
		t.Fatal("owned original writer refused")
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		input.Close()
		if command.Wait() != nil {
			t.Error("owned original writer did not join normally")
		}
	}
	t.Cleanup(stop)
	ready := make(chan bool, 1)
	go func() {
		var marker [1]byte
		_, err := io.ReadFull(output, marker[:])
		ready <- err == nil && marker[0] == 'R'
		io.Copy(io.Discard, output)
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("owned original writer readiness refused")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("owned original writer readiness deadline")
	}
	return command.Process.Pid, stop
}

func TestConnectorMaintenanceLifecycleWriterProcess(t *testing.T) {
	if os.Getenv("ZASP_CONNECTOR_LIFECYCLE_WRITER") != "1" {
		t.Skip("owned subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(os.Getenv("ZASP_CONNECTOR_LIFECYCLE_DSN"))
	if err != nil {
		t.Fatal("writer database config refused")
	}
	config.ConnConfig.User = "auth80_outbox"
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("writer pool refused")
	}
	defer pool.Close()
	token, err := os.ReadFile(os.Getenv("ZASP_CONNECTOR_LIFECYCLE_TOKEN_FILE"))
	if err != nil {
		t.Fatal("writer credential unavailable")
	}
	defer clear(token)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	pins := runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-lifecycle", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGATokenFile: os.Getenv("ZASP_CONNECTOR_LIFECYCLE_TOKEN_FILE"), Timeout: 5 * time.Second, FGAURL: os.Getenv("ZASP_CONNECTOR_LIFECYCLE_ENDPOINT"), StoreID: os.Getenv("ZASP_CONNECTOR_LIFECYCLE_STORE"), ModelID: os.Getenv("ZASP_CONNECTOR_LIFECYCLE_MODEL")}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.FGAURL, StoreId: pins.StoreID, AuthorizationModelId: pins.ModelID, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: string(token)}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal("writer official SDK refused")
	}
	repo, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		t.Fatal("writer repository refused")
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal("writer tuple adapter refused")
	}
	receipt, err := authorization.Reconcile(ctx, repo, writer, os.Getenv("ZASP_CONNECTOR_LIFECYCLE_ORG"), pins.StoreID, pins.ModelID)
	if err != nil || !receipt.Applied {
		t.Fatal("original writer reconciliation refused")
	}
	os.Stdout.Write([]byte("R"))
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal("writer shutdown input refused")
	}
}

func connectorLifecycleOfficialClient(t *testing.T, f *connectorLifecycleFGA, store, model string) (*fga.OpenFgaClient, runtimeservices.Config) {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	pins := runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-lifecycle", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGATokenFile: f.newFile, FGAURL: f.endpoint, StoreID: store, ModelID: model, Timeout: 5 * time.Second}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: f.endpoint, StoreId: store, AuthorizationModelId: model, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: f.newToken}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal("official owned lifecycle SDK refused")
	}
	return client, pins
}

// The outer harness verifies the official archive and supplies its exact member
// hash. This helper retains that executable's descriptor and verifies bytes and
// inode before/after execution; a path/hash alone does not replace archive proof.
func (f *connectorLifecycleFGA) verifyExecutable(t *testing.T) {
	t.Helper()
	info, err := f.executable.Stat()
	pathInfo, pathErr := os.Lstat(f.binary)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0500 || info.Size() != 64577698 || !os.SameFile(f.executableInfo, info) || !os.SameFile(info, pathInfo) || info.Size() != f.executableInfo.Size() || !info.ModTime().Equal(f.executableInfo.ModTime()) {
		t.Fatal("official executable immutable metadata refused")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		t.Fatal("official executable ownership refused")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(f.executable, 0, info.Size())); err != nil || hex.EncodeToString(hash.Sum(nil)) != f.executableHash {
		t.Fatal("official executable digest refused")
	}
	after, err := f.executable.Stat()
	if err != nil || !os.SameFile(info, after) || !after.ModTime().Equal(info.ModTime()) || after.Size() != info.Size() {
		t.Fatal("official executable changed during verification")
	}
}
