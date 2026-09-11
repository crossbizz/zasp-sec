package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The executable is real and runs as UID 65532. The upload and Kubernetes
// services are local fixtures; this isn't a live cluster or durable API proof.
func TestLineageConsumerDaemonActualBinaryUploadsAndRetiresWithoutToken(t *testing.T) {
	testLineageConsumerDaemonBinary(t, false)
}

func TestLineageConsumerDaemonActualBinaryRotatesProjectedToken(t *testing.T) {
	if os.Getenv("ZASP_TEST_LINEAGE_DAEMON_PROJECTED") != "1" {
		t.Skip("requires separate read-only projected-token fixture")
	}
	testLineageConsumerDaemonBinary(t, true)
}

func testLineageConsumerDaemonBinary(t *testing.T, projected bool) {
	t.Helper()
	if os.Getenv("ZASP_TEST_LINEAGE_DAEMON_FIXTURE") != "1" {
		t.Skip("requires isolated Linux daemon composition")
	}
	if os.Geteuid() != 0 || os.Getegid() != 65532 || os.Getenv("ZASP_TEST_LINEAGE_PRODUCER_BINARY") != "/proof/sensor-agent" {
		t.Fatal("invalid isolated fixture identity")
	}
	var capabilities [2]unix.CapUserData
	if unix.Capget(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &capabilities[0]) != nil || capabilities[0].Effective&(1<<unix.CAP_KILL) == 0 {
		t.Fatal("root harness needs KILL to join its non-root child")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	const credentials = "/var/run/secrets/kubernetes.io/serviceaccount"
	var filesystem syscall.Statfs_t
	if syscall.Statfs(credentials, &filesystem) != nil || filesystem.Type != 0x01021994 {
		t.Fatal("credential fixture isn't private tmpfs")
	}
	if entries, err := os.ReadDir(credentials); err != nil || len(entries) != 0 {
		t.Fatal("credential fixture isn't empty", err)
	}
	var uploads atomic.Int32
	var attemptMu sync.Mutex
	var firstBody []byte
	var firstKey string
	firstAttempt := make(chan struct{}, 1)
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/api") {
			if request.Header.Get("Authorization") != "Bearer fixture-lineage-kubernetes" {
				t.Error("wrong Kubernetes credential")
			}
			// Failed cluster coordination must not prevent stream/retirement work.
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		authorization := request.Header.Get("Authorization")
		if request.URL.Path != "/internal/v1/runtime/events" || request.Method != http.MethodPost || authorization != "Bearer "+fixtureAgentToken() && (!projected || authorization != "Bearer "+projectedTokenFixture(1)) {
			t.Error("unexpected product request")
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
		if err != nil || !bytes.Contains(raw, []byte(`"boot_id":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"`)) {
			t.Error("upload lost producer lineage")
		}
		if projected {
			attemptMu.Lock()
			if firstBody == nil {
				firstBody = bytes.Clone(raw)
				firstKey = request.Header.Get("Idempotency-Key")
				if firstKey == "" || authorization != "Bearer "+fixtureAgentToken() {
					t.Error("first attempt didn't use original credential and identity")
				}
			} else if !bytes.Equal(firstBody, raw) || firstKey != request.Header.Get("Idempotency-Key") {
				t.Error("credential rotation changed pending request")
			}
			attemptMu.Unlock()
			if authorization == "Bearer "+fixtureAgentToken() {
				select {
				case firstAttempt <- struct{}{}:
				default:
				}
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		uploads.Add(1)
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusAccepted)
		io.WriteString(response, `{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`)
	}))
	api.Listener.Close()
	var err error
	api.Listener, err = net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	api.StartTLS()
	defer api.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	for name, raw := range map[string][]byte{"ca.crt": ca, "token": []byte("fixture-lineage-kubernetes"), "namespace": []byte("agentsec")} {
		path := filepath.Join(credentials, name)
		if err := os.WriteFile(path, raw, 0444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:8082")
	if err != nil {
		t.Fatal(err)
	}
	ready := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" || request.Header.Get("Authorization") != "" {
			t.Error("unexpected producer request")
		}
		io.WriteString(response, `{"status":"ready"}`)
	}), ReadHeaderTimeout: time.Second}
	go ready.Serve(listener)
	defer ready.Close()

	generation, path := lineageSpoolReaderFixture(t)
	spool := filepath.Dir(path)
	for _, directory := range []string{spool, filepath.Dir(spool)} {
		if err := os.Chmod(directory, 0750); err != nil {
			t.Fatal(err)
		}
	}
	event := lineageProviderFixture("exec")
	event.Time = timestamppb.New(time.Now())
	line, err := sanitizeLineageEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
		t.Fatal(err)
	}
	generation.Close()

	outputs := t.TempDir()
	if err := os.Chmod(outputs, 0750); err != nil {
		t.Fatal(err)
	}
	acks, state, tokenDir := filepath.Join(outputs, "acks"), filepath.Join(outputs, "state"), filepath.Join(outputs, "credentials")
	directories := []string{acks, state}
	if projected {
		tokenDir = "/projection"
		projectedTokenWaitFixture(t, "/control/ready", 0)
	} else {
		directories = append(directories, tokenDir)
	}
	for _, directory := range directories {
		mode := os.FileMode(0700)
		if directory == acks {
			mode = 0750
		}
		if err := os.Mkdir(directory, mode); err != nil {
			t.Fatal(err)
		}
		// Populate the token before handing ownership to the consumer.
		if directory == tokenDir {
			if err := os.WriteFile(filepath.Join(directory, "token"), []byte(fixtureAgentToken()), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(filepath.Join(directory, "token"), 65532, 65532); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chown(directory, 65532, 65532); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chown(directory, 0, 65532); err != nil {
				t.Error(err)
			}
		})
	}
	inputs := make([]string, 2)
	for index, name := range []string{"osrelease", "vmlinux"} {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0750); err != nil {
			t.Fatal(err)
		}
		inputs[index] = filepath.Join(directory, name)
		if err := os.WriteFile(inputs[index], []byte("6.8.1\n"), 0444); err != nil {
			t.Fatal(err)
		}
	}
	env := validSensorAgentEnvironment()
	delete(env, "ZASP_TETRAGON_LOG_FILE")
	delete(env, "ZASP_SENSOR_CURSOR_FILE")
	env["ZASP_SENSOR_ROLE"] = "lineage-consumer"
	env["ZASP_SENSOR_TOKEN_SOURCE"] = "owned-file"
	if projected {
		env["ZASP_SENSOR_TOKEN_SOURCE"] = "kubernetes-projected"
	}
	env["ZASP_SENSOR_ENROLLMENT_BINDING"] = generation.source.EnrollmentBinding
	env["ZASP_SENSOR_CONTROL_PLANE_URL"] = strings.TrimSuffix(api.URL, ":443")
	env["ZASP_SENSOR_TOKEN_FILE"] = filepath.Join(tokenDir, "token")
	env["ZASP_LINEAGE_SPOOL_DIRECTORY"], env["ZASP_LINEAGE_ACK_DIRECTORY"], env["ZASP_LINEAGE_STATE_DIRECTORY"] = spool, acks, state
	env["ZASP_SENSOR_KERNEL_FILE"], env["ZASP_SENSOR_BTF_FILE"] = inputs[0], inputs[1]
	env["ZASP_TETRAGON_METRICS_URL"] = "http://127.0.0.1:2112/metrics"
	env["ZASP_SENSOR_POLL_INTERVAL"], env["ZASP_SENSOR_OPERATION_TIMEOUT"], env["ZASP_SENSOR_SHUTDOWN_TIMEOUT"] = "100ms", "2s", "5s"
	host, port, err := net.SplitHostPort(strings.TrimPrefix(api.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	env["KUBERNETES_SERVICE_HOST"], env["KUBERNETES_SERVICE_PORT"] = host, port
	if _, err := loadSensorAgentConfig(func(key string) string { return env[key] }); err != nil {
		t.Fatal("invalid daemon fixture configuration", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proof/sensor-agent")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	command.Env = []string{"PATH=/usr/bin:/bin", "GOMEMLIMIT=96MiB", "SSL_CERT_FILE=" + filepath.Join(credentials, "ca.crt")}
	for key, value := range env {
		command.Env = append(command.Env, key+"="+value)
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	joined := false
	defer func() {
		if !joined {
			command.Process.Kill()
			<-done
		}
	}()
	receipts, err := newProductionLineageReceiptReader(acks, 65532)
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Close()
	waitFor := func(label string, condition func() bool) {
		t.Helper()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for !condition() {
			select {
			case err := <-done:
				joined = true
				safe := strings.NewReplacer(fixtureAgentToken(), "[redacted]", projectedTokenFixture(1), "[redacted]", "fixture-lineage-kubernetes", "[redacted]").Replace(output.String())
				t.Fatal("consumer exited during "+label, err, safe)
			case <-ctx.Done():
				t.Fatal("consumer timed out during " + label)
			case <-tick.C:
			}
		}
	}
	destination := env["ZASP_SENSOR_CONTROL_PLANE_URL"] + "/internal/v1/runtime/events"
	if projected {
		waitFor("initial failed attempt", func() bool {
			select {
			case <-firstAttempt:
				return true
			default:
				return false
			}
		})
		if _, found, err := generation.spool.VerifyAcknowledgment(ctx, receipts, generation.source, destination); err != nil || found {
			t.Fatal("failed upload produced acknowledgment", err)
		}
		if err := os.WriteFile("/control/done", []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
		projectedTokenWaitFixture(t, "/control/ready", 1)
	}
	waitFor("upload", func() bool {
		_, found, err := generation.spool.VerifyAcknowledgment(ctx, receipts, generation.source, destination)
		return err == nil && found
	})
	processStatus, err := os.ReadFile("/proc/" + strconv.Itoa(command.Process.Pid) + "/status")
	if err != nil || !bytes.Contains(processStatus, []byte("Uid:\t65532\t65532\t65532\t65532")) || !bytes.Contains(processStatus, []byte("CapEff:\t0000000000000000")) {
		t.Fatal("consumer didn't run non-root with zero effective capabilities", err)
	}
	healthClient := &http.Client{Timeout: time.Second}
	for path, expected := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusServiceUnavailable} {
		response, err := healthClient.Get("http://127.0.0.1:8081" + path)
		if err != nil {
			t.Fatal("consumer health endpoint", err)
		}
		response.Body.Close()
		if response.StatusCode != expected {
			t.Fatal("failed cluster authority became ready", path, response.StatusCode)
		}
	}
	if uploads.Load() != 1 {
		t.Fatal("unexpected upload count", uploads.Load())
	}
	// Remove only the synthetic upload token file, then require local cleanup.
	// This isn't a server-side credential revocation proof.
	if projected {
		if err := os.WriteFile("/control/done", []byte("1"), 0644); err != nil {
			t.Fatal(err)
		}
		projectedTokenWaitFixture(t, "/control/ready", 2)
	} else {
		if err := os.Chown(tokenDir, 0, 65532); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(tokenDir, "token")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(tokenDir, 65532, 65532); err != nil {
			t.Fatal(err)
		}
	}
	request := lineageReclaimRequest{Source: generation.source, Destination: destination, ConsumerUID: 65532}
	if done, err := generation.spool.ReclaimAcknowledged(ctx, receipts, request); err != nil || !done {
		t.Fatal("root reclamation", err)
	}
	waitFor("credential-free retirement", func() bool {
		done, err := generation.spool.CollectCompletion(ctx, receipts, request)
		return err == nil && done
	})
	waitFor("credential-free release", func() bool {
		_, err := os.Lstat(filepath.Join(acks, "ack-"+generation.source.GenerationID+".json"))
		if !os.IsNotExist(err) {
			return false
		}
		// ACK removal precedes the final assignment/evidence unlink. Observe the
		// private directory as its actual owner before interrupting the daemon.
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		probe := exec.CommandContext(ctx, binary, "-test.run=^TestLineageConsumerDaemonStateProbe$")
		probe.Env = []string{"GOMEMLIMIT=32MiB", "ZASP_TEST_LINEAGE_CONSUMER_STATE_CHECK=" + state}
		probe.SysProcAttr = command.SysProcAttr
		return probe.Run() == nil
	})
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("consumer shutdown", err)
		}
	case <-ctx.Done():
		t.Fatal("consumer didn't stop")
	}
	if err := os.Chown(state, 0, 65532); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 3 {
		t.Fatal("consumer retained slot history", len(entries), err)
	}
	if uploads.Load() != 1 || bytes.Contains(output.Bytes(), []byte(fixtureAgentToken())) || bytes.Contains(output.Bytes(), []byte(projectedTokenFixture(1))) || bytes.Contains(output.Bytes(), []byte("fixture-lineage-kubernetes")) {
		t.Fatal("duplicate upload or credential output")
	}
	if projected {
		if err := os.WriteFile("/control/done", []byte("2"), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLineageConsumerDaemonProjectionWriter(t *testing.T) {
	if os.Getenv("ZASP_TEST_PROJECTED_TOKEN_PHASE") != "daemon-writer" {
		t.Skip("requires isolated projection writer")
	}
	if os.Geteuid() != 0 {
		t.Fatal("writer must be root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	for _, directory := range []string{"/projection", "/control"} {
		if err := os.Chmod(directory, 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(directory, 0, 65532); err != nil {
			t.Fatal(err)
		}
	}
	for i, name := range []string{"first", "rotated", "removed"} {
		projectedTokenPublishFixture(t, i, name)
		if err := os.WriteFile("/control/ready", []byte(strconv.Itoa(i)), 0644); err != nil {
			t.Fatal(err)
		}
		projectedTokenWaitFixture(t, "/control/done", i)
	}
}

func TestLineageConsumerDaemonStateProbe(t *testing.T) {
	path := os.Getenv("ZASP_TEST_LINEAGE_CONSUMER_STATE_CHECK")
	if path == "" {
		t.Skip("invoked by isolated consumer daemon fixture")
	}
	if os.Geteuid() != 65532 || !validAbsolute(path) {
		t.Fatal("invalid probe identity")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 3 || entries[0].Name() != ".slots.lock" || entries[1].Name() != lineageHealthName || entries[2].Name() != "cursor-0.json.lock" {
		t.Fatal("retirement not complete")
	}
}
