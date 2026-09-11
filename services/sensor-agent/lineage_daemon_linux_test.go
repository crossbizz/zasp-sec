package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run only in the explicitly provisioned disposable container: a private tmpfs
// service-account directory, root producer group 65532, and the compiled binary.
// The Kubernetes API and Tetragon server are fixtures; procfs and the daemon are
// real. No test switches are added to the production executable.
func TestLineageProducerDaemonActualBinaryRotatesAndStops(t *testing.T) {
	if os.Getenv("ZASP_TEST_LINEAGE_DAEMON_FIXTURE") != "1" {
		t.Skip("requires isolated Linux daemon composition")
	}
	if os.Geteuid() != 0 || os.Getegid() != 65532 || os.Getenv("ZASP_TEST_LINEAGE_PRODUCER_BINARY") != "/proof/sensor-agent" {
		t.Fatal("invalid isolated fixture identity")
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
	boot, err := newProcBootReader("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	bootID, err := boot.Read()
	boot.Close()
	if err != nil {
		t.Fatal(err)
	}
	apiFixture := newLineageIdentityAPIFixture()
	apiFixture.node.Status.NodeInfo.BootID = bootID
	api := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer fixture-lineage-kubernetes" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/nodes/node-a":
			json.NewEncoder(response).Encode(apiFixture.node)
		case "/api/v1/namespaces/kube-system":
			json.NewEncoder(response).Encode(apiFixture.namespace)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	for name, raw := range map[string][]byte{"ca.crt": ca, "token": []byte("fixture-lineage-kubernetes"), "namespace": []byte("default")} {
		path := filepath.Join(credentials, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		})
	}
	socket, _, events := startLineageGRPCFixture(t, "v1.7.0")
	spool, acks := t.TempDir(), t.TempDir()
	if err := os.Chmod(spool, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(acks, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(acks, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	env := lineageDaemonEnvironment()
	env["ZASP_LINEAGE_SPOOL_DIRECTORY"], env["ZASP_LINEAGE_ACK_DIRECTORY"] = spool, acks
	env["ZASP_TETRAGON_SOCKET"], env["ZASP_HOST_BOOT_ID_FILE"] = socket, "/proc/sys/kernel/random/boot_id"
	env["ZASP_LINEAGE_MAX_GENERATION_AGE"], env["ZASP_LINEAGE_FLUSH_INTERVAL"], env["ZASP_LINEAGE_IDENTITY_INTERVAL"] = "1s", "50ms", "1s"
	host, port, err := net.SplitHostPort(strings.TrimPrefix(api.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	env["KUBERNETES_SERVICE_HOST"], env["KUBERNETES_SERVICE_PORT"] = host, port
	command := exec.Command("/proof/sensor-agent")
	command.Env = []string{"PATH=/usr/bin:/bin", "GOMEMLIMIT=96MiB"}
	for key, value := range env {
		command.Env = append(command.Env, key+"="+value)
	}
	// Reject unreadable/mis-grouped producer roots before creating any lock.
	for _, invalid := range []string{"mode", "group"} {
		if invalid == "mode" {
			if err := os.Chmod(spool, 0700); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Chown(spool, 0, 65531); err != nil {
				t.Fatal(err)
			}
		}
		probe := exec.Command("/proof/sensor-agent")
		probe.Env = command.Env
		if err := probe.Run(); err == nil {
			t.Fatal("unsafe spool permissions accepted", invalid)
		}
		if entries, err := os.ReadDir(spool); err != nil || len(entries) != 0 {
			t.Fatal("rejected spool received writes", invalid, err)
		}
		if err := os.Chmod(spool, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(spool, 0, 65532); err != nil {
			t.Fatal(err)
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	select {
	case <-events.requests:
		events.events <- lineageProviderFixture("exec")
	case err := <-done:
		joined = true
		t.Fatal("daemon startup", err, output.String())
	case <-ctx.Done():
		t.Fatal("daemon didn't subscribe")
	}
	client := &http.Client{Timeout: time.Second}
	readySeen, rotated := false, false
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for !rotated {
		select {
		case err := <-done:
			joined = true
			t.Fatal("daemon stopped before rotation", err, output.String())
		case <-ctx.Done():
			t.Fatal("daemon rotation deadline")
		case <-tick.C:
			if response, err := client.Get("http://127.0.0.1:8082/readyz"); err == nil {
				readySeen = readySeen || response.StatusCode == http.StatusOK
				response.Body.Close()
			}
			entries, err := os.ReadDir(spool)
			if err != nil {
				t.Fatal(err)
			}
			count, closed := 0, 0
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), "generation-") {
					continue
				}
				count++
				var seal lineageSpoolSeal
				if raw, err := os.ReadFile(filepath.Join(spool, entry.Name(), "closed.json")); err == nil && json.Unmarshal(raw, &seal) == nil && seal.Reason == "rotation" {
					closed++
				}
			}
			rotated = count >= 2 && closed >= 1
		}
	}
	if !readySeen {
		t.Fatal("daemon never reported readiness")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("daemon shutdown", err, output.String())
		}
	case <-ctx.Done():
		t.Fatal("daemon didn't stop")
	}
	entries, err := os.ReadDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	seen, records, shutdown := map[string]bool{}, 0, false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "generation-") {
			continue
		}
		reader, err := newProductionLineageSpoolReader(filepath.Join(spool, entry.Name()), env["ZASP_SENSOR_ENROLLMENT_BINDING"])
		if err != nil {
			t.Fatal(err)
		}
		source := reader.Source()
		seal, found, err := reader.ReadSeal()
		reader.Close()
		if err != nil || !found || source.BootID != bootID || seen[source.GenerationID] || seal.CoverageComplete {
			t.Fatal("daemon source/seal proof", source, seal, err)
		}
		seen[source.GenerationID] = true
		records += seal.Records
		shutdown = shutdown || seal.Reason == "shutdown"
	}
	if len(seen) < 2 || records != 1 || !shutdown {
		t.Fatal("daemon rotation/shutdown evidence", len(seen), records, shutdown)
	}
	if entries, err := os.ReadDir(acks); err != nil || len(entries) != 0 {
		t.Fatal("producer wrote consumer acknowledgment state", err)
	}
	if !strings.Contains(output.String(), "sensor-lineage-producer build") || strings.Contains(output.String(), "fixture-lineage-kubernetes") {
		t.Fatal("unsafe daemon output")
	}
}
