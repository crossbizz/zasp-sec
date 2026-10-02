package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Existing local runner-assets image, built from the pinned worker Dockerfile.
// Never pull a mutable tag or substitute another engine in this native proof.
const orderedNativeEngineImage = "sha256:35693f52bb18536d511ca9ec3bb7f2fa12163fc9d81c066e80e0bf201774a1a5"
const orderedNativeEngineLabel = "io.zasp.ordered-engine-owner"

func recordOrderedNativeContainer(name string) error {
	directory := os.Getenv("ZASP_ORDERED_CONTAINER_RECORDS")
	if directory == "" {
		return nil
	}
	if !filepath.IsAbs(directory) {
		return errWorkerExecution
	}
	return os.WriteFile(filepath.Join(directory, name), []byte(name), 0600)
}

func cleanOrderedNativeContainer(t *testing.T, name string) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cleanup, "docker", "inspect", "--format", `{{index .Config.Labels "`+orderedNativeEngineLabel+`"}}`, name).CombinedOutput()
	if err != nil {
		if strings.TrimSpace(strings.ToLower(string(out))) != "error: no such object: "+name {
			t.Error("owned engine cleanup could not verify absence")
		}
		return
	}
	if strings.TrimSpace(string(out)) != name {
		t.Error("owned engine cleanup identity mismatch")
		return
	}
	if err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run(); err != nil {
		t.Error("owned engine cleanup failed", err)
	}
}

type orderedNativeEngine struct {
	t                          *testing.T
	credentials, module, relay string
	port                       int
	calls                      int
}

func (r *orderedNativeEngine) Run(ctx context.Context, executable string, args, environment []string, directory string) error {
	if r == nil || ctx.Err() != nil || executable != "/usr/local/bin/node" || len(args) != 4 || args[0] != "/app/redteam-runner.mjs" || args[1] != "run" || !filepath.IsAbs(directory) || filepath.Dir(args[2]) != directory || filepath.Dir(args[3]) != directory || args[2] == args[3] || r.port < 1024 || r.port > 65535 {
		return errWorkerExecution
	}
	want := map[string]string{
		"HOME":                             directory,
		"ZASP_PROMPTFOO_BIN":               "/app/dist/src/entrypoint.js",
		"ZASP_RED_TEAM_TARGET_ENDPOINT":    "https://agentsec-red-team-adapter.zasp-system.svc.cluster.local/v1/effects/evaluate",
		"ZASP_RED_TEAM_ADAPTER_TOKEN_FILE": filepath.Join(r.credentials, "token"),
		"ZASP_RED_TEAM_TARGET_CA_FILE":     filepath.Join(r.credentials, "ca.pem"),
	}
	seen := map[string]bool{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || seen[key] {
			return errWorkerExecution
		}
		seen[key] = true
		if key == "ZASP_RED_TEAM_EFFECT_KEY" {
			if len(value) != 64 {
				return errWorkerExecution
			}
			if _, err := hex.DecodeString(value); err != nil {
				return errWorkerExecution
			}
		} else if expected, ok := want[key]; !ok || value != expected {
			return errWorkerExecution
		}
	}
	if len(seen) != 6 || !seen["ZASP_RED_TEAM_EFFECT_KEY"] {
		return errWorkerExecution
	}
	for key := range want {
		if !seen[key] {
			return errWorkerExecution
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "zasp-ordered-engine-" + hex.EncodeToString(nonce[:])
	if err := recordOrderedNativeContainer(name); err != nil {
		return err
	}
	// A cancelled Docker client can leave its container. Inspect its exact
	// random owner label before removing only this disposable invocation.
	defer cleanOrderedNativeContainer(r.t, name)
	dockerArgs := []string{"run", "--rm", "--name", name, "--label", orderedNativeEngineLabel + "=" + name, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1g", "--cpus", "2", "--sysctl", "net.ipv4.ip_unprivileged_port_start=0", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--add-host", "agentsec-red-team-adapter.zasp-system.svc.cluster.local:127.0.0.1"}
	for _, mount := range []string{
		"type=bind,src=" + directory + ",dst=" + directory,
		"type=bind,src=" + r.credentials + ",dst=" + r.credentials + ",readonly",
		"type=bind,src=" + r.module + ",dst=/app/redteam-runner.mjs,readonly",
		"type=bind,src=" + r.relay + ",dst=/proof/ordered-native-relay.mjs,readonly",
	} {
		dockerArgs = append(dockerArgs, "--mount", mount)
	}
	for _, value := range environment {
		dockerArgs = append(dockerArgs, "--env", value)
	}
	dockerArgs = append(dockerArgs, "--entrypoint", "/usr/local/bin/node", orderedNativeEngineImage, "/proof/ordered-native-relay.mjs", strconv.Itoa(r.port), args[2], args[3])
	r.calls++
	command := exec.CommandContext(ctx, "docker", dockerArgs...)
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	// Native engine output can contain customer or authority data. Report only
	// exit classification and byte count; the artifact decoder is the oracle.
	r.t.Log("actual pinned Ordered engine", "error", err, "diagnostic_bytes", len(output))
	return err
}

func TestOrderedNativeEnginePrerequisites(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_ENGINE_PREFLIGHT") != "1" {
		t.Skip("explicit local image preflight required")
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalCtx, 30*time.Second)
	defer cancel()
	for _, check := range []struct {
		args []string
		want string
	}{
		{[]string{"--version"}, "v22.23.1"},
		{[]string{"/app/dist/src/entrypoint.js", "--version"}, "0.121.19"},
	} {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		name := "zasp-ordered-engine-preflight-" + hex.EncodeToString(nonce[:])
		if err := recordOrderedNativeContainer(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cleanOrderedNativeContainer(t, name) })
		args := []string{"run", "--rm", "--name", name, "--label", orderedNativeEngineLabel + "=" + name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,mode=1777", "--entrypoint", "/usr/local/bin/node", orderedNativeEngineImage}
		out, err := exec.CommandContext(ctx, "docker", append(args, check.args...)...).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != check.want {
			t.Fatal("pinned engine prerequisite", check.want, "error", err, "diagnostic_bytes", len(out))
		}
	}
}
