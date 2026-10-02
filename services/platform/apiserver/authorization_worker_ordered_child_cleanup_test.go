package apiserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func orderedRunnerChildOutput(child *exec.Cmd) ([]byte, error) {
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	child.Cancel = func() error { return syscall.Kill(-child.Process.Pid, syscall.SIGTERM) }
	child.WaitDelay = 10 * time.Second
	defer func() {
		if child.Process != nil {
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		}
	}()
	return child.CombinedOutput()
}

// The child records each random container before launching it. Cleanup belongs
// to this parent too, so a forced child exit cannot bypass exact-owner removal.
func cleanupOrderedRunnerContainers(t *testing.T, directory string) {
	t.Helper()
	files, err := os.ReadDir(directory)
	if err != nil {
		t.Error("read owned container records", err)
		return
	}
	valid := regexp.MustCompile(`^zasp-ordered-engine-(?:preflight-)?[0-9a-f]{32}$`)
	for _, file := range files {
		name := file.Name()
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !valid.MatchString(name) || string(body) != name {
			t.Error("invalid owned container record")
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", `{{index .Config.Labels "io.zasp.ordered-engine-owner"}}`, name).CombinedOutput()
		if err != nil {
			if strings.TrimSpace(strings.ToLower(string(out))) != "error: no such object: "+name {
				t.Error("could not verify owned container absence")
			}
		} else if strings.TrimSpace(string(out)) != name {
			t.Error("owned container identity mismatch")
		} else if err := exec.CommandContext(ctx, "docker", "rm", "-f", name).Run(); err != nil {
			t.Error("owned parent container cleanup", err)
		}
		cancel()
	}
}
