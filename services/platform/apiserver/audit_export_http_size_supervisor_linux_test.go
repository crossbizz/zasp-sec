package apiserver

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

func TestAuditHTTPSizeMemorySupervisor(t *testing.T) {
	const phaseKey = "ZASP_AUDIT_RSS_UNIT_PHASE"
	if phase := os.Getenv(phaseKey); phase != "" {
		// The application has its own protocol FD, but cannot write the
		// supervisor's kernel witness, even by finding it on another FD.
		fds, err := filepath.Glob("/proc/self/fd/*")
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range fds {
			if target, _ := os.Readlink(fd); target == os.Getenv("ZASP_AUDIT_RSS_UNIT_PIPE") {
				t.Fatal("measured application inherited its witness pipe")
			}
		}
		out := os.NewFile(3, "application")
		if _, err := fmt.Fprintln(out, os.Getpid()); err != nil {
			t.Fatal(err)
		}
		out.Close()
		switch phase {
		case "cancel":
			time.Sleep(30 * time.Second)
		case "nonzero":
			os.Exit(7)
		case "signal":
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		case "small", "large":
			size := 8 << 20
			if phase == "large" {
				size += 72 << 20
			}
			pages := make([]byte, size)
			for i := 0; i < len(pages); i += os.Getpagesize() {
				pages[i] = 1
			}
			runtime.KeepAlive(pages)
		default:
			t.Fatal("unknown memory regression phase")
		}
		return
	}

	root := t.TempDir()
	auditHTTPSizeBuildSupervisor(t, root)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "measured-child")
	if err := os.Symlink(exe, target); err != nil {
		t.Fatal(err)
	}
	// Make the parent measurably larger than the first measured child.
	parent := make([]byte, 120<<20)
	for i := 0; i < len(parent); i += os.Getpagesize() {
		parent[i] = 1
	}
	defer runtime.KeepAlive(parent)
	peaks := map[string]int64{}
	var smallLauncherPeak int64
	for _, phase := range []string{"small", "large", "nonzero", "signal", "cancel", "absent"} {
		t.Run(phase, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			path := target
			if phase == "absent" {
				path = filepath.Join(root, "absent")
			}
			cmd := exec.Command(path, "-test.run=^TestAuditHTTPSizeMemorySupervisor$")
			cmd.ExtraFiles = []*os.File{w}
			m, err := auditHTTPSizeSupervise(cmd)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			privatePipe, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", m.writer.Fd()))
			if err != nil || !strings.HasPrefix(privatePipe, "pipe:[") {
				t.Fatal("missing private witness descriptor", err)
			}
			cmd.Env = append(os.Environ(), phaseKey+"="+phase, "ZASP_AUDIT_RSS_UNIT_PIPE="+privatePipe)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			done := make(chan struct{})
			var runErr error
			go func() {
				_, runErr = testprocess.Run(ctx, cmd)
				close(done)
			}()
			defer func() { cancel(); <-done }()
			var reported int
			if phase != "absent" {
				if err := r.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				line, readErr := bufio.NewReader(r).ReadString('\n')
				reported, err = strconv.Atoi(strings.TrimSpace(line))
				if readErr != nil || err != nil || reported <= 0 {
					t.Fatal("missing application PID", readErr, err)
				}
			}
			if phase == "cancel" {
				cancel()
			}
			<-done
			pid, rss, measuredErr := m.Complete(cmd)
			if phase == "small" || phase == "large" {
				if runErr != nil || measuredErr != nil || pid != reported || pid == cmd.Process.Pid {
					t.Fatal("child measurement refused", reported, pid, rss, runErr, measuredErr)
				}
				peaks[phase] = rss
				if phase == "small" {
					// The joined launcher carries the parent's pre-exec footprint.
					smallLauncherPeak, err = auditHTTPSizePeak(cmd.ProcessState)
					if err != nil {
						t.Fatal(err)
					}
				}
			} else if runErr == nil || measuredErr == nil || pid != 0 || rss != 0 {
				t.Fatal("failed process produced an accepted measurement", runErr, measuredErr)
			}
			if reported != 0 && syscall.Kill(reported, 0) != syscall.ESRCH {
				t.Fatal("measured child survived or was not reaped", reported)
			}
		})
	}
	if t.Failed() {
		return
	}
	t.Logf("retained parent bytes=%d joined launcher peak=%d measured child peaks=%d/%d", len(parent), smallLauncherPeak, peaks["small"], peaks["large"])
	if peaks["small"] >= smallLauncherPeak || peaks["large"]-peaks["small"] <= 48<<20 ||
		auditHTTPSizeMemoryGate(peaks["small"], peaks["large"]) == nil {
		t.Fatal("parent footprint masked deliberate worker growth", peaks)
	}
	for _, raw := range []string{"", "rusage-v1 12 12 10 20\n", "rusage-v1 13 14 10 20\n", "rusage-v1 12 14 10 10\n", "rusage-v1 12 14 10 20\nextra"} {
		if _, _, err := auditHTTPSizeKernelWitness(raw, 12); err == nil {
			t.Fatal("invalid kernel witness accepted", raw)
		}
	}
}
