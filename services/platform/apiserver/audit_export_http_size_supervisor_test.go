//go:build darwin || linux

package apiserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

const auditHTTPSizeSupervisorName = "audit-rss-supervisor"

func auditHTTPSizeBuildSupervisor(t *testing.T, root string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	goTool, err := auditHTTPSizeToolchain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, auditHTTPSizeSupervisorName)
	cmd := exec.Command(goTool, "build", "-o", binary, "./testdata/audit-rss-supervisor")
	cmd.Env = auditHTTPSizeBuildEnvironment()
	if output, err := testprocess.Run(ctx, cmd); err != nil {
		t.Fatalf("build RSS supervisor: %v\n%s", err, output)
	}
	if err := auditHTTPSizeVerifyBinary(binary, ""); err != nil {
		t.Fatal(err)
	}
}

type auditHTTPSizeMeasurement struct{ reader, writer *os.File }

func auditHTTPSizeSupervise(cmd *exec.Cmd) (*auditHTTPSizeMeasurement, error) {
	m := &auditHTTPSizeMeasurement{}
	if runtime.GOOS != "linux" {
		return m, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(cmd.Path), auditHTTPSizeSupervisorName)
	fd := 3 + len(cmd.ExtraFiles)
	cmd.Args = append([]string{path, fmt.Sprint(fd), cmd.Path}, cmd.Args[1:]...)
	cmd.Path = path
	cmd.ExtraFiles = append(cmd.ExtraFiles, w)
	m.reader, m.writer = r, w
	return m, nil
}

func (m *auditHTTPSizeMeasurement) Close() {
	if m != nil && m.reader != nil {
		m.reader.Close()
		if m.writer != nil {
			m.writer.Close()
		}
	}
}

func (m *auditHTTPSizeMeasurement) Complete(cmd *exec.Cmd) (int, int64, error) {
	if m == nil || cmd.Process == nil || cmd.ProcessState == nil || cmd.Process.Pid != cmd.ProcessState.Pid() ||
		!cmd.ProcessState.Success() || !cmd.ProcessState.Exited() {
		return 0, 0, errors.New("RSS measurement requires a normally joined process")
	}
	if runtime.GOOS != "linux" {
		peak, err := auditHTTPSizePeak(cmd.ProcessState)
		return cmd.Process.Pid, peak, err
	}
	if m.reader == nil || m.writer == nil {
		return 0, 0, errors.New("missing RSS witness pipe")
	}
	if err := m.writer.Close(); err != nil {
		return 0, 0, err
	}
	m.writer = nil
	if err := m.reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return 0, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(m.reader, 129))
	if err != nil || len(data) > 128 {
		return 0, 0, errors.New("invalid RSS witness length or EOF")
	}
	return auditHTTPSizeKernelWitness(string(data), cmd.Process.Pid)
}

func auditHTTPSizeKernelWitness(raw string, expectedSupervisor int) (int, int64, error) {
	var supervisor, child int
	var floor, peak int64
	const form = "rusage-v1 %d %d %d %d"
	if _, err := fmt.Sscanf(raw, form, &supervisor, &child, &floor, &peak); err != nil ||
		raw != fmt.Sprintf(form+"\n", supervisor, child, floor, peak) ||
		supervisor <= 0 || supervisor != expectedSupervisor || child <= 0 || child == supervisor || floor <= 0 || peak <= floor {
		return 0, 0, errors.New("invalid RSS kernel witness")
	}
	n, err := auditHTTPSizeNormalizeRSS("linux", peak)
	if err != nil {
		return 0, 0, err
	}
	return child, n, nil
}
