//go:build darwin || linux

package testprocess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func Run(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	if ctx == nil || command == nil || command.Process != nil || command.Cancel != nil {
		return nil, errors.New("invalid owned worker command")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	// Only Start creates this group. No CommandContext watcher or concurrent
	// Cmd.Wait can reap its leader before all group signals are finished.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout, command.Stderr = writer, writer
	if err := command.Start(); err != nil {
		_ = writer.Close()
		return nil, err
	}
	_ = writer.Close()
	type outputResult struct {
		body []byte
		err  error
	}
	output := make(chan outputResult, 1)
	go func() { body, err := io.ReadAll(reader); output <- outputResult{body, err} }()
	exited := make(chan error, 1)
	go func() { exited <- observeSandboxWorkerExit(command.Process.Pid) }()
	var observed, stopErr error
	permissionDenied := false
	signalGroup := func(signal unix.Signal) {
		err := sandboxWorkerGroupSignal(command.Process.Pid, signal)
		if err == unix.EPERM {
			// Darwin may return EPERM for a zombie-only group. Reconcile it
			// only after Wait and proven group disappearance, never by ignoring
			// a denied signal while descendants might still be running.
			permissionDenied = true
		} else {
			stopErr = errors.Join(stopErr, err)
		}
	}
	select {
	case observed = <-exited:
	case <-ctx.Done():
		signalGroup(unix.SIGTERM)
		select {
		case observed = <-exited:
		case <-time.After(250 * time.Millisecond):
			signalGroup(unix.SIGKILL)
			select {
			case observed = <-exited:
			case <-time.After(2 * time.Second):
				// An uninterruptible leader cannot be synchronously reaped within
				// a fixed bound. Retain wait ownership; report incomplete cleanup.
				go func() { <-exited; _ = command.Wait() }()
				_ = reader.Close()
				result := <-output
				return result.body, errors.Join(ctx.Err(), stopErr, errors.New("owned worker leader did not exit after SIGKILL"))
			}
		}
	}
	if observed != nil {
		// Lost observation/wait ownership is not permission to signal a numeric
		// group. Keep reconciliation separate and fail the fixture closed.
		go func() { _ = command.Wait() }()
		_ = reader.Close()
		result := <-output
		return result.body, errors.Join(observed, ctx.Err(), stopErr)
	}
	// The exited leader is still an unreaped child, pinning its PID/PGID. Kill
	// descendants even after successful leader exit, then reap the direct child.
	signalGroup(unix.SIGKILL)
	waitErr := command.Wait()
	// No group signals occur after Wait. Absence is a read-only confirmation;
	// a recycled ID can only cause a timeout, never a signal to another group.
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := unix.Kill(-command.Process.Pid, 0)
		if err == unix.ESRCH {
			break
		}
		if err != nil && err != unix.EPERM || !time.Now().Before(deadline) {
			stopErr = errors.Join(stopErr, fmt.Errorf("owned worker process group did not disappear: %w", ErrGroupRemaining))
			if permissionDenied || err == unix.EPERM {
				stopErr = errors.Join(stopErr, unix.EPERM)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case result := <-output:
		return result.body, errors.Join(ctx.Err(), stopErr, waitErr, result.err)
	case <-time.After(250 * time.Millisecond):
		// Closing our pipe bounds local I/O cleanup, but is explicitly a failure,
		// not proof that an escaped or uninterruptible descendant was joined.
		_ = reader.Close()
		result := <-output
		return result.body, errors.Join(ctx.Err(), stopErr, waitErr, errors.New("owned worker descendant output did not close"))
	}
}

var ErrGroupRemaining = errors.New("process group still present")

func sandboxWorkerGroupSignal(pid int, signal unix.Signal) error {
	if pid <= 1 {
		return errors.New("invalid owned worker process group")
	}
	err := unix.Kill(-pid, signal)
	if err == unix.ESRCH {
		return nil
	}
	return err
}
