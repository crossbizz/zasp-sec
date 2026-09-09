//go:build linux

package main

import (
	"context"
	"io"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (productionRedTeamCommand) Run(ctx context.Context, executable string, arguments, environment []string, directory string) error {
	if ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	// No CommandContext watcher or concurrent Cmd.Wait may reap the leader.
	command := exec.Command(executable, arguments...)
	command.Dir = directory
	command.Env = append([]string(nil), environment...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	// The launcher and its pinned engine must share a dedicated process group.
	// No caller-selected process or another run belongs to this group.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() {
		var information unix.Siginfo
		for {
			err := unix.Waitid(unix.P_PID, command.Process.Pid, &information, unix.WEXITED|unix.WNOWAIT, nil)
			if err == unix.EINTR {
				continue
			}
			exited <- err
			return
		}
	}()
	// WNOWAIT leaves even an exited leader unreaped. Its PID/PGID cannot be
	// recycled until this function has finished all group signals and calls Wait.
	finish := func(observed error) error {
		if observed != nil {
			// Lost wait ownership is not permission to signal any numeric identity.
			// Reconcile Cmd's resources without blocking the failed operation or
			// relying on optional kernel pidfd support for safe signaling.
			go func() { _ = command.Wait() }()
			return errRuntimeUnavailable
		}
		groupErr := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		waitErr := command.Wait()
		if groupErr != nil && groupErr != unix.ESRCH {
			return errRuntimeUnavailable
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return waitErr
	}
	select {
	case observed := <-exited:
		return finish(observed)
	case <-ctx.Done():
	}
	_ = unix.Kill(-command.Process.Pid, unix.SIGTERM)
	grace := time.NewTimer(2 * time.Second)
	defer grace.Stop()
	select {
	case observed := <-exited:
		return finish(observed)
	case <-grace.C:
	}
	_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
	forced := time.NewTimer(2 * time.Second)
	defer forced.Stop()
	select {
	case observed := <-exited:
		return finish(observed)
	case <-forced.C:
		// A kernel-uninterruptible process can delay reap. Keep its ownership
		// pinned in this cleanup goroutine while the cancelled operation returns.
		go func() { _ = finish(<-exited) }()
		return ctx.Err()
	}
}
