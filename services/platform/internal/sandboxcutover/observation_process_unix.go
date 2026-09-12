//go:build darwin || linux

package sandboxcutover

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const observationOutputLimit = 4 << 20
const observationErrorLimit = 4 << 10

// Own the unreaped leader until every group signal is complete. WaitDelay only
// bounds Go pipe waits; it is not descendant cleanup and is not used here.
func runObservationProcess(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	return runObservationProcessWithWatcher(ctx, command, observeObservationExit)
}

// The production wrapper fixes the watcher; the private boundary also permits
// deterministic failure testing without exhausting host kernel resources.
func runObservationProcessWithWatcher(ctx context.Context, command *exec.Cmd, watcher func(int) error) ([]byte, error) {
	if ctx == nil || command == nil || watcher == nil || command.Process != nil || command.Cancel != nil || command.SysProcAttr != nil {
		return nil, errRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Any non-file Reader makes os/exec create a stdin-copy goroutine which
	// Cmd.Wait joins without a bound. An escaped descendant can retain that
	// pipe after the leader exits. The caller must own a bounded request file.
	if command.Stdin != nil {
		if file, ok := command.Stdin.(*os.File); !ok || file == nil {
			return nil, errRejected
		}
	}
	stdout, outWriter, err := os.Pipe()
	if err != nil {
		return nil, errRejected
	}
	defer stdout.Close()
	stderr, errWriter, err := os.Pipe()
	if err != nil {
		outWriter.Close()
		return nil, errRejected
	}
	defer stderr.Close()
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout, command.Stderr = outWriter, errWriter
	if err := command.Start(); err != nil {
		outWriter.Close()
		errWriter.Close()
		return nil, errRejected
	}
	outWriter.Close()
	errWriter.Close()
	type output struct {
		body     []byte
		err      error
		overflow bool
	}
	overflow := make(chan struct{}, 2)
	read := func(reader *os.File, limit int) <-chan output {
		done := make(chan output, 1)
		go func() {
			body, err := io.ReadAll(io.LimitReader(reader, int64(limit+1)))
			large := len(body) > limit
			if large {
				overflow <- struct{}{}
				body = body[:limit]
			}
			done <- output{body, err, large}
		}()
		return done
	}
	out, diagnostic := read(stdout, observationOutputLimit), read(stderr, observationErrorLimit)
	exited := make(chan error, 1)
	go func() { exited <- watcher(command.Process.Pid) }()
	var observed error
	stopFailed := false
	signal := func(value unix.Signal) {
		if err := unix.Kill(-command.Process.Pid, value); err != nil && err != unix.ESRCH && err != unix.EPERM {
			stopFailed = true
		}
	}
	stopping := false
	select {
	case observed = <-exited:
	case <-ctx.Done():
		stopping = true
	case <-overflow:
		stopping = true
	}
	if stopping {
		signal(unix.SIGTERM)
		select {
		case observed = <-exited:
		case <-time.After(250 * time.Millisecond):
			signal(unix.SIGKILL)
			select {
			case observed = <-exited:
			case <-time.After(2 * time.Second):
				// Retain eventual wait ownership for an uninterruptible direct
				// child, but never publish evidence or claim synchronous cleanup.
				go func() { <-exited; _ = command.Wait() }()
				stdout.Close()
				stderr.Close()
				<-out
				<-diagnostic
				return nil, errors.Join(errRejected, ctx.Err())
			}
		}
	}
	// No path has begun Wait yet, so even a failed watcher leaves the direct
	// child unreaped and its numeric PID/PGID pinned. Make the final group
	// signal before starting any reap, including after watcher failure.
	signal(unix.SIGKILL)
	var waitErr error
	if observed != nil {
		stopFailed = true
		waited := make(chan error, 1)
		go func() { waited <- command.Wait() }()
		select {
		case waitErr = <-waited:
		case <-time.After(2 * time.Second):
			// The goroutine retains eventual direct-child ownership. A failed
			// watcher cannot justify an unbounded synchronous wait or success.
			stdout.Close()
			stderr.Close()
			<-out
			<-diagnostic
			return nil, errors.Join(errRejected, ctx.Err())
		}
	} else {
		waitErr = command.Wait()
	}
	// After Wait, only read-only disappearance checks are allowed. Never signal
	// a potentially recycled group ID. EPERM is not disappearance.
	cleanupDeadline := time.Now().Add(2 * time.Second)
	for {
		err := unix.Kill(-command.Process.Pid, 0)
		if err == unix.ESRCH {
			break
		}
		if (err != nil && err != unix.EPERM) || !time.Now().Before(cleanupDeadline) {
			stopFailed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	collect := func(done <-chan output, reader *os.File) output {
		select {
		case result := <-done:
			return result
		case <-time.After(250 * time.Millisecond):
			reader.Close()
			result := <-done
			result.err = errRejected
			return result
		}
	}
	result, noise := collect(out, stdout), collect(diagnostic, stderr)
	if stopping || stopFailed || waitErr != nil || result.err != nil || noise.err != nil || result.overflow || noise.overflow || len(noise.body) != 0 || ctx.Err() != nil {
		return nil, errors.Join(errRejected, ctx.Err())
	}
	return result.body, nil
}
