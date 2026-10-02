//go:build darwin || linux

package testprocess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// exitObserver must never reap. owned means the direct child remains unreaped
// under this runner's exclusive ownership; only its owner may call Wait.
type exitObservation struct {
	err   error
	owned bool
}

type exitObserver func(int) exitObservation

type exitPublication struct {
	mu       sync.Mutex
	observed *exitObservation
	result   chan exitObservation
}

func newExitPublication() *exitPublication {
	return &exitPublication{result: make(chan exitObservation, 1)}
}

func (p *exitPublication) publish(observation exitObservation) {
	// Called once, after the blocking platform observer returns. Publication
	// and signal dispatch share one lock so loss cannot slip between a check
	// and a numeric group signal, even when select chooses another ready event.
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observed = &observation
	p.result <- observation
}

func (p *exitPublication) signal(pid int, signal unix.Signal, send func(int, unix.Signal) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.observed != nil && !p.observed.owned {
		return errors.Join(p.observed.err, errors.New("owned worker child ownership lost"))
	}
	return send(pid, signal)
}

func (p *exitPublication) forceKill(pid int, send func(int, unix.Signal) error) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Fault provenance requires pending observation, even when a terminal
	// result still owns the child for ordinary final descendant cleanup.
	if p.observed != nil {
		return false, nil
	}
	err := send(pid, unix.SIGKILL)
	return err == nil, err
}

func Run(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	return runOwned(ctx, command, observeSandboxWorkerExit)
}

// RunWithForceKill accepts one value or closure of request as a SIGKILL request.
// A nil channel disables it; a request pending before Start refuses the command.
// Only exact ErrForceKilled proves requested SIGKILL and joined cleanup. The
// caller must not reap or signal the child concurrently, including via Process.
func RunWithForceKill(ctx context.Context, command *exec.Cmd, request <-chan struct{}) ([]byte, error) {
	return runOwnedWithForceKill(ctx, command, observeSandboxWorkerExit, sandboxWorkerGroupSignal, request)
}

// ErrForceKilled is returned alone, never wrapped or joined with another error.
var ErrForceKilled = errors.New("owned worker force-killed and cleanup confirmed")

func runOwned(ctx context.Context, command *exec.Cmd, observe exitObserver) ([]byte, error) {
	return runOwnedWithSignals(ctx, command, observe, sandboxWorkerGroupSignal)
}

func runOwnedWithSignals(ctx context.Context, command *exec.Cmd, observe exitObserver, signalOwned func(int, unix.Signal) error) ([]byte, error) {
	return runOwnedWithForceKill(ctx, command, observe, signalOwned, nil)
}

func runOwnedWithForceKill(ctx context.Context, command *exec.Cmd, observe exitObserver, signalOwned func(int, unix.Signal) error, request <-chan struct{}) ([]byte, error) {
	if ctx == nil || command == nil || command.Process != nil || command.Cancel != nil {
		return nil, errors.New("invalid owned worker command")
	}
	if command.Stdin != nil {
		file, ok := command.Stdin.(*os.File)
		if !ok || file == nil {
			return nil, errors.New("owned worker stdin must be nil or a nonnil file")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-request:
		return nil, errors.New("owned worker force request before start")
	default:
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
	output := make(chan outputResult, 1)
	go func() { output <- readOwnedOutput(reader) }()
	exit := newExitPublication()
	exited := exit.result
	go func() { exit.publish(observe(command.Process.Pid)) }()
	var result outputResult
	var stopErr error
	var observed exitObservation
	var haveObservation bool
	permissionDenied := false
	signalGroup := func(signal unix.Signal) {
		err := exit.signal(command.Process.Pid, signal, signalOwned)
		if err == unix.EPERM {
			// Darwin may return EPERM for a zombie-only group. Reconcile it
			// only after Wait and proven group disappearance, never by ignoring
			// a denied signal while descendants might still be running.
			permissionDenied = true
		} else {
			stopErr = errors.Join(stopErr, err)
		}
	}
	// A successful EOF is not exit authority. Save it and disable that case;
	// errors (including overflow) request termination without waiting for EOF.
	finishOutput := func(closeNow bool) outputResult {
		if output == nil {
			return result
		}
		if !closeNow {
			select {
			case result = <-output:
				output = nil
				return result
			case <-time.After(250 * time.Millisecond):
				stopErr = errors.Join(stopErr, errors.New("owned worker descendant output did not close"))
			}
		}
		_ = reader.Close()
		result = <-output
		output = nil
		return result
	}
	timer := time.NewTimer(250 * time.Millisecond)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timeout <-chan time.Time
	ctxDone := ctx.Done()
	killed := false
	forceDispatched := false
	forceKill := func() {
		request = nil
		if killed {
			return // Ordinary escalation cannot earn requested-fault credit.
		}
		var err error
		forceDispatched, err = exit.forceKill(command.Process.Pid, signalOwned)
		// A denied fault is always a failure, even if later cleanup reconciles
		// an ordinary Darwin zombie-only EPERM.
		stopErr = errors.Join(stopErr, err)
		killed = true
		timer.Reset(2 * time.Second)
		timeout = timer.C
	}
	beginStop := func() {
		select {
		case <-request:
			forceKill()
		default:
		}
		if timeout == nil {
			signalGroup(unix.SIGTERM)
			timer.Reset(250 * time.Millisecond)
			timeout = timer.C
		}
	}
observeLoop:
	for {
		select {
		case <-request:
			forceKill()
		case observed = <-exited:
			haveObservation = true
			break observeLoop
		case result = <-output:
			output = nil
			if result.err != nil {
				beginStop()
			}
		case <-ctxDone:
			ctxDone = nil
			beginStop()
		case <-timeout:
			if killed {
				break observeLoop
			}
			signalGroup(unix.SIGKILL)
			killed = true
			timer.Reset(2 * time.Second)
		}
	}
	if !haveObservation {
		// The observer is still active. One background owner awaits it before
		// reaping, and sends no more signals even if it completes much later.
		go func() { <-exited; _ = command.Wait() }()
		result = finishOutput(true)
		if permissionDenied {
			stopErr = errors.Join(stopErr, unix.EPERM)
		}
		return result.body, errors.Join(ctx.Err(), result.err, stopErr, errors.New("owned worker leader did not exit after SIGKILL"))
	}
	if observed.owned {
		// Normal exit and failed observation both leave an exclusive unreaped
		// child. Finish group signaling now, before starting the only Wait.
		signalGroup(unix.SIGKILL)
	} else {
		stopErr = errors.Join(stopErr, errors.New("owned worker child ownership lost"))
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-time.After(2 * time.Second):
		// The same Wait remains the sole background owner. Never signal again.
		result = finishOutput(true)
		if permissionDenied {
			stopErr = errors.Join(stopErr, unix.EPERM)
		}
		return result.body, errors.Join(ctx.Err(), observed.err, result.err, stopErr, errors.New("owned worker direct child reap incomplete"))
	}
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
	result = finishOutput(false)
	contextErr := ctx.Err()
	if classifyForceKill(forceDispatched, waitErr, errors.Join(contextErr, observed.err, stopErr, result.err)) == ErrForceKilled {
		return result.body, ErrForceKilled
	}
	// Keep Run's original joined-error order for every non-fault outcome.
	return result.body, errors.Join(contextErr, observed.err, stopErr, waitErr, result.err)
}

func classifyForceKill(dispatched bool, waitErr, cleanupErr error) error {
	if dispatched && cleanupErr == nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok && exitErr.ProcessState != nil {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
				return ErrForceKilled
			}
		}
	}
	return errors.Join(waitErr, cleanupErr)
}

var ErrGroupRemaining = errors.New("process group still present")

// ErrOutputLimit reports the first byte beyond the merged output allowance.
var ErrOutputLimit = errors.New("owned worker output exceeds 1 MiB")

const outputLimit = 1 << 20

type outputResult struct {
	body []byte
	err  error
}

func readOwnedOutput(reader io.Reader) outputResult {
	var body []byte
	var scratch [32 * 1024]byte
	for {
		remaining := outputLimit - len(body)
		want := min(len(scratch), remaining+1)
		n, readErr := reader.Read(scratch[:want])
		keep := min(n, remaining)
		body = append(body, scratch[:keep]...)
		if n > remaining {
			if readErr == io.EOF {
				readErr = nil
			}
			return outputResult{body, errors.Join(ErrOutputLimit, readErr)}
		}
		if readErr != nil {
			if readErr == io.EOF {
				readErr = nil
			}
			return outputResult{body, readErr}
		}
	}
}

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
