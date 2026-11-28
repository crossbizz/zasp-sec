//go:build linux

// The Linux RSS fixture launches its measured executable from this small
// address space. Linux includes the pre-exec resident set in the child's
// final kernel rusage.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 3 || !filepath.IsAbs(os.Args[2]) || syscall.Getpgrp() != os.Getpid() {
		return fmt.Errorf("invalid RSS supervisor invocation")
	}
	fd, err := strconv.Atoi(os.Args[1])
	if err != nil || fd < 3 || fd > 5 {
		return fmt.Errorf("invalid RSS witness descriptor")
	}
	witness := os.NewFile(uintptr(fd), "rusage-witness")
	defer witness.Close()
	syscall.CloseOnExec(fd)
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	for i := 3; i < fd; i++ {
		files = append(files, os.NewFile(uintptr(i), "application-protocol"))
	}

	// Keep the creating thread alive for the child's parent-death signal.
	// On group cancellation stay alive long enough to reap the measured PID.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	child, err := os.StartProcess(os.Args[2], os.Args[2:], &os.ProcAttr{
		Env: os.Environ(), Files: files, Sys: &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	})
	for _, f := range files[3:] {
		f.Close()
	}
	if err != nil {
		return err
	}
	done := make(chan struct{})
	var state *os.ProcessState
	go func() {
		state, err = child.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-signals:
		_ = child.Kill()
		<-done
		return fmt.Errorf("RSS supervisor cancelled")
	}
	if err != nil || state == nil || state.Pid() != child.Pid || !state.Exited() || !state.Success() {
		return fmt.Errorf("measured child did not exit successfully")
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil || usage.Maxrss <= 0 {
		return fmt.Errorf("measured child has no kernel peak")
	}
	// VmHWM refers only to this supervisor's post-exec memory map. Reject
	// measurements small enough to be explained by the launcher's footprint.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		var floor int64
		var unit string
		if _, err := fmt.Sscanf(line, "VmHWM: %d %s", &floor, &unit); err != nil || unit != "kB" || floor <= 0 || usage.Maxrss <= floor {
			return fmt.Errorf("measured peak does not exceed supervisor footprint")
		}
		_, err := fmt.Fprintf(witness, "rusage-v1 %d %d %d %d\n", os.Getpid(), child.Pid, floor, usage.Maxrss)
		return err
	}
	return fmt.Errorf("missing supervisor memory footprint")
}
