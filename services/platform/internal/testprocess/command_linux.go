//go:build linux

package testprocess

import "golang.org/x/sys/unix"

func observeSandboxWorkerExit(pid int) exitObservation {
	var information unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &information, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			// WNOWAIT never reaps. ECHILD is the exception to exclusive child
			// ownership: there is no waitable child, so signaling is forbidden.
			return exitObservation{err: err, owned: err != unix.ECHILD}
		}
	}
}
