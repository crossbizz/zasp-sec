//go:build darwin

package sandboxcutover

import "golang.org/x/sys/unix"

func observeObservationExit(pid int) error {
	queue, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(queue)
	unix.CloseOnExec(queue)
	var change unix.Kevent_t
	unix.SetKevent(&change, pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	change.Fflags = unix.NOTE_EXIT
	if _, err := unix.Kevent(queue, []unix.Kevent_t{change}, nil, nil); err != nil {
		if err == unix.ESRCH {
			return nil
		}
		return err
	}
	events := make([]unix.Kevent_t, 1)
	for {
		count, err := unix.Kevent(queue, nil, events, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if count == 1 && events[0].Ident == uint64(pid) && events[0].Fflags&unix.NOTE_EXIT != 0 {
			return nil
		}
		return errRejected
	}
}
