#!/usr/bin/env python3
"""Run the fixed dependency regressions with process-local Linux child reaping.

Only descendants of this fresh launcher are adopted. This does not repair PID1
or reap historical processes, and it does not isolate hostile same-UID actors.
"""
import argparse
import ctypes
import os
from pathlib import Path
import selectors
import shutil
import signal
import sys
import time


class _OwnershipError(Exception):
    pass


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise _OwnershipError()


def _stat_fields(path, expected_pid=None):
    with open(path, 'rb') as source:
        raw = source.read(16385)
    if len(raw) > 16384:
        raise _OwnershipError()
    fields = raw.rsplit(b') ', 1)[1].split()
    actual_pid = int(raw.split(b' ', 1)[0])
    if (expected_pid is not None and actual_pid != expected_pid) or len(fields) < 20:
        raise _OwnershipError()
    return actual_pid, fields


def _children(deadline):
    _check_deadline(deadline)
    parent = os.getpid()
    try:
        with open('/proc/self/task/' + str(parent) + '/children', 'rb') as source:
            raw = source.read(65537)
    except FileNotFoundError:
        # Some Linux procfs builds omit the optional task children interface.
        # Enumeration is metadata-only: PPID classifies candidates; ownership
        # and pidfd checks remain mandatory before any cleanup signal.
        actual_pid, _ = _stat_fields('/proc/self/stat', parent)
        if actual_pid != parent:
            raise _OwnershipError()
        result = []
        numeric_entries = 0
        with os.scandir('/proc') as entries:
            for entry in entries:
                _check_deadline(deadline)
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                numeric_entries += 1
                if numeric_entries > 65536:
                    raise _OwnershipError()
                pid = int(entry.name)
                try:
                    _, fields = _stat_fields('/proc/' + entry.name + '/stat', pid)
                    _check_deadline(deadline)
                    if int(fields[1]) != parent:
                        continue
                    current = _identity(pid)
                    _check_deadline(deadline)
                    if current[0] == parent:
                        result.append(pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if len(result) > 1024:
                    raise _OwnershipError()
        return result
    _check_deadline(deadline)
    if len(raw) > 65536:
        raise _OwnershipError()
    result = [int(value) for value in raw.split()]
    if len(result) > 1024 or any(pid <= 1 for pid in result):
        raise _OwnershipError()
    return result


def _identity(pid):
    root = Path('/proc', str(pid))
    _, fields = _stat_fields(root / 'stat', pid)
    with (root / 'status').open('rb') as source:
        status = source.read(16385)
    if len(status) > 16384:
        raise _OwnershipError()
    uids = [line.split()[1:] for line in status.splitlines() if line.startswith(b'Uid:')]
    if len(uids) != 1 or [int(value) for value in uids[0]] != [os.geteuid()] * 4:
        raise _OwnershipError()
    return (int(fields[1]), fields[19], fields[0], int(fields[3]))


def _pin_child(pid):
    before = _identity(pid)
    if before[0] != os.getpid():
        raise _OwnershipError()
    fd = os.pidfd_open(pid, 0)
    try:
        after = _identity(pid)
        if before[:2] != after[:2] or after[0] != os.getpid():
            raise _OwnershipError()
        return {'fd': fd, 'start': after[1]}
    except BaseException:
        os.close(fd)
        raise


def _signal_child(pid, record, requested):
    current = _identity(pid)
    if current[0] != os.getpid() or current[1] != record['start']:
        raise _OwnershipError()
    if current[2] != b'Z':
        signal.pidfd_send_signal(record['fd'], requested, None, 0)


def _child_exec(argv, gate, ready, parent, close_fds):
    # No parent authorization, including EOF or early cancellation, means no
    # exec. These handlers cover the interval before the parent's pidfd exists.
    try:
        signal.set_wakeup_fd(-1)
        signal.signal(signal.SIGTERM, lambda *_: os._exit(125))
        signal.signal(signal.SIGINT, lambda *_: os._exit(125))
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        for fd in close_fds:
            os.close(fd)
        os.setsid()
        os.write(ready, b'R')
        os.close(ready)
        if os.read(gate, 1) != b'G' or os.getppid() != parent:
            os._exit(125)
        os.close(gate)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        os.execve(argv[0], argv, os.environ.copy())
    except BaseException:
        # Never reflect executable arguments, environment or child material.
        os.write(2, b'scoped dependency reaper: child setup or exec failed\n')
        os._exit(127)


def _run_owned(argv, timeout_seconds=90):
    """Private lifecycle seam; production main supplies only the fixed Node argv."""
    if (sys.platform != 'linux' or not isinstance(argv, list) or not argv
            or not all(isinstance(value, str) and '\0' not in value for value in argv)
            or not os.path.isabs(argv[0]) or not 0 < timeout_seconds <= 90):
        return 125
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        return 125
    selector = None
    wake_read = wake_write = gate_read = gate_write = ready_read = ready_write = None
    old_wakeup = None
    handlers = {}
    old_subreaper = ctypes.c_int()
    acquired = False
    joined = False
    main_pid = None
    main_status = None
    owned = {}
    cancelled = [None]
    cleanup_reason = None
    cleanup_started = None
    term_sent = set()
    kill_sent = set()
    libc = None
    deadline = time.monotonic() + 5

    def note_signal(number, _frame):
        if number != signal.SIGCHLD and cancelled[0] is None:
            cancelled[0] = number

    def reap():
        nonlocal main_status
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
            if pid == 0:
                return False
            if pid == main_pid:
                main_status = os.waitstatus_to_exitcode(status)
            record = owned.pop(pid, None)
            if record is not None:
                os.close(record['fd'])

    def wait_tick(seconds=0.025):
        for key, _ in selector.select(seconds):
            if key.fd == wake_read:
                try:
                    while os.read(wake_read, 4096):
                        pass
                except BlockingIOError:
                    pass

    def cleanup_signals(requested):
        sent = term_sent if requested == signal.SIGTERM else kill_sent
        for pid in _children(cleanup_started + 5 if cleanup_started is not None else deadline):
            try:
                record = owned.get(pid)
                if record is None:
                    record = _pin_child(pid)
                    owned[pid] = record
                marker = (pid, record['start'])
                if marker not in sent:
                    _signal_child(pid, record, requested)
                    sent.add(marker)
            except ProcessLookupError:
                continue
            except FileNotFoundError:
                continue

    try:
        if _children(deadline):
            raise _OwnershipError()
        # Capability refusal is checked before creating a child. These are
        # process-local primitives, unrelated to service/resource admission.
        probe = os.pidfd_open(os.getpid(), 0)
        try:
            signal.pidfd_send_signal(probe, 0, None, 0)
        finally:
            os.close(probe)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(37, ctypes.byref(old_subreaper), 0, 0, 0) != 0:
            raise _OwnershipError()
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise _OwnershipError()
        acquired = True
        actual = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(actual), 0, 0, 0) != 0 or actual.value != 1:
            raise _OwnershipError()
        wake_read, wake_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        os.set_blocking(ready_read, False)
        selector = selectors.DefaultSelector()
        selector.register(wake_read, selectors.EVENT_READ)
        old_wakeup = signal.set_wakeup_fd(wake_write)
        for number in (signal.SIGCHLD, signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.getsignal(number)
            signal.signal(number, note_signal)
        sys.stdout.flush()
        sys.stderr.flush()
        deadline = time.monotonic() + timeout_seconds
        parent = os.getpid()
        main_pid = os.fork()
        if main_pid == 0:
            _child_exec(argv, gate_read, ready_write, parent,
                        [gate_write, ready_read, wake_read, wake_write])
            os._exit(127)
        os.close(gate_read)
        gate_read = None
        os.close(ready_write)
        ready_write = None
        # Child cannot exec until its pidfd and current parent/start identity
        # have been recorded, even if setup fails or the launcher is cancelled.
        owned[main_pid] = _pin_child(main_pid)
        ready_deadline = min(deadline, time.monotonic() + 1)
        prepared = False
        while not prepared:
            if cancelled[0] is not None or time.monotonic() >= ready_deadline:
                raise _OwnershipError()
            try:
                value = os.read(ready_read, 1)
                if value == b'R':
                    prepared = True
                elif value == b'':
                    raise _OwnershipError()
            except BlockingIOError:
                wait_tick(0.01)
        current = _identity(main_pid)
        if (current[0] != parent or current[1] != owned[main_pid]['start']
                or current[3] != main_pid or cancelled[0] is not None):
            raise _OwnershipError()
        os.write(gate_write, b'G')
        os.close(gate_write)
        gate_write = None
        os.close(ready_read)
        ready_read = None
        while True:
            empty = reap()
            now = time.monotonic()
            if cancelled[0] is not None and cleanup_reason is None:
                cleanup_reason, cleanup_started = 'cancel', now
            elif now >= deadline and cleanup_reason is None:
                cleanup_reason, cleanup_started = 'timeout', now
            if empty:
                joined = True
                break
            if main_status is not None and cleanup_reason is None:
                # A live descendant after Node completion is a failure even if
                # cleanup subsequently succeeds. Normal running only reaps.
                cleanup_reason, cleanup_started = 'leak', now
            if cleanup_reason is not None:
                if now - cleanup_started >= 5:
                    raise _OwnershipError()
                cleanup_signals(signal.SIGTERM if now - cleanup_started < 1 else signal.SIGKILL)
            wait_tick()
    except BaseException:
        cleanup_reason = cleanup_reason or ('cancel' if cancelled[0] is not None else 'setup')
        # Closing the gate is mandatory before any cleanup: an unapproved fork
        # child receives EOF and exits without ever executing the Node command.
        if gate_write is not None:
            os.close(gate_write)
            gate_write = None
        if main_pid is not None and main_pid > 0:
            began = cleanup_started if cleanup_started is not None else time.monotonic()
            end = began + 5
            cleanup_started = began
            while time.monotonic() < end:
                try:
                    if reap():
                        joined = True
                        break
                    cleanup_signals(signal.SIGTERM if time.monotonic() - began < 1 else signal.SIGKILL)
                    if selector is not None:
                        wait_tick()
                    else:
                        time.sleep(0.01)
                except BaseException:
                    # Refused or ambiguous ownership never broadens to a PID,
                    # process-group, host scan, or historical-process fallback.
                    break
    finally:
        for record in owned.values():
            os.close(record['fd'])
        if old_wakeup is not None:
            signal.set_wakeup_fd(old_wakeup)
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if selector is not None:
            selector.close()
        for fd in (wake_read, wake_write, gate_read, gate_write, ready_read, ready_write):
            if fd is not None:
                os.close(fd)
        if acquired and (main_pid is None or joined):
            if libc.prctl(36, old_subreaper.value, 0, 0, 0) != 0:
                joined = False
                cleanup_reason = 'setup'
    if main_pid is None or not joined or main_status is None:
        print('scoped dependency reaper: setup or owned cleanup incomplete', file=sys.stderr)
        if main_status is not None and main_status != 0:
            return main_status if main_status > 0 else 128 - main_status
        return 125
    if cleanup_reason == 'cancel':
        return 128 + cancelled[0]
    if cleanup_reason == 'timeout':
        return 124
    if cleanup_reason == 'setup':
        return 125
    if cleanup_reason == 'leak':
        print('scoped dependency reaper: live descendant survived Node exit', file=sys.stderr)
        return (main_status if main_status > 0 else 128 - main_status) if main_status else 125
    return main_status if main_status >= 0 else 128 - main_status


def main():
    parser = argparse.ArgumentParser(description='Run the fixed local dependency regressions')
    parser.add_argument('--node', metavar='ABSOLUTE_NODE_EXECUTABLE')
    options = parser.parse_args()
    if sys.platform not in ('linux', 'darwin'):
        print('scoped dependency reaper: unsupported platform', file=sys.stderr)
        return 125
    selected_node = shutil.which('node')
    node = options.node or selected_node
    if (options.node and (not selected_node or not os.path.isabs(options.node)
                          or not os.path.exists(options.node)
                          or not os.path.samefile(options.node, selected_node))):
        print('scoped dependency reaper: Node selection differs from configured runtime', file=sys.stderr)
        return 125
    if not node or not os.path.isabs(node) or not os.path.isfile(node) or not os.access(node, os.X_OK):
        print('scoped dependency reaper: Node prerequisite unavailable', file=sys.stderr)
        return 125
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    argv = [node, '--test', 'scripts/dependency-parser-regression.test.mjs',
            'scripts/dependency-esbuild-regression.test.mjs']
    if sys.platform == 'darwin':
        try:
            os.execve(node, argv, os.environ.copy())
        except OSError:
            print('scoped dependency reaper: Node exec failed', file=sys.stderr)
        return 125
    return _run_owned(argv)


if __name__ == '__main__':
    sys.exit(main())
