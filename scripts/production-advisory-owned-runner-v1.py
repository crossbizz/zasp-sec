#!/usr/bin/python3.13
"""Closed Linux child owner. Collection success is not release acceptance."""
import base64
import ctypes
import datetime
import hashlib
import json
import os
import pathlib
import selectors
import signal
import subprocess
import sys
import tempfile
import time

ROOT = '/workspace/zasp-sec'
GO = '/workspace/scratch/toolchains/go/bin/go'
SCANNER = '/workspace/scratch/trivy-0.75.0/go-tools/govulncheck'
DATABASE = 'file:///workspace/scratch/official-go-vulndb-generated'
MODULE_CACHE = '/home/agent/go/pkg/mod'
SNAPSHOT = '/workspace/scratch/production-go-advisory-owned-inputs-v1'
ROOTS = {'health': 'services/health', 'platform': 'services/platform',
         'event-ingest': 'services/event-ingest', 'gateway-control': 'services/gateway-control',
         'runtime-gateway': 'services/runtime-gateway', 'sensor-agent': 'services/sensor-agent',
         'cli': 'cmd/agentsecctl'}
COMMANDS = {}
MODE_ROOTS = {}
for name, relative in ROOTS.items():
    for operation in ('scan', 'graph', 'packages', 'verify'):
        mode = operation + '-' + name
        COMMANDS[mode] = ([SCANNER, '-json', '-scan=package', '-db=' + DATABASE, './...']
                          if operation == 'scan' else
                          [GO, 'list', '-mod=readonly', '-m', '-json', 'all']
                          if operation == 'graph' else
                          [GO, 'list', '-mod=readonly', '-deps', '-json', './...']
                          if operation == 'packages' else [GO, 'mod', 'verify'])
        MODE_ROOTS[mode] = ROOT + '/' + relative
for name, relative in ROOTS.items():
    mode = 'snapshot-packages-' + name
    COMMANDS[mode] = [SNAPSHOT + '/go/bin/go', 'list', '-mod=readonly', '-deps', '-json', './...']
    MODE_ROOTS[mode] = SNAPSHOT + '/repo/' + relative
COMMANDS['snapshot-python'] = [SNAPSHOT + '/python/bin/python3.13', '-I', '-S', '-B', '-c', 'import json,sys;print(json.dumps({"prefix":sys.prefix,"path":sys.path,"executable":sys.executable,"isolated":sys.flags.isolated,"no_site":sys.flags.no_site}))']
COMMANDS['snapshot-env'] = [SNAPSHOT + '/go/bin/go', 'env', '-json', 'GOROOT', 'GOMODCACHE', 'GOWORK', 'GOENV', 'GOPROXY', 'GOFLAGS', 'GOTOOLCHAIN', 'GOOS', 'GOARCH', 'CGO_ENABLED']
MODE_ROOTS['snapshot-python'] = SNAPSHOT
MODE_ROOTS['snapshot-env'] = SNAPSHOT + '/repo/services/health'
TIMEOUT_SECONDS = 180
OUTPUT_LIMIT = 64 * 1024 * 1024
# Actual scanner entry points remain disabled until reviewed immutable inputs exist.
SCANS_APPROVED = True
# TEST_FIXTURE_INSERTION


def processes():
    result = {}
    for path in pathlib.Path('/proc').glob('[0-9]*/stat'):
        try:
            raw = path.read_text()
            after = raw[raw.rindex(')') + 2:].split()
            result[int(path.parent.name)] = {'state': after[0], 'ppid': int(after[1]),
                                            'pgrp': int(after[2]), 'start': after[19]}
        except (OSError, ValueError, IndexError):
            continue
    return result


def mapped_files(pid):
    files = set()
    try:
        lines = pathlib.Path('/proc/' + str(pid) + '/maps').read_text().splitlines()
    except OSError:
        return files
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and 'x' in fields[1] and fields[5].startswith('/'):
            file = pathlib.Path(fields[5]).resolve(strict=True)
            if not file.is_file():
                raise RuntimeError('runtime mapping topology')
            files.add(file)
    return files

def runtime_inputs(files):
    return [{'path': str(file), 'bytes': file.stat().st_size,
             'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}
            for file in sorted(files)]


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS or sys.platform != 'linux':
        raise ValueError('closed runner mode refused')
    mode = sys.argv[1]
    use_snapshot = mode.startswith('scan-') or mode.startswith('snapshot-')
    if mode.startswith('scan-'):
        if not SCANS_APPROVED or sys.executable != SNAPSHOT + '/python/bin/python3.13' or str(pathlib.Path(__file__)) != SNAPSHOT + '/runner.py':
            raise ValueError('closed owned scanner authority unavailable')
        for file, expected_mode in [(pathlib.Path(SNAPSHOT),0o700),(pathlib.Path(__file__),0o400),(pathlib.Path(sys.executable),0o500)]:
            st=file.lstat()
            if file.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o777 != expected_mode:
                raise ValueError('owned scanner topology unavailable')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError('subreaper unavailable')
    before = processes()
    loaded_files = mapped_files('self')
    zombies = [{'pid': pid, 'start': row['start']} for pid, row in sorted(before.items())
               if row['state'] == 'Z']
    started = utc()
    deadline = time.monotonic() + TIMEOUT_SECONDS
    stdout = bytearray()
    stderr = bytearray()
    timed_out = overflow = terminated = False
    adopted = 0
    child = None
    child_exit = None
    known = {}
    own_pid = os.getpid()
    temp = tempfile.TemporaryDirectory(prefix='zasp-advisory-owned-', dir='/workspace/scratch')
    os.chmod(temp.name, 0o700)
    environment = {'PATH': str(pathlib.Path(GO).parent), 'HOME': temp.name,
                   'GOCACHE': temp.name + '/go-cache', 'GOMODCACHE': MODULE_CACHE,
                   'GOROOT': str(pathlib.Path(GO).parent.parent), 'GOTOOLCHAIN': 'local',
                   'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOFLAGS': '-mod=readonly',
                   'GOOS': 'linux', 'GOARCH': 'amd64', 'CGO_ENABLED': '0',
                   'GOWORK': 'off', 'GOENV': 'off',
                   'GOMAXPROCS': '2', 'TZ': 'UTC', 'LANG': 'C', 'LC_ALL': 'C'}
    if use_snapshot:
        environment.update({'PATH': SNAPSHOT + '/go/bin', 'GOMODCACHE': SNAPSHOT + '/module-cache', 'GOROOT': SNAPSHOT + '/go'})
        if mode.startswith('scan-'):
            COMMANDS[mode] = [SNAPSHOT + '/scanner/govulncheck', '-json', '-scan=package', '-db=file://' + SNAPSHOT + '/database', './...']
            MODE_ROOTS[mode] = SNAPSHOT + '/repo/' + ROOTS[mode[5:]]
    selection = selectors.DefaultSelector()

    def owned(current):
        pids = {pid for pid, row in current.items() if row['ppid'] == own_pid}
        if child is not None:
            pids |= {pid for pid, row in current.items() if row['pgrp'] == child.pid}
        changed = True
        while changed:
            more = {pid for pid, row in current.items() if row['ppid'] in pids}
            changed = not more.issubset(pids)
            pids |= more
        return pids

    def stop_owned():
        current = processes()
        for pid in owned(current):
            known[pid] = current[pid]['start']
        # Only identities observed as our descendants/group may be signalled.
        for pid, start in list(known.items()):
            row = processes().get(pid)
            if row is not None and row['start'] == start:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    try:
        child = subprocess.Popen(COMMANDS[mode], cwd=MODE_ROOTS[mode], env=environment,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        for stream, target in [(child.stdout, stdout), (child.stderr, stderr)]:
            os.set_blocking(stream.fileno(), False)
            selection.register(stream, selectors.EVENT_READ, target)
        while selection.get_map() or child.poll() is None:
            current = processes()
            for pid in owned(current):
                known[pid] = current[pid]['start']
                loaded_files.update(mapped_files(pid))
            if len(known) > 256:
                overflow = True
            if time.monotonic() >= deadline:
                timed_out = True
            if overflow or timed_out:
                terminated = True
                stop_owned()
            for key, _ in selection.select(0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selection.unregister(key.fileobj)
                else:
                    if len(key.data) + len(data) > OUTPUT_LIMIT:
                        overflow = True
                    else:
                        key.data.extend(data)
            # Do not allow inherited pipes/orphans to extend an exited parent.
            if child.poll() is not None:
                stop_owned()
            if time.monotonic() > deadline + 5:
                raise RuntimeError('bounded child join failed')
        child_exit = child.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        terminated = True
    finally:
        stop_owned()
        if child is not None:
            try:
                child_exit = child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise RuntimeError('direct child join failed')
        reap_deadline = time.monotonic() + 3
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid > 0:
                    adopted += 1
                    continue
            except ChildProcessError:
                break
            stop_owned()
            if time.monotonic() >= reap_deadline:
                raise RuntimeError('adopted child join failed')
            time.sleep(0.01)
        after = processes()
        survivors = [{'pid': pid, 'start': after[pid]['start']} for pid in sorted(owned(after))]
        selection.close()
        for stream in ([] if child is None else [child.stdout, child.stderr]):
            if stream is not None:
                stream.close()
        temp.cleanup()
    receipt = {'format': 'production-advisory-owned-runner-v1', 'mode': mode,
               'startedAt': started, 'endedAt': utc(), 'childExit': child_exit,
               'stdoutBase64': base64.b64encode(stdout).decode('ascii'),
               'stdoutSHA256': hashlib.sha256(stdout).hexdigest(),
               'stderrSHA256': hashlib.sha256(stderr).hexdigest(),
               'timeout': timed_out, 'overflow': overflow, 'terminated': terminated,
               'preexistingZombies': zombies, 'newSurvivors': survivors,
               'adoptedReaped': adopted, 'waitJoined': child is not None,
               'releaseAccepted': False, 'runtimeInputs': runtime_inputs(loaded_files),
               'preProcessIDs': [{'pid': pid, 'start': row['start'], 'ppid': row['ppid'], 'state': row['state']} for pid, row in sorted(before.items())],
               'postProcessIDs': [{'pid': pid, 'start': row['start'], 'ppid': row['ppid'], 'state': row['state']} for pid, row in sorted(after.items())]}
    sys.stdout.write(json.dumps(receipt, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('owned advisory runner refused\n')
        sys.exit(1)
