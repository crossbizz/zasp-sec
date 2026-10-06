"""Root-owned, local-only exact browser workflow reproduction. Not auto-started."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

SOURCE = Path('/workspace/.zasp-cloud-owned/sbom-0b-graph-diagnosis-pgt18jsv/candidate')
HEAD = '0b788520159170a825a925a3f639b0b1d63169f5'
NODE = '/tmp/zasp-cloud-tools/node-v22.23.1-linux-x64/bin/node'
TINI = '/tmp/zasp-cloud-tools/bin/tini'
COMMANDS = [
    [NODE, '--test', 'scripts/browser-prerequisites.test.mjs', 'scripts/browser-e2e-helpers.test.mjs', 'scripts/owned-browser-postgres.test.mjs', 'scripts/compliance-browser-bytes.test.mjs'],
    [NODE, 'scripts/production-combined-e2e.mjs'],
]
ATTESTATION = Path('/workspace/.zasp-cloud-owned/full-0b-joined-attestation-k7qib38a')
ATTESTATION_HASHES = {
    'capture-summary.json': '4ceda8011b2767391df1cafb21f9e5c1cd36957d8fd3b1b8a390cb9da19d00e3',
    'post-full-source-6674-manifest.json': '359d7008f324567b4b5e05e3df9c1bf90484eaff947fd39ec4a97f1855513ad4',
    'post-full-actual-build-manifest.json': '27de1aef879ac802f9459169dcc03b8df96433abf1db8e053218f28e4c1bb764',
    'dependency-postfull-closure.json': 'edeba3cdfd5af03313234e07dda2c23c6755b6a11f6fb1ddcbf28ceea1f07576',
}
FULL_RECEIPTS = Path('/tmp/zasp-cloud-evidence/root-full-0b-165ef1231a7942979fee52fb7f8f8fca')
FULL_RECEIPT_HASHES = {
    'before.json': '0c3ac2d12811bbf8c0ab122135b289eea88172f949550a56cc36e4efc1213692',
    'process-binding.json': 'fee5c2899b01b2b8b68cef6f1b194d15dbda5ae62d3740fcd1fbb626b1fae900',
    'result.json': 'fa1dee88d005d416736aa0bc858ba56a07b7b9f1aace09cb009cf8ec39de21ad',
}
PG_LIBRARY_DIRECTORY = '/tmp/zasp-cloud-tools/postgres-18.3/deps'
RAW_PSQL = '/tmp/zasp-cloud-tools/postgres-18.3/usr/lib/postgresql/18/bin/psql'
PG_PIN_MANIFEST_SHA256 = '50f4b59eae4b254cad89d6dbc316c52bab976c9c9dddb5059a92838ea2fe8020'

def validate_pg_pins():
    raw = Path(__file__).with_name('pg-client-closure-pins.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PG_PIN_MANIFEST_SHA256:
        raise RuntimeError('PG client closure manifest identity refusal')
    pins = json.loads(raw)['files']
    for file, expected in pins.items():
        path = Path(file)
        if stat.S_IMODE(path.stat().st_mode) != expected['mode'] or hashlib.sha256(path.read_bytes()).hexdigest() != expected['sha256']:
            raise RuntimeError('PG client closure pin refusal')
    return {'manifest_sha256': PG_PIN_MANIFEST_SHA256, 'members_checked': len(pins)}

def raw_psql_preflight(env):
    version = subprocess.check_output([RAW_PSQL, '--version'], env=env, text=True, timeout=5).strip()
    if version != 'psql (PostgreSQL) 18.3 (Debian 18.3-1.pgdg12+1)':
        raise RuntimeError('raw PG client version refusal')
    return version

def validate_members(root, manifest):
    for relative, expected in manifest['members'].items():
        file = root / relative
        metadata = file.lstat()
        if stat.S_IMODE(metadata.st_mode) != expected['mode']:
            raise RuntimeError('manifest mode mismatch')
        if expected['type'] == 'file':
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected['bytes'] or hashlib.sha256(file.read_bytes()).hexdigest() != expected['sha256']:
                raise RuntimeError('manifest file mismatch')
        elif expected['type'] == 'directory':
            if not stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError('manifest directory mismatch')
        else:
            raise RuntimeError('unsupported manifest entry')

def cleanup_signal_recorder(result):
    def record_signal(signum, frame):
        result.setdefault('cleanup_signals', []).append(signum)
        result['failure_class'] = 'CleanupInterrupted'
        result['completed'] = False
        result['exit_code'] = 1
    return record_signal

def successful_result(result, processes):
    return bool(result.get('commands_passed')) and not result.get('failure_class') and not result.get('cleanup_signals') and not result['survivors'] and not result['unexpected_descendants_after_commands'] and all(p.returncode == 0 for p in processes) and result['head_after'] == HEAD and result['tracked_clean_after'] and result['compiled_server_sha256_after'] == result['compiled_server_sha256_before']

def observe_storage(result):
    observed = {'monotonic': time.monotonic()}
    for name, directory in [('workspace', '/workspace'), ('tmp', '/tmp')]:
        space = os.statvfs(directory)
        observed[name + '_available_bytes'] = space.f_bavail * space.f_frsize
    result.setdefault('storage_observations', []).append(observed)
    if observed['workspace_available_bytes'] < 1_500_000_000 or observed['tmp_available_bytes'] < 100_000_000:
        raise RuntimeError('storage reserve refusal')

def durable(directory, name, data):
    target = directory / name
    temporary = directory / (name + '.next')
    with temporary.open('x') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    fd = os.open(directory, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def proc_table():
    table = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            table[int(entry.name)] = {'state': fields[0], 'ppid': int(fields[1]), 'group': int(fields[2]), 'start_ticks': int(fields[19])}
        except (FileNotFoundError, ProcessLookupError):
            pass
    return table

def descendants():
    table = proc_table()
    owned = {os.getpid()}
    while True:
        expanded = owned | {pid for pid, value in table.items() if value['ppid'] in owned}
        if expanded == owned:
            break
        owned = expanded
    return {pid: table[pid] for pid in owned if pid != os.getpid()}

def interrupt(signum, frame):
    raise InterruptedError('supervisor interrupted')

def main():
    # The parent must first join full92412 and attest exact source/build bytes.
    evidence = Path(sys.argv[1]).resolve()
    os.umask(0o077)
    evidence.mkdir(mode=0o700, exist_ok=False)
    temporary = evidence / 'tmp'
    temporary.mkdir(mode=0o700)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupt)
    env = {
        'HOME': '/home/agent',
        'PATH': '/tmp/zasp-cloud-tools/node-v22.23.1-linux-x64/bin:/tmp/zasp-cloud-tools/go/bin:/tmp/zasp-cloud-tools/bin:/tmp/zasp-cloud-tools/postgres-18.3/bin:/usr/local/bin:/usr/bin:/bin',
        'GOROOT': '/tmp/zasp-cloud-tools/go', 'GOTOOLCHAIN': 'local',
        'GOPROXY': 'direct', 'GOFLAGS': '-mod=readonly',
        'LD_LIBRARY_PATH': PG_LIBRARY_DIRECTORY,
        'TMPDIR': str(temporary), 'LANG': 'C.UTF-8', 'TZ': 'UTC',
        'ZASP_COMBINED_E2E_CHROME': '/usr/bin/chromium',
        'ZASP_COMBINED_E2E_COMPLIANCE': 'true',
    }
    processes = []
    records = []
    result = {'source_expected': HEAD, 'commands': COMMANDS, 'environment': env,
              'aggregate_seconds': 900, 'cleanup_seconds': 30, 'umask': '0077',
              'completed': False, 'exit_code': 1, 'failure_class': None,
              'scope': 'local connected browser, controlled identity/SDK providers; not deployed acceptance'}
    cleanup_deadline = None
    capture_deadline = None
    started = None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'subreaper unavailable')
        result['pg_client_closure_before'] = validate_pg_pins()
        result['actual_raw_psql_version'] = raw_psql_preflight(env)
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, env=env, text=True, timeout=5).strip()
        status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=SOURCE, env=env, text=True, timeout=5)
        if actual != HEAD or status:
            raise RuntimeError('source identity refusal')
        for name, expected in FULL_RECEIPT_HASHES.items():
            if hashlib.sha256((FULL_RECEIPTS / name).read_bytes()).hexdigest() != expected:
                raise RuntimeError('full joined receipt identity refusal')
        joined = json.loads((FULL_RECEIPTS / 'result.json').read_text())
        if hashlib.sha256((FULL_RECEIPTS / 'verify.log').read_bytes()).hexdigest() != joined['log_sha256']:
            raise RuntimeError('full log identity refusal')
        if joined['exit_code'] != 0 or joined['timed_out'] or not joined['main_wait_joined'] or joined['unexpected_surviving_children'] or joined['source_sha_before'] != HEAD or joined['source_sha_after'] != HEAD or joined['tracked_status_after']:
            raise RuntimeError('full joined result refusal')
        result['parent_full_receipt_sha256'] = FULL_RECEIPT_HASHES
        result['parent_full_log_sha256'] = joined['log_sha256']
        result['parent_attestation_files'] = {}
        for name, expected in ATTESTATION_HASHES.items():
            raw = (ATTESTATION / name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise RuntimeError('parent attestation identity refusal')
            result['parent_attestation_files'][name] = expected
        for name in ('post-full-source-6674-manifest.json', 'post-full-actual-build-manifest.json'):
            manifest = json.loads((ATTESTATION / name).read_text())
            if manifest['commit'] != HEAD or manifest['candidate'] != str(SOURCE):
                raise RuntimeError('parent manifest source refusal')
            validate_members(SOURCE, manifest)
        tool_paths = [sys.executable, NODE, '/tmp/zasp-cloud-tools/go/bin/go', TINI, '/usr/bin/chromium', '/usr/lib/chromium/chromium', '/usr/local/bin/docker', '/usr/bin/openssl', '/tmp/zasp-cloud-tools/postgres-18.3/bin/pg_config', '/tmp/zasp-cloud-tools/postgres-18.3/usr/lib/postgresql/18/bin/psql']
        result['tool_sha256'] = {file: hashlib.sha256(Path(file).read_bytes()).hexdigest() for file in tool_paths}
        result['tool_versions'] = {}
        for label, argv in [('python', [sys.executable, '--version']), ('node', [NODE, '--version']), ('go', ['/tmp/zasp-cloud-tools/go/bin/go', 'version']), ('tini', [TINI, '--version']), ('chromium', ['/usr/bin/chromium', '--version']), ('docker', ['/usr/local/bin/docker', '--version']), ('openssl', ['/usr/bin/openssl', 'version']), ('pg_config', ['/tmp/zasp-cloud-tools/postgres-18.3/bin/pg_config', '--version'])]:
            result['tool_versions'][label] = subprocess.check_output(argv, cwd=SOURCE, env=env, text=True, timeout=5).strip()
        if result['tool_versions']['node'] != 'v22.23.1' or 'go1.25.13 ' not in result['tool_versions']['go']:
            raise RuntimeError('pinned runtime version refusal')
        result['go_cache_paths_observed_not_immutable_closure'] = json.loads(subprocess.check_output(['/tmp/zasp-cloud-tools/go/bin/go', 'env', '-json', 'GOCACHE', 'GOMODCACHE', 'GOTMPDIR'], cwd=SOURCE, env=env, text=True, timeout=5))
        result['storage_monitor'] = {'interval_seconds_max': 2, 'workspace_minimum_bytes': 1_500_000_000, 'tmp_minimum_bytes': 100_000_000, 'refusal_cleanup': 'ordinary TERM then bounded KILL/join; no assertion/deadline changes'}
        observe_storage(result)
        result['head_before'] = actual
        result['compiled_server_sha256_before'] = hashlib.sha256((SOURCE / 'dist/server/index.js').read_bytes()).hexdigest()
        result['launcher_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result['supervisor_identity'] = {'pid': os.getpid(), **proc_table()[os.getpid()]}
        result['started_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        started = time.monotonic()
        capture_deadline = started + 900
        result['capture_deadline_monotonic'] = capture_deadline
        durable(evidence, 'initial.json', result)
        for number, command in enumerate(COMMANDS, 1):
            label = f'stage-{number}'
            remaining = capture_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('aggregate deadline')
            with (evidence / (label + '.raw.log')).open('xb') as log:
                proc = subprocess.Popen([TINI, '-s', '--', *command], cwd=SOURCE, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                processes.append(proc)
                identity = proc_table().get(proc.pid)
                record = {'argv': [TINI, '-s', '--', *command], 'cwd': str(SOURCE), 'source_head': HEAD,
                          'pid': proc.pid, 'identity': identity, 'joined': False,
                          'started_monotonic': time.monotonic(), 'capture_deadline_monotonic': capture_deadline}
                records.append(record)
                durable(evidence, label + '-start.json', record)
                if identity is None or identity['group'] != proc.pid:
                    raise RuntimeError('child identity unavailable')
                while True:
                    observe_storage(result)
                    remaining = capture_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('aggregate deadline')
                    try:
                        proc.wait(timeout=min(2, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= capture_deadline:
                            raise
                log.flush()
                os.fsync(log.fileno())
                record.update(joined=True, exit_code=proc.returncode, ended_monotonic=time.monotonic())
                durable(evidence, label + '-wait.json', record)
                if proc.returncode != 0:
                    raise RuntimeError('workflow command failed')
                if descendants():
                    raise RuntimeError('workflow command left descendants')
        result['commands_passed'] = True
    except BaseException as error:
        result['failure_class'] = type(error).__name__
    finally:
        # One absolute cleanup deadline; never reset per process/group.
        cleanup_deadline = time.monotonic() + 30
        result['cleanup_deadline_monotonic'] = cleanup_deadline
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, cleanup_signal_recorder(result))
        try:
            initial_descendants = descendants()
            result['unexpected_descendants_after_commands'] = bool(initial_descendants) and result.get('commands_passed', False)
            term_groups = {v['group'] for v in initial_descendants.values()}
            for group in term_groups:
                if group != os.getpgrp():
                    try: os.killpg(group, signal.SIGTERM)
                    except ProcessLookupError: pass
            kill_at = cleanup_deadline - 2
            while time.monotonic() < cleanup_deadline:
                for proc in processes:
                    proc.poll()
                # Reap adopted descendants only after direct Popen children joined.
                if all(proc.returncode is not None for proc in processes):
                    while True:
                        try:
                            pid, _ = os.waitpid(-1, os.WNOHANG)
                            if pid == 0: break
                        except ChildProcessError: break
                remaining = descendants()
                if not remaining and all(proc.returncode is not None for proc in processes):
                    break
                if time.monotonic() >= kill_at:
                    for group in {v['group'] for v in remaining.values()}:
                        if group != os.getpgrp():
                            try: os.killpg(group, signal.SIGKILL)
                            except ProcessLookupError: pass
                time.sleep(min(.02, max(0, cleanup_deadline - time.monotonic())))
            result['survivors'] = descendants()
            result['process_waits'] = [{'pid': proc.pid, 'joined': proc.returncode is not None, 'exit_code': proc.returncode} for proc in processes]
            remaining_seconds = cleanup_deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise TimeoutError('cleanup deadline exhausted')
            result['head_after'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, env=env, text=True, timeout=min(2, remaining_seconds)).strip()
            remaining_seconds = cleanup_deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise TimeoutError('cleanup deadline exhausted')
            result['tracked_clean_after'] = not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=SOURCE, env=env, text=True, timeout=min(2, remaining_seconds))
            result['compiled_server_sha256_after'] = hashlib.sha256((SOURCE / 'dist/server/index.js').read_bytes()).hexdigest()
            result['pg_client_closure_after'] = validate_pg_pins()
            result['completed'] = successful_result(result, processes)
        except BaseException as error:
            result['cleanup_failure_class'] = type(error).__name__
        result['exit_code'] = 0 if result['completed'] else 1
        result['completed_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        result['elapsed_seconds'] = time.monotonic() - started if capture_deadline else None
        result['stage_records'] = records
        durable(evidence, 'result.json', result)
    return result['exit_code']

if __name__ == '__main__':
    sys.exit(main())
