"""Offline regression controls for hosted request evidence and process churn."""
import contextlib
import ctypes
import subprocess
import hashlib
import io
import os
import json
from pathlib import Path
import runpy
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

BASE = Path(__file__).resolve().parent


class HostedControls(unittest.TestCase):
    def runner(self, root):
        plan = root / 'plan.json'
        raw = json.dumps({'ghExecutable': '/unused', 'sourceBase': str(BASE)}).encode()
        plan.write_bytes(raw)
        with patch.object(sys, 'argv', ['run-hosted.py', str(plan), hashlib.sha256(raw).hexdigest()]), \
             patch('tempfile.mkdtemp', return_value=str(root)):
            return runpy.run_path(str(BASE / 'run-hosted.py'))

    def test_departed_processes_and_changed_identity(self):
        with tempfile.TemporaryDirectory() as root:
            runner = self.runner(Path(root))
            members = runner['owned_session']
            original = {'pid': 40, 'sid': 40, 'pgid': 40, 'ppid': 17, 'startTicks': '80'}
            deadline = time.monotonic() + 10
            with patch('os.scandir', return_value=[SimpleNamespace(name='40')]):
                for error in (FileNotFoundError(), ProcessLookupError()):
                    with patch.dict(members.__globals__, proc_row=lambda *_: self.raise_error(error)):
                        self.assertEqual(members(40, deadline), [])
                with patch.dict(members.__globals__, proc_row=lambda *_: original,
                                credential_row=lambda *_: dict(original, startTicks='81')):
                    with self.assertRaisesRegex(RuntimeError, '^owned_session_identity_unknown$'):
                        members(40, deadline)

    def test_normal_join_allows_an_exiting_helper_but_refuses_a_lingering_one(self):
        # Observe a real fork in the query's session after its leader returns.
        # The pipe model is the same as acquire(): descendants close both pipes.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        self.addCleanup(lambda: self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0))
        for linger in (False, True):
            with self.subTest(linger=linger), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                acquire = self.runner(root)['acquire']
                get_members = acquire.__globals__['owned_session']
                get_credential = acquire.__globals__['credential_row']
                helper = root / 'query'
                helper.write_text(f'''#!{sys.executable}
import os, time
from pathlib import Path
root = Path({tmp!r})
if os.environ.get('GH_TELEMETRY') != '0' or os.environ.get('GH_NO_UPDATE_NOTIFIER') != '1':
    raise SystemExit(2)
until = time.monotonic() + 5
while not (root/'started').exists() and time.monotonic() < until:
    time.sleep(.005)
if os.fork() == 0:
    os.close(1)
    os.close(2)
    while not (root/'observed').exists() and time.monotonic() < until:
        time.sleep(.005)
    time.sleep({2 if linger else .06})
    os._exit(0)
os.write(1, b"HTTP/2 200 OK\\r\\ncontent-type: application/json\\r\\n\\r\\n[]")
''')
                helper.chmod(0o700)
                def credentials(*args):
                    row = get_credential(*args)
                    (root / 'started').touch()
                    return row
                def members(*args):
                    rows = get_members(*args)
                    if rows:
                        (root / 'observed').touch()
                    return rows
                cleanups = []
                with patch.dict(os.environ, GH_TELEMETRY='enabled', GH_NO_UPDATE_NOTIFIER=''), \
                     patch.dict(acquire.__globals__, guard=lambda: None, GH=str(helper),
                                owned_session=members, credential_row=credentials, CLEANUPS=cleanups):
                    if linger:
                        with self.assertRaisesRegex(RuntimeError, 'owned public query cleanup refusal'):
                            acquire('/advisories?type=reviewed', 65536)
                    else:
                        self.assertEqual(acquire('/advisories?type=reviewed', 65536)[0], 200)
                self.assertTrue(cleanups[0]['normalJoin'])
                self.assertEqual(cleanups[0]['cliExitBeforeCleanup'], 0)
                self.assertGreaterEqual(cleanups[0]['elapsedMs'], 0)
                self.assertTrue(cleanups[0]['membersBefore'])
                self.assertEqual(cleanups[0]['membersAfter'], [])
                self.assertTrue(cleanups[0]['completed'])
                self.assertFalse(cleanups[0]['unknown'])
                self.assertEqual(cleanups[0]['intervened'], linger)
                self.assertEqual(bool(cleanups[0]['signals']), linger)

    def test_request_refusal_survives_required_child_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            acquire = self.runner(Path(tmp))['acquire']
            def guarded():
                if acquire.__globals__['PHASE'] == 'read_response':
                    raise RuntimeError('memory floor')
            def sleeper(*_args, **kwargs):
                return original_popen([sys.executable, '-c', 'import time; time.sleep(5)'], **kwargs)
            original_popen = subprocess.Popen
            cleanups = []
            with patch.dict(acquire.__globals__, guard=guarded, CLEANUPS=cleanups), \
                 patch.object(subprocess, 'Popen', side_effect=sleeper):
                with self.assertRaisesRegex(RuntimeError, '^memory floor$'):
                    acquire('/advisories?type=reviewed', 65536)
                self.assertEqual(acquire.__globals__['PHASE'], 'read_response')
            self.assertTrue(cleanups[0]['intervened'])
            self.assertTrue(cleanups[0]['completed'])

    @staticmethod
    def raise_error(err):
        raise err

    def test_comm_is_an_opaque_kernel_field(self):
        with tempfile.TemporaryDirectory() as root:
            proc_row = self.runner(Path(root))['proc_row']
            tail = [b'R', b'1', b'20', b'20'] + [b'0'] * 15 + [b'1234']
            row = b'20 (name) \xff) ' + b' '.join(tail)
            with patch.object(Path, 'open', return_value=io.BytesIO(row)):
                value = proc_row(20, time.monotonic() + 10)
            self.assertEqual((value['sid'], value['pid'], value['startTicks']), (20, 20, '1234'))

    def test_summary_publishes_only_fixed_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / 'result.json'
            value = dict(format='root-owned-official-public-lock-query-observation-v1',
                         releaseAccepted=False, requests=[], failureClass='RuntimeError',
                         failureCode='memory_floor', failurePhase='read_response',
                         ownedSessionCleanup=[dict(unknown=True, reason='untrusted diagnostic', normalJoin=True,
                                                  cliExitBeforeCleanup=0, elapsedMs=252, sid=10,
                                                  membersBefore=[dict(pid=10, nameClass='other'),
                                                                 dict(pid=11, nameClass='gh'),
                                                                 dict(pid=12, nameClass='untrusted diagnostic')])])
            evidence.write_text(json.dumps(value))
            capture = io.StringIO()
            real_glob = Path.glob
            def isolated_glob(path, pattern):
                if path == Path('/tmp'):
                    return [evidence]
                return real_glob(path, pattern)
            with patch.object(sys, 'argv', ['safe-summary.py', str(root)]), \
                 patch.object(Path, 'glob', isolated_glob), contextlib.redirect_stdout(capture):
                runpy.run_path(str(BASE / 'safe-summary.py'))
            emitted = json.loads(capture.getvalue().split('::')[-1])
            self.assertFalse(emitted['complete'])
            self.assertFalse(emitted['releaseAccepted'])
            self.assertTrue(emitted['cleanupUnknown'])
            self.assertEqual(emitted['cleanupCliExitBeforeCleanup'], 0)
            self.assertEqual(emitted['cleanupElapsedMs'], 252)
            self.assertEqual(emitted['observedHelperNames'], ['gh'])
            self.assertEqual(emitted['failureCode'], 'memory_floor')
            self.assertEqual(emitted['failurePhase'], 'read_response')
            self.assertNotIn('untrusted diagnostic', capture.getvalue())
