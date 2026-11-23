"""Offline regression controls for hosted request evidence and process churn."""
import contextlib
import hashlib
import io
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
                         failureCode='cleanup_refused', failurePhase='cleanup_child',
                         ownedSessionCleanup=[dict(unknown=True, reason='untrusted diagnostic')])
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
            self.assertEqual(emitted['failurePhase'], 'cleanup_child')
            self.assertNotIn('untrusted diagnostic', capture.getvalue())
