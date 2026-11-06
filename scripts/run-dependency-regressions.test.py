"""Grouped application process-ownership checks; executed only by root."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "scripts/run-dependency-regressions.py"
DRIVER = """import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('scoped_dependency_reaper',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
sys.exit(module._run_owned(json.loads(sys.argv[2]),float(sys.argv[3])))
"""
# These existing real semantic/process-group guards are immutable in this batch.
IMMUTABLE = {
    'scripts/dependency-esbuild-regression.test.mjs': 'e95dbf56f6b30313954ff6a4d3a5780a1a03026d81d83152148019717ec692d9',
    'scripts/fixtures/dependency-esbuild-regression-child.mjs': '2a456acd0302ea8563b4f22d7ddb7b5d5f207b96a67f1a5abd67605162971640',
}


def identity(pid):
    raw = Path('/proc', str(pid), 'stat').read_text()
    tail = raw.rsplit(') ', 1)[1].split()
    return int(tail[1]), tail[19], tail[0]


def signal_owned(fd, sig):
    try:
        signal.pidfd_send_signal(fd, sig, None, 0)
    except ProcessLookupError:
        pass


class ScopedReaperTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, 'linux', 'root Linux process-ownership executor required')
        self.node = shutil.which('node')
        self.assertIsNotNone(self.node, 'actual Node prerequisite missing')
        self.assertTrue(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                        'actual Linux pidfd prerequisite missing')

    def driver(self, argv, timeout=90, **kwargs):
        return subprocess.Popen([sys.executable, '-c', DRIVER, str(LAUNCHER), json.dumps(argv), str(timeout)],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

    def finish(self, process, seconds=10):
        fd = os.pidfd_open(process.pid)
        try:
            try:
                stdout, stderr = process.communicate(timeout=seconds)
            except subprocess.TimeoutExpired:
                signal_owned(fd, signal.SIGKILL)
                process.communicate(timeout=3)
                self.fail('scoped launcher exceeded application lifecycle bound')
            return process.returncode, stdout, stderr
        finally:
            os.close(fd)

    def test_reaps_actual_orphan_while_node_test_runner_remains_active(self):
        with tempfile.TemporaryDirectory(prefix='zasp-reaper-node-') as directory:
            fixture = Path(directory, 'owned.test.mjs')
            fixture.write_text(r'''import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
test('actual orphan group disappears while Node activity continues', async()=>{
 const helper=spawn(process.execPath,['-e',"const {spawn}=require('node:child_process');spawn(process.execPath,['-e','setTimeout(()=>process.exit(0),40)'],{stdio:'ignore'});process.exit(0);"],{detached:true,stdio:'ignore'});
 await new Promise((resolve,reject)=>{helper.once('error',reject);helper.once('close',(code)=>code===0?resolve():reject(new Error('fixture helper failed')));});
 let gone=false;
 for(let attempt=0;attempt<20;attempt++){
  try{process.kill(-helper.pid,0);}catch(error){if(error.code==='ESRCH'){gone=true;break;}throw error;}
  await delay(25);
 }
 assert.equal(gone,true,'real exited orphan must be reaped, not ignored');
 console.log('ORPHAN_REAPED_WHILE_NODE_ALIVE');
 await delay(40);
});
''')
            status, stdout, stderr = self.finish(self.driver([self.node, '--test', str(fixture)]))
            self.assertEqual(status, 0, 'actual Node fixture failed under scoped reaper')
            self.assertIn(b'ORPHAN_REAPED_WHILE_NODE_ALIVE', stdout)
            self.assertIn(b'# pass 1', stdout)
            self.assertEqual(stderr, b'')

    def test_preserves_actual_exit_status_output_and_existing_strict_guards(self):
        for code in (0, 37):
            status, stdout, stderr = self.finish(self.driver([
                self.node, '-e', "process.stdout.write('ACTUAL_STDOUT');process.stderr.write('ACTUAL_STDERR');process.exit(" + str(code) + ");"
            ]))
            self.assertEqual((status, stdout, stderr), (code, b'ACTUAL_STDOUT', b'ACTUAL_STDERR'))
        status, _, _ = self.finish(self.driver([self.node, '-e', "process.kill(process.pid,'SIGTERM')"]))
        self.assertEqual(status, 128 + signal.SIGTERM)
        for name, expected in IMMUTABLE.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected,
                             'existing strict semantic/group guard or real fixture changed')
        # CLI is purpose-fixed: arbitrary commands/arguments cannot be used as a
        # broader executor. Parse rejection must occur before any child spawn.
        result = subprocess.run([sys.executable, str(LAUNCHER), '--', '/bin/sh', '-c', 'exit 0'],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        self.assertNotEqual(result.returncode, 0)

    def exercise_stop(self, mode):
        with tempfile.TemporaryDirectory(prefix='zasp-reaper-stop-') as directory:
            marker = Path(directory, 'owned.json')
            # The sibling belongs to THIS test, outside the launcher subtree.
            sibling = subprocess.Popen([self.node, '-e', 'setInterval(()=>{},1000)'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            sibling_fd = os.pidfd_open(sibling.pid)
            owned_fds = []
            process = None
            driver_fd = None
            try:
                code = r"""const {spawn}=require('node:child_process');const fs=require('node:fs');
const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{detached:true,stdio:'ignore'});
fs.writeFileSync(process.argv[1],JSON.stringify({parent:process.pid,child:child.pid}));
setInterval(()=>{},1000);
"""
                process = self.driver([self.node, '-e', code, str(marker)], timeout=0.7 if mode == 'timeout' else 90)
                driver_fd = os.pidfd_open(process.pid)
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline and process.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), 'actual owned Node subtree was not launched')
                data = json.loads(marker.read_text())
                parent_ppid, parent_start, _ = identity(data['parent'])
                child_ppid, child_start, _ = identity(data['child'])
                self.assertEqual(parent_ppid, process.pid)
                self.assertEqual(child_ppid, data['parent'])
                for pid, start in [(data['parent'], parent_start), (data['child'], child_start)]:
                    fd = os.pidfd_open(pid)
                    self.assertEqual(identity(pid)[1], start)
                    owned_fds.append((fd, pid, start))
                if mode == 'cancel':
                    signal_owned(driver_fd, signal.SIGTERM)
                status, _, _ = self.finish(process, seconds=8)
                self.assertEqual(status, 124 if mode == 'timeout' else 128 + signal.SIGTERM)
                self.assertIsNone(sibling.poll(), 'cleanup touched unrelated sibling')
                for _, pid, start in owned_fds:
                    try:
                        row = identity(pid)
                    except FileNotFoundError:
                        continue
                    self.assertNotEqual(row[1], start, 'owned live or zombie descendant survived join')
            finally:
                # Cleanup is restricted to exact current pidfds opened while
                # ancestry/start identity was proven, never marker PID kills.
                for fd, _, _ in owned_fds:
                    signal_owned(fd, signal.SIGKILL)
                    os.close(fd)
                if driver_fd is not None:
                    if process.poll() is None:
                        signal_owned(driver_fd, signal.SIGKILL)
                        process.communicate(timeout=3)
                    os.close(driver_fd)
                signal_owned(sibling_fd, signal.SIGTERM)
                try:
                    sibling.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    signal_owned(sibling_fd, signal.SIGKILL)
                    sibling.wait(timeout=2)
                os.close(sibling_fd)

    def test_bounded_cancel_and_timeout_reap_only_owned_descendants(self):
        for mode in ('cancel', 'timeout'):
            self.exercise_stop(mode)


if __name__ == '__main__':
    unittest.main()
