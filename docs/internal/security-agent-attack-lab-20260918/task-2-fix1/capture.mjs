// Freeze inherited bytes before touching a task-owned path. Never stages source.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const out = path.join(root, 'docs/internal/security-agent-attack-lab-20260918/task-2-fix1');
const manifest = path.join(out, 'blobs.json');
const entries = fs.existsSync(manifest) ? JSON.parse(fs.readFileSync(manifest, 'utf8')) : [];
const blob = file => fs.existsSync(path.join(root, file)) ? execFileSync('git', ['hash-object', '-w', '--', file], { cwd: root, encoding: 'utf8' }).trim() : null;
const [mode, ...args] = process.argv.slice(2);
if (mode === 'before') {
  for (const file of args) if (!entries.some(e => e.path === file)) {
    const before = blob(file);
    entries.push({ path: file, before, after: null });
    if (before) {
      const original = path.join(out, 'before', file);
      fs.mkdirSync(path.dirname(original), { recursive: true });
      fs.writeFileSync(original, execFileSync('git', ['cat-file', 'blob', before], { cwd: root }), { flag: 'wx' });
    }
  }
  fs.writeFileSync(manifest, JSON.stringify(entries, null, 2) + '\n');
} else if (mode === 'finish') {
  let patch = '';
  for (const entry of entries) {
    entry.after = blob(entry.path);
    const original = entry.before ? path.join(out, 'before', entry.path) : '/dev/null';
    const result = spawnSync('git', ['diff', '--no-index', '--', original, path.join(root, entry.path)], { cwd: root, encoding: 'utf8' });
    if (result.status !== 0 && result.status !== 1) throw new Error(result.stderr);
    patch += result.stdout.replace(/^diff --git .*$/m, () => `diff --git a/${entry.path} b/${entry.path}`)
      .replace(/^--- .*$/m, () => entry.before ? `--- a/${entry.path}` : '--- /dev/null')
      .replace(/^\+\+\+ .*$/m, () => `+++ b/${entry.path}`);
  }
  fs.writeFileSync(manifest, JSON.stringify(entries, null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'scoped.patch'), patch);
} else throw new Error('expected before or finish');
