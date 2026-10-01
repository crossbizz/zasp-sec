import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

function git(root, args) {
  const result = spawnSync('git', ['-C', root, ...args], {encoding: 'utf8'});
  if (result.status !== 0) throw new Error(result.stderr || 'Git inspection failed');
  return result.stdout;
}

// Include untracked inputs and ignored environment files. Never print their contents.
function fingerprint(root, task, env) {
  if (task.reusable && env.NODE_OPTIONS?.trim())
    throw new Error('Reusable verification requires NODE_OPTIONS to be unset; external preloads are not fingerprinted');
  const files = new Set(git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean));
  for (const name of fs.readdirSync(root)) if (name === '.env' || name.startsWith('.env.')) files.add(name);
  // Some retained source evidence is ignored by Git but consumed by generators.
  const evidenceRoot = path.join(root, '.superpowers');
  function addEvidence(directory) {
    if (fs.lstatSync(directory).isSymbolicLink()) throw new Error('Unsupported symlink evidence directory: ' + directory);
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) addEvidence(file);
      else {
        if (entry.isSymbolicLink() && fs.statSync(file).isDirectory())
          throw new Error('Unsupported symlink evidence directory: ' + file);
        files.add(path.relative(root, file));
      }
    }
  }
  if (fs.existsSync(evidenceRoot)) addEvidence(evidenceRoot);
  const hash = crypto.createHash('sha256');
  hash.update(JSON.stringify({task, runtime: process.version, platform: process.platform, arch: process.arch,
    environment: Object.entries(env).sort(([a], [b]) => a.localeCompare(b))}));
  const resolved = path.isAbsolute(task.command) ? task.command : (env.PATH || '').split(path.delimiter)
    .map(dir => path.join(dir, task.command)).find(file => fs.existsSync(file));
  if (!resolved) throw new Error(`Command unavailable: ${task.command}`);
  files.add(resolved);
  for (const name of [...files].sort()) {
    const file = path.resolve(root, name);
    hash.update(JSON.stringify(name));
    if (!fs.existsSync(file)) { hash.update('missing'); continue; }
    const stat = fs.lstatSync(file);
    hash.update(String(stat.mode));
    if (stat.isSymbolicLink()) {
      if (fs.statSync(file).isDirectory()) throw new Error('Unsupported symlink input directory: ' + file);
      hash.update(fs.readlinkSync(file));
      if (fs.statSync(file).isFile()) hash.update(fs.readFileSync(file));
    } else if (stat.isFile()) hash.update(fs.readFileSync(file));
    else hash.update('directory');
  }
  return hash.digest('hex');
}

export async function runChecks({root, cache, tasks, reuse = false, env = process.env}) {
  const results = [];
  const verifiedInputs = [];
  for (const task of tasks) {
    const started = performance.now();
    const before = fingerprint(root, task, env);
    verifiedInputs.push({task, before});
    const receipt = path.join(cache, `${before}.json`);
    if (reuse && task.reusable && fs.existsSync(receipt)) {
      const saved = JSON.parse(fs.readFileSync(receipt, 'utf8'));
      if (saved.fingerprint === before && saved.status === 'passed') {
        results.push({name: task.name, status: 'reused', verifiedAt: saved.verifiedAt,
          fingerprint: before, log: saved.log, elapsedMs: performance.now() - started, executionMs: 0});
        continue;
      }
    }
    process.stdout.write(`Running ${task.name}\n`);
    fs.mkdirSync(cache, {recursive: true});
    const log = path.join(cache, `${before}-${crypto.randomUUID()}.log`);
    const fd = fs.openSync(log, 'wx', 0o600);
    let result;
    const executionStarted = performance.now();
    try {
      result = spawnSync(task.command, task.args, {cwd: root, env, stdio: ['ignore', fd, fd],
        timeout: task.timeoutMs || 900000});
    } finally { fs.closeSync(fd); }
    const executionMs = performance.now() - executionStarted;
    if (result.error || result.signal || result.status !== 0) {
      if (task.reusable && fs.existsSync(receipt)) fs.unlinkSync(receipt);
      throw new Error(`${task.name} failed: ${result.error?.message || result.signal || result.status}. Log: ${log}`);
    }
    if (fingerprint(root, task, env) !== before) {
      if (task.reusable && fs.existsSync(receipt)) fs.unlinkSync(receipt);
      throw new Error(`${task.name}: inputs changed during verification; rerun on a stable snapshot`);
    }
    const record = {name: task.name, status: 'passed', fingerprint: before, log,
      elapsedMs: performance.now() - started, executionMs, verifiedAt: new Date().toISOString()};
    // Only deterministic, local checks can opt into reuse. Release gates always execute.
    if (task.reusable) {
      fs.mkdirSync(cache, {recursive: true});
      const temporaryReceipt = receipt + '.' + crypto.randomUUID() + '.tmp';
      fs.writeFileSync(temporaryReceipt, JSON.stringify(record) + '\n', {mode: 0o600, flag: 'wx'});
      fs.renameSync(temporaryReceipt, receipt);
    }
    results.push(record);
  }
  for (const {task, before} of verifiedInputs)
    if (fingerprint(root, task, env) !== before)
      throw new Error(`${task.name}: batch snapshot inputs changed; rerun on a stable snapshot`);
  return results;
}

export function batchTasks(mode) {
  const tools = 'services/platform/migrations/tools/';
  if (mode === 'artifacts') return [
    'build-ordered-current-development.mjs', 'build-ordered-current-consolidated-reference.mjs',
    'ordered-current-native379-packet-v1.mjs'
  ].map(name => ({name, command: process.execPath, args: [tools + name, '--check'], reusable: true}));
  if (mode === 'release') return ['typecheck', 'build'].map(name => ({name, command: 'npm', args: ['run', name], reusable: false}));
  throw new Error('Use artifacts or release');
}

async function main() {
  const [mode, ...options] = process.argv.slice(2);
  const rootIndex = options.indexOf('--root');
  let requestedRoot = process.cwd();
  if (rootIndex !== -1) {
    if (!options[rootIndex + 1] || options[rootIndex + 1].startsWith('--')) throw new Error('--root requires a worktree path');
    requestedRoot = path.resolve(options[rootIndex + 1]);
    options.splice(rootIndex, 2);
  }
  if (!['artifacts', 'refresh', 'release'].includes(mode) || options.some(value => !['--run', '--reuse'].includes(value)))
    throw new Error('Usage: node scripts/launch-batch.mjs artifacts|refresh|release [--root PATH] [--run] [--reuse]. Default prints the plan.');
  if (mode === 'refresh' && options.includes('--reuse')) throw new Error('Refresh cannot reuse verification');
  const root = git(requestedRoot, ['rev-parse', '--show-toplevel']).trim();
  const tasks = batchTasks(mode === 'refresh' ? 'artifacts' : mode);
  if (!options.includes('--run')) {
    console.log(JSON.stringify({root, mode, tasks, scope: 'local verification; deployed acceptance remains separate'}, null, 2));
    return;
  }
  if (mode === 'refresh') {
    for (const task of tasks.slice(0, 2)) {
      process.stdout.write(`Regenerating ${task.name}\n`);
      const result = spawnSync(task.command, [task.args[0], '--write'], {cwd: root, stdio: 'inherit', timeout: 900000});
      if (result.error || result.signal || result.status !== 0) throw new Error(`${task.name} regeneration failed`);
    }
  }
  const cache = path.join(git(root, ['rev-parse', '--absolute-git-dir']).trim(), 'launch-batch-receipts');
  console.log(JSON.stringify({scope: 'local verification only; deployed acceptance remains separate',
    results: await runChecks({root, cache, tasks, reuse: options.includes('--reuse')})}, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(error => {console.error(error.message); process.exitCode = 1;});
