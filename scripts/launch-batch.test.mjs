import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const moduleURL = new URL('./launch-batch.mjs', import.meta.url);
const fixture = t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'launch-batch-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
  fs.writeFileSync(path.join(root, 'source.txt'), 'original');
  return root;
};

test('release plan always executes typecheck and production build', async () => {
  const {batchTasks} = await import(moduleURL);
  assert.deepEqual(batchTasks('release').map(task => [task.args, task.reusable]), [
    [['run', 'typecheck'], false], [['run', 'build'], false]
  ]);
});

test('cache reuses only successful unchanged deterministic checks', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const cache = path.join(root, '.git', 'batch-receipts');
  const task = {name: 'local', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  const run = () => runChecks({root, cache, tasks: [task], reuse: true, env: {PATH: process.env.PATH}});
  assert.equal((await run())[0].status, 'passed');
  assert.equal((await run())[0].status, 'reused');
  fs.writeFileSync(path.join(root, 'source.txt'), 'changed');
  assert.equal((await run())[0].status, 'passed');
});

test('reports fresh supervision time separately from cached execution time', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const task = {name: 'timed', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  const run = () => runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks: [task], reuse: true});
  const fresh = (await run())[0];
  assert.equal(fresh.status, 'passed');
  assert.ok(Number.isFinite(fresh.elapsedMs) && fresh.elapsedMs >= 0);
  assert.ok(Number.isFinite(fresh.executionMs) && fresh.executionMs > 0);
  assert.ok(fresh.elapsedMs >= fresh.executionMs);
  const reused = (await run())[0];
  assert.equal(reused.status, 'reused');
  assert.ok(Number.isFinite(reused.elapsedMs) && reused.elapsedMs >= 0);
  assert.equal(reused.executionMs, 0);
});

test('failure stops the batch and never creates a passing receipt', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const cache = path.join(root, '.git', 'batch-receipts');
  const tasks = [{name: 'bad', command: process.execPath, args: ['-e', 'process.exit(7)'], reusable: true},
    {name: 'later', command: process.execPath, args: ['-e', 'throw Error("must not run")']}];
  await assert.rejects(runChecks({root, cache, tasks, reuse: true}), /bad.*7/);
  assert.deepEqual(fs.existsSync(cache) ? fs.readdirSync(cache).filter(name => name.endsWith('.json')) : [], []);
});

test('environment changes invalidate receipts; release checks always rerun', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const cache = path.join(root, '.git', 'batch-receipts');
  const local = {name: 'local', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  const release = {...local, name: 'build', reusable: false};
  const run = env => runChecks({root, cache, tasks: [local, release], reuse: true, env});
  await run({PATH: process.env.PATH, TEST_MODE: 'one'});
  assert.deepEqual((await run({PATH: process.env.PATH, TEST_MODE: 'one'})).map(r => r.status), ['reused', 'passed']);
  assert.deepEqual((await run({PATH: process.env.PATH, TEST_MODE: 'two'})).map(r => r.status), ['passed', 'passed']);
});

test('a concurrent source change refuses verification evidence', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const task = {name: 'racing', command: process.execPath, args: ['-e', 'require("fs").writeFileSync("source.txt", "raced")'], reusable: true};
  await assert.rejects(runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks: [task]}), /inputs changed/);
});

test('missing ignored environment file changes also invalidate receipts', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  fs.writeFileSync(path.join(root, '.gitignore'), '.env\n');
  const task = {name: 'local', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  const run = () => runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks: [task], reuse: true});
  await run();
  fs.writeFileSync(path.join(root, '.env'), 'TEST_VALUE=changed');
  assert.equal((await run())[0].status, 'passed');
});

test('ignored source evidence invalidates a cached generator check', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  fs.writeFileSync(path.join(root, '.gitignore'), '.superpowers/\n');
  fs.mkdirSync(path.join(root, '.superpowers'));
  const input = path.join(root, '.superpowers', 'source.json');
  fs.writeFileSync(input, '{}');
  const task = {name: 'local', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  const run = () => runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks: [task], reuse: true});
  await run();
  fs.writeFileSync(input, '{"changed":true}');
  assert.equal((await run())[0].status, 'passed');
});

test('a later check cannot certify an earlier check from a different snapshot', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const tasks = [
    {name: 'first', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true},
    {name: 'later', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true},
  ];
  const later = tasks[1];
  // Simulate a concurrent edit at the boundary, before the next check snapshots inputs.
  Object.defineProperty(tasks, '1', {get() {
    fs.writeFileSync(path.join(root, 'source.txt'), 'between checks');
    return later;
  }});
  await assert.rejects(runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks}), /inputs changed|snapshot/);
});

test('forced failed reruns preserve the log of an earlier passing receipt', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const marker = path.join(root, '.git', 'already-ran');
  const task = {name: 'sometimes', command: process.execPath, args: ['-e',
    'const fs=require("fs"); const marker=' + JSON.stringify(marker) + '; if(fs.existsSync(marker)){console.log("failure");process.exit(7)}fs.writeFileSync(marker,"1");console.log("success")'], reusable: true};
  const options = {root, cache: path.join(root, '.git', 'receipts'), tasks: [task]};
  const saved = (await runChecks(options))[0];
  await assert.rejects(runChecks(options), /sometimes.*7/);
  assert.match(fs.readFileSync(saved.log, 'utf8'), /success/);
  assert.doesNotMatch(fs.readFileSync(saved.log, 'utf8'), /failure/);
  await assert.rejects(runChecks({...options, reuse: true}), /sometimes.*7/);
});

test('refuses reusable verification with externally injected Node preloads', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  const preload = path.join(root, '.git', 'preload.cjs');
  fs.writeFileSync(preload, '');
  const task = {name: 'local', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  await assert.rejects(runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks: [task],
    reuse: true, env: {...process.env, NODE_OPTIONS: '--require=' + preload}}), /NODE_OPTIONS/);
});

test('refuses evidence directories whose symlinked children hide inputs', async t => {
  const {runChecks} = await import(moduleURL);
  const root = fixture(t);
  fs.writeFileSync(path.join(root, '.gitignore'), '.superpowers/\n');
  fs.mkdirSync(path.join(root, '.superpowers'));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), 'launch-evidence-'));
  t.after(() => fs.rmSync(external, {recursive: true, force: true}));
  fs.writeFileSync(path.join(external, 'source.json'), '{}');
  fs.symlinkSync(external, path.join(root, '.superpowers', 'linked'), 'dir');
  const task = {name: 'local', command: process.execPath, args: ['-e', 'process.exit(0)'], reusable: true};
  await assert.rejects(runChecks({root, cache: path.join(root, '.git', 'receipts'), tasks: [task], reuse: true}), /symlink.*directory/i);
});
