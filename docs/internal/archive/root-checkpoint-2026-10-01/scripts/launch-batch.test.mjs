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
