import test from 'node:test';
import assert from 'node:assert/strict';
import {migrationTestCommands} from './migration-test-partition.mjs';
import {runOwnedMigrationTests} from './owned-migration-tests.mjs';

const env = {RUNNER_TEMP: '/tmp/runner', ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT: '/tmp/archives', ZASP_BROWSER_RUNTIME_RAW_ROOT: '/tmp/raw', ZASP_P6_NATIVE_OPENFGA_URL: 'ambient'};
const commands = Object.values(migrationTestCommands);
function fixture(mode) {
  const calls = [];
  const controller = new AbortController();
  const pending = Promise.withResolvers();
  const adapters = {
    async reopen(name) {calls.push('open ' + name); return name;},
    async closeTool(name) {calls.push('close ' + name);},
    async start() {
      calls.push('start services');
      return {
        completed: pending.promise,
        environment: {ZASP_OPENFGA_URL: 'http://127.0.0.1:12408', ZASP_OPENFGA_TOKEN_FILE: '/private/token'},
        async close() {calls.push('close services');},
      };
    },
    run(exe, args, childEnv) {
      assert.equal(exe, 'go');
      assert.ok(commands.some(cmd => cmd.slice(1).join(' ') === args.join(' ')));
      assert.equal(childEnv.ZASP_P6_NATIVE_OPENFGA_URL, 'http://127.0.0.1:12408');
      assert.equal(childEnv.ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE, '/private/token');
      assert.equal(env.ZASP_P6_NATIVE_OPENFGA_URL, 'ambient');
      assert.equal(Object.hasOwn(childEnv, 'OPENFGA_AUTHN_PRESHARED_KEYS'), false);
      calls.push('start tests');
      const complete = Promise.withResolvers();
      if (mode === 'lost') pending.resolve();
      else if (mode === 'cancel') queueMicrotask(() => controller.abort());
      else complete.resolve({status: mode === 'fail' ? 1 : 0, signal: null});
      return {completed: complete.promise, async stop() {calls.push('stop tests'); complete.resolve({status:null, signal:'SIGTERM'});}};
    },
  };
  return {adapters, calls, controller};
}
for (const [i,command] of commands.entries()) test('migration lane '+i+' uses owned local service credentials and joins all processes', async () => {
  const {adapters, calls, controller} = fixture();
  await runOwnedMigrationTests(['--', ...command], env, controller.signal, adapters);
  assert.deepEqual(calls, ['open temporal','open openfga','start services','start tests','stop tests','close services','close temporal','close openfga']);
});
for (const mode of ['fail','lost','cancel']) test('joins tests and services on '+mode, async () => {
  const {adapters, calls, controller} = fixture(mode);
  await assert.rejects(runOwnedMigrationTests(['--', ...commands[0]], env, controller.signal, adapters));
  assert.ok(calls.indexOf('stop tests') < calls.indexOf('close services'));
  assert.ok(calls.includes('close temporal') && calls.includes('close openfga'));
});
test('partial tool setup and unreviewed command cannot launch tests', async () => {
  for (const args of [[], ['--', ...commands[0], '-run=^$'], ['--', ...commands[0].slice(0,-1)]]) {
    const {adapters, calls} = fixture();
    await assert.rejects(runOwnedMigrationTests(args, env, undefined, adapters));
    assert.deepEqual(calls, []);
  }
  const {adapters, calls} = fixture();
  const open = adapters.reopen;
  adapters.reopen = name => { if (name === 'openfga') throw Error('missing archive'); return open(name); };
  await assert.rejects(runOwnedMigrationTests(['--', ...commands[0]], env, undefined, adapters));
  assert.deepEqual(calls, ['open temporal','close temporal']);
});
