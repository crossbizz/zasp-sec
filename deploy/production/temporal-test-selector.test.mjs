import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { selectorDeploymentCommands } from './temporal-test-selector.mjs';

test('selector deployment installs the shipped independent one-second configuration', async () => {
  const config = JSON.parse(await readFile(new URL('./temporal-test-selector.config.json', import.meta.url), 'utf8'));
  const commands = selectorDeploymentCommands(config);
  assert.equal(commands.length, 2);
  assert.deepEqual(commands[0].args, ['up-temporal-test-selector']);
  assert.deepEqual(commands[1].args, ['configure-temporal-test-selector']);
  assert.deepEqual(JSON.parse(commands[1].env.ZASP_TEST_SELECTOR_CONFIGURATION), { revision: 1, cadence_seconds: 1, enabled: true });
  assert.equal(commands[1].env.ZASP_POLL_INTERVAL, undefined);
});
test('invalid or fractional selector deployment configuration fails before dispatch', () => {
  for (const config of [undefined, {}, {revision:1, cadence_seconds:1.5, enabled:true}, {revision:0, cadence_seconds:1, enabled:true}, {revision:1,cadence_seconds:'1',enabled:true}, {revision:1,cadence_seconds:1,enabled:true, polling:'1s'}]) {
    assert.throws(() => selectorDeploymentCommands(config));
  }
});
