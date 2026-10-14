import test from 'node:test';
import assert from 'node:assert/strict';
import { CONNECTOR_ACCEPTANCE_GROUPS as groups, selectConnectorAcceptanceGroup as select, validateConnectorAcceptanceTrace as validate, parseConnectorNativeObservation as observation } from './connector-acceptance-groups.mjs';
const pkg = 'github.com/zasp-ai/zasp-sec/services/platform/apiserver';
const trace = selected => [...selected.names.flatMap(Test => [{Package: pkg, Test, Action: 'run'}, {Package: pkg, Test, Action: 'pass'}]), {Package: pkg, Action: 'pass'}];
test('required application groups retain every flow and owned database', () => {
  assert.deepEqual(Object.keys(groups), ['oauth', 'lifecycle', 'pkce', 'callback']);
  assert.deepEqual(Object.values(groups).map(g => [g.names.length, g.postgresJoins]), [[3, 1], [6, 2], [4, 2], [4, 2]]);
  const names = Object.values(groups).flatMap(g => g.names);
  assert.equal(names.length, 17); assert.equal(new Set(names).size, 17);
  assert.equal(Object.values(groups).reduce((n, g) => n + g.postgresJoins, 0), 7);
  for (const key of Object.keys(groups)) { assert.equal(select([key]), groups[key]); validate(trace(groups[key]), groups[key]); }
});
test('missing, arbitrary, inherited, or multiple selectors cannot silently run a subset', () => {
  for (const args of [[], [''], ['all'], ['oauth|callback'], ['oauth', 'pkce'], ['constructor'], ['__proto__'], null, 'oauth']) assert.throws(() => select(args));
});
test('partial, duplicated, skipped, failed, foreign, or cross-group traces refuse', () => {
  const selected = groups.callback, good = trace(selected);
  for (const bad of [good.slice(1), [...good, good[0]], [...good, {Package: pkg, Action: 'skip'}], [...good, {Package: pkg, Action: 'fail'}], [...good, {Package: pkg, Action: 'unknown'}], [...good, {Package: pkg, Test: groups.pkce.top, Action: 'run'}], good.map(row => ({...row, Package: 'other/package'})), good.filter(row => row.Test !== undefined)]) assert.throws(() => validate(bad, selected));
  assert.throws(() => validate(good, {...selected}));
});

test('native observations expose only bounded closed catalog and cutover fields', () => {
  const value = observation('    connector_maintenance_catalog_diagnostic_test.go:12: connector catalog kind=function before=4 after=4 added=0 removed=0 changed=1\n');
  assert.deepEqual(value, {kind: 'catalog-object', value: {kind: 'function', before:4, after:4, added:0, removed:0, changed:1}});
  assert.deepEqual(observation('connector cutover prepare stage=model-read\n'), {kind:'cutover',stage:'model-read'});
  assert.deepEqual(observation('connector catalog diagnostic=unavailable\n'), {kind:'catalog-summary',value:{observed:false}});
  const summary='connector catalog diagnostic=observed before_rows=20 after_rows=20 before_duplicates=0 after_duplicates=0 before_registered=true after_registered=false before_guc_equal=true after_guc_equal=false owner_guc_stable=true api_guc_stable=true';
  assert.equal(observation(summary).value.afterRegistered,false);
  for (const input of [summary+' PRIVATE_CANARY',summary+'\nPRIVATE_CANARY',summary.replace('20','4097'),'connector catalog kind=PRIVATE_CANARY before=1 after=1 added=0 removed=0 changed=0','connector cutover prepare stage=PRIVATE_CANARY','PRIVATE_CANARY'+summary,'x'.repeat(16385),null]) assert.equal(observation(input),null);
});
