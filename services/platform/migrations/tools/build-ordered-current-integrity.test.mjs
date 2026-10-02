import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {inspectOrderedSource, inspectOrderedCompiled, verifyOrderedPartition} from './build-ordered-current-integrity.mjs';

const input = process.env.ZASP_ORDERED_INVENTORY_CAPTURE;
if (!input) {
  test('external inventory capture unavailable without ZASP_ORDERED_INVENTORY_CAPTURE', {skip:'external pinned capture is not present in this checkout'}, ()=>{});
} else {
const raw = fs.readFileSync(input);
assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), '720683fb7646085a2ecc226746cb3a71d9dd24d296a6ab2103cbf0d36573bb7c');
const functions = new Map(JSON.parse(raw).functions.map(f => [f.signature, f]));
const source = signature => { assert.ok(functions.has(signature)); return functions.get(signature).source; };

test('actual mixed predecessor retains static relations and dynamic tail as separate obligations', () => {
  const got = inspectOrderedSource(source('zasp_temporal68.predecessor_ready(text,text)'));
  assert.ok(got.calls.some(x => x.name === 'zasp_temporal68.base_ready'));
  assert.ok(got.relations.some(x => x.name === 'zasp_temporal67.registration'));
  assert.ok(got.dynamic.some(x => x.keyword === 'EXECUTE'));
  assert.equal(verifyOrderedPartition(got, []), false, 'an unclassified actual source must not be accepted');
});

test('source inventory preserves actual closed-namespace predicates verbatim', () => {
  const s = source('zasp_authorization80_worker.catalog_ready()');
  const got = inspectOrderedSource(s);
  assert.ok(got.relations.some(x => x.name === 'pg_proc'));
  assert.ok(got.universe.some(x => x.expression.includes("'zasp_authorization80_worker'::regnamespace")));
  for (const x of [...got.calls, ...got.relations, ...got.dynamic, ...got.universe]) {
    assert.equal(s.slice(x.start, x.end), x.text);
  }
  assert.deepEqual(got, inspectOrderedSource(s));
});

test('literal/comment names cannot become executable dependencies; unknown live names remain visible', () => {
  const got = inspectOrderedSource("SELECT zasp_new_unknown.helper() FROM pg_catalog.pg_proc p WHERE p.pronamespace='zasp_authorization80_worker'::regnamespace; -- zasp_fake.call()\n");
  assert.deepEqual(got.calls.map(x => x.name), ['zasp_new_unknown.helper']);
  assert.deepEqual(got.relations.map(x => x.name), ['pg_catalog.pg_proc']);
  assert.throws(() => inspectOrderedSource("SELECT 'unterminated"), /unterminated/);
});

test('partition refuses missing, duplicate and unknown dispositions rather than silently dropping refs', () => {
  const got = inspectOrderedSource('SELECT zasp_temporal68.current_ready()');
  const rows = got.calls.map(x => ({id: x.id, disposition: 'retain-live'}));
  assert.equal(verifyOrderedPartition(got, rows), true);
  assert.equal(verifyOrderedPartition(got, []), false);
  assert.equal(verifyOrderedPartition(got, [...rows, ...rows]), false);
  assert.equal(verifyOrderedPartition(got, rows.map(x => ({...x, disposition:'ignore'}))), false);
});

test('actual current compiler inventories declarations without pretending later transforms are absent', () => {
  const file=process.env.ZASP_ORDERED_INVENTORY_COMPILED;
  assert.ok(file, 'explicit current compiler artifact required');
  const artifact=JSON.parse(fs.readFileSync(file));
  assert.equal(artifact.checksum,'e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960');
  assert.equal(sha(artifact.source),'816a024518918d4d1fd5f0fd532323e8d3c4458f8905fbdf9af545693520a17a');
  const result=inspectOrderedCompiled(artifact.source);
  assert.ok(result.declarations.some(d=>d.name==='zasp_authorization80_worker.catalog_ready' && d.source.includes('pg_get_functiondef')));
  assert.ok(result.declarations.some(d=>d.name==='zasp_authorization80_worker.ordered69_stop'));
  assert.ok(result.transforms.some(t=>t.tag==='$ordered_lifecycle_copies$' && t.source.includes('EXECUTE d')));
  assert.ok(result.transforms.some(t=>t.tag==='$higher_readiness$' || t.source.includes('higher_records')));
  for(const d of [...result.declarations,...result.transforms]) assert.equal(artifact.source.slice(d.start,d.end),d.text);
  assert.deepEqual(result,inspectOrderedCompiled(artifact.source));
});
function sha(s){return crypto.createHash('sha256').update(s).digest('hex');}
}
