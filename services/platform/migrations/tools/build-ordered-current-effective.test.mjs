import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {reconcileOrderedEffective, inspectOrderedSource, partitionOrderedBody, inspectOrderedCallTokens, inspectOrderedInlineLive} from './build-ordered-current-integrity.mjs';

const sha = x => crypto.createHash('sha256').update(x).digest('hex');
function pinned(variable, expected) {
  assert.ok(process.env[variable], 'explicit current reference required');
  const raw = fs.readFileSync(process.env[variable]);
  assert.equal(sha(raw), expected, 'reviewed input file identity');
  return JSON.parse(raw);
}
if(!process.env.ZASP_ORDERED_INVENTORY_EFFECTIVE||!process.env.ZASP_ORDERED_INVENTORY_COMPILED){
 test('external current reference unavailable without explicit inventory inputs',{skip:'current effective reference paths are not present in this checkout'},()=>{});
} else {
const catalog = pinned('ZASP_ORDERED_INVENTORY_EFFECTIVE', 'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
const compiled = pinned('ZASP_ORDERED_INVENTORY_COMPILED', '9600d455d8e03d14a3c37983ab1ba8654981befe0d39818eb9197e2d4312a8f4');
const root = 'zasp_authorization80_worker.ordered69_stop(jsonb)';

test('current compiled declarations reconcile to effective bodies instead of treating pre-transform source as final', () => {
  const got = reconcileOrderedEffective(catalog, compiled.source, [root]);
  assert.equal(got.declarations.length, 156);
  assert.equal(got.declarations.filter(x => x.status === 'body-exact').length, 148);
  const transformed = got.declarations.find(x => x.identity === 'zasp_authorization80_worker.ordered68_policy_store(text,jsonb,text,bytea,bytea,text)');
  assert.equal(transformed?.status, 'effective-body-differs');
  assert.notEqual(transformed?.compiledBodySHA256, transformed?.effectiveBodySHA256);
  assert.equal(got.transforms.length, 89);
  assert.equal(got.transforms.find(x => x.tag === '$ordered_lifecycle_copies$')?.disposition, 'retained-install-provenance');
});

test('actual lifecycle graph resolves native children and INSERT targets without inventing callable objects', () => {
  const got = reconcileOrderedEffective(catalog, compiled.source, [root]);
  assert.ok(got.edges.some(x => x.from === root && x.to === 'zasp_authorization80_worker.require_ordered69(text,jsonb)' && x.kind === 'call'));
  assert.ok(got.edges.some(x => x.from === root && x.to === 'zasp_authorization80_worker.ordered69_stop_inner(jsonb)' && x.kind === 'call'));
  assert.ok(got.edges.some(x => x.to === 'public.zasp_security_agent_audit' && x.kind === 'insert-target'));
  assert.ok(!got.nodes.some(x => x.identity.startsWith('public.zasp_security_agent_audit(')));
  assert.ok(got.nodes.some(x => x.identity === 'zasp_authorization80.runtime_audit_ready()' && x.inventory.dynamic.some(d => d.keyword === 'EXECUTE')));
  assert.deepEqual(got, reconcileOrderedEffective(catalog, compiled.source, [root]));
});

test('unknown executable edge and ambiguous callable name refuse the fixed inventory', () => {
  const altered = structuredClone(catalog);
  const f = altered.functions.find(x => x.identity === root);
  f.definition = f.definition.replace('zasp_authorization80_worker.ordered69_finish(proof)', 'zasp_unclassified.execute(proof)');
  assert.throws(() => reconcileOrderedEffective(altered, compiled.source, [root]), /unresolved callable/);
  const ambiguous = structuredClone(catalog);
  const helper = structuredClone(ambiguous.functions.find(x => x.identity === 'zasp_authorization80_worker.ordered69_finish(jsonb)'));
  helper.identity = 'zasp_authorization80_worker.ordered69_finish(text)';
  ambiguous.functions.push(helper);
  assert.throws(() => reconcileOrderedEffective(ambiguous, compiled.source, [root]), /ambiguous callable/);
});

test('missing or duplicate current root and non-supported body representation refuse', () => {
  assert.throws(() => reconcileOrderedEffective(catalog, compiled.source, [root, root]), /root/);
  assert.throws(() => reconcileOrderedEffective(catalog, compiled.source, ['zasp_not_installed.root()']), /root/);
  const altered = structuredClone(catalog);
  altered.functions.find(x => x.identity === root).definition = 'CREATE FUNCTION unsupported';
  assert.throws(() => reconcileOrderedEffective(altered, compiled.source, [root]), /effective body/);
});

test('body partition preserves non-call clock, MAC, revision, locks and exception bytes around exact gate edges', () => {
  const source = catalog.functions.find(x => x.identity === 'zasp_authorization80_worker.require_ordered69(text,jsonb)').definition.split('$function$')[1];
  const sites = inspectOrderedSource(source).calls.filter(x => x.name === 'zasp_authorization80_worker.catalog_ready');
  assert.equal(sites.length, 1);
  const pieces = partitionOrderedBody(source, sites.map(x => x.id));
  assert.equal(pieces.map(x => x.text).join(''), source);
  assert.equal(pieces.filter(x => x.disposition === 'replace-structural-edge').length, 1);
  const kept = pieces.filter(x => x.disposition === 'retain-original').map(x => x.text).join('');
  for (const guard of ['clock_timestamp()', 'hmac(', 'FOR SHARE', 'FOR UPDATE', 'proof', 'data_exception']) assert.ok(kept.includes(guard));
  assert.throws(() => partitionOrderedBody(source, [...sites.map(x => x.id), sites[0].id]), /duplicate/);
  assert.throws(() => partitionOrderedBody(source, ['not-a-real-call-site']), /unknown/);
});

test('supplemental tokens expose bare and differently qualified calls while leaving strings and comments inert', () => {
  const got = inspectOrderedCallTokens("SELECT custom_check(x), other_schema.verify(x), clock_timestamp(); -- hidden(x)\n SELECT 'quoted_call(x)';");
  assert.deepEqual(got.map(x => x.name), ['custom_check', 'other_schema.verify', 'clock_timestamp']);
  const actual = catalog.functions.find(x => x.identity === root).definition.split('$function$')[1];
  assert.ok(inspectOrderedCallTokens(actual).some(x => x.name === 'zasp_authorization80_worker.ordered69_finish'));
});

test('all three compiled higher regions reconstruct exact current bodies including retained predecessor tail', () => {
  const regions = JSON.parse(compiled.source.split('$higher_records$')[1]).regions;
  assert.equal(regions.length, 3);
  for (const r of regions) {
    const actual = catalog.functions.find(x => x.identity === r.signature).definition.split('$function$')[1];
    const expected = r.prefix || r.suffix ? r.prefix + '(' + r.query + ')' + r.suffix : r.query;
    assert.equal(actual, '\n' + expected + '\n');
  }
  const tail = regions.find(x => x.signature === 'zasp_temporal68.predecessor_ready(text,text)').suffix;
  for (const clause of ['IS DISTINCT FROM FOUND', 'retired.original_fingerprint', "EXECUTE format('SELECT %I.fingerprint()',n)", "has_function_privilege('zasp_security_agent_worker',oid,'EXECUTE')"]) assert.ok(tail.includes(clause));
});

test('nested replacement sites refuse instead of dropping enclosing original expression bytes', () => {
  const source = 'SELECT zasp_a.outer_gate(zasp_b.inner_gate());';
  const sites = inspectOrderedSource(source).calls.map(x => x.id);
  assert.equal(sites.length, 2);
  assert.throws(() => partitionOrderedBody(source, sites), /overlapping/);
  assert.deepEqual(partitionOrderedBody(source, []).map(x => x.text), [source]);
});

test('actual base67 and materialized predecessor retain both inlined live principal normalization clauses', () => {
  for (const identity of ['zasp_temporal77.base67_fingerprint()', 'zasp_temporal68.predecessor_ready(text,text)']) {
    const f = catalog.functions.find(x => x.identity === identity);
    const source = f.definition.split('$function$')[1];
    const clauses = inspectOrderedInlineLive(source);
    assert.equal(clauses.length, 2, identity + ': inlined live predicates were not classified');
    for (const c of clauses) {
      assert.equal(source.slice(c.start, c.end), c.text);
      assert.equal(sha(c.text), c.sha256);
      assert.equal(c.disposition, 'retain-live-inline-expression');
      assert.ok(c.text.includes("b.authority_role='zasp_discovery_authority'"));
    }
    assert.ok(clauses.find(c => c.kind === 'metadata-owner-normalization').text.includes('r.rolcanlogin'));
    assert.ok(clauses.find(c => c.kind === 'saved-export-migration-owner').text.includes("pg_has_role(r.oid,'zasp_discovery_authority','MEMBER')"));
    assert.throws(() => inspectOrderedInlineLive(source.replace('AND r.rolcanlogin)', 'AND true)')), /inline live clause changed/);
    assert.throws(() => inspectOrderedInlineLive(source.replace("pg_has_role(r.oid,'zasp_discovery_authority','MEMBER')", 'true')), /inline live clause changed/);
  }
});

test('inline clauses match their unchanged source predicates and preserve surrounding structural recipe bytes', () => {
  const bodies = ['zasp_sa_attack_lab_prior.audit_fingerprint()', 'public.zasp_sa_export_live_fingerprint()'].map(identity => catalog.functions.find(f => f.identity === identity).definition.split('$function$')[1]);
  const originalClauses = bodies.flatMap(inspectOrderedInlineLive);
  assert.equal(originalClauses.length, 2);
  for (const identity of ['zasp_temporal77.base67_fingerprint()', 'zasp_temporal68.predecessor_ready(text,text)']) {
    const body = catalog.functions.find(f => f.identity === identity).definition.split('$function$')[1];
    for (const c of inspectOrderedInlineLive(body)) assert.equal(c.text, originalClauses.find(o => o.kind === c.kind).text);
    assert.ok(body.includes('pg_get_functiondef'));
    assert.ok(body.includes('string_agg'));
  }
  for (const identity of ['zasp_temporal68.ready(text,text)', 'zasp_temporal78.ready(text,text)']) {
    assert.deepEqual(inspectOrderedInlineLive(catalog.functions.find(f => f.identity === identity).definition.split('$function$')[1]), []);
  }
});

test('successor contract emits live spans and fresh fixed-role invariants under exact effective frames', () => {
  const contract = pinned('ZASP_ORDERED_INVENTORY_CONTRACT', 'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
  assert.equal(contract.materializedObligations.length, 4);
  const expected = {
    'zasp_temporal68.predecessor_ready(text,text)': [2, 3, 0],
    'zasp_temporal68.ready(text,text)': [0, 1, 3],
    'zasp_temporal78.ready(text,text)': [0, 2, 1],
    'zasp_temporal77.base67_fingerprint()': [2, 1, 0]
  };
  for (const row of contract.materializedObligations) {
    const f = catalog.functions.find(f => f.identity === row.identity);
    const body = f.definition.split('$function$')[1];
    assert.equal(row.sourceSHA256, sha(body));
    assert.equal(row.owner, f.owner);
    assert.deepEqual(row.config, f.config);
    assert.equal(row.security_definer, f.security_definer);
    const counts = [row.inlineLiveSpans.length, ...['fixed-current-profile', 'fixed-native-role-shape-and-membership'].map(k => row.structuralInvariantSpans.filter(s => s.kind === k).length)];
    assert.deepEqual(counts, expected[row.identity]);
    let offset = 0;
    for (const span of row.recipeSegments) {
      assert.equal(span.start, offset);
      assert.equal(span.sha256, sha(body.slice(span.start, span.end)));
      offset = span.end;
    }
    assert.equal(offset, body.length);
    for (const span of [...row.inlineLiveSpans, ...row.structuralInvariantSpans]) assert.equal(span.text, body.slice(span.start, span.end));
  }
  assert.equal(contract.partition.find(p => p.identity === 'zasp_temporal77.base67_fingerprint()').disposition, 'structural-recipe-with-explicit-inline-live-spans');
  assert.equal(contract.partition.flatMap(p => p.inlineLiveSpans).length, 6);
});
}
