import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {staticDescriptor, staticRelations} from './ordered-current-static-catalog.mjs';

const identity="'['||pg_catalog.to_json(s.source_table::text)::text||','||pg_catalog.to_json(s.row_key)::text||']'";

test('saved view projects its complete table-qualified key and raw definition without normalization', () => {
  assert.deepEqual(staticDescriptor('saved_view',['zasp_authorization80_worker']), {
    identity, namespace:'s.namespace::text',
    from:"(SELECT 'zasp_authorization80_worker'::text AS namespace,'zasp_authorization80_worker.predecessor_views'::text AS source_table,signature AS row_key,definition FROM zasp_authorization80_worker.predecessor_views) s",
    fields:{definition:'s.definition::text'}
  });
});

test('constraint union keeps distinct source tables and original keys without filtering or deduplicating rows', () => {
  const got=staticDescriptor('saved_constraint',['zasp_temporal76','zasp_sa_export_prior']);
  assert.equal(got.identity,identity);
  assert.deepEqual(got.fields,{definition:'s.definition::text'});
  assert.equal(got.from,"(SELECT 'zasp_sa_export_prior'::text AS namespace,'zasp_sa_export_prior.job_constraints'::text AS source_table,name AS row_key,definition FROM zasp_sa_export_prior.job_constraints UNION ALL SELECT 'zasp_temporal76'::text AS namespace,'zasp_temporal76.predecessor_constraints'::text AS source_table,signature AS row_key,definition FROM zasp_temporal76.predecessor_constraints) s");
  assert.equal(staticDescriptor('saved_constraint',['zasp_temporal76']).from,"(SELECT 'zasp_temporal76'::text AS namespace,'zasp_temporal76.predecessor_constraints'::text AS source_table,signature AS row_key,definition FROM zasp_temporal76.predecessor_constraints) s");
});

test('saved trigger keys by relation_name and preserves name, definition and raw enabled mode as facts', () => {
  const got=staticDescriptor('saved_trigger',['zasp_existing_tests_predecessor']);
  assert.equal(got.identity,identity);
  assert.equal(got.from,"(SELECT 'zasp_existing_tests_predecessor'::text AS namespace,'zasp_existing_tests_predecessor.global_control_triggers'::text AS source_table,relation_name AS row_key,trigger_name,definition,enabled FROM zasp_existing_tests_predecessor.global_control_triggers) s");
  assert.deepEqual(got.fields,{name:'s.trigger_name::text',definition:'s.definition::text',enabled:'s.enabled::text'});
});

test('portable registration projection excludes fingerprint and predecessor modes; profile has only real fields', () => {
  const regular=staticDescriptor('registration',['zasp_temporal65','zasp_authorization80']);
  assert.equal(regular.identity,identity);
  assert.deepEqual(regular.fields,{singleton:'s.singleton',checksum:'s.checksum::text'});
  assert.equal(regular.from,"(SELECT 'zasp_authorization80'::text AS namespace,'zasp_authorization80.registration'::text AS source_table,singleton AS row_key,singleton,checksum FROM zasp_authorization80.registration UNION ALL SELECT 'zasp_temporal65'::text AS namespace,'zasp_temporal65.registration'::text AS source_table,singleton AS row_key,singleton,checksum FROM zasp_temporal65.registration) s");
  const profile=staticDescriptor('profile_registration',['zasp_authorization80_temporal']);
  assert.deepEqual(profile.fields,{singleton:'s.singleton',checksum:'s.checksum::text',profile_name:'s.profile_name::text'});
  assert.equal(profile.from,"(SELECT 'zasp_authorization80_temporal'::text AS namespace,'zasp_authorization80_temporal.registration'::text AS source_table,singleton AS row_key,singleton,checksum,profile_name FROM zasp_authorization80_temporal.registration) s");
});

test('closed admission refuses malformed selectors, cross-kind sources and executable selector text', () => {
  for(const kind of [undefined,null,{},'saved_function','fingerprint','__proto__','constructor']) assert.throws(()=>staticDescriptor(kind,['zasp_temporal76']),/unsupported static/);
  for(const namespaces of [undefined,null,{},'zasp_temporal76',[],[null],[1],[''],['zasp_temporal76','zasp_temporal76'],['zasp_temporal76; SELECT 1'],[' zasp_temporal76'],['zasp_temporal76\0'],['public'],['zasp_temporal76.predecessor_constraints'],['zasp_temporal76','zasp_authorization80_worker']]) assert.throws(()=>staticDescriptor('saved_constraint',namespaces),/unsupported static/);
  assert.throws(()=>staticDescriptor('saved_view',['zasp_authorization80_runtime']),/unsupported static/);
  assert.throws(()=>staticDescriptor('profile_registration',['zasp_temporal68']),/unsupported static/);
});

test('runtime registration preserves the exact source-required raw fingerprint only for its development descriptor', () => {
  const got=staticDescriptor('runtime_registration',['zasp_authorization80_runtime']);
  assert.equal(got.identity,identity);
  assert.equal(got.from,"(SELECT 'zasp_authorization80_runtime'::text AS namespace,'zasp_authorization80_runtime.registration'::text AS source_table,singleton AS row_key,singleton,checksum,fingerprint FROM zasp_authorization80_runtime.registration) s");
  assert.deepEqual(got.fields,{singleton:'s.singleton',checksum:'s.checksum::text',fingerprint:'s.fingerprint::text'});
  for(const ns of ['zasp_authorization80','zasp_authorization80_worker','zasp_authorization80_temporal','zasp_temporal68']) assert.throws(()=>staticDescriptor('runtime_registration',[ns]),/unsupported static/);
  assert.deepEqual(staticDescriptor('registration',['zasp_authorization80_runtime']).fields,{singleton:'s.singleton',checksum:'s.checksum::text'});
});

test('caller order and result mutation cannot alter later compiler descriptors or widen source admission', () => {
  const namespaces=['zasp_temporal76','zasp_sa_export_prior'];
  const got=staticDescriptor('saved_constraint',namespaces);
  assert.deepEqual(namespaces,['zasp_temporal76','zasp_sa_export_prior']);
  assert.deepEqual(got,staticDescriptor('saved_constraint',[...namespaces].reverse()));
  assert.throws(()=>{got.fields.definition='COALESCE(s.definition,\'\')';},TypeError);
  assert.throws(()=>staticRelations.push('public.zasp_identity_memberships'),TypeError);
  assert.equal(staticRelations.length,24);
  assert.equal(new Set(staticRelations).size,24);
});

test('worker self registration preserves fingerprint and complete singleton key without selecting extra facts', () => {
  const got=staticDescriptor('worker_registration',['zasp_authorization80_worker']);
  assert.equal(got.identity,identity);
  assert.equal(got.from,"(SELECT 'zasp_authorization80_worker'::text AS namespace,'zasp_authorization80_worker.registration'::text AS source_table,singleton AS row_key,fingerprint FROM zasp_authorization80_worker.registration) s");
  assert.deepEqual(got.fields,{fingerprint:'s.fingerprint::text'});
  for(const ns of ['zasp_authorization80_runtime','zasp_authorization80','zasp_temporal68']) assert.throws(()=>staticDescriptor('worker_registration',[ns]),/unsupported static/);
});

test('fixed table and original key choices match the pinned effective schema, not guessed exporter aliases', () => {
  const path=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-catalog1.json',import.meta.url);
  const raw=fs.readFileSync(path);
  assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
  const actual=JSON.parse(raw);
  for(const [kind,namespace,table,key,fields] of [
    ['saved_view','zasp_authorization80_worker','predecessor_views','signature',['definition']],
    ['saved_constraint','zasp_temporal76','predecessor_constraints','signature',['definition']],
    ['saved_constraint','zasp_sa_export_prior','job_constraints','name',['definition']],
    ['saved_trigger','zasp_existing_tests_predecessor','global_control_triggers','relation_name',['trigger_name','definition','enabled']]
  ]) {
    const relation=namespace+'.'+table;
    const descriptor=staticDescriptor(kind,[namespace]);
    assert.ok(descriptor.from.includes(key+' AS row_key'));
    assert.ok(staticRelations.includes(relation));
    const columns=actual.columns.filter(c=>c.relation===relation);
    for(const name of [key,...fields]) assert.ok(columns.some(c=>c.name===name),relation+'.'+name);
    assert.ok(actual.constraints.some(c=>c.relation===relation&&c.definition==='PRIMARY KEY ('+key+')'));
  }
  for(const row of actual.registrations) {
    const relation=row.schema+'.registration';
    assert.ok(staticRelations.includes(relation));
    for(const name of ['singleton','checksum']) assert.ok(actual.columns.some(c=>c.relation===relation&&c.name===name));
  }
});
