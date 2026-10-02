import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as privateCompiler from './ordered-current-private.mjs';
import {compareFacts,admitCollectorSource} from './build-ordered-current-integrity.mjs';
import {compileOrderedCollector} from './ordered-current-catalog.mjs';
const template=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url),'utf8');
test('new private source and complete declared frame are independent of target deparse',()=>{
  assert.equal(typeof privateCompiler.compileOrderedPrivateRoutines,'function');
  const compiled=privateCompiler.compileOrderedPrivateRoutines(template);
  assert.equal(compiled.facts.length,4);
  assert.doesNotThrow(()=>compileOrderedCollector(compiled.rules));
  assert.equal(compiled.facts.every(r=>JSON.parse(r.identity)[0]==='private-routines'),true);
  assert.equal(compiled.facts.every(r=>r.fact.config[0]==='search_path=pg_catalog'),true);
  for(const [field,value] of [['source','RETURN true'],['acl',null],['default_count',1],['argument_defaults','default'],['result_type','boolean'],['argument_names',['wrong']],['config',['search_path=pg_catalog, public']],['sql_body','parsed'],['input_types',['text']]]){
    const changed=structuredClone(compiled.facts);changed[0].fact[field]=value;
    assert.equal(compareFacts(compiled.facts,changed),false,field);
  }
  assert.throws(()=>privateCompiler.compileOrderedPrivateRoutines(template.replace('SET search_path=pg_catalog AS $catalog$','SET search_path=pg_catalog,public AS $catalog$')),/declaration/);
  assert.throws(()=>privateCompiler.compileOrderedPrivateRoutines(template.replace('RETURNS void','RETURNS text')),/declaration/);
});
test('SQL normalizer uses a single ordered row aggregate, not growing JSON concatenation',()=>{
  const body=template.split('AS $normalize$')[1].split('$normalize$;')[0];
  assert.doesNotMatch(body,/result\s*:=\s*result\s*\|\|/);
  assert.match(body,/jsonb_agg\(/);
  assert.match(body,/manifest_sha256.*IS DISTINCT FROM expected_manifest/);
  assert.match(body,/substring\(body FROM start_at\+1 FOR 64\) IS DISTINCT FROM expected_manifest/);
});
test('private installation removes nonowner default-ACL grants only in its new schema',()=>{
  assert.match(template,/DO \$private_acl\$/);
  const block=template.split('DO $private_acl$')[1].split('$private_acl$;')[0];
  assert.match(block,/grantee<>0 AND grants\.grantee<>owner/);
  assert.equal((block.match(/n\.nspname='zasp_authorization80_ordered_current'/g)??[]).length,3);
  assert.doesNotMatch(block,/ALTER DEFAULT PRIVILEGES/);
  assert.match(template,/catalog\(expected_manifest\) IS DISTINCT FROM true/);
});
test('new trust path uses core SHA256 instead of an application-owned digest function',()=>{
  const body=template.split('AS $catalog$')[1].split('$catalog$;')[0];
  assert.doesNotMatch(body,/public\.digest/);
  assert.match(body,/pg_catalog\.sha256\(convert_to\(/);
  assert.match(body,/provenance->>'postgres' IS DISTINCT FROM pg_catalog\.version\(\)/);
});
test('private object universe includes generated composite and array types without guessed deparse',()=>{
  const rules=privateCompiler.privateObjectRules();
  assert.ok(rules.some(r=>r.kind==='type'));
  assert.doesNotThrow(()=>compileOrderedCollector(rules));
  assert.match(compileOrderedCollector(rules).sql,/FROM pg_catalog\.pg_type t/);
});
test('private ordered input types bind explicit function and ordinality column names',()=>{
  const {rules}=privateCompiler.compileOrderedPrivateRoutines(template);
  const sql=compileOrderedCollector(rules).sql;
  assert.match(sql,/ARRAY\(SELECT args\.unnest::regtype::text FROM pg_catalog\.unnest\(p\.proargtypes\) WITH ORDINALITY AS args\(unnest, ordinality\) ORDER BY args\.ordinality\)/);
  assert.doesNotMatch(sql,/WITH ORDINALITY AS args ORDER/);
  assert.throws(()=>admitCollectorSource('SELECT args(1)'),/unadmitted collector edge/);
  assert.throws(()=>admitCollectorSource(sql.replace('AS args(unnest, ordinality)','AS args(other, ordinality)')),/unadmitted collector edge/);
  assert.throws(()=>admitCollectorSource(sql+' UNION ALL SELECT args(1)'),/unadmitted collector edge/);
});
