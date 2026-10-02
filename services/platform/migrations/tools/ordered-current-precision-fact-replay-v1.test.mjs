import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {canonicalizeOrderedCurrentPrecisionFacts} from './ordered-current-direct-reference-v2.mjs';
import {orderedCurrentPrecisionConflictSettlementsV1} from './ordered-current-precision-conflict-settlement-v1.mjs';

const tools=new URL('./',import.meta.url);
const capture=JSON.parse(fs.readFileSync(new URL('ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json',tools)));
const precisionRoster=capture.observations.find(row=>row.ruleId==='temporal72:precision-function').rows
  .map(row=>({kind:'routine',identity:JSON.stringify(['temporal72:precision-function',row.identity]),fact:row.fields}));
const aliasRows=precisionRoster.filter(row=>{const signature=JSON.parse(row.identity)[1];return signature.includes('(')&&!signature.endsWith('()');}).slice(0,36).map(row=>{
 const signature=JSON.parse(row.identity)[1],open=signature.indexOf('('),close=signature.lastIndexOf(')'),args=signature.slice(open+1,close).split(',').map(item=>item.trim());
 const named=args.map((item,index)=>`precision_arg_${index} ${item}`).join(', ');
 return {kind:'routine',identity:JSON.stringify(['temporal72:precision-function',`${signature.slice(0,open)}(${named})`]),fact:{...row.fact,identity_arguments:named}};
});
const precisionFacts=[...precisionRoster,...aliasRows];
const sourceRosterSHA256=crypto.createHash('sha256').update(canonicalOrderedJSON(precisionRoster.slice().sort((a,b)=>Buffer.from(a.identity).compare(Buffer.from(b.identity))))).digest('hex');
const clone=value=>structuredClone(value);

const firstAliasIndex=precisionRoster.length;
test('precision refuses an array that coerces to an otherwise valid argument string',()=>{
 const facts=clone(precisionFacts),row=facts[firstAliasIndex];
 row.fact.identity_arguments=[row.fact.identity_arguments];
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(facts,precisionRoster),/precision.*(shape|argument)/);
});
// These cases catch string interpolation of malformed arguments, extra tuple atoms and mode erasure.
for(const value of [[],{},null,['text'],undefined])test(`precision refuses non-string fact arguments ${JSON.stringify(value)}`,()=>{
 const facts=clone(precisionFacts);
 if(value===undefined)delete facts[firstAliasIndex].fact.identity_arguments;
 else facts[firstAliasIndex].fact.identity_arguments=value;
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(facts,precisionRoster),/precision.*(shape|argument)/);
});

for(const value of [
 ['temporal72:precision-function'],['temporal72:precision-function',null],
 ['temporal72:precision-function',[]],['temporal72:precision-function',{}],
 ['temporal72:precision-function',17],
])test(`precision refuses malformed outer signature ${JSON.stringify(value)}`,()=>{
 const facts=clone(precisionFacts);facts[firstAliasIndex].identity=JSON.stringify(value);
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(facts,precisionRoster),/precision.*identity/);
});

test('precision refuses an extra outer tuple atom',()=>{
 const facts=clone(precisionFacts),outer=JSON.parse(facts[firstAliasIndex].identity);
 facts[firstAliasIndex].identity=JSON.stringify([...outer,'extra']);
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(facts,precisionRoster),/precision.*identity/);
});

for(const mode of ['OUT','INOUT','VARIADIC'])for(const field of ['identity','fact'])test(`precision refuses ${mode} mutation in ${field}`,()=>{
 const facts=clone(precisionFacts),row=facts[firstAliasIndex];
 if(field==='fact')row.fact.identity_arguments=`${mode} ${row.fact.identity_arguments}`;
 else {const [ruleId,signature]=JSON.parse(row.identity);row.identity=JSON.stringify([ruleId,signature.replace('(',`(${mode} `)]);}
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(facts,precisionRoster),/precision.*(argument|candidate)/);
});

test('precision accepts explicit IN without changing source facts',()=>{
 const facts=clone(precisionFacts),row=facts[firstAliasIndex],[ruleId,signature]=JSON.parse(row.identity);
 row.identity=JSON.stringify([ruleId,signature.replace('(','(IN ')]);
 row.fact.identity_arguments=`IN ${row.fact.identity_arguments}`;
 const result=canonicalizeOrderedCurrentPrecisionFacts(facts,precisionRoster);
 assert.equal(result.facts.length,51);
 assert.deepEqual(result.facts,precisionRoster);
});

test('precision source roster is exactly 51 pinned identities and canonicalizes aliases to 51 facts',()=>{
 assert.equal(precisionRoster.length,51);
 assert.equal(new Set(precisionRoster.map(row=>row.identity)).size,51);
 assert.equal(sourceRosterSHA256,'8274273e43ae89e7ba3928ba1891b17f02814133169e04605cbc69705fa18c90');
 const result=canonicalizeOrderedCurrentPrecisionFacts(precisionFacts,precisionRoster);
 const rows=result.facts.filter(row=>JSON.parse(row.identity)[0]==='temporal72:precision-function');
 assert.equal(rows.length,51);
 assert.equal(new Set(rows.map(row=>row.identity)).size,51);
 assert.equal(result.mappings.length,87);
 assert.equal(result.merges.length,36);
 assert.ok(result.merges.every(row=>row.proof==='byte-identical-source-bound-facts'));
});

test('precision canonicalization refuses zero, ambiguous, wrong-namespace and semantic candidates',()=>{
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(precisionFacts,precisionRoster.slice(1)),/roster cardinality/);
 const duplicateRoster=[...precisionRoster,precisionRoster[0]];
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(precisionFacts,duplicateRoster),/roster cardinality/);
 const wrong=clone(precisionFacts); wrong[0].identity=JSON.stringify(['temporal72:precision-function','private.zasp_production_runtime_precision_live_fingerprint()']);
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(wrong,precisionRoster),/candidate|namespace/);
 const changed=clone(precisionFacts); const row=changed.find(item=>{const id=JSON.parse(item.identity)[1];return id.includes('zasp_runtime_claim_archive_v2(')&&id.includes('precision_arg_0');}); row.fact.owner='executor';
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(changed,precisionRoster),/semantic fact/);
 const extra=clone(precisionFacts); extra.push(clone(extra[0]));
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(extra,precisionRoster),/duplicate capture identity/);
});

test('precision canonicalization rejects mutations to canonical source fields',()=>{
 const changedOwner=clone(precisionRoster);
 changedOwner.find(row=>row.identity===precisionRoster[0].identity).fact.owner='attacker';
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(changedOwner,precisionRoster),/semantic fact/);
});

test('precision canonicalization rejects unpinned NULL definitions',()=>{
 const missingDefinition=clone(precisionRoster);
 missingDefinition.find(row=>row.identity===precisionRoster[1].identity).fact.precision_definition=null;
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(missingDefinition,precisionRoster),/semantic fact/);
});

test('precision canonicalization admits only the seven exact pinned NULL predecessors',()=>{
 const old=clone(precisionRoster),settlements=orderedCurrentPrecisionConflictSettlementsV1();
 assert.equal(settlements.length,7);
 for(const settlement of settlements){
  const row=old.find(candidate=>candidate.identity===settlement.identity);
  assert.ok(row);
  row.fact.precision_definition=null;
  assert.equal(crypto.createHash('sha256').update(canonicalOrderedJSON(row.fact)).digest('hex'),settlement.existingFactSHA256);
 }
 const result=canonicalizeOrderedCurrentPrecisionFacts(old,precisionRoster);
 assert.equal(result.facts.filter(row=>JSON.parse(row.identity)[0]==='temporal72:precision-function').length,51);
 const unauthorized=clone(old);
 unauthorized.find(row=>row.identity===settlements[0].identity).fact.owner='different-owner';
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(unauthorized,precisionRoster),/semantic fact/);
});

test('precision canonicalization requires complete 51-identity closure',()=>{
 const missingCapture=precisionRoster.filter(row=>row.identity!==precisionRoster[2].identity);
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(missingCapture,precisionRoster),/closure|cardinality/);
});

test('precision canonicalization binds alias identity arguments to exact ordered source types',()=>{
 const changed=clone(precisionFacts);
 const alias=changed.find(row=>row.identity!==precisionRoster.find(source=>source.identity===row.identity)?.identity);
 assert.ok(alias);
 alias.fact.identity_arguments=alias.fact.identity_arguments.replace(/precision_arg_0 [^,]+/,'precision_arg_0 bytea');
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(changed,precisionRoster),/semantic fact|argument|candidate/);
 const reordered=clone(precisionFacts);
 const multiArgument=reordered.find(row=>row.identity!==precisionRoster.find(source=>source.identity===row.identity)?.identity&&row.fact.identity_arguments.includes(','));
 assert.ok(multiArgument);
 const args=multiArgument.fact.identity_arguments.split(', ');
 multiArgument.fact.identity_arguments=[args[1],args[0],...args.slice(2)].join(', ');
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(reordered,precisionRoster),/semantic fact|argument|candidate/);
});

test('precision canonicalization rejects changed kind and unpinned fact fields',()=>{
 const changedKind=clone(precisionFacts);
 changedKind[0].kind='constraint';
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(changedKind,precisionRoster),/shape|kind/);
 const extraField=clone(precisionFacts);
 extraField[0].fact.injected='not pinned';
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(extraField,precisionRoster),/shape|field/);
 const extraRowField=clone(precisionFacts);
 extraRowField[0].isTrusted=true;
 assert.throws(()=>canonicalizeOrderedCurrentPrecisionFacts(extraRowField,precisionRoster),/shape|field/);
});

test('precision canonicalization preserves unrelated facts and source-bound definitions',()=>{
 const unrelated={kind:'constraint',identity:JSON.stringify(['unrelated','x']),fact:{definition:'CHECK (true)',validated:true}};
 const result=canonicalizeOrderedCurrentPrecisionFacts([...precisionFacts,unrelated],precisionRoster);
 assert.deepEqual(result.facts.at(-1),unrelated);
 for(const row of result.facts.filter(item=>JSON.parse(item.identity)[0]==='temporal72:precision-function')){
  const source=precisionRoster.find(candidate=>candidate.identity===row.identity);
  assert.ok(source);
  assert.equal(row.fact.precision_definition,source.fact.precision_definition);
  assert.equal(row.fact.owner,source.fact.owner);
  assert.equal(row.fact.acl_text_or_empty,source.fact.acl_text_or_empty);
 }
});

test('runtime predecessor source closes all seven precision guard definitions',()=>{
 const source=fs.readFileSync(new URL('../sql/0080_authorization_runtime_profile.sql',tools),'utf8');
 const initial=source.slice(source.indexOf('-- Only these installed source identities'),source.indexOf('DO $clone$'));
 const guards=source.slice(source.indexOf('DO $guards$'),source.indexOf('$guards$;'));
 const initialSignatures=[...initial.matchAll(/'public\.([^']+)'::regprocedure/g)].map(match=>match[1]);
 const guardNames=[...guards.matchAll(/\('((?:zasp_runtime_precision|zasp_runtime_sandbox_search|zasp_runtime_legacy_search)[^']*)'/g)].map(match=>match[1]);
 assert.equal(initialSignatures.length,43);
 assert.deepEqual(guardNames,[
  'zasp_runtime_precision_batch_insert_guard','zasp_runtime_precision_batch_update_guard',
  'zasp_runtime_precision_stage_insert_guard','zasp_runtime_precision_claim_version_guard',
  'zasp_runtime_precision_reconciliation_guard','zasp_runtime_precision_outbox_guard',
  'zasp_runtime_precision_delivery_guard','zasp_runtime_sandbox_search_mutation_guard',
  'zasp_runtime_legacy_search_insert_guard',
 ]);
 for(const name of guardNames)assert.ok(!initialSignatures.includes(`${name}()`),`${name} is saved by exactly one source path`);
 assert.match(source,/SELECT count\(\*\) FROM zasp_authorization80_runtime\.predecessor_functions\)<>43/);
 assert.equal((guards.match(/INSERT INTO zasp_authorization80_runtime\.predecessor_functions/g)??[]).length,1);
 assert.ok(guards.indexOf('SELECT pg_get_functiondef')<guards.indexOf('INSERT INTO zasp_authorization80_runtime.predecessor_functions'));
 assert.ok(guards.indexOf('INSERT INTO zasp_authorization80_runtime.predecessor_functions')<guards.indexOf('EXECUTE replace(d,needle,replacement)'));
});
