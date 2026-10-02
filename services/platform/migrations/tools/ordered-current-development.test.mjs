import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {propagateNative21WorkerTailFacts} from './build-ordered-current-development.mjs';
import {native19WorkerSourceReplay} from './ordered-current-worker-source-replay-v1.mjs';
import {canonicalizeOrderedCurrentDevelopmentFacts} from './ordered-current-catalog.mjs';
import {reconcileOrderedCurrentFactCollectionsV1} from './ordered-current-capture-reconciliation-v1.mjs';
import {compileOrderedPrivateRoutines} from './ordered-current-private.mjs';
import * as sourceClosure from './ordered-current-source-closure-v1.mjs';
const evidence=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const output=new URL('../ordered_current/',import.meta.url);
const json=(base,name)=>JSON.parse(fs.readFileSync(new URL(name,base)));
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const nextGates=[
 'full 379-rule native truth/drift/NULL/forged-entry/frame parity',
 'varied-login/OID and exact production PostgreSQL',
 'connected installed-worker acceptance',
 'full100 capacity under unchanged limits',
 'deployment/provider acceptance',
];

test('native15 source aliases qualify only unique pinned relations, overloads, tuples, and profile forms',()=>{
 const rules=[
  {id:'inventory-fields:table',kind:'relation',selector:{all:[{field:'namespace',equals:'public'},{field:'name',equals:'zasp_table'}]}},
  {id:'inventory-fields:policy',kind:'policy',selector:{field:'namespace',equals:'public'}},
  {id:'worker-edge:gateway_projected27:12',kind:'trigger',selector:{field:'namespace',equals:'public'}},
  {id:'inventory-fields:function',kind:'routine',selector:{field:'namespace',equals:'public'}},
  {id:'role-profile:current-profile',kind:'fixed_runtime_profile',selector:null},
 ];
 const catalog={
  relations:[{identity:'public.zasp_table'}],
  policies:[{relation:'public.zasp_table',name:'authority'}],
  triggers:[{relation:'public.zasp_table',name:'audit'}],
  functions:[{identity:'public.overload(text)'},{identity:'public.overload(integer)'}],
 };
 const rows=[
  {kind:'relation',identity:JSON.stringify(['inventory-fields:table',JSON.stringify('zasp_table')]),fact:{name:'zasp_table'}},
  {kind:'policy',identity:JSON.stringify(['inventory-fields:policy',JSON.stringify(['zasp_table','authority'])]),fact:{name:'authority'}},
  {kind:'trigger',identity:JSON.stringify(['worker-edge:gateway_projected27:12',JSON.stringify(['public.zasp_table','audit'])]),fact:{name:'audit'}},
  {kind:'routine',identity:JSON.stringify(['inventory-fields:function',JSON.stringify('overload(arg text)')]),fact:{name:'overload'}},
  {kind:'fixed_runtime_profile',identity:JSON.stringify(['role-profile:current-profile',JSON.stringify([true,'canonical61-temporal78-authorization79-80-v1'])]),fact:{singleton:true,name:'canonical61-temporal78-authorization79-80-v1'}},
 ];
 const canonical=canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,catalog);
 assert.deepEqual(canonical.map(row=>JSON.parse(row.identity)[1]),[
  'public.zasp_table',JSON.stringify(['public.zasp_table','authority']),JSON.stringify(['public.zasp_table','audit']),'public.overload(text)',JSON.stringify(['zasp_authorization80.runtime_profile',true])
 ]);
 const wrongNamespace={...catalog,relations:[{identity:'other.zasp_table'}]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([rows[0]],rules,wrongNamespace),/catalog join/);
 const ambiguous={...catalog,functions:[...catalog.functions,{identity:'public.overload(text)'}]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([rows[3]],rules,ambiguous),/catalog join/);
 const missing={...catalog,functions:catalog.functions.filter(row=>row.identity!=='public.overload(text)')};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([rows[3]],rules,missing),/catalog join/);
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([{...rows[0],identity:JSON.stringify(['inventory-fields:table',JSON.stringify('other_table')])}],rules,catalog),/catalog join/);
});
test('complete dormant manifest binds all closed contracts and exact collector inventory without promoting availability',async()=>{
 const checkpoint=json(output,'development-checkpoint.json'),manifest=json(output,'development-manifest.json');
 const evaluator=checkpoint.dormantEvaluator;
 assert.ok(evaluator,'one complete dormant evaluator manifest is required');
 assert.equal(evaluator.status,'SOURCE-CONTRACT-COMPLETE-NATIVE-PARITY-PENDING');
 assert.equal(evaluator.installable,false);assert.equal(evaluator.nativeVerified,false);
 assert.equal(evaluator.ledgerStatus,'component-only');assert.equal(evaluator.executableReplacementVerified,false);
 assert.equal(evaluator.facts,10053);assert.equal(evaluator.rules.length,379);
 assert.equal(evaluator.rules.filter(r=>r.collector==='direct').length,366);
 assert.equal(evaluator.rules.filter(r=>r.collector==='transform').length,13);
 assert.equal(new Set(evaluator.rules.map(r=>r.id)).size,379);
 assert.equal(evaluator.rules.reduce((sum,r)=>sum+r.expectedFacts,0),10052);
 assert.deepEqual(evaluator.nextGates,nextGates);
 assert.deepEqual(checkpoint.missingRequiredLowering,nextGates);
 assert.deepEqual(checkpoint.sourceCoverage.captureBundle.remainingBlockers,nextGates);
 assert.equal(evaluator.sourceContracts.worker.packetSHA256,sha(canonicalOrderedJSON(json(output,'consolidated-reference-contract.json').workerSourceClosure)));
 assert.equal(evaluator.sourceContracts.current.packetSHA256,checkpoint.sourceCoverage.currentSourceClosure.packetSHA256);
 assert.equal(evaluator.sourceContracts.precision.settlements,7);
 assert.equal(evaluator.sourceContracts.precision.unresolvedConflicts,0);
 const provenance=manifest.facts.find(r=>r.kind==='build').fact;
 assert.ok(provenance.module_sha256.includes('ordered-current-dormant-evaluator-v1.packet='+sha(canonicalOrderedJSON(evaluator))));
 const api=await import('./build-ordered-current-development.mjs');
 assert.equal(api.assertOrderedCurrentDormantEvaluatorV1(evaluator),undefined);
});
test('native21 worker-tail replay is propagated into exactly two expected facts',()=>{
 const manifest=json(output,'development-manifest.json');
 const identities=['zasp_authorization80_worker.test74_effect_source(text,jsonb)','zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)'];
 const rows=new Map(manifest.facts.filter(row=>identities.some(identity=>row.identity===JSON.stringify(['worker-line-5',identity]))).map(row=>[row.identity,row]));
 assert.equal(sha(JSON.stringify(rows.get(JSON.stringify(['worker-line-5','zasp_authorization80_worker.test74_effect_source(text,jsonb)'])).fact)),'f4790e0ba19116b50fc9acaba7f9fc60cf1c205312a4cab48e3ce86f063b79e6');
 assert.equal(sha(JSON.stringify(rows.get(JSON.stringify(['worker-line-5','zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)'])).fact)),'f353007355371b13b1a38fb250e9fa72aacadfcc5a90eea6489a5630b2b8b908');
 assert.equal(rows.size,2);
});
test('native21 propagation is fail-closed and preserves unrelated facts',()=>{
 const manifest=json(output,'development-manifest.json'), catalog=json(evidence,'effective-catalog1.json'), replay=native19WorkerSourceReplay();
 const baseFacts=manifest.facts.map(row=>{if(row.kind!=='routine'||!row.identity.startsWith('["worker-line-5",'))return row;const identity=JSON.parse(row.identity)[1],source=catalog.functions?.find(value=>value.identity===identity);return source?{...row,fact:{...row.fact,definition:source.definition}}:row;});
 const projected=propagateNative21WorkerTailFacts(baseFacts,replay);
 const changed=projected.filter((row,index)=>canonicalOrderedJSON(row.fact)!==canonicalOrderedJSON(baseFacts[index].fact));
 assert.equal(changed.length,2);
 assert.deepEqual(changed.map(row=>JSON.parse(row.identity)[1]).sort(),['zasp_authorization80_worker.test74_effect_source(text,jsonb)','zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)']);
 for(const mutate of [r=>({...r,accepted:r.accepted.filter(row=>!row.identity.includes('test74_'))}),r=>({...r,accepted:[...r.accepted,...r.accepted.filter(row=>row.identity.includes('test74_effect'))]}),r=>({...r,accepted:[...r.accepted,{category:'worker-tail-unknown',identity:'unknown',replacementDefinition:'x',replacementFactSHA256:'f'.repeat(64)}]}),r=>({...r,accepted:r.accepted.map(row=>row.identity.includes('test74_effect')?{...row,replacementFactSHA256:'f'.repeat(64)}:row)})]) assert.throws(()=>propagateNative21WorkerTailFacts(baseFacts,mutate(structuredClone(replay))),/native21 worker-tail/);
});

test('development capture admission canonicalizes proven catalog identities and refuses ambiguous joins',async()=>{
 const rules=[
  {id:'edge-column',kind:'column_name',fields:['name'],namespaces:[],identities:[],selector:{field:'name',equals:'column'}},
  {id:'edge-column-all',kind:'column_all',fields:['name'],namespaces:[],identities:[],selector:{field:'name',equals:'column'}},
  {id:'edge-constraint',kind:'constraint',fields:['name'],namespaces:[],identities:[],selector:{field:'name',equals:'constraint'}},
  {id:'edge-fk',kind:'foreign_key_trigger',fields:['name','event_bits','sentinel'],namespaces:[],identities:[],selector:{field:'namespace',equals:'s'}}
 ];
 const catalog={columns:[{relation:'s.table',position:2,name:'column'}],constraints:[{relation:'s.table',name:'constraint'}],triggers:[{relation:'s.table',name:'trigger',function:'s.function()'}]};
 const rows=[
  {kind:'column_name',identity:JSON.stringify(['edge-column',JSON.stringify(['s.table',2,'column'])]),fact:{name:'column',sentinel:'capture-only'}},
  {kind:'column_all',identity:JSON.stringify(['edge-column-all',JSON.stringify(['s.table',2,'column'])]),fact:{name:'column',sentinel:'capture-only'}},
  {kind:'constraint',identity:JSON.stringify(['edge-constraint',JSON.stringify(['s','s.table',null,'constraint'])]),fact:{name:'constraint',sentinel:'capture-only'}},
  {kind:'foreign_key_trigger',identity:JSON.stringify(['edge-fk',JSON.stringify(['s.table','trigger'])]),fact:{name:'constraint',event_bits:9,sentinel:'capture-only'}}
 ];
 const canonical=canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,catalog);
 assert.deepEqual(canonical.map(row=>row.identity),[
  JSON.stringify(['edge-column',JSON.stringify(['s.table','column'])]),
  JSON.stringify(['edge-column-all',JSON.stringify(['s.table','column'])]),
  JSON.stringify(['edge-constraint',JSON.stringify(['s.table','constraint'])]),
  JSON.stringify(['edge-fk',JSON.stringify(['s.table','constraint','s.table','s.function()',9])])
 ]);
 assert.deepEqual(canonical.map(row=>row.fact),rows.map(row=>row.fact));
 const ambiguous={...catalog,columns:[...catalog.columns,{relation:'s.table',position:2,name:'column'}]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,ambiguous),/catalog join/);
 const missing={...catalog,columns:[]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,missing),/catalog join/);
});
test('development capture admission canonicalizes only uniquely proven index and policy view relocations',()=>{
 const rules=[
  {id:'edge-index-view',kind:'index_view',fields:['name','definition'],namespaces:[],identities:[],selector:{all:[{field:'namespace',equals:'public'},{field:'table_name',equals:'table'}]}},
  {id:'edge-policy',kind:'policy',fields:['name','using'],namespaces:[],identities:[],selector:{field:'namespace',equals:'public'}},
  {id:'edge-policy-view',kind:'policy_view',fields:['namespace_name','table_name','name'],namespaces:[],identities:[],selector:{all:[{field:'namespace',equals:'public'},{field:'table_name',equals:'table'}]}},
 ];
 const catalog={
  indexes:[{identity:'public.table_idx',relation:'public.table'}],
  policies:[{relation:'public.table',name:'authority'}],
  columns:[],constraints:[],triggers:[],
 };
 const rows=[
  {kind:'index_view',identity:JSON.stringify(['edge-index-view','public.table_idx']),fact:{name:'table_idx',namespace_name:'public',table_name:'table',sentinel:'capture-only'}},
  {kind:'policy',identity:JSON.stringify(['edge-policy',JSON.stringify(['public.table','authority'])]),fact:{name:'authority',using:'true',sentinel:'capture-only'}},
  {kind:'policy_view',identity:JSON.stringify(['edge-policy-view',JSON.stringify(['public.table','authority'])]),fact:{namespace_name:'public',table_name:'table',name:'authority',sentinel:'capture-only'}},
 ];
 const canonical=canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,catalog);
 assert.deepEqual(canonical.map(row=>row.identity),[
  JSON.stringify(['edge-index-view',JSON.stringify(['public','table','table_idx'])]),
  JSON.stringify(['edge-policy',JSON.stringify(['public.table','authority'])]),
  JSON.stringify(['edge-policy-view',JSON.stringify(['public','table','authority'])]),
 ]);
 assert.deepEqual(canonical.map(row=>row.fact),rows.map(row=>row.fact));
 const ambiguous={...catalog,indexes:[...catalog.indexes,{identity:'public.table_idx',relation:'public.table'}]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,ambiguous),/catalog join/);
 const missing={...catalog,policies:[]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts(rows,rules,missing),/catalog join/);
});
test('development capture admission canonicalizes a column relation only through its pinned catalog identity',()=>{
 const rules=[{id:'edge-column-relation',kind:'column_name',fields:['relation','name'],namespaces:[],identities:[],selector:{field:'name',equals:'column'}}];
 const catalog={columns:[{relation:'public.table',position:2,name:'column'}],constraints:[],triggers:[],indexes:[],policies:[]};
 const row={kind:'column_name',identity:JSON.stringify(['edge-column-relation',JSON.stringify(['public.table',2,'column'])]),fact:{relation:'table',name:'column'}};
 const canonical=canonicalizeOrderedCurrentDevelopmentFacts([row],rules,catalog);
 assert.deepEqual(canonical[0].fact,{relation:'public.table',name:'column'});
 const nonQualification={...row,fact:{relation:'other_table',name:'column'}};
  assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([nonQualification],rules,catalog),/semantic fact join/);
});
test('development capture admission canonicalizes only FK relation fields through pinned catalog joins',()=>{
 const rules=[{id:'edge-fk-relations',kind:'foreign_key_trigger',fields:['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits'],namespaces:[],identities:[],selector:{field:'namespace',equals:'public'}}];
 const catalog={
  relations:[{identity:'public.source'},{identity:'public.target'},{identity:'public.constraint_host'}],
  constraints:[{relation:'public.source',name:'fk',definition:'FOREIGN KEY (id) REFERENCES public.target(id)',referenced_relation:'public.target',constraint_relation:'public.constraint_host'}],
  triggers:[{relation:'public.source',name:'RI_FKey_check_ins',function:'pg_catalog."RI_FKey_check_ins"()'}],
  columns:[],indexes:[],policies:[],
 };
 const row={kind:'foreign_key_trigger',identity:JSON.stringify(['edge-fk-relations',JSON.stringify(['public.source','RI_FKey_check_ins'])]),fact:{relation:'public.source',name:'fk',referenced_relation:'target',trigger_relation:'source',constraint_relation:'target',function:'pg_catalog."RI_FKey_check_ins"()',event_bits:9}};
 const canonical=canonicalizeOrderedCurrentDevelopmentFacts([row],rules,catalog);
 assert.deepEqual(canonical[0].fact,{...row.fact,referenced_relation:'public.target',trigger_relation:'public.source',constraint_relation:'public.target'});
 const nonQualification={...row,fact:{...row.fact,referenced_relation:'other_target'}};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([nonQualification],rules,catalog),/semantic fact join/);
 const wrongExisting={...row,fact:{...row.fact,referenced_relation:'public.constraint_host'}};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([wrongExisting],rules,catalog),/semantic fact join/);
 const unknown={...row,fact:{...row.fact,unknown_relation:'forged'}};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([unknown],rules,catalog),/unknown field/);
 const ambiguous={...catalog,constraints:[...catalog.constraints,{...catalog.constraints[0]}]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([row],rules,ambiguous),/catalog join/);
 const missing={...catalog,constraints:[{...catalog.constraints[0],definition:'CHECK (id > 0)'}]};
 assert.throws(()=>canonicalizeOrderedCurrentDevelopmentFacts([row],rules,missing),/FK definition form/);
 const optional={...row,fact:{name:'fk',function:row.fact.function,event_bits:row.fact.event_bits},captureProvenance:{source:'pinned'}};
 const preserved=canonicalizeOrderedCurrentDevelopmentFacts([optional],rules,catalog)[0];
 assert.deepEqual(preserved.fact,optional.fact);
 assert.equal(preserved.captureProvenance,optional.captureProvenance);
 assert.equal(preserved.identity,JSON.stringify(['edge-fk-relations',JSON.stringify(['public.source','fk','public.source','pg_catalog."RI_FKey_check_ins"()',9])]));
});
test('complete dormant manifest retains exact role-site inventories and rejects every changed classification or authority',async()=>{
 const evaluator=json(output,'development-checkpoint.json').dormantEvaluator;
 assert.ok(evaluator,'complete role-site inventory is required');
 assert.deepEqual(evaluator.sourceInventory.counts,{workerCatalog:34,workerClosure:172,currentClosure:246,supplementary:105,auth80:8});
 assert.equal(evaluator.sourceInventory.sites.length,565);
 assert.equal(new Set(evaluator.sourceInventory.sites.map(s=>s.siteId)).size,565);
 assert.equal(evaluator.sourceInventory.unclassified,0);
 for(const site of evaluator.sourceInventory.sites){assert.match(site.siteSHA256,/^[a-f0-9]{64}$/);assert.ok(site.frame);assert.notEqual(site.disposition,'unclassified');}
 const api=await import('./build-ordered-current-development.mjs');
 const mutations=[
  p=>p.rules.pop(),p=>p.rules.push(structuredClone(p.rules[0])),p=>p.rules[0].id='unknown',p=>p.rules[0].fields.push('forged'),p=>p.rules[0].expectedFacts++,
  p=>p.sourceInventory.sites.pop(),p=>p.sourceInventory.sites.push(structuredClone(p.sourceInventory.sites[0])),p=>p.sourceInventory.sites[0].siteSHA256='0'.repeat(64),p=>p.sourceInventory.sites[0].frame.owner='forged',p=>p.sourceInventory.sites[0].disposition='unclassified',p=>p.sourceInventory.unclassified=1,
  p=>p.sourceContracts.worker.packetSHA256='0'.repeat(64),p=>p.sourceContracts.current.packetSHA256='0'.repeat(64),p=>p.sourceContracts.precision.settlements=0,
  p=>p.nextGates.pop(),p=>p.nextGates[3]='full100 with relaxed limits',p=>p.runtimeObligations.current=[],p=>p.runtimeObligations.worker=[],p=>p.ledgerStatus='production-available',p=>p.installable=true,p=>p.nativeVerified=true,p=>p.executableReplacementVerified=true,p=>p.facts++,p=>p.collectorSHA256='0'.repeat(64),p=>p.path='/tmp/caller-authority',
 ];
 for(const mutate of mutations){const changed=structuredClone(evaluator);mutate(changed);assert.throws(()=>api.assertOrderedCurrentDormantEvaluatorV1(changed),/dormant evaluator/);}
 assert.throws(()=>api.assertOrderedCurrentDormantEvaluatorV1(evaluator,{authority:evaluator}),/dormant evaluator/);
 assert.throws(()=>api.admitOrderedCurrentDormantEvaluatorV1({path:'/tmp/caller-authority'}),/dormant evaluator/);
 const admitted=api.admitOrderedCurrentDormantEvaluatorV1();admitted.nextGates=[];
 assert.deepEqual(api.admitOrderedCurrentDormantEvaluatorV1(),evaluator,'caller mutation cannot replace tracked authority');
});
test('dormant manifest regenerates all eight outputs without output authority and stays byte-stable in an isolated tree',()=>{
 const names=['effective-contract4.json','development-manifest.json','development-collector.sql','development-admission.sql','development-module.sql','development-checkpoint.json','consolidated-reference-contract.json','consolidated-reference-select.sql'];
 const expected=Object.fromEntries(names.map(name=>[name,sha(fs.readFileSync(new URL(name,output)))]));
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-task4-clean-'));
 try{
  const migrations=path.join(temporary,'services/platform/migrations');
  fs.mkdirSync(path.dirname(migrations),{recursive:true});
  fs.cpSync(new URL('../',import.meta.url),migrations,{recursive:true});
  assert.equal(fs.existsSync(path.join(temporary,'.superpowers')),false);
  for(const name of names)fs.unlinkSync(path.join(migrations,'ordered_current',name));
  const builder=path.join(migrations,'tools/build-ordered-current-development.mjs');
  for(const mode of ['--write','--check','--write','--check']){
   const run=spawnSync(process.execPath,[builder,mode],{cwd:temporary,encoding:'utf8',maxBuffer:32*1024*1024});
   assert.equal(run.status,0,run.stderr);
   assert.deepEqual(Object.fromEntries(names.map(name=>[name,sha(fs.readFileSync(path.join(migrations,'ordered_current',name)))])),expected,mode);
  }
  const checkpoint=JSON.parse(fs.readFileSync(path.join(migrations,'ordered_current/development-checkpoint.json')));
  assert.ok(checkpoint.dormantEvaluator,'clean output includes the complete dormant contract');
  const validate=spawnSync(process.execPath,['--input-type=module','-e',`import {admitOrderedCurrentDormantEvaluatorV1,assertOrderedCurrentDormantEvaluatorV1} from ${JSON.stringify(new URL('file://'+builder).href)}; assertOrderedCurrentDormantEvaluatorV1(admitOrderedCurrentDormantEvaluatorV1());`],{cwd:temporary,encoding:'utf8'});
  assert.equal(validate.status,0,validate.stderr);
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});
test('emitted attached packet validates and accepts bounded observations using its exact in-memory assembly witness',()=>{
 const checkpoint=json(output,'development-checkpoint.json'),packet=checkpoint.sourceCoverage.currentSourceClosure.packet;
 const contract=json(evidence,'effective-contract3.json');
 const generated=fs.readFileSync(new URL('development-module.sql',output),'utf8');
 const insertion='INSERT INTO zasp_authorization80_ordered_current.registration(singleton,format_version,profile_checksum,manifest_sha256)';
 assert.equal(generated.split(insertion).length,2);
 const sql=generated.slice(0,generated.indexOf(insertion))+'-- ordered-current:embedded-expectations\n';
 const assembly={kind:'generator-in-memory',sql,privateClosure:compileOrderedPrivateRoutines(sql)};
 assert.equal(typeof sourceClosure.assertOrderedCurrentAttachedSourceClosureV1,'function');
 assert.equal(sourceClosure.assertOrderedCurrentAttachedSourceClosureV1(packet,contract,assembly),undefined);
 assert.equal(sourceClosure.assertOrderedCurrentSourceClosureV1(packet,contract,assembly),undefined);
 const observation={rules:packet.nativeObservation.rules.map(r=>({ruleId:r.ruleId,rows:0,bytes:0})),totalRows:0,totalBytes:0,truncated:false};
 assert.equal(sourceClosure.assertOrderedCurrentObservationBoundsV1(observation,packet,assembly),undefined);
 observation.rules[0].rows=1024;observation.rules[0].bytes=1048576;observation.totalRows=1024;observation.totalBytes=1048576;
 assert.equal(sourceClosure.assertOrderedCurrentObservationBoundsV1(observation,packet,assembly),undefined);
 for(const mutate of [p=>p.private.assemblyAuthority='source-template-only',p=>p.private.compilerInputSHA256='0'.repeat(64),p=>p.private.routineFactsSHA256='0'.repeat(64),p=>p.private.ordinaryFrameDeclarations.pop(),p=>p.private.ordinaryFrameRoutineCount=22,p=>p.private.importedRoutineObservations=1,p=>p.private.expectedFacts=[],p=>p.sourceSites.pop(),p=>p.nativeObservation.rules[0].maxRows++,p=>p.sourceAuthority.fileSHA256='0'.repeat(64)]){
  const changed=structuredClone(packet);mutate(changed);
  assert.throws(()=>sourceClosure.assertOrderedCurrentSourceClosureV1(changed,contract,assembly),/closure/);
  assert.throws(()=>sourceClosure.assertOrderedCurrentObservationBoundsV1(observation,changed,assembly),/closure/);
 }
 for(const mutate of [a=>a.sql+=' ',a=>a.privateClosure.facts[0].fact.source+=' ',a=>a.kind='caller-selected',a=>a.path='/tmp/authority',a=>a.compilerInputSHA256=packet.private.compilerInputSHA256]){
  const changed=structuredClone(assembly);mutate(changed);
  assert.throws(()=>sourceClosure.assertOrderedCurrentAttachedSourceClosureV1(packet,contract,changed),/closure/);
  assert.throws(()=>sourceClosure.assertOrderedCurrentObservationBoundsV1(observation,packet,changed),/closure/);
 }
 assert.throws(()=>sourceClosure.assertOrderedCurrentSourceClosureV1(packet,contract),/closure/);
 assert.throws(()=>sourceClosure.assertOrderedCurrentObservationBoundsV1(observation,packet),/closure/);
});
test('generator binds the complete Task3 closure, exact caps and in-memory private authority into manifest provenance',()=>{
 const checkpoint=json(output,'development-checkpoint.json'),manifest=json(output,'development-manifest.json');
 const coverage=checkpoint.sourceCoverage.currentSourceClosure;
 assert.ok(coverage,'generator consumes Task3 closure');
 assert.equal(coverage.packet.sourceSites.length,233);
 assert.equal(coverage.packet.completeInventory.sites.length,246);
 assert.equal(coverage.packet.completeInventory.unclassified,0);
 assert.equal(coverage.packet.nativeObservation.rules.length,82);
 assert.deepEqual(coverage.packet.nativeObservation.limits,{maxRows:83968,maxBytes:67108864});
 for(const r of coverage.packet.nativeObservation.rules){assert.equal(r.maxRows,1024);assert.equal(r.maxBytes,1048576);}
 assert.equal(coverage.packet.private.assemblyAuthority,'generator-in-memory');
 const currentPrivate=compileOrderedPrivateRoutines(fs.readFileSync(new URL('development-module.sql',output),'utf8'));
 assert.equal(coverage.packet.private.routineFactsSHA256,sha(canonicalOrderedJSON(currentPrivate.facts)));
 assert.equal(coverage.packet.private.continuityFacts.length,35);assert.equal(coverage.packet.private.importedRoutineObservations,0);
 assert.equal(coverage.packetSHA256,sha(canonicalOrderedJSON(coverage.packet)));
 const provenance=manifest.facts.find(r=>r.kind==='build').fact;
 assert.ok(provenance.module_sha256.includes('ordered-current-source-closure-v1.packet='+coverage.packetSHA256));
 for(const [name,pin]of Object.entries(coverage.modules)){
  assert.equal(pin,sha(fs.readFileSync(new URL(name,import.meta.url))));
  assert.ok(provenance.module_sha256.includes(name+'='+pin));
 }
 assert.ok(Object.hasOwn(coverage.modules,'ordered-current-source-closure-v1.mjs'));
 assert.ok(Object.hasOwn(coverage.modules,'ordered-current-mixed-transforms.mjs'));
 assert.equal(checkpoint.facts,10053);assert.equal(checkpoint.rules,379);assert.equal(checkpoint.nativeVerified,false);assert.equal(manifest.installable,false);
 for(const mutate of [p=>p.sourceSites.pop(),p=>p.completeInventory.unclassified=1,p=>p.nativeObservation.limits.maxRows++,p=>p.private.importedRoutineObservations=1]){
  const changed=structuredClone(coverage.packet);mutate(changed);assert.notEqual(sha(canonicalOrderedJSON(changed)),coverage.packetSHA256);
 }
});
test('capture reconciliation admits declared exact facts and refuses every untyped conflict',()=>{
  const role=(identity,login)=>({kind:'role',identity:JSON.stringify(['declared-role',identity]),fact:{login}});
  const declarations={direct:[{id:'declared-role',kind:'role',fields:['login']}],missing:[],private:[]};
  const existing=[role('equal',false)];
  const incoming={direct:[{kind:'role',identity:'["declared-role","equal"]',fact:{login:false}},role('new',true)],missing:[],private:[]};
  const value=reconcileOrderedCurrentFactCollectionsV1({existingFacts:existing,collections:incoming,declarations,settlements:[]});
  assert.deepEqual(value.counts,{admitted:2,equalExisting:1,newlySupplied:1,settledConflicts:0,unresolvedConflicts:0});
  assert.deepEqual(value.collections.direct,{admitted:2,equalExisting:1,newlySupplied:1,settledConflicts:0,unresolvedConflicts:0});
  assert.equal(value.facts.length,2);
  assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:[role('arbitrary',false)],collections:{direct:[role('arbitrary',true)],missing:[],private:[]},declarations,settlements:[]}),/conflicting capture fact/);
  assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:[],collections:{direct:[role('duplicate',false),role('duplicate',false)],missing:[],private:[]},declarations,settlements:[]}),/duplicate capture fact/);
  assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:[],collections:{direct:[{...role('bad-schema',false),fact:{login:false,superuser:false}}],missing:[],private:[]},declarations,settlements:[]}),/source declaration/);
  assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:[],collections:{direct:[{...role('bad-type',false),fact:{login:'false'}}],missing:[],private:[]},declarations,settlements:[]}),/source-declared type/);
  assert.throws(()=>reconcileOrderedCurrentFactCollectionsV1({existingFacts:[],collections:{direct:[],missing:[],private:[{kind:'routine',identity:'["private-routines","x()"]',fact:{name:'x'}}]},declarations:{...declarations,private:[{id:'private-routines',kind:'routine',fields:['name']}]},settlements:[]}),/private routine/);
});
test('generated checkpoint records the fixed Task1 bundle without claiming product-native verification',()=>{
  const checkpoint=json(output,'development-checkpoint.json'),capture=checkpoint.sourceCoverage.captureBundle;
  assert.equal(capture.captureStatus,'LOCAL-NATIVE-VERIFIED-UNBOUND');
  assert.equal(capture.installable,false);
  assert.equal(checkpoint.nativeVerified,false);
  assert.deepEqual(capture.counts,{admitted:1839,equalExisting:230,newlySupplied:1602,settledConflicts:7,unresolvedConflicts:0});
  assert.deepEqual(capture.collections.direct,{admitted:1600,equalExisting:0,newlySupplied:1600,settledConflicts:0,unresolvedConflicts:0});
  assert.deepEqual(capture.collections.missing,{admitted:204,equalExisting:195,newlySupplied:2,settledConflicts:7,unresolvedConflicts:0});
  assert.deepEqual(capture.collections.private,{admitted:35,equalExisting:35,newlySupplied:0,settledConflicts:0,unresolvedConflicts:0});
  assert.equal(capture.equalExisting.length,230);
  assert.equal(capture.newlySupplied.length,1602);
  const qualification=capture.qualificationLedger;
  assert.equal(qualification.version,'native16-qualification-v2');
  assert.equal(qualification.catalogSHA256,'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df');
  assert.equal(qualification.transformVersion,'native16-qualification-v2');
  assert.deepEqual(qualification.counts,{accepted:132,refused:6,total:138});
  assert.equal(qualification.accepted.length,132);assert.equal(qualification.refused.length,6);
  assert.ok(qualification.accepted.every(row=>row.status==='accepted'&&typeof row.captureIdentity==='string'&&/^[a-f0-9]{64}$/.test(row.rawFactSHA256)&&Array.isArray(row.tokenSpans)));
  assert.ok(qualification.refused.every(row=>row.status==='refused'&&typeof row.captureIdentity==='string'&&/^[a-f0-9]{64}$/.test(row.rawFactSHA256)&&row.catalogSHA256===qualification.catalogSHA256));
  const refusalRelations=new Set(qualification.refused.filter(row=>row.ruleId==='worker-edge:gateway_projected27:7').map(row=>row.catalogRelation));
  assert.deepEqual([...refusalRelations].sort(),[
    'public.zasp_recovery_audit','public.zasp_recovery_backups','public.zasp_recovery_fairness',
    'public.zasp_recovery_request_receipts','public.zasp_recovery_restores'
  ].sort());
  const refusalIdentityText=qualification.refused.map(row=>row.captureIdentity).join('\n');
  for(const name of ['zasp_recovery_audit_check','zasp_recovery_backups_check','zasp_recovery_fairness_last_organization_id_check','zasp_recovery_request_receipts_check','zasp_recovery_restores_check','zasp_security_agent_targets_policy_sequence'])assert.ok(refusalIdentityText.includes(name),`refusal identity ${name}`);
  assert.ok(qualification.refused.some(row=>row.ruleId==='worker-edge:ordered_projected28:9'&&row.catalogRelation==='public.zasp_security_agent_temporary_policy_targets'&&row.catalogRegprocedure==='public.zasp_policy_deployment_target_sequence_guard()'&&row.refusal==='unexplained-when-parentheses'));
  assert.equal(qualification.refused.filter(row=>row.refusal==='non-qualification-parentheses-pretty-deparse-no-authority').length,5);
  assert.equal(qualification.refused.filter(row=>row.refusal==='unexplained-when-parentheses').length,1);
  assert.ok(Buffer.byteLength(JSON.stringify(qualification))<524288);
  const ledgerKey=row=>`${row.collection}\0${row.kind}\0${row.identity}`;
  for(const [name,rows,countField] of [['equalExisting',capture.equalExisting,'equalExisting'],['newlySupplied',capture.newlySupplied,'newlySupplied']]){
    assert.equal(new Set(rows.map(ledgerKey)).size,rows.length,`${name} identities are unique`);
    assert.ok(rows.every(row=>Object.keys(row).sort().join(',')==='collection,identity,kind'&&['direct','missing','private'].includes(row.collection)),`${name} has no fact payload or open fields`);
    const encoded=rows.map(canonicalOrderedJSON);
    assert.deepEqual(encoded,[...encoded].sort((left,right)=>Buffer.compare(Buffer.from(left),Buffer.from(right))),`${name} uses deterministic canonical byte order`);
    for(const collection of ['direct','missing','private'])assert.equal(rows.filter(row=>row.collection===collection).length,capture.collections[collection][countField],`${name} ${collection} partition`);
  }
  assert.ok(capture.equalExisting.some(row=>row.collection==='missing'&&row.identity==='["role-profile:native-roles","zasp_temporal_accounting"]'));
  assert.ok(capture.equalExisting.some(row=>row.collection==='private'&&row.identity==='["private-namespace","zasp_authorization80_ordered_current"]'));
  assert.ok(capture.newlySupplied.some(row=>row.collection==='direct'&&row.identity==='["worker-edge:gateway_projected24:2","public.zasp_security_agent_temporary_policy_targets"]'));
  assert.ok(capture.equalExisting.some(row=>row.collection==='missing'&&row.identity==='["role-profile:current-profile","[\\"zasp_authorization80.runtime_profile\\",true]"]'));
  assert.equal(capture.settledConflicts.length,7);
  assert.ok(capture.settledConflicts.every(row=>row.identity.startsWith('["temporal72:precision-function",')&&row.disposition==='supersede-incomplete-null-precision-definition-with-source-selected-predecessor-definition'));
  const conflictKeys=new Set(capture.settledConflicts.map(row=>`${row.kind}\0${row.identity}`));
  assert.ok(capture.newlySupplied.every(row=>!conflictKeys.has(`${row.kind}\0${row.identity}`)),'settled conflicts stay separate from newly supplied facts');
  assert.deepEqual(capture.unresolvedConflicts,[]);
  assert.equal(capture.equalExisting.length,capture.counts.equalExisting);
  assert.equal(capture.newlySupplied.length,capture.counts.newlySupplied);
  assert.deepEqual(capture.bundleHashes,{manifest:'742061cb79130a9e866daa63babe914cf1052e4958ba40c798b8e030c1dd7899',directPacket:'c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab',missingPacket:'23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287',missingCapture:'76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39',privatePacket:'6a487133102fb497db4e3209842a00ce3a0cec48ffd595c84dc3216a982a9cd0',privateCapture:'b8694163c33accd304e85324bddda311bf4ab4704e898823bb2814c1647c0d80',compositionLog:'2a875ddd77d36971fa5f66921d45b69ae3f8f9165be95c070fc159327948100a'});
  assert.equal(capture.remainingBlockers.length>0,true);
});
test('native17 trigger projection preserves raw relname fields while qualifying only sourced relation and definition fields',()=>{
 const manifest=json(output,'development-manifest.json');
 const rowsFor=id=>manifest.facts.filter(row=>{try{return JSON.parse(row.identity)[0]===id}catch{return false}});
 const gateway=rowsFor('worker-edge:gateway_projected27:12'),ordered=rowsFor('worker-edge:ordered_projected28:9');
 assert.equal(gateway.length,101);assert.equal(ordered.length,5);
 for(const row of [...gateway,...ordered]){
  const descriptor=JSON.parse(JSON.parse(row.identity)[1]);
  assert.match(descriptor[0],/^public\./);assert.doesNotMatch(row.fact.relation_name,/\./);
 }
 const approved=ordered.filter(row=>row.fact.name!=='zasp_security_agent_targets_policy_sequence');
 assert.equal(approved.length,4);
 for(const row of [...gateway,...approved]){
  assert.match(row.fact.definition_pretty,/ ON public\./);
  assert.match(row.fact.definition_pretty,/EXECUTE FUNCTION public\./);
 }
 const refused=ordered.find(row=>row.fact.name==='zasp_security_agent_targets_policy_sequence');
 assert.equal(refused.fact.relation_name,'zasp_security_agent_temporary_policy_targets');
 assert.doesNotMatch(refused.fact.definition_pretty,/ ON public\./);
});
test('connected development artifact preserves every accepted supplementary fact and immutable provenance',()=>{
  const raw=fs.readFileSync(new URL('supplementary-reference1.json',evidence));
  assert.equal(sha(raw),'484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b');
  const reference=JSON.parse(raw),manifest=json(output,'development-manifest.json');
  const expected=new Map(manifest.facts.map(row=>[row.identity,row]));
  assert.equal(reference.rows.length,520);
  for(const row of reference.rows)assert.deepEqual(expected.get(row.identity),row,row.identity);
  const provenance=manifest.facts.find(row=>row.kind==='build'&&row.identity==='provenance').fact;
  assert.equal(provenance.postgres,reference.postgres);
  assert.equal(provenance.pgcrypto,reference.pgcrypto);
  assert.ok(provenance.module_sha256.includes('ordered-current-supplementary-reference1.json=484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b'));
  assert.equal(manifest.installable,false);
  const checkpoint=json(output,'development-checkpoint.json');
  assert.equal(checkpoint.sourceCoverage.supplementary.rules,57);
  assert.equal(checkpoint.sourceCoverage.supplementary.sites.length,105);
  assert.ok(checkpoint.sourceCoverage.supplementary.obligations.length>0);
  assert.equal(checkpoint.nativeVerified,false);
});
test('legacy private continuity provenance is explicitly historical and never expected truth',()=>{
 const checkpoint=json(output,'development-checkpoint.json');
 const continuity=checkpoint.sourceCoverage.legacyPrivateContinuity;
 assert.equal(continuity.provenance.authority,'historical-non-authoritative');
 assert.equal(continuity.provenance.usedForExpectedTruth,false);
 assert.equal(continuity.scope.includes('superseded predecessor'),true);
});
test('private reference packet binds source-only DDL and a complete bounded own-namespace query',()=>{
  assert.ok(fs.existsSync(new URL('private-reference-contract.json',output)),'finite private capture contract emitted');
  const contract=json(output,'private-reference-contract.json');
  const ddl=fs.readFileSync(new URL('private-reference-ddl.sql',output));
  const query=fs.readFileSync(new URL('private-reference-select.sql',output));
  assert.equal(sha(ddl),contract.ddlSHA256);
  assert.equal(sha(query),contract.querySHA256);
  assert.equal(contract.status,'REFERENCE-CAPTURE-ONLY');
  assert.equal(contract.maxRows,39);
  assert.deepEqual(contract.categoryMaxRows,{routine:4,namespace:1,relation:4,column:10,constraint:14,index:2,policy:0,trigger:0,view:0,rewrite:0,type:4});
  assert.equal(contract.rules.length,11);
  assert.ok(contract.rules.every(r=>r.namespaces.length===1&&r.namespaces[0]==='zasp_authorization80_ordered_current'&&r.identities.length===0));
  assert.doesNotMatch(ddl.toString(),/INSERT INTO zasp_authorization80_ordered_current\.(?:expected|registration)/);
  assert.equal((ddl.toString().match(/CREATE FUNCTION /g)??[]).length,4);
  assert.equal(contract.expectedRoutineFacts.length,4);
  assert.ok(contract.expectedRoutineFacts.every(r=>r.fact.config[0]==='search_path=pg_catalog'));
  assert.equal(contract.referencePostgres,json(evidence,'supplementary-reference1.json').postgres);
  assert.equal(contract.expectedManifestRows,0);
  assert.equal(contract.registrationRows,0);
});
test('connected temporal and public collection retains unavailable projections without inventing expected facts',()=>{
  const checkpoint=json(output,'development-checkpoint.json');
  const manifest=json(output,'development-manifest.json');
  assert.ok(checkpoint.sourceCoverage.temporalPublic,'accepted temporal/public sources connected');
  const coverage=checkpoint.sourceCoverage.temporalPublic;
  assert.equal(coverage.staticRules,151);
  assert.equal(coverage.resolvedStaticRules,113);
  assert.equal(coverage.resolvedStaticFacts,1572);
  assert.equal(coverage.pendingStaticRules.length,0);
  assert.equal(coverage.capturedStaticRules,38);
  assert.equal(coverage.transformedRecipes,13);
  assert.deepEqual(coverage.pendingTransformedReferences,[]);
  assert.equal(coverage.transformedFacts,380);
  assert.equal(coverage.specialFieldRules,10);
  assert.equal(coverage.unresolvedTransforms.length,2);
  assert.equal(coverage.sites.length,232);
  assert.ok(coverage.obligations.length>0);
  const facts=manifest.facts.filter(row=>/^(temporal:|public:)/.test(JSON.parse(row.identity==='provenance'?'[]':row.identity)[0]??''));
  assert.ok(facts.length>1572);
  assert.ok(manifest.facts.every(row=>!row.identity.includes('raw-transform:')));
  for(const ruleId of coverage.connectedTransformedReferences)assert.ok(manifest.facts.some(row=>row.identity.startsWith(JSON.stringify([ruleId]).slice(0,-1)+',')));
  const collector=fs.readFileSync(new URL('development-collector.sql',output),'utf8');
  assert.match(collector,/transform_inputs AS MATERIALIZED/);
  assert.match(collector,/pg_catalog\.replace\(/);
  assert.equal(checkpoint.rules,379);
  assert.equal(manifest.installable,false);
  assert.equal(checkpoint.nativeVerified,false);
  assert.equal(sha(fs.readFileSync(new URL('private-reference-contract.json',output))),'df377d893445cf178ec90f99f77db865e40ca203fb24f9215f0cb0c53cfcf05a');
});
test('every expected INSERT row round-trips literally to its manifest fact without replacement expansion',()=>{
  const manifest=json(output,'development-manifest.json');
  const sql=fs.readFileSync(new URL('development-module.sql',output),'utf8');
  const marker='INSERT INTO zasp_authorization80_ordered_current.expected(kind,identity,fact) VALUES\n';
  assert.equal(sql.split(marker).length,2);
  const inserted=sql.slice(sql.indexOf(marker)+marker.length);
  const rows=[];
  const tuple=/\('((?:''|[^'])*)','((?:''|[^'])*)','((?:''|[^'])*)'::jsonb\)(,\n|;)/gy;
  let offset=0,match;
  while((match=tuple.exec(inserted))!==null){
    const decode=s=>s.replaceAll("''","'");
    rows.push({kind:decode(match[1]),identity:decode(match[2]),fact:JSON.parse(decode(match[3]))});
    offset=tuple.lastIndex;
    if(match[4]===';')break;
  }
  assert.equal(rows.length,manifest.facts.length,'complete expected SQL tuple cardinality');
  assert.deepEqual(rows,manifest.facts,'SQL string literals preserve all canonical fact bytes');
  assert.ok(!inserted.slice(offset).includes("'::jsonb)"),'no extra expected tuples');
  assert.ok(rows.some(row=>JSON.stringify(row.fact).includes("$'")),'actual source includes replacement-metacharacter coverage');
});
test('successor capture imports only35 nonroutine private facts while current routine source remains freshly generated',()=>{
  const checkpoint=json(output,'development-checkpoint.json'),manifest=json(output,'development-manifest.json');
  const capture=checkpoint.sourceCoverage.captureBundle;
  assert.equal(capture.collections.private.admitted,35);
  assert.equal(capture.collections.private.equalExisting,35);
  assert.equal(capture.validatedPrivateRoutineRows,22);
  assert.equal(capture.importedPrivateRoutineRows,0);
  assert.equal(capture.manifestSHA256,'742061cb79130a9e866daa63babe914cf1052e4958ba40c798b8e030c1dd7899');
  assert.ok(!capture.provenanceModules.some(name=>name.includes('private-reference-alias')),'superseded private predecessor is not final fact authority');
  assert.equal(manifest.facts.filter(row=>row.identity.startsWith('["private-routines",')).length,7);
 assert.equal(manifest.facts.length,10053);
  assert.equal(manifest.installable,false);
});
test('remaining64 static projections stay connected while old-frame transformed expectations are deferred',()=>{
  const checkpoint=json(output,'development-checkpoint.json'),manifest=json(output,'development-manifest.json');
  assert.ok(checkpoint.sourceCoverage.remainingReference,'accepted remaining reference connected');
  const coverage=checkpoint.sourceCoverage.remainingReference;
  assert.equal(coverage.capturedRows,2507);
  assert.equal(coverage.staticFacts,2062);
  assert.equal(coverage.rawTransformInputs,445);
  assert.equal(coverage.transformedFacts,380);
  assert.equal(coverage.unresolvedRawRows,445);
  assert.equal(coverage.unresolvedRawRuleIds.length,16);
  const reference=json(evidence,'remaining-reference1.json');
  const settled=new Set(checkpoint.sourceCoverage.captureBundle.settledConflicts.map(row=>`${row.kind}\0${row.identity}`));
  const precisionAliases=new Map(checkpoint.sourceCoverage.captureBundle.precisionIdentityCanonicalization.mappings.map(row=>[row.captureIdentity,row.canonicalIdentity]));
  for(const row of reference.rows.filter(row=>!JSON.parse(row.identity)[0].startsWith('raw-transform:')&&!settled.has(`${row.kind}\0${row.identity}`))){
    const canonicalIdentity=precisionAliases.get(row.identity)??row.identity;
    assert.deepEqual(manifest.facts.find(f=>f.kind===row.kind&&f.identity===canonicalIdentity),{...row,identity:canonicalIdentity});
  }
  for(const row of reference.rows.filter(row=>settled.has(`${row.kind}\0${row.identity}`))){
    const replacement=manifest.facts.find(f=>f.kind===row.kind&&f.identity===row.identity);
    assert.equal(row.fact.precision_definition,null);assert.equal(typeof replacement.fact.precision_definition,'string');assert.ok(replacement.fact.precision_definition.length>0);
    assert.deepEqual(Object.fromEntries(Object.entries(replacement.fact).filter(([field])=>field!=='precision_definition')),Object.fromEntries(Object.entries(row.fact).filter(([field])=>field!=='precision_definition')));
  }
  const identities=new Set(manifest.facts.map(row=>row.identity));
  for(const row of reference.rows.filter(row=>JSON.parse(row.identity)[0].startsWith('raw-transform:')))assert.ok(!identities.has(row.identity));
  const temporal=manifest.facts.filter(row=>row.identity.startsWith('["temporal:70.fingerprint:function",'));
  assert.equal(temporal.length,91);
  assert.equal(checkpoint.consolidation.deferredFactIdentities.filter(row=>row.identity.startsWith('["temporal:70.fingerprint:function",')).length,91);
  assert.equal(checkpoint.consolidation.deferredFactIdentities.length,204);
  assert.equal(checkpoint.sourceCoverage.temporalPublic.pendingExpectedRuleIds.length,0);
  assert.equal(checkpoint.nativeVerified,false);
});
test('connected six-family source accounting and blocked consolidated query never become expected truth',()=>{
 const checkpoint=json(output,'development-checkpoint.json'),manifest=json(output,'development-manifest.json');
 const edge=checkpoint.sourceCoverage.workerEdge;
 assert.equal(edge.rules.length,39);assert.equal(edge.sites.length,60);assert.equal(edge.recipes.length,7);
 assert.equal(edge.obligations.filter(o=>o.type==='membership-bag').length,2);
 assert.equal(edge.obligations.filter(o=>o.type==='original-delegate').length,6);
 assert.equal(edge.connectedRules.length,39);assert.equal(edge.connectedFacts,799);
 assert.equal(manifest.facts.filter(row=>row.identity.startsWith('["worker-edge:')).length,799);
 const missing=json(output,'consolidated-reference-contract.json');
 assert.equal(sha(fs.readFileSync(new URL('consolidated-reference-select.sql',output))),missing.sqlSHA256);
 assert.equal(sha(fs.readFileSync(new URL('consolidated-reference-contract.json',output))),checkpoint.sourceCoverage.missingReference.contractSHA256);
 assert.equal(missing.workerNeeds.length,11);assert.equal(missing.edgeNeeds.length,39);
 assert.equal(missing.captureReady,false);
 assert.equal(missing.pendingCaps.length,0);
 assert.ok(missing.maxRows>0);assert.equal(missing.maxBytes,67108864);
 assert.equal(Object.values(missing.ruleMaxRows).every(value=>value>0),true);
 assert.equal(Object.values(missing.ruleMaxBytes).every(value=>value>0),true);
 assert.equal(missing.retainedOpaqueNeeds.length,2);
 assert.equal(missing.workerSourceClosure.sourceSites.length,172);
 assert.equal(missing.workerSourceClosure.sourceSites.some(row=>row.disposition==='unclassified'),false);
 assert.equal(missing.workerSourceClosure.workerRecipes.length,28);
 assert.equal(missing.workerSourceClosure.nativeObservation.rules.length,37);
 assert.equal(missing.workerSourceClosure.nativeObservation.limits.maxRows,35843);
 assert.equal(missing.workerSourceClosure.nativeObservation.limits.maxBytes,67108864);
 assert.equal(missing.workerSourceClosure.nativeObservation.rules.every(rule=>rule.maxRows>0&&rule.maxBytes>0),true);
 assert.equal(missing.workerSourceClosure.installable,false);
 assert.ok(missing.rules.every(r=>!r.id.startsWith('worker:projected74:')));
 const collector=fs.readFileSync(new URL('development-collector.sql',output),'utf8');
 for(const rule of edge.connectedRules)assert.ok(collector.includes("'"+rule.id+"'"));
 assert.equal(checkpoint.consolidation.compiledTransformSHA256,'2569f199c762f3efe4cc0c3414fb49df849e243d2a9f4107020415b23e68f80e');
 assert.deepEqual(checkpoint.consolidation.factDelta,{prior:8651,deferred:204,newPrivateRoutines:3,captureSupplied:1602,settledCaptureConflicts:7,unresolvedCaptureConflicts:0,current:10053});
});
test('worker projections connect63 direct rules while opaque74 and unavailable or transformed branches stay excluded',()=>{
  const checkpoint=json(output,'development-checkpoint.json'),manifest=json(output,'development-manifest.json');
  const coverage=checkpoint.sourceCoverage.workerProjections;
  assert.ok(coverage,'worker projection source/reference partition is connected');
  assert.equal(coverage.availableRules,60);
  assert.equal(coverage.connectedRules.length,63);
  assert.equal(coverage.connectedFacts,3207);
  assert.deepEqual(coverage.retainedOpaqueRules.map(r=>r.id),['schema','column','index','policy','trigger','owner-policy','mutation-trigger','saved'].map(branch=>'worker:projected74:'+branch));
  assert.equal(coverage.pendingReferenceRules.length,2);
  assert.equal(coverage.uncompiledRecipes.length,28);
  assert.equal(coverage.sites.length,112);
  assert.equal(coverage.sourceContractSHA256,'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
  assert.equal(coverage.referenceFileSHA256,'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
  const facts=manifest.facts.filter(r=>r.identity.startsWith('["worker:'));
  assert.equal(facts.length,3207);
  assert.equal(new Set(facts.map(r=>JSON.parse(r.identity)[0])).size,62,'one selected universe is empty but must remain in the live collector');
  const forbidden=new Set([...coverage.retainedOpaqueRules,...coverage.pendingReferenceRules].map(r=>r.id).concat(coverage.uncompiledRecipes.map(r=>r.ruleId)));
  for(const row of facts)assert.ok(!forbidden.has(JSON.parse(row.identity)[0]),'no unavailable or transformed projection is treated as an expectation');
  const collector=fs.readFileSync(new URL('development-collector.sql',output),'utf8');
  for(const rule of coverage.connectedRules)assert.ok(collector.includes("'"+rule.id+"'"),'live negative/addition universe retained even for an empty reference');
  for(const rule of coverage.retainedOpaqueRules)assert.ok(!collector.includes("'"+rule.id+"'"),'original P source not turned into direct comparison');
  const column=facts.find(r=>r.kind==='column'&&r.fact.relation_name==='current_grants'&&r.fact.name==='organization_id');
  assert.deepEqual(column.fact,{default:null,name:'organization_id',not_null:false,position:1,relation_name:'current_grants',type:'text'});
  const policy=facts.find(r=>r.identity.startsWith('["worker:projected79:policy",')&&r.fact.relation_name==='grants');
  assert.deepEqual(policy.fact,{check:"(CURRENT_USER = 'zasp_discovery_authority'::name)",name:'authority',relation_name:'grants',roles:'{-}',using:"(CURRENT_USER = 'zasp_discovery_authority'::name)"});
  const provenance=manifest.facts.find(r=>r.kind==='build').fact;
  assert.ok(provenance.module_sha256.includes('ordered-current-worker-projections.mjs=0bcd29c17c316416b38f978b22b4cb2ce561e0655d85b0cdd2f87439e85f65a8'));
  assert.equal(checkpoint.nativeVerified,false);
  assert.equal(manifest.installable,false);
});
