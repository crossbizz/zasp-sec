import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {compileOrderedTransforms,evaluateOrderedTransform} from './ordered-current-transform-compiler.mjs';
import {formatOrderedProconfigText} from './ordered-current-public-function-transforms.mjs';
import {staticDescriptor} from './ordered-current-static-catalog.mjs';
import {compileOrderedPrivateRoutines,withOrderedFrameClosure} from './ordered-current-private.mjs';

const subject=await import('./ordered-current-source-closure-v1.mjs').catch(()=>({}));
const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
const build=()=>{assert.equal(typeof subject.buildOrderedCurrentSourceClosureV1,'function');return subject.buildOrderedCurrentSourceClosureV1(contract);};

// A dropped or incorrectly discharged source site must fail the closed packet
// validator, independently of whether the old selectors still compile.
test('current-source packet covers temporal/public source sites and the exact retirement tail without inventing truth',()=>{
 const packet=build();
 assert.deepEqual(subject.admitOrderedCurrentSourceClosureV1(),packet);
 assert.deepEqual(packet.counts,{temporalSites:137,publicSites:95,retirementSites:1,sourceSites:233,temporalRules:92,publicRules:59,temporalWrappers:12,publicWrappers:4});
 assert.equal(packet.sourceSites.length,233);
 assert.equal(new Set(packet.sourceSites.map(s=>s.sourceIdentity+':'+s.start+':'+s.end)).size,233);
 assert.equal(packet.sourceSites.some(s=>s.disposition==='unclassified'),false);
 assert.equal(packet.installable,false);assert.equal(packet.nativeVerified,false);assert.equal(packet.captureReady,false);
 assert.equal(packet.expectedFacts,undefined);
 assert.equal(subject.assertOrderedCurrentSourceClosureV1(packet,contract),undefined);
});

test('both temporal77 branches retain dynamic LIKE membership and selected helper demand as noninstallable source contracts',()=>{
 const p=build(),t=p.temporal77;
 assert.equal(t.recipes.length,2);assert.equal(t.helper.bindings.length,15);
 assert.deepEqual(t.recipes.map(r=>r.ruleId),['temporal:78.predecessor77_fingerprint:function','temporal:78.predecessor77_fingerprint:effective-policy-boundary']);
 assert.equal(t.candidate.installable,false);assert.equal(t.candidate.native_unverified,true);
 for(const r of t.recipes){
  let n=r.fields.definition;while(n.op==='replace')n=n.input;
  assert.equal(n.op,'saved-membership-case');assert.equal(n.pattern,'zasp_temporal77.%');assert.equal(n.cast,'regprocedure');
  assert.equal(n.else.cases[0].identity,'zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)');
  const demand=n.else.else.cases[0].then;
  assert.equal(demand.op,'demand-frame');assert.equal(demand.frame.security_definer,false);
  assert.deepEqual(demand.frame.config,['search_path=pg_catalog, public']);
  assert.equal(demand.bindings.length,15);
 }
 for(const id of ['like-underscore','membership-null','membership-duplicates','membership-cast-error','saved-zero-null','saved-multiple-error','helper-unselected-no-demand','helper-selected-binding-error','put-source-before-helper'])assert.ok(t.nativeCases.includes(id),id);
 assert.throws(()=>compileOrderedTransforms(t.recipes),/unknown transform op/);
});

test('schedule helper preserves dynamic universe, original72 guard and the two ordered replacement constants',()=>{
 const s=build().mixed.schedule;
 assert.equal(s.recipe.selector.op,'saved-signature-universe');
 assert.equal(s.recipe.selector.cast,'regprocedure');
 assert.equal(s.recipe.fields.definition.op,'original-helper-demand');
 let n=s.recipe.fields.definition.expression,replacements=[];
 while(n.op==='replace'){replacements.push(n.from);n=n.input;}
 assert.equal(replacements.length,2);assert.equal(new Set(replacements).size,2);
 assert.equal(n.op,'identity-membership-case');assert.equal(n.identities.length,2);
 assert.equal(n.then.op,'original72-guard');assert.equal(n.then.primitiveException,false);assert.equal(n.then.outsideCollectorAuthorized,false);
 assert.equal(n.then.then.signatureResolution,'to_regprocedure');assert.equal(n.then.else.value,null);
 assert.equal(s.guardInputs.length,4);
 for(const id of ['outer-cast-error','unselected-helper-binding','selected-helper-binding','guard-false-null','guard-null-null','saved-zero-null','saved-multiple-error','native-first-error'])assert.ok(s.nativeCases.includes(id),id);
});

test('saved export closure keeps fresh owner/MEMBER EXISTS and original ordered tagged ACL bytes',()=>{
 const e=build().mixed.export,r=e.recipe,b=r.bindings.migration_owned;
 assert.equal(b.signatures.length,2);assert.equal(b.roleTest,'MEMBER');assert.equal(b.ownerField,'owner_name');
 assert.equal(r.fields.owner.registered,'<registered-migration-principal>');
 assert.equal(r.fields.acl.order,'original-ordinality');assert.equal(r.fields.acl.removeOnly,'grantee');assert.equal(r.fields.acl.emptyAggregate,null);
 assert.equal(r.fields.acl.result,'original-jsonb-text');
 for(const id of ['owner-not-registered','member-false','member-null','duplicate-bindings-exists','acl-ordinality','acl-tags-cannot-collide','acl-remove-grantee-only','acl-empty-null','acl-scalar-error','raw-else-text'])assert.ok(e.nativeCases.includes(id),id);
 assert.equal(e.expectedFacts,undefined);
});

test('higher wrappers retain exact source predicates, per-call identity and frames instead of cached booleans',()=>{
 const p=build();assert.equal(p.wrappers.length,16);
 const publicWrappers=p.wrappers.filter(w=>w.sourceIdentity.startsWith('public.'));
 assert.deepEqual(publicWrappers.map(w=>[w.family,w.fallback]),[['execution',null],['policy_deployment_execution',null],['recovery_execution',''],['security_agent_session_isolation','']]);
 for(const w of p.wrappers){
  assert.equal(w.disposition,'retain-original-live-demand');
  assert.deepEqual(w.frame.config,['search_path=pg_catalog, public']);
  assert.ok(w.calls.length>0);assert.ok(w.calls.every(c=>c.targetSourceSHA256&&c.targetDefinitionSHA256&&c.targetFrame));
  for(const id of ['condition-false-fallback','condition-null-fallback','selected-call-error','unselected-call-no-demand','registration-cardinality','owner-acl-frame-drift'])assert.ok(w.nativeCases.includes(id),id);
 }
});

test('typed public routines stay source-compiled while raw original-frame/config witnesses remain mandatory',()=>{
 const p=build();assert.equal(p.publicFunctions.recipes.length,4);
 assert.equal(compileOrderedTransforms(p.publicFunctions.recipes).recipes,4);
 for(const r of p.publicFunctions.recipes){
  for(const field of ['security_definer','strict','leakproof']){
   assert.equal(evaluateOrderedTransform(r.fields[field],{[field]:false},{}),false);
   assert.equal(evaluateOrderedTransform(r.fields[field],{[field]:null},{}),null);
   assert.throws(()=>evaluateOrderedTransform(r.fields[field],{[field]:'false'},{}),/type/);
  }
 }
 assert.equal(formatOrderedProconfigText(['search_path=pg_catalog, public'],{dimensions:1,lowerBound:1,upperBound:1}),'{"search_path=pg_catalog, public"}');
 assert.throws(()=>formatOrderedProconfigText(['a'],{dimensions:2,lowerBound:1,upperBound:1}),/dimension/);
 assert.throws(()=>formatOrderedProconfigText(['a'],{dimensions:1,lowerBound:0,upperBound:0}),/dimension/);
 assert.throws(()=>formatOrderedProconfigText(['a']),/witness/);
 assert.equal(p.publicFunctions.referencePolicy,'independent-original-frame-raw-fields-only');
 assert.equal(p.publicFunctions.targetDerivedConfigAllowed,false);
});

test('retirement tail is source-pinned and keeps FOUND, absent CONTINUE, dynamic fingerprint and worker privileges ordered',()=>{
 const t=build().retirement;
 assert.equal(t.start,118841);assert.equal(t.end,119679);
 assert.equal(t.siteSHA256,'5b50a6159ba6a8afb26d656ca91273a2c838558d06a14b6d59d0e3230eeb736a');
 assert.deepEqual(t.steps.map(s=>s.kind),['select-into-nonstrict','namespace-found-distinct','absent-continue','fixed-original-fingerprint','dynamic-fingerprint','retired-fingerprint-or-worker-execute']);
 assert.deepEqual(t.schemas,['zasp_ordered_worker63','zasp_ordered_scheduler64']);
 assert.deepEqual(t.originalFingerprints,['c81c4cb4cb799894ab9bf69b16815341ac53665e967fd0405b32009898510239','9a8a090c97a4c8b913921dd1503b6ca0925c837adf5da9219c3c8f1e3a6d0419']);
 for(const schema of t.schemas)assert.throws(()=>staticDescriptor('registration',[schema]),/unsupported/);
 assert.doesNotThrow(()=>staticDescriptor('registration',['zasp_ordered_public62']));
 assert.equal(t.nativeCases.includes('duplicate-select-into-not-scalar-error'),true);
 assert.deepEqual(t.staticRegistration,{catalogFileSHA256:'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',capturedOrderedSchemas:['zasp_ordered_public62'],forbiddenSchemas:['zasp_ordered_worker63','zasp_ordered_scheduler64'],capturedFingerprintsAreAuthority:false});
});

test('private authority imports exactly 35 nonroutine continuity facts and zero observed routines',()=>{
 const p=build().private;
 assert.equal(p.continuityFacts.length,35);assert.equal(p.continuityFacts.some(f=>f.kind==='routine'),false);
 assert.equal(p.validatedLegacyRows,39);assert.equal(p.validatedLegacyRoutines,4);assert.equal(p.importedRoutineObservations,0);
 assert.equal(p.ordinaryFrameRoutineCount,7);assert.equal(p.directFrameRoutineCount,22);
 assert.equal(p.routineAuthority,'current-compiler-evaluator-only');
});

test('bounded observation contract refuses truncation, missing/extra/duplicate rules and every cap widening',()=>{
 const p=build(),n=p.nativeObservation;
 assert.equal(n.captureReady,false);assert.equal(n.installable,false);
 assert.equal(n.rules.length,82);assert.equal(n.limits.maxRows,83968);assert.equal(n.limits.maxBytes,67108864);
 for(const r of n.rules){assert.equal(r.maxRows,1024);assert.equal(r.maxBytes,1048576);}
 const o={rules:n.rules.map(r=>({ruleId:r.ruleId,rows:0,bytes:0})),totalRows:0,totalBytes:0,truncated:false};
 assert.equal(subject.assertOrderedCurrentObservationBoundsV1(o,p),undefined);
 for(const mutate of [x=>x.rules.pop(),x=>x.rules.push({...x.rules[0]}),x=>x.rules[0].ruleId='unknown',x=>x.rules[0].rows=n.rules[0].maxRows+1,x=>x.rules[0].bytes=n.rules[0].maxBytes+1,x=>x.totalRows=1,x=>x.totalBytes=1,x=>x.truncated=true]){
  const x=structuredClone(o);mutate(x);assert.throws(()=>subject.assertOrderedCurrentObservationBoundsV1(x,p),/observation/);
 }
 const changed=structuredClone(p);changed.nativeObservation.rules[0].maxRows++;
 assert.throws(()=>subject.assertOrderedCurrentObservationBoundsV1(o,changed),/closure/);
 const overflow=structuredClone(o);for(const r of overflow.rules.slice(0,65))r.bytes=1048576;overflow.totalBytes=65*1048576;
 assert.throws(()=>subject.assertOrderedCurrentObservationBoundsV1(overflow,p),/observation/);
 for(const field of ['maxRows','maxBytes'])for(const value of [null,0,-1,0.5,Number.MAX_SAFE_INTEGER]){
  const changed=structuredClone(p);changed.nativeObservation.rules[0][field]=value;
  assert.throws(()=>subject.assertOrderedCurrentObservationBoundsV1(o,changed),/closure/);
 }
});

test('complete packet assertion refuses source/frame/helper/wrapper/ACL/order and expected-value substitutions',()=>{
 const mutations=[p=>p.sourceSites.pop(),p=>p.sourceSites.push({...p.sourceSites[0]}),p=>p.temporal77.helper.bindings.pop(),p=>p.temporal77.recipes[0].fields.definition={op:'field',field:'definition'},p=>p.mixed.schedule.guardInputs.pop(),p=>p.mixed.export.recipe.bindings.migration_owned.roleTest='USAGE',p=>p.mixed.export.recipe.fields.acl.order='sorted',p=>p.wrappers[0].frame.security_definer=true,p=>p.wrappers[0].calls[0].identity='public.unknown()',p=>p.retirement.steps.reverse(),p=>p.retirement.originalFingerprints.reverse(),p=>p.private.continuityFacts.push({kind:'routine'}),p=>p.private.importedRoutineObservations=1,p=>p.publicFunctions.targetDerivedConfigAllowed=true,p=>p.expectedFacts=[],p=>p.nativeVerified=true];
 for(const mutate of mutations){const p=build();mutate(p);assert.throws(()=>subject.assertOrderedCurrentSourceClosureV1(p,contract),/closure/);}
 assert.throws(()=>subject.buildOrderedCurrentSourceClosureV1(contract,{path:'/tmp/authority'}),/caller-selected/);
 assert.throws(()=>subject.admitOrderedCurrentSourceClosureV1(contract),/caller-selected/);
 const changed=structuredClone(contract);changed.nodes[0].source+=' ';
 assert.throws(()=>subject.buildOrderedCurrentSourceClosureV1(changed),/source contract pin/);
});

test('source packet builds from repository files in an isolated tree with no ignored evidence directory',()=>{
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-current-source-'));
 try{
  const migrations=path.join(temporary,'services/platform/migrations');
  fs.mkdirSync(path.dirname(migrations),{recursive:true});fs.cpSync(new URL('../',import.meta.url),migrations,{recursive:true});
  assert.equal(fs.existsSync(path.join(temporary,'.superpowers')),false);
  fs.writeFileSync(path.join(migrations,'ordered_current/development-module.sql'),'untrusted generated output');
  const script="import {admitOrderedCurrentSourceClosureV1} from './services/platform/migrations/tools/ordered-current-source-closure-v1.mjs'; const p=admitOrderedCurrentSourceClosureV1(); console.log(JSON.stringify({sites:p.sourceSites.length,routines:p.private.importedRoutineObservations,installable:p.installable}));";
  const result=spawnSync(process.execPath,['--input-type=module','-e',script],{cwd:temporary,encoding:'utf8',maxBuffer:1024*1024});
  assert.equal(result.status,0,result.stderr);assert.deepEqual(JSON.parse(result.stdout),{sites:233,routines:0,installable:false});
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});

test('complete classified inventory includes mixed spans and independently admitted helper and guard sources',()=>{
 const p=build();assert.ok(Array.isArray(p.secondarySites));
 assert.equal(p.secondarySites.filter(s=>s.component==='mixed').length,4);
 assert.equal(p.secondarySites.filter(s=>s.component==='public-helper').length,4);
 assert.equal(p.secondarySites.filter(s=>s.component==='temporal77-helper').length,1);
 assert.equal(p.secondarySites.filter(s=>s.component==='mixed-guard').length,4);
 assert.equal(p.completeInventory.sites.length,246);
 assert.equal(new Set(p.completeInventory.sites.map(s=>s.siteId)).size,246);
 assert.equal(p.completeInventory.unclassified,0);
 for(const s of p.secondarySites){assert.ok(s.frame);assert.ok(s.semantics);assert.ok(s.blocker);assert.notEqual(s.disposition,'unclassified');}
 const changed=structuredClone(p);changed.secondarySites[0].disposition='unclassified';
 assert.throws(()=>subject.assertOrderedCurrentSourceClosureV1(changed,contract),/closure/);
});

test('private authority attaches only an in-memory compiler closure and does not consult generated output',()=>{
 assert.equal(typeof subject.attachOrderedCurrentPrivateAuthorityV1,'function');
 const p=build(),sql=withOrderedFrameClosure(fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url),'utf8'));
 const compiled=compileOrderedPrivateRoutines(sql);
 const attached=subject.attachOrderedCurrentPrivateAuthorityV1(p,sql,compiled);
 assert.equal(attached.private.assemblyAuthority,'generator-in-memory');
 assert.equal(attached.private.importedRoutineObservations,0);
 assert.equal(typeof attached.private.compilerInputSHA256,'string');
 assert.equal(typeof attached.private.routineFactsSHA256,'string');
 const changed=structuredClone(compiled);changed.facts[0].fact.source+=' ';
 assert.throws(()=>subject.attachOrderedCurrentPrivateAuthorityV1(p,sql,changed),/private|closure/);
 assert.equal(p.private.assemblyAuthority,'source-template-only');
});
