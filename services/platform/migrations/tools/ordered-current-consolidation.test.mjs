import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {compileOrderedTransforms,projectOrderedTransforms} from './ordered-current-transform-compiler.mjs';
import * as privateCompiler from './ordered-current-private.mjs';
import {compileOrderedCollector,projectOrderedFacts,validateOrderedSelectors} from './ordered-current-catalog.mjs';
const root=new URL('../../../../',import.meta.url);
const contract=JSON.parse(fs.readFileSync(new URL('services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',root)));
const catalog=JSON.parse(fs.readFileSync(new URL('services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',root)));
const recipes=[...lowerOrderedTemporalTransforms(contract).recipes,...lowerOrderedPublicFunctionTransforms(contract).recipes];
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
test('one missing-reference contract excludes opaque74 and refuses incomplete frame or bound evidence',async()=>{
 const component=await import('./ordered-current-consolidation-needs.mjs').catch(()=>({}));
 assert.equal(typeof component.buildOrderedConsolidationNeeds,'function');
 const result=component.buildOrderedConsolidationNeeds(contract,catalog);
 assert.equal(result.contract.status,'BLOCKED-NOT-CAPTURE-READY');
 assert.equal(result.contract.installable,false);assert.equal(result.contract.captureReady,false);
 assert.equal(result.contract.workerNeeds.length,11);assert.equal(result.contract.edgeNeeds.length,39);
 assert.equal(result.contract.transformNeeds.length,13);
 assert.equal(result.contract.workerSourceClosure?.format,'ordered-current-worker-source-closure-v1');
 assert.equal(result.contract.workerSourceClosure?.sourceSites.length,172);
 assert.equal(result.contract.workerSourceClosure?.sourceSites.some(row=>row.disposition==='unclassified'),false);
 assert.equal(result.contract.workerSourceClosure?.nativeObservation.rules.length,37);
 assert.equal(result.contract.workerSourceClosure?.installable,false);
 assert.ok(result.contract.rules.every(r=>!r.id.startsWith('worker:projected74:')));
 assert.equal(result.contract.pendingCaps.length,0);
 assert.ok(Number.isSafeInteger(result.contract.maxRows)&&result.contract.maxRows>0);
 assert.equal(result.contract.maxBytes,67108864);
 assert.equal(Object.values(result.contract.ruleMaxRows).every(value=>Number.isSafeInteger(value)&&value>0),true);
 assert.equal(Object.values(result.contract.ruleMaxBytes).every(value=>Number.isSafeInteger(value)&&value>0),true);
 assert.equal(result.contract.workerSourceClosure.nativeObservation.limits.maxRows,35843);
 assert.equal(result.contract.workerSourceClosure.nativeObservation.limits.maxBytes,67108864);
 assert.equal(result.contract.workerSourceClosure.nativeObservation.rules.every(rule=>rule.maxRows>0&&rule.maxBytes>0),true);
 assert.ok(result.contract.transformNeeds.every(r=>r.referenceStatus==='missing-independent-original-frame-input'));
 assert.throws(()=>component.admitOrderedConsolidationCapture(result.contract),/incomplete/);
 assert.doesNotMatch(result.sql,/\bLIMIT\b/);
 assert.throws(()=>component.buildOrderedConsolidationNeeds({...contract,nodes:[]},catalog));
});
test('consolidation admits only the exact tracked source and catalog authorities',async()=>{
 const component=await import('./ordered-current-consolidation-needs.mjs');
 assert.deepEqual(component.admitOrderedWorkerConsolidationNeedsV1(),component.buildOrderedConsolidationNeeds(contract,catalog));
 assert.equal(component.orderedWorkerConsolidationAuthorityV1.source.fileSHA256,'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
 assert.equal(component.orderedWorkerConsolidationAuthorityV1.catalog.fileSHA256,'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
 const source=fs.readFileSync(new URL('./ordered-current-consolidation-needs.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(source,/\.superpowers|\/private\/tmp/);
 const changed=structuredClone(catalog);changed.reviewOnlyMutation=true;
 assert.throws(()=>component.buildOrderedConsolidationNeeds(contract,changed),/catalog pin/);
 assert.throws(()=>component.admitOrderedWorkerConsolidationNeedsV1('caller-selected'),/caller-selected/);
});
test('outer worker reference contract refuses missing, duplicate and over-cap observations without truncation',async()=>{
 const component=await import('./ordered-current-consolidation-needs.mjs'),packet=component.buildOrderedConsolidationNeeds(contract,catalog).contract;
 const observation={rules:packet.rules.map(rule=>({ruleId:rule.id,rows:0,bytes:0})),totalRows:0,totalBytes:0,truncated:false};
 assert.equal(component.assertOrderedConsolidationCaptureBoundsV1(observation,packet),undefined);
 for(const mutate of [
  value=>value.rules.pop(),value=>value.rules.push({...value.rules[0]}),
  value=>value.rules[0].rows=packet.ruleMaxRows[value.rules[0].ruleId]+1,
  value=>value.rules[0].bytes=packet.ruleMaxBytes[value.rules[0].ruleId]+1,
  value=>value.totalRows=packet.maxRows+1,value=>value.totalBytes=packet.maxBytes+1,value=>value.truncated=true,
 ]){const changed=structuredClone(observation);mutate(changed);assert.throws(()=>component.assertOrderedConsolidationCaptureBoundsV1(changed,packet),/consolidation capture/);}
 for(const mutate of [
  value=>delete value.ruleMaxRows[value.rules[0].id],value=>value.ruleMaxRows[value.rules[0].id]=null,value=>value.ruleMaxRows[value.rules[0].id]=0,value=>value.ruleMaxRows[value.rules[0].id]++,
  value=>delete value.ruleMaxBytes[value.rules[0].id],value=>value.ruleMaxBytes[value.rules[0].id]=null,value=>value.ruleMaxBytes[value.rules[0].id]=0,value=>value.ruleMaxBytes[value.rules[0].id]++,
  value=>delete value.maxRows,value=>value.maxRows=null,value=>value.maxRows=0,value=>value.maxRows++,
  value=>delete value.maxBytes,value=>value.maxBytes=null,value=>value.maxBytes=0,value=>value.maxBytes++,
 ]){
  const changed=structuredClone(packet);mutate(changed);assert.throws(()=>component.assertOrderedConsolidationCaptureBoundsV1(observation,changed),/consolidation capture/);
 }
});
test('consolidated compiler consumes exact native5 framed thirteen projection semantics',()=>{
 const out=compileOrderedTransforms(recipes,{definitionFrame:'pg_catalog, public'});
 assert.equal(sha(out.sql),'2569f199c762f3efe4cc0c3414fb49df849e243d2a9f4107020415b23e68f80e');
 assert.equal(out.frameVersion,2);
 assert.ok(out.rawRules.every(r=>r.fields.includes('routine_oid')&&!r.fields.includes('definition')&&!r.fields.includes('identity_arguments')));
 assert.match(out.admissionSQL,/\) IS TRUE\),false\)/);
 assert.throws(()=>projectOrderedTransforms(recipes,[],{}, {definitionFrame:'pg_catalog, public'}),/framed reference/);
 for(const options of [{definitionFrame:'public'},{definitionFrame:'pg_catalog, public',extra:true},null])assert.throws(()=>compileOrderedTransforms(recipes,options));
 const selected=compileOrderedTransforms([recipes.find(r=>r.ruleId==='temporal:74.outbox65_fingerprint:function')],{definitionFrame:'pg_catalog, public'}).sql;
 const arm=selected.slice(selected.indexOf('(CASE WHEN object_identity::regprocedure='));
 assert.ok(arm.indexOf('FROM zasp_temporal74.predecessor_functions')<arm.indexOf(' ELSE (CASE WHEN true='));
 assert.ok(!selected.slice(selected.indexOf('transform_inputs AS MATERIALIZED'),selected.indexOf(') transform_raw)')).includes('function_definition_public('));
});
test('private assembly binds seven exact routines and NULL-safe pre-call admission before catalog work',()=>{
 assert.equal(typeof privateCompiler.withOrderedFrameClosure,'function');
 const template=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url),'utf8');
 const sql=privateCompiler.withOrderedFrameClosure(template),closure=privateCompiler.compileOrderedPrivateRoutines(sql);
 assert.equal(closure.facts.length,7);
 assert.equal(closure.facts.filter(r=>r.fact.config.length===2).length,3);
 for(const row of closure.facts.filter(r=>r.fact.config.length===2)){
  assert.deepEqual(row.fact.config,['search_path=pg_catalog, public','TimeZone=UTC']);
  assert.deepEqual(row.fact.input_types,['oid']);assert.equal(row.fact.volatility,'s');
  assert.equal(row.fact.acl,'{zasp_discovery_authority=X/zasp_discovery_authority}');
 }
 assert.ok(sql.indexOf('CREATE FUNCTION zasp_authorization80_ordered_current.function_definition_public')<sql.indexOf('DO $private_acl$'));
 const body=closure.facts.find(r=>r.identity.includes('.catalog(text)')).fact.source;
 assert.ok(body.indexOf(') IS TRUE),false)')<body.indexOf('SELECT jsonb_agg'));
 assert.match(body,/IS DISTINCT FROM true THEN RETURN false/);
 for(const mutation of [sql.replace("SET TimeZone='UTC'","SET TimeZone='Europe/London'"),sql.replace('$body$\nBEGIN\n RETURN value::pg_catalog.regprocedure::pg_catalog.text;','$body$\nBEGIN\n RETURN NULL;')])assert.throws(()=>privateCompiler.compileOrderedPrivateRoutines(mutation),/frame|declaration/);
});
test('new source descriptors retain nonpositive attributes, index owner and policy schema',()=>{
 const rules=[{id:'gateway-column',kind:'column_all',namespaces:[],identities:[],fields:['relation_name','name','type_identity','not_null','default_text_or_empty'],selector:{all:[{field:'namespace',equals:'public'},{field:'relation_name',equals:'zasp_runtime_gateway_events'},{field:'name',equals:'policy_ids'}]}},{id:'index-owner',kind:'index',namespaces:['public'],identities:[],fields:['owner']},{id:'policy-schema',kind:'policy_view',namespaces:['public'],identities:[],fields:['namespace_name']}];
 const sql=compileOrderedCollector(rules).sql;
 assert.match(sql,/NOT a\.attisdropped/);assert.doesNotMatch(sql,/a\.attnum>0/);
 assert.match(sql,/'owner',index_class\.relowner::regrole::text/);assert.match(sql,/'namespace_name',v\.schemaname::text/);
 assert.throws(()=>validateOrderedSelectors([{...rules[0],fields:['unknown']}]),/field/);
});
test('direct trigger collector uses OID-independent dual-relation WHEN authority and preserves NULL',()=>{
 const rule={id:'dual-relation-trigger',kind:'trigger',namespaces:[],identities:[],fields:['relation','name','when'],selector:{all:[{field:'namespace',equals:'public'},{field:'relation_name',equals:'dual_relation_when'}]}};
 const noWhenRule={...rule,id:'no-when-trigger',selector:{all:[{field:'namespace',equals:'public'},{field:'relation_name',equals:'no_when'}]}};
 const rules=[rule,noWhenRule],sql=compileOrderedCollector(rules).sql;
 assert.match(sql,/pg_catalog\.pg_trigger t/);
 assert.match(sql,/CASE WHEN t\.tgqual IS NULL THEN NULL ELSE pg_catalog\.pg_get_triggerdef\(t\.oid,true\) END/);
 assert.doesNotMatch(sql,/pg_catalog\.pg_get_expr\(t\.tgqual,t\.tgrelid\)/);
 assert.doesNotMatch(sql,/t\.tgqual::text/);
 assert.equal(sql,compileOrderedCollector(rules).sql,'collector SQL is deterministic across OID-bearing catalog contents');
 const definition='CREATE TRIGGER dual_relation_when BEFORE UPDATE ON public.dual_relation_when FOR EACH ROW WHEN ((old.value = new.value)) EXECUTE FUNCTION public.dual_relation_when_fn()';
 const rows=projectOrderedFacts(rules,[
  {kind:'trigger',namespace:'public',identity:'public.dual_relation_when',relation_name:'dual_relation_when',fact:{relation:'public.dual_relation_when',name:'dual_relation_when',when:definition}},
  {kind:'trigger',namespace:'public',identity:'public.no_when',relation_name:'no_when',fact:{relation:'public.no_when',name:'no_when',when:null}},
 ]);
 assert.equal(rows.length,2);
 assert.equal(rows[0].fact.when,definition);
 assert.equal(rows[1].fact.when,null);
});
test('regprocedure selector requires exact resolution metadata even on an empty offline reference',()=>{
 const selector={field:'identity',regprocedureEquals:'public.page(timestamptz)'};
 const rule={id:'resolved',kind:'routine',namespaces:[],identities:[],fields:['name'],selector};
 const sql=compileOrderedCollector([rule]).sql;
 assert.match(sql,/p\.oid::regprocedure::text::regprocedure='public\.page\(timestamptz\)'::regprocedure/);
 assert.throws(()=>projectOrderedFacts([rule],[]),/resolution/);
 assert.throws(()=>validateOrderedSelectors([{...rule,kind:'relation'}]),/selector/);
 assert.throws(()=>validateOrderedSelectors([{...rule,selector:{...selector,extra:true}}]),/selector/);
});
