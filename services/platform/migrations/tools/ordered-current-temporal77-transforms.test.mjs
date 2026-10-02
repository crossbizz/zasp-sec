import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {compileOrderedTransforms} from './ordered-current-transform-compiler.mjs';
const moduleURL=new URL('./ordered-current-temporal77-transforms.mjs',import.meta.url);
const evidence=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const contract=JSON.parse(fs.readFileSync(new URL('ordered-current-effective-contract3.json',evidence)));
const load=async()=>{assert.ok(fs.existsSync(moduleURL),'closed temporal77 demand-boundary representation exists');return import(moduleURL.href);};
test('two exact77 sites preserve live membership before put-source and demanded helper expansion',async()=>{
  const {lowerOrderedTemporal77Transforms}=await load();
  const lowered=lowerOrderedTemporal77Transforms(contract);
  assert.equal(lowered.recipes.length,2);
  assert.equal(lowered.sites.length,2);
  assert.equal(lowered.helperBindings.length,15);
  assert.equal(lowered.helperBindings[0],'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)');
  assert.equal(lowered.helperBindings[14],'zasp_temporal77.base67_fingerprint()');
  const [routine,boundary]=lowered.recipes;
  assert.deepEqual(Object.keys(routine.fields),['name','identity_arguments','owner','acl','definition']);
  assert.deepEqual(Object.keys(boundary.fields),['identity','owner','acl','definition']);
  let expression=routine.fields.definition;
  const replacements=[];
  while(expression.op==='replace'){replacements.push(expression.to);expression=expression.input;}
  assert.deepEqual(replacements,['<domain-fingerprint>','<base-fingerprint>','<fingerprint>','<checksum>']);
  assert.deepEqual(expression,boundary.fields.definition);
  assert.equal(expression.op,'saved-membership-case');
  assert.equal(expression.pattern,'zasp_temporal77.%');
  assert.equal(expression.cast,'regprocedure');
  assert.equal(expression.schema,'zasp_temporal78');
  assert.deepEqual(expression.then,{op:'saved-current-scalar',schema:'zasp_temporal78',field:'definition',key:'identity::regprocedure::text'});
  assert.equal(expression.else.cases[0].identity,'zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)');
  const demand=expression.else.else.cases[0].then;
  assert.equal(demand.op,'demand-frame');
  assert.equal(demand.identity,'zasp_authorization80_worker.ordered_writer_definition(oid)');
  assert.equal(demand.bindings.length,15);
  assert.deepEqual(demand.frame.config,['search_path=pg_catalog, public']);
  assert.equal(demand.frame.security_definer,false);
  assert.equal(demand.frame.strict,false);
  assert.equal(demand.expression.op,'identity-case');
  assert.equal(demand.expression.cases.length,15);
  assert.equal(lowered.unsupported.length,2);
  assert.ok(lowered.unsupported.every(row=>row.reason.includes('selected helper-call')));
  assert.throws(()=>compileOrderedTransforms(lowered.recipes),/unknown transform op/);
});
test('changed helper source, frame, body site and missing or extra helper identities refuse',async()=>{
  const {lowerOrderedTemporal77Transforms}=await load();
  for(const change of [
    c=>{c.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)').source+=' ';},
    c=>{c.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)').config=['search_path=pg_catalog'];},
    c=>{c.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)').acl=null;},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal78.predecessor77_fingerprint()').source=c.nodes.find(n=>n.identity==='zasp_temporal78.predecessor77_fingerprint()').source.replace("LIKE 'zasp_temporal77.%'","LIKE 'zasp_temporal77x%'");},
    c=>{c.nodes=c.nodes.filter(n=>n.identity!=='zasp_authorization80_worker.ordered_writer_definition(oid)');},
    c=>{c.nodes.push(structuredClone(c.nodes.find(n=>n.identity==='zasp_authorization80_worker.ordered_writer_definition(oid)')));},
  ]){const changed=structuredClone(contract);change(changed);assert.throws(()=>lowerOrderedTemporal77Transforms(changed));}
});

// Test-only model of the proposed nodes. This checks emitted representation,
// not PostgreSQL planner/error order or central compiler support.
const put='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)';
const base='zasp_temporal77.base67_fingerprint()';
function fixture(recipe){
  let expression=recipe.fields.definition;while(expression.op==='replace')expression=expression.input;
  const demand=expression.else.else.cases[0].then;
  return {identities:new Set([put,base,'zasp_temporal77.other()',...demand.bindings]),tables:{zasp_temporal78:[],zasp_authorization80_worker:[]},frames:[],expression};
}
function evaluate(ast,row,env){
  const bind=node=>{
    if(node.op==='demand-frame')return;
    if(node.op==='identity-case')for(const arm of node.cases){if(!env.identities.has(arm.identity))throw Error('literal binding');bind(arm.then);}
    if(['saved-current-scalar','saved-membership-case'].includes(node.op)&&!Object.hasOwn(env.tables,node.schema))throw Error('table binding');
    if(node.input)bind(node.input);if(node.then)bind(node.then);if(node.else)bind(node.else);
  };bind(ast);
  const run=node=>{
    switch(node.op){
      case 'field':return row[node.field];
      case 'literal':return node.value;
      case 'replace':{const value=run(node.input);return value===null?null:value.replaceAll(node.from,node.to);}
      case 'coalesce':{for(const arg of node.args){const result=run(arg);if(result!==null)return result;}return null;}
      case 'identity-case':return run(node.cases.find(arm=>arm.identity===row.identity)?.then??node.else);
      case 'saved-current-scalar':{const rows=env.tables[node.schema].filter(r=>r.signature===row.identity);if(rows.length>1)throw Error('multiple scalar rows');return rows.length?rows[0][node.field]:null;}
      case 'saved-membership-case':{
        const regex=new RegExp('^'+node.pattern.replace(/[.+^${}()|[\]\\]/g,'\\$&').replaceAll('_','.').replaceAll('%','.*')+'$');
        const matches=env.tables[node.schema].filter(r=>r.signature!==null&&regex.test(r.signature));
        for(const saved of matches)if(!env.identities.has(saved.signature))throw Error('saved signature cast');
        return run(matches.some(r=>r.signature===row.identity)?node.then:node.else);
      }
      case 'demand-frame':{
        for(const identity of node.bindings)if(!env.identities.has(identity))throw Error('helper literal binding');
        bind(node.expression);env.frames.push(node.frame);return run(node.expression);
      }
      default:throw Error('unknown test node');
    }
  };return run(ast);
}
test('membership casts and scalar cardinality remain live while helper-local binding is demanded only on its branch',async()=>{
  const {lowerOrderedTemporal77Transforms}=await load();
  const {recipes,helperBindings}=lowerOrderedTemporal77Transforms(contract);
  const raw={identity:'zasp_temporal77.other()',definition:'raw-body'};
  let env=fixture(recipes[0]);
  env.identities.delete(helperBindings[0]);
  assert.equal(evaluate(env.expression,raw,env),'raw-body');
  assert.equal(env.frames.length,0);
  assert.throws(()=>evaluate(env.expression,{identity:base,definition:'base-raw'},env),/helper literal binding/);
  env.tables.zasp_temporal78.push({signature:base,definition:'saved-first'});
  assert.equal(evaluate(env.expression,{identity:base,definition:'base-raw'},env),'saved-first');
  assert.equal(env.frames.length,0);
  env.tables.zasp_temporal78.push({signature:base,definition:'duplicate'});
  assert.throws(()=>evaluate(env.expression,{identity:base,definition:'base-raw'},env),/multiple scalar rows/);
  env=fixture(recipes[0]);
  assert.equal(evaluate(env.expression,{identity:put,definition:'put-raw'},env),null);
  env.tables.zasp_authorization80_worker.push({signature:put,definition:'worker-put'},{signature:base,definition:'worker-base'});
  assert.equal(evaluate(env.expression,{identity:put,definition:'put-raw'},env),'worker-put');
  assert.equal(env.frames.length,0);
  assert.equal(evaluate(env.expression,{identity:base,definition:'base-raw'},env),'worker-base');
  assert.equal(env.frames.length,1);
  env=fixture(recipes[0]);
  env.tables.zasp_temporal78.push({signature:null,definition:'ignored'},{signature:'outside.invalid()',definition:'ignored'});
  assert.equal(evaluate(env.expression,raw,env),'raw-body');
  env.tables.zasp_temporal78.push({signature:'zaspXtemporal77.invalid()',definition:'must-cast'});
  assert.throws(()=>evaluate(env.expression,raw,env),/saved signature cast/);
  env=fixture(recipes[0]);delete env.tables.zasp_temporal78;
  assert.throws(()=>evaluate(env.expression,raw,env),/table binding/);
});
