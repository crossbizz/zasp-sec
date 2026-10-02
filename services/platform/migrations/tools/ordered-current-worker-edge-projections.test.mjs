import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {validateOrderedSelectors,compileOrderedCollector,projectOrderedFacts} from './ordered-current-catalog.mjs';
const subject=await import('./ordered-current-worker-edge-projections.mjs').catch(()=>({}));
const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
const counts={gateway_projected24:7,gateway_projected27:13,ordered_projected28:10,runtime_projected40:7,runtime_projected50_binding:8,runtime_projected50_search:9};
const lower=()=>{assert.equal(typeof subject.lowerOrderedWorkerEdgeProjections,'function');return subject.lowerOrderedWorkerEdgeProjections(contract);};
const id=(family,ordinal)=>`worker-edge:${family}:${ordinal}`;
test('six source bodies cover54 branches plus six tails without duplicate labels losing dispositions',()=>{
  const out=lower();assert.equal(out.installable,false);assert.equal(out.sites.length,60);
  for(const [family,count]of Object.entries(counts)){
    const n=contract.nodes.find(n=>n.identity===`zasp_authorization80_worker.${family}()`),s=out.sites.filter(s=>s.family===family);
    assert.equal(s.length,count+1);assert.equal(s[0].start,0);assert.equal(s.at(-1).end,Buffer.byteLength(n.source));assert.equal(s.map(x=>x.text).join(''),n.source);
    for(let i=1;i<s.length;i++)assert.equal(s[i-1].end,s[i].start);
    for(let i=1;i<=count;i++)assert.equal([...out.rules.map(r=>r.id),...out.recipes.map(r=>r.ruleId),...out.obligations.filter(o=>o.type==='original-delegate'||o.type==='membership-bag').map(o=>o.ruleId)].filter(x=>x===id(family,i)).length,1);
  }
  assert.equal(out.rules.filter(r=>r.id.startsWith('worker-edge:runtime_projected50_binding:')&&r.kind==='routine').length,4);
  assert.equal(out.obligations.filter(o=>o.type==='original-aggregate-digest').length,6);
  validateOrderedSelectors(out.rules);assert.match(compileOrderedCollector(out.rules).sql,/LIKE 'zasp_recovery_%'/);
});
test('wildcard and global universes consume off-prefix and off-schema additions without widening paired index branches',()=>{
  const out=lower(),rule=(f,n)=>out.rules.find(r=>r.id===id(f,n));
  const r=rule('gateway_projected27',4),fact=Object.fromEntries(r.fields.map(k=>[k,null]));
  const rows=['zasp_recovery_a','zaspXrecoveryYa','unrelated'].map(name=>({kind:r.kind,identity:'public.'+name,namespace:'public',name,relation_kind:'r',fact:{...fact,name}}));
  assert.equal(projectOrderedFacts([r],rows).length,2);
  const global=rule('gateway_projected27',7),gfact=Object.fromEntries(global.fields.map(k=>[k,null]));
  assert.equal(projectOrderedFacts([global],[{kind:global.kind,identity:'x',namespace:'off_schema',relation_name:'zasp_recovery_any',fact:gfact}]).length,1);
  assert.deepEqual(rule('gateway_projected24',5).selector,{any:[{all:[{field:'relation',equals:'public.zasp_runtime_gateway_events'},{field:'name',equals:'zasp_runtime_gateway_events_session_v24_idx'}]},{field:'relation',equals:'public.zasp_security_agent_temporary_policy_targets'}]});
  assert.equal(rule('ordered_projected28',9).predicate,undefined);assert.deepEqual(rule('ordered_projected28',9).selector,{any:[{field:'name',like:'%policy_deployment%'},{field:'name',like:'%policy_sequence'},{field:'name',like:'%policy_verify'}]});
});
test('original selected fields retain regtype, nullable expressions, pretty formatting and missing descriptor distinctions',()=>{
  const out=lower(),rule=(f,n)=>out.rules.find(r=>r.id===id(f,n));
  assert.deepEqual(rule('gateway_projected24',3).fields,['name','type_identity','not_null','identity','generated','default_text_or_empty']);
  assert.deepEqual(rule('gateway_projected24',4).fields,['name','constraint_type','validated','deferrable','deferred','definition_pretty']);
  assert.deepEqual(rule('gateway_projected27',11).fields,['relation_name','name','permissive','using','check']);
  assert.deepEqual(rule('runtime_projected50_search',9).fields,['relation','name','enabled','definition']);
  assert.deepEqual(rule('runtime_projected50_binding',3).fields,['name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition']);
  assert.equal(rule('gateway_projected27',8).kind,'column_all');
  assert.deepEqual(rule('gateway_projected27',8).fields,['relation_name','name','type_identity','not_null','default_text_or_empty']);
  assert.deepEqual(rule('gateway_projected27',10).fields,['name','owner','valid','ready','unique','primary','definition']);
  assert.deepEqual(rule('runtime_projected40',6).fields,['namespace_name','table_name','name','roles_text','command','using','check']);
});
test('two membership bags, six delegates and seven conditional transformations stay outside direct rules',()=>{
  const out=lower();assert.equal(out.obligations.filter(o=>o.type==='membership-bag').length,2);assert.equal(out.obligations.filter(o=>o.type==='original-delegate').length,6);
  const transformed=out.recipes.filter(r=>r.type==='conditional-routine');assert.equal(transformed.length,7);
  for(const r of transformed){assert.equal(r.projections.length,7);assert.ok(out.unsupported.some(u=>u.ruleId===r.ruleId));assert.ok(!out.rules.some(x=>x.id===r.ruleId));}
  const saved=transformed.find(r=>r.ruleId===id('runtime_projected50_search',2));assert.match(saved.projections[6],/to_regprocedure\(signature\)=p.oid/);assert.ok(saved.bindings.length===4);
  const helper=out.helpers[0];assert.equal(helper.identity,'zasp_authorization80_worker.ordered_writer_definition(oid)');assert.equal(helper.bindings.length,15);assert.equal(helper.demand,'selected original helper-call arm only');assert.equal(helper.frame.security_definer,false);
  assert.ok(out.obligations.some(o=>o.type==='helper-demand-frame'&&o.ruleId===id('ordered_projected28',10)));
  for(const r of out.obligations.filter(o=>o.type==='membership-bag'))assert.deepEqual(r.projections,['granted.rolname','member.rolname','membership.admin_option']);
});
test('every source, definition, complete frame, missing node and added overload is rejected before lowering',()=>{
  lower();for(const family of [...Object.keys(counts),'ordered_writer_definition'])for(const key of ['source','definition','owner','acl','config','language','result','arguments','security_definer','strict','parallel','volatility','leakproof','cost','rows']){
    const c=structuredClone(contract),n=c.nodes.find(n=>n.identity.startsWith(`zasp_authorization80_worker.${family}(`));n[key]=Array.isArray(n[key])?[]:typeof n[key]==='boolean'?!n[key]:typeof n[key]==='number'?n[key]+1:n[key]+' ';
    assert.throws(()=>subject.lowerOrderedWorkerEdgeProjections(c),`${family}.${key}`);
  }
  const missing=structuredClone(contract);missing.nodes=missing.nodes.filter(n=>n.identity!=='zasp_authorization80_worker.gateway_projected24()');assert.throws(()=>subject.lowerOrderedWorkerEdgeProjections(missing));
  const extra=structuredClone(contract);extra.nodes.push({...extra.nodes.find(n=>n.identity==='zasp_authorization80_worker.gateway_projected24()'),identity:'zasp_authorization80_worker.gateway_projected24(text)'});assert.throws(()=>subject.lowerOrderedWorkerEdgeProjections(extra));
});
test('regprocedure aliases cannot silently become unmatched canonical identity filters',()=>{
  const out=lower(),target=id('runtime_projected50_binding',7);
  const selected=out.rules.find(r=>r.id===target);assert.ok(selected);
  assert.deepEqual(selected.selector,{any:[{field:'identity',regprocedureEquals:'public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)'},{field:'identity',regprocedureEquals:'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)'}]});
  const r=out.referenceNeeds.find(r=>r.ruleId===target);assert.ok(r);
  assert.deepEqual(r.bindings,[{identity:'public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)',cast:'regprocedure'},{identity:'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)',cast:'regprocedure'}]);
  assert.equal(r.projections.at(-1),'pg_get_functiondef(p.oid)');assert.equal(r.resolution,'independent-regprocedure-resolution-required');
  assert.ok(out.obligations.some(u=>u.ruleId===target&&u.type==='original-reg-object-binding'));
  const sql=compileOrderedCollector([selected]).sql;
  assert.match(sql,/'public\.zasp_runtime_sandbox_session_event_page\(text,text,text,text,text,timestamptz,text,integer\)'::regprocedure/);
  assert.throws(()=>projectOrderedFacts([selected],[]),/independent regprocedure resolution metadata required/);
  assert.throws(()=>projectOrderedFacts([selected],[{kind:'routine',identity:'public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamp with time zone,text,integer)',namespace:'public',fact:{}}]),/independent regprocedure resolution metadata required/);
});

test('reference handoff preserves each exact source span and blocks unbounded or unavailable reference admission',()=>{
  const out=lower();assert.equal(out.rules.length,39);assert.equal(out.referenceNeeds.length,39);assert.equal(out.recipes.length,7);
  for(const need of out.referenceNeeds){
    const rule=out.rules.find(r=>r.id===need.ruleId),site=out.sites.find(s=>s.identity===need.sourceIdentity&&s.sha256===need.siteSHA256);
    assert.deepEqual(need.fields,rule.fields);assert.deepEqual(need.selector,rule.selector);
    assert.equal(need.source,site.text);assert.equal(need.start,site.start);assert.equal(need.end,site.end);assert.deepEqual(need.frame,site.frame);
    assert.equal(need.referenceStatus,'missing-independent-reference');assert.equal(need.expectedFacts,undefined);
    assert.equal(need.captureFrame,'original-source-frame');assert.equal(need.keyFrame,'pg_catalog');
    assert.ok(out.unsupported.some(u=>u.ruleId===need.ruleId&&u.type==='independent-reference-and-native'));
  }
  const need=(f,n)=>out.referenceNeeds.find(r=>r.ruleId===id(f,n));
  assert.equal(need('gateway_projected27',8).sourceMaxRows,1);
  assert.equal(need('gateway_projected27',10).sourceMaxRows,2);
  assert.equal(need('runtime_projected50_binding',7).sourceMaxRows,2);
  assert.equal(need('runtime_projected40',6).sourceMaxRows,null);
  assert.equal(need('runtime_projected40',6).captureBoundStatus,'requires-reviewed-refusal-cap');
  assert.equal(need('gateway_projected27',4).sourceMaxRows,null);
  assert.deepEqual(need('gateway_projected27',8).universe,{positiveAttributes:false,excludeDropped:true});
});

test('new emitted descriptors preserve nonpositive attributes, index owner and nullable schema-qualified policies',()=>{
  const out=lower(),r=(f,n)=>out.rules.find(r=>r.id===id(f,n));
  const attribute=r('gateway_projected27',8),sql=compileOrderedCollector([attribute]).sql;
  assert.match(sql,/NOT a\.attisdropped/);assert.doesNotMatch(sql,/a\.attnum\s*>\s*0/);
  assert.doesNotMatch(sql,/\bLIMIT\b/);
  const attributeFact={relation_name:'zasp_runtime_gateway_events',name:'policy_ids',type_identity:'text[]',not_null:false,default_text_or_empty:''};
  assert.equal(projectOrderedFacts([attribute],[{kind:'column_all',identity:'["public.zasp_runtime_gateway_events","policy_ids"]',namespace:'public',relation_name:'zasp_runtime_gateway_events',name:'policy_ids',fact:attributeFact}]).length,1);
  const index=r('gateway_projected27',10),indexSQL=compileOrderedCollector([index]).sql;
  assert.match(indexSQL,/index_class\.relowner/);
  const policy=r('runtime_projected40',6);
  const fact={namespace_name:'public',table_name:'zasp_runtime_session_events',name:'p',roles_text:'{public}',command:'ALL',using:null,check:null};
  const rows=[{kind:'policy_view',identity:'p',namespace:'public',table_name:fact.table_name,fact},{kind:'policy_view',identity:'off',namespace:'elsewhere',table_name:fact.table_name,fact:{...fact,namespace_name:'elsewhere'}}];
  const result=projectOrderedFacts([policy],rows);assert.equal(result.length,1);assert.equal(result[0].fact.using,null);assert.equal(result[0].fact.namespace_name,'public');
});
