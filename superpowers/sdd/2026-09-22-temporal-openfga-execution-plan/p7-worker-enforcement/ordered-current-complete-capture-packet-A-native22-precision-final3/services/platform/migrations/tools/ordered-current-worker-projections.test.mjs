import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {validateOrderedSelectors,compileOrderedCollector} from './ordered-current-catalog.mjs';
const subject=await import('./ordered-current-worker-projections.mjs').catch(()=>({}));
const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
const counts={projected_domain:7,projected_temporal_profile:8,projected62:8,projected68:10,projected69:10,projected72:14,projected74:25,projected78:13,projected79:8};
test('all nine pinned bodies have complete nonoverlapping byte coverage and one disposition per103 original branches',()=>{
  assert.equal(typeof subject.lowerOrderedWorkerProjections,'function');
  const out=subject.lowerOrderedWorkerProjections(contract);
  for(const [family,count]of Object.entries(counts)){
    const node=contract.nodes.find(n=>n.identity==='zasp_authorization80_worker.'+family+'()'),sites=out.sites.filter(s=>s.family===family);
    assert.equal(sites.length,count+1,family);assert.equal(sites[0].start,0);
    for(let i=1;i<sites.length;i++)assert.equal(sites[i].start,sites[i-1].end);
    assert.equal(sites.at(-1).end,Buffer.byteLength(node.source));assert.equal(sites.map(s=>s.text).join(''),node.source);
    for(const site of sites.filter(s=>s.type!=='digest')){
      const matches=[...out.rules.map(r=>r.id),...out.recipes.map(r=>r.ruleId),...out.obligations.filter(o=>o.type==='original-delegate').map(o=>o.ruleId)].filter(id=>id==='worker:'+family+':'+site.type);
      assert.equal(matches.length,1,family+':'+site.type);
    }
  }
  assert.equal(out.sites.length,112);assert.equal(out.installable,false);
  assert.equal(out.obligations.filter(o=>o.type==='original-delegate').length,2);
});
test('source fields preserve nullable ACL/default and79 policy distinctions without extra comparisons',()=>{
  assert.equal(typeof subject.lowerOrderedWorkerProjections,'function');const out=subject.lowerOrderedWorkerProjections(contract);
  const rule=id=>out.rules.find(r=>r.id==='worker:'+id);
  assert.deepEqual(rule('projected79:schema').fields,['owner','acl']);
  assert.deepEqual(rule('projected_temporal_profile:column').fields,['relation_name','position','name','type','not_null','acl','default']);
  assert.deepEqual(rule('projected79:column').fields,['relation_name','position','name','type','not_null','default']);
  assert.deepEqual(rule('projected79:policy').fields,['relation_name','name','roles','using','check']);
  assert.deepEqual(rule('projected79:trigger').fields,['relation','enabled','definition']);assert.equal(rule('projected79:trigger').predicate,undefined);
  assert.deepEqual(rule('projected62:trigger').fields,['relation_name','name','enabled','definition']);
  validateOrderedSelectors(out.rules);assert.match(compileOrderedCollector(out.rules).sql,/pg_catalog\.pg_constraint/);
});
test('fixed domain23 universe and exact trigger pair exclusions preserve additions and original bindings',()=>{
  assert.equal(typeof subject.lowerOrderedWorkerProjections,'function');const out=subject.lowerOrderedWorkerProjections(contract);
  const rule=id=>out.rules.find(r=>r.id==='worker:'+id);
  const d=rule('projected_domain:table');assert.equal(d.selector.all[0].equals,'public');assert.equal(d.selector.all[1].any.length,23);
  assert.deepEqual(d.selector.all[1].any.slice(-2),[{field:'name',equals:'zasp_discovery_snapshot_inputs'},{field:'name',equals:'zasp_discovery_snapshot_projection_items'}]);
  assert.deepEqual(rule('projected68:trigger').selector,{all:[{field:'namespace',equals:'zasp_temporal68'},{not:{all:[{field:'relation',equals:'zasp_temporal68.deliveries'},{any:[{field:'name',equals:'ordered_policy_capture'},{field:'name',equals:'ordered_policy_no_truncate'}]}]}}]});
  const domain=out.recipes.find(r=>r.ruleId==='worker:projected_domain:trigger');assert.ok(domain);assert.match(domain.source,/to_regprocedure\(signature\)=p.oid/);assert.match(domain.source,/zasp_authorization79_capture/);assert.ok(!out.rules.some(r=>r.id===domain.ruleId));
  assert.ok(out.obligations.some(o=>o.type==='original-reg-object-binding'&&o.ruleId==='worker:projected68:trigger'));
});
test('transformed and parent-lock branches retain full original expression sites and never emit raw definition rules',()=>{
  assert.equal(typeof subject.lowerOrderedWorkerProjections,'function');const out=subject.lowerOrderedWorkerProjections(contract);
  for(const id of ['projected74:constraint','projected74:lock-role','projected74:lock-default-grant','projected74:delivery-role-membership','projected74:approval-dependency','projected72:saved','projected78:effective-predecessor','projected79:view']){
    const recipe=out.recipes.find(r=>r.ruleId==='worker:'+id);assert.ok(recipe,id);assert.ok(recipe.projections.length);assert.equal(recipe.disposition,'source-pinned representation only');assert.ok(out.unsupported.some(u=>u.ruleId===recipe.ruleId));assert.ok(!out.rules.some(r=>r.id===recipe.ruleId));
  }
  const roles=out.recipes.find(r=>r.ruleId==='worker:projected74:lock-role');assert.equal(roles.projections.length,11);assert.equal(roles.projections.at(-3),'rolconnlimit');
  const approval=out.recipes.find(r=>r.ruleId==='worker:projected74:approval-dependency');assert.equal(approval.projections.length,10);assert.equal(approval.projections[8],'p.proconfig');
  assert.equal(out.recipes.find(r=>r.ruleId==='worker:projected72:saved').projectionMode,'whole-case-value');
});
test('each original body, definition, overload and complete frame pin refuses altered contract input',()=>{
  assert.equal(typeof subject.lowerOrderedWorkerProjections,'function');
  for(const family of Object.keys(counts))for(const key of ['source','definition','owner','acl','config','security_definer','parallel','leakproof','cost','rows']){
    const changed=structuredClone(contract),n=changed.nodes.find(n=>n.identity==='zasp_authorization80_worker.'+family+'()');
    n[key]=Array.isArray(n[key])?[]:typeof n[key]==='boolean'?!n[key]:typeof n[key]==='number'?n[key]+1:n[key]+' ';
    assert.throws(()=>subject.lowerOrderedWorkerProjections(changed),family+' '+key);
  }
  const changed=structuredClone(contract);changed.nodes.push({...changed.nodes.find(n=>n.identity==='zasp_authorization80_worker.projected62()'),identity:'zasp_authorization80_worker.projected62(text)'});assert.throws(()=>subject.lowerOrderedWorkerProjections(changed));
});
