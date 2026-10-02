import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
import {projectOrderedFacts,validateOrderedSelectors} from './ordered-current-catalog.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const raw=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(raw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(raw),lower=()=>lowerOrderedPublicCatalog(contract);
const families=['attack_lab_execution','discovery_schedule_replay','execution','inventory','policy_deployment_execution','recovery_execution','red_team_execution','sa_attack_lab','sa_export','sa_multistep','sa_webhook','security_agent_connector_revocation','security_agent_session_isolation'];
const id=f=>`public.zasp_${f}_live_fingerprint()`;
const rule=(o,f,b)=>o.rules.find(x=>x.id===`public:${f}:${b}`);
const obligation=(o,f,b)=>o.obligations.find(x=>x.family===f&&x.branch===b);

test('thirteen pinned sources lower to 59 static rules with all95 byte sites and original security frames',()=>{
  const o=lower();assert.equal(o.rules.length,59);assert.equal(o.sites.length,95);assert.deepEqual([...new Set(o.sites.map(x=>x.identity))],families.map(id));
  for(const f of families){const n=contract.nodes.find(n=>n.identity===id(f));let end=0;for(const s of o.sites.filter(x=>x.family===f)){assert.equal(s.start,end);assert.equal(s.text,Buffer.from(n.source).subarray(s.start,s.end).toString());assert.equal(s.sha256,sha(s.text));assert.equal(s.sourceSHA256,n.sourceSHA256);assert.equal(s.definitionSHA256,n.definitionSHA256);assert.equal(s.security_definer,['inventory','execution'].includes(f));assert.equal(s.owner,f==='inventory'?'zasp_inventory_authority':'zasp_discovery_authority');end=s.end;}assert.equal(end,Buffer.byteLength(n.source));}
});

test('conditional wrappers distinguish NULL fallback from empty text and never return captured constants',()=>{
  const o=lower(),wrappers=o.obligations.filter(x=>x.type==='conditional-wrapper');assert.equal(wrappers.length,4);
  assert.deepEqual(wrappers.map(x=>[x.family,x.fallback]),[['execution',null],['policy_deployment_execution',null],['recovery_execution',''],['security_agent_session_isolation','']]);
  assert.deepEqual(wrappers.find(x=>x.family==='execution').targets,['zasp_temporal72.fingerprint()','zasp_temporal72.retained_execution_fingerprint()']);
  assert.deepEqual(wrappers.find(x=>x.family==='recovery_execution').targets,['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.gateway_projected27()']);
  for(const w of wrappers)assert.ok(o.unsupported.some(x=>x.siteSHA256===w.siteSHA256));
});

test('LIKE wildcard public table selection and globally named constraints/policies retain different universes',()=>{
  const o=lower(),r=rule(o,'attack_lab_execution','table');
  assert.deepEqual(r.selector,{all:[{field:'namespace',equals:'public'},{field:'name',like:'zasp_attack_lab_%'},{any:[{field:'relation_kind',equals:'r'},{field:'relation_kind',equals:'i'}]}]});
  const fact={name:'zaspXattackYlabZq',owner:'owner',row_security:false,forced_row_security:false,acl_text_or_empty:''};
  const rows=[['public','r'],['public','i'],['public','p'],['foreign','r']].map(([namespace,relation_kind],i)=>({kind:'relation',identity:String(i),namespace,relation_kind,name:fact.name,fact}));
  assert.equal(projectOrderedFacts([r],rows).length,2);
  const c=rule(o,'attack_lab_execution','constraint');assert.deepEqual(c.selector,{field:'relation_name',like:'zasp_attack_lab_%'});
  assert.deepEqual(c.fields,['relation_name','name','constraint_type','validated','definition_pretty']);
  const cf={relation_name:fact.name,name:'check',constraint_type:'c',validated:true,definition_pretty:'check (true)'};
  assert.equal(projectOrderedFacts([c],[{kind:'constraint',identity:'foreign-check',namespace:'foreign',relation_name:cf.relation_name,fact:cf}]).length,1);
  assert.deepEqual(rule(o,'red_team_execution','policy').fields,['relation_name','name','permissive','using','check']);
  assert.deepEqual(rule(o,'red_team_execution','function').selector,{all:[{field:'namespace',equals:'public'},{any:[{field:'name',like:'zasp_red_team_%'},{field:'name',equals:'zasp_effective_scope_permissions'}]}]});
});

test('starts_with remains literal, webhook global policies are not accidentally namespace-limited',()=>{
  const o=lower(),p=rule(o,'sa_webhook','policy');
  assert.deepEqual(p.selector,{any:[{field:'relation_name',equals:'zasp_security_agent_webhook_deliveries'},{field:'relation_name',startsWith:'zasp_sa_webhook_'}]});
  const make=(name,i)=>({kind:'policy',identity:String(i),namespace:'foreign',relation_name:name,fact:{relation_name:name,name:'policy',command:'r',roles:'{PUBLIC}',using:null,check:null}});
  const projected=projectOrderedFacts([p],[make('zasp_sa_webhook_added',1),make('zaspXsaYwebhookZadded',2),make('zasp_security_agent_webhook_deliveries',3)]);
  assert.equal(projected.length,2);assert.equal(projected[0].fact.using,null);
  assert.throws(()=>projectOrderedFacts([p],[make('zasp_sa_webhook_added',1),make('zasp_sa_webhook_added',1)]),/duplicate descriptor/);
  assert.deepEqual(rule(o,'sa_attack_lab','constraint').fields,['relation_name','name','definition']);
});

test('class-based indexes, regtype columns and multistep physical/table-kind contracts remain exact',()=>{
  const o=lower();
  assert.equal(rule(o,'attack_lab_execution','index').kind,'class_index');assert.deepEqual(rule(o,'attack_lab_execution','index').selector,{all:[{field:'namespace',equals:'public'},{field:'name',like:'zasp_attack_lab_%'},{field:'relation_kind',equals:'i'}]});
  const inventoryIndex=rule(o,'inventory','index');assert.equal(inventoryIndex.kind,'class_index');assert.equal(JSON.stringify(inventoryIndex.selector).includes('relation_kind'),false);assert.deepEqual(inventoryIndex.fields,['definition']);
  assert.deepEqual(rule(o,'attack_lab_execution','column').fields,['relation_name','name','type_identity','not_null','default_text_or_empty']);
  assert.deepEqual(rule(o,'security_agent_connector_revocation','column').fields,['name','type_identity','not_null','identity','generated','default_text_or_empty']);
  assert.deepEqual(rule(o,'sa_multistep','table').selector.all[2],{any:['r','v','m','p','S'].map(v=>({field:'relation_kind',equals:v}))});
  assert.deepEqual(rule(o,'sa_multistep','column').selector.all[2],{any:['r','p'].map(v=>({field:'relation_kind',equals:v}))});
  assert.deepEqual(rule(o,'sa_multistep','column').fields,['relation_name','position','name','type','not_null','identity','generated','collation','default_text_or_empty','acl_text_or_empty']);
  assert.deepEqual(rule(o,'sa_multistep','index').fields,['relation_name','definition','valid','ready','live']);
  assert.equal(rule(o,'sa_multistep','foreign-key-trigger').kind,'foreign_key_trigger');
});

test('registered export login tags, membership bag cardinality and inventory live rows are unresolved not aliases',()=>{
  const o=lower(),binding=obligation(o,'sa_export','registered-migration-binding');assert.equal(binding.type,'registered-migration-binding');assert.match(binding.source,/pg_has_role/);assert.match(binding.source,/s\.owner_name/);assert.match(binding.required,/literal/);
  const saved=obligation(o,'sa_export','saved');assert.equal(saved.type,'original-transformation');assert.match(saved.source,/jsonb_build_array\('registered-migration-principal'/);assert.ok(!rule(o,'sa_export','saved'));
  for(const f of ['attack_lab_execution','red_team_execution']){const m=obligation(o,f,'membership');assert.equal(m.type,'membership-cardinality');assert.match(m.required,/grantor/);assert.ok(!rule(o,f,'membership'));}
  for(const b of ['rule','restore']){const x=obligation(o,'inventory',b);assert.equal(x.type,'live-metadata');assert.ok(!rule(o,'inventory',b));}
  assert.match(obligation(o,'inventory','function').source,/zasp-core-owner/);assert.match(obligation(o,'inventory','role').source,/current_database/);
  assert.deepEqual(obligation(o,'inventory','function').selector,{all:[{field:'namespace',equals:'public'},{any:[{field:'name',like:'zasp_inventory_%'},...['zasp_discovery_apply_snapshot','zasp_execution_job_input','zasp_execution_apply_risk_projection','zasp_typed_inventory_job_input_v13','zasp_workflow_mutate','zasp_risk_mutate','zasp_core_read','zasp_core_inventory_cutover','zasp_core_inventory_write_fence'].map(n=>({field:'name',equals:n}))]},{not:{field:'name',equals:'zasp_inventory_live_fingerprint'}}]});
  for(const x of [binding,saved,...o.obligations.filter(x=>x.type==='live-metadata')])assert.ok(o.unsupported.some(u=>u.siteSHA256===x.siteSHA256));
});

test('identity helper dependencies, saved-table nested aggregates and body transformations never become raw-body rules',()=>{
  const o=lower();
  for(const f of ['discovery_schedule_replay','sa_attack_lab','sa_export','sa_multistep','sa_webhook','inventory']){assert.ok(!rule(o,f,'function'));const x=obligation(o,f,'function');assert.equal(x.type,'original-transformation');if(f!=='discovery_schedule_replay')assert.ok(x.selector);assert.ok(o.unsupported.some(u=>u.siteSHA256===x.siteSHA256));}
  const schedule=obligation(o,'discovery_schedule_replay','function');assert.equal(schedule.selector,null);assert.match(schedule.required,/saved-signature/);
  const st=obligation(o,'sa_attack_lab','saved-table');assert.equal(st.type,'nested-aggregate');assert.match(st.source,/ORDER BY a.attnum/);assert.match(st.required,/NULL/);
  assert.deepEqual(rule(o,'security_agent_connector_revocation','table_constraint').fields,['name','constraint_type','validated','deferrable','deferred','definition_pretty']);
  assert.deepEqual(rule(o,'security_agent_connector_revocation','policy').fields,['name','command','permissive','roles_csv_public_sorted','using_text_or_empty','check_text_or_empty']);
});

test('changed or rehashed selected source/frame/definition and missing/duplicate/overload reject',()=>{
  const selected=id('inventory');const changes=[c=>c.nodes=c.nodes.filter(n=>n.identity!==selected),c=>c.nodes.push({...c.nodes.find(n=>n.identity===selected)}),c=>c.nodes.push({...c.nodes.find(n=>n.identity===selected),identity:selected.replace('()','(text)')}),c=>{const n=c.nodes.find(n=>n.identity===selected);n.source+=' ';n.sourceSHA256=sha(n.source);},c=>{const n=c.nodes.find(n=>n.identity===selected);n.definition+=' ';n.definitionSHA256=sha(n.definition);},...Object.entries({owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',security_definer:false,config:[],language:'plpgsql',strict:true,parallel:'s',volatility:'v',leakproof:true,cost:1,rows:1,result:'boolean',arguments:'x text'}).map(([k,v])=>c=>{c.nodes.find(n=>n.identity===selected)[k]=v;})];
  for(const change of changes){const c=structuredClone(contract);change(c);assert.throws(()=>lowerOrderedPublicCatalog(c),/public source/);}assert.throws(()=>lowerOrderedPublicCatalog(null),/public source/);
});

test('output is deterministic, input immutable, unrelated accepted families stay excluded',()=>{
  const before=JSON.stringify(contract),o=lower();assert.equal(o.rules.length,59);const c=structuredClone(contract);c.nodes.find(n=>n.identity==='zasp_temporal77.base67_fingerprint()').source='unrelated';assert.deepEqual(o,lowerOrderedPublicCatalog(c));assert.deepEqual(o,lowerOrderedPublicCatalog({...contract,nodes:[...contract.nodes].reverse()}));assert.equal(JSON.stringify(contract),before);
});

test('any proposed rule needing unavailable descriptors remains an explicit integration blocker',()=>{
  const o=lower();assert.equal(o.rules.length,59);
  for(const r of o.rules){try{validateOrderedSelectors([r]);}catch{assert.ok(o.unsupported.some(u=>u.ruleId===r.id),'unmarked unsupported rule: '+r.id);}}
});
