import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
import {projectOrderedFacts} from './ordered-current-catalog.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const raw=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(raw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(raw),lower=()=>lowerOrderedTemporalCatalog(contract);
const id=f=>'zasp_temporal'+f+'()';
const families=['65.fingerprint','66.fingerprint','67.base_fingerprint','67.fingerprint','68.fingerprint','69.fingerprint','70.fingerprint','71.fingerprint','72.fingerprint','72.retained_execution_fingerprint','72.retained_precision_fingerprint','73.fingerprint','74.fingerprint','74.outbox65_fingerprint','74.owner66_fingerprint','75.fingerprint','76.executor74_fingerprint','76.fingerprint','77.domain67_fingerprint','77.fingerprint','78.fingerprint','78.predecessor73_fingerprint','78.predecessor76_fingerprint','78.predecessor77_fingerprint'];
const rule=(o,f,b)=>o.rules.find(r=>r.id===`temporal:${f}:${b}`);
const obligation=(o,f,b)=>o.obligations.find(r=>r.family===f&&r.branch===b);

test('24 fixed temporal bodies are accounted for, excluding base67, with all 137 exact byte sites',()=>{
  const o=lower();assert.deepEqual([...new Set(o.sites.map(s=>s.identity))],families.map(id));
  assert.equal(o.sites.length,137);assert.equal(o.rules.length,92);
  assert.equal(o.obligations.filter(x=>x.type==='conditional-wrapper'||x.type==='delegate').length,13);
  assert.equal(o.obligations.filter(x=>x.type==='digest-semantics').length,11);
  for(const f of families){const n=contract.nodes.find(n=>n.identity===id(f));let end=0;for(const s of o.sites.filter(s=>s.family===f)){assert.equal(s.start,end);assert.equal(s.text,Buffer.from(n.source).subarray(s.start,s.end).toString());assert.equal(s.sha256,sha(s.text));assert.equal(s.sourceSHA256,n.sourceSHA256);assert.equal(s.definitionSHA256,n.definitionSHA256);assert.equal(s.security_definer,f==='72.retained_execution_fingerprint');end=s.end;}assert.equal(end,Buffer.byteLength(n.source));}
});

test('wrappers keep conditional registration/catalog/frame tests and exact outgoing calls unresolved',()=>{
  const o=lower(),wrapper=f=>o.obligations.find(x=>x.family===f&&['conditional-wrapper','delegate'].includes(x.type));
  assert.deepEqual(wrapper('65.fingerprint').targets,['zasp_temporal74.fingerprint()','zasp_temporal74.outbox65_fingerprint()']);
  assert.deepEqual(wrapper('68.fingerprint').targets,['zasp_authorization80_temporal.projected68()']);
  assert.equal(wrapper('68.fingerprint').type,'delegate');
  assert.deepEqual(wrapper('69.fingerprint').targets,['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected69()']);
  assert.match(wrapper('65.fingerprint').required,/cardinality/);assert.match(wrapper('69.fingerprint').required,/NULL/);
  for(const w of o.obligations.filter(x=>['conditional-wrapper','delegate'].includes(x.type)))assert.ok(o.unsupported.some(u=>u.siteSHA256===w.siteSHA256));
  assert.ok(!o.rules.some(r=>r.id.startsWith('temporal:69.')));
});

test('namespace recipes retain physical columns, persistence, raw coalescing and FK source namespace',()=>{
  const o=lower();
  assert.deepEqual(rule(o,'70.fingerprint','table').fields,['name','kind','persistence','owner','row_security','forced_row_security','acl_text_or_empty']);
  assert.deepEqual(rule(o,'74.owner66_fingerprint','table').fields,['name','kind','owner','row_security','forced_row_security','acl_text_or_empty']);
  assert.deepEqual(rule(o,'70.fingerprint','column').fields,['relation_name','position','name','type','not_null','default_text_or_empty','acl_text_or_empty']);
  assert.deepEqual(rule(o,'74.outbox65_fingerprint','column').fields,['relation_name','position','name','type','not_null','default_text_or_empty']);
  assert.deepEqual(rule(o,'70.fingerprint','foreign-key-trigger'),{id:'temporal:70.fingerprint:foreign-key-trigger',kind:'foreign_key_trigger',namespaces:['zasp_temporal70'],identities:[],fields:['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty']});
  assert.ok(o.unsupported.some(x=>x.family==='70.fingerprint'&&x.branch==='foreign-key-trigger'));
  const r=rule(o,'70.fingerprint','table'),fact={name:'a',kind:'r',persistence:'p',owner:'owner',row_security:true,forced_row_security:true,acl_text_or_empty:''};
  assert.equal(projectOrderedFacts([r],[{kind:'relation',identity:'zasp_temporal70.a',namespace:'zasp_temporal70',fact},{kind:'relation',identity:'zasp_temporal71.a',namespace:'zasp_temporal71',fact}]).length,1);
});

test('owner66 global-name universes and targeted triggers do not gain namespace/internal restrictions',()=>{
  const o=lower();
  assert.deepEqual(rule(o,'74.owner66_fingerprint','policy').selector,{any:[{field:'namespace',equals:'zasp_temporal66'},{field:'name',equals:'zasp_temporal66_owner'}]});
  assert.deepEqual(rule(o,'74.owner66_fingerprint','trigger').selector,{any:[{field:'namespace',equals:'zasp_temporal66'},{any:[{field:'name',equals:'zasp_temporal66_lease'},{field:'name',equals:'zasp_temporal66_capture'}]}]});
  assert.equal(rule(o,'74.owner66_fingerprint','trigger').predicate,'user-triggers');
  const targeted=rule(o,'74.outbox65_fingerprint','trigger');assert.equal(targeted.predicate,undefined);
  assert.deepEqual(targeted.selector,{all:[{field:'relation',equals:'public.zasp_security_agent_request_receipts'},{field:'name',equals:'zasp_temporal65_capture'}]});
  assert.deepEqual(rule(o,'78.predecessor77_fingerprint','source-capture').selector,{any:[{all:[{field:'relation',equals:'public.zasp_risk_findings'},{field:'name',equals:'zasp_temporal77_finding_source'}]},{all:[{field:'relation',equals:'public.zasp_risk_attack_paths'},{field:'name',equals:'zasp_temporal77_path_source'}]},{all:[{field:'relation',equals:'public.zasp_runtime_gateway_events'},{field:'name',equals:'zasp_temporal77_runtime_source'}]}]});
});

test('paired exclusions stay paired and are not broadened to name-only or relation-only exclusions',()=>{
  const o=lower(),r=rule(o,'78.predecessor77_fingerprint','trigger');
  assert.deepEqual(r.selector,{all:[{field:'namespace',equals:'zasp_temporal77'},{not:{all:[{any:[{field:'relation',equals:'zasp_temporal77.runtime_evaluations'},{field:'relation',equals:'zasp_temporal77.source_events'}]},{any:[{field:'name',equals:'zasp_authorization80_worker_runtime_capture'},{field:'name',equals:'zasp_authorization80_worker_runtime_no_truncate'}]}]}}]});
  const p=rule(o,'72.retained_precision_fingerprint','trigger');assert.equal(p.predicate,'user-triggers');assert.equal(p.selector.all.length,3);
  assert.deepEqual(p.selector.all.slice(1),[{not:{all:[{field:'relation',equals:'public.zasp_runtime_stage_work'},{field:'name',equals:'zasp_authorization80_runtime_stage_insert'}]}},{not:{all:[{field:'relation',equals:'public.zasp_discovery_outbox'},{field:'name',equals:'zasp_temporal72_outbox_guard'}]}}]);
  const rows=[
    ['zasp_temporal77','zasp_temporal77.runtime_evaluations','zasp_authorization80_worker_runtime_capture',false],
    ['zasp_temporal77','zasp_temporal77.runtime_evaluations','other',false],
    ['zasp_temporal77','zasp_temporal77.other','zasp_authorization80_worker_runtime_capture',false],
    ['zasp_temporal77','zasp_temporal77.source_events','other',true],
    ['foreign','foreign.other','other',false]
  ].map(([namespace,relation,name,internal],i)=>({kind:'trigger',identity:String(i),namespace,relation,name,fact:{relation,name,enabled:'O',definition:'body',internal}}));
  assert.deepEqual(projectOrderedFacts([r],rows).map(x=>x.fact.name).sort(),['other','zasp_authorization80_worker_runtime_capture']);
  assert.throws(()=>projectOrderedFacts([r],[rows[1],rows[1]]),/duplicate descriptor/);
});

test('retained execution preserves SQL wildcard/negative selection, pretty fields and JSON NULL semantics obligations',()=>{
  const o=lower(),c=rule(o,'72.retained_execution_fingerprint','constraint');
  assert.equal(c.selector.all[0].equals,'public');assert.deepEqual(c.selector.all[1].any[0],{field:'relation_name',like:'zasp_discovery_execution_%'});
  assert.deepEqual(c.selector.all[2],{any:[{field:'name',like:'zasp_execution_%'},{not:{field:'relation_name',equals:'zasp_integration_connections'}}]});
  assert.deepEqual(c.fields,['definition_pretty']);
  assert.deepEqual(rule(o,'72.retained_execution_fingerprint','column').fields,['type','not_null','default_pretty_text_or_empty']);
  assert.equal(rule(o,'72.retained_execution_fingerprint','column').kind,'column_name');
  assert.deepEqual(rule(o,'72.retained_execution_fingerprint','index').selector,{all:[{field:'namespace',equals:'public'},{field:'name',like:'zasp_execution_%'}]});
  assert.deepEqual(rule(o,'72.retained_execution_fingerprint','index').fields,['definition_pretty']);
  const f=obligation(o,'72.retained_execution_fingerprint','function');assert.equal(f.type,'original-transformation');assert.match(f.source,/acldefault\('f'/);assert.match(f.source,/split_part/);assert.match(f.source,/NOT IN/);assert.match(f.required,/multiple-row/);
  assert.ok(!rule(o,'72.retained_execution_fingerprint','function'));assert.ok(!rule(o,'72.retained_execution_fingerprint','role'));
  assert.match(obligation(o,'72.retained_execution_fingerprint','role').source,/shobj_description/);
  assert.equal(o.obligations.find(x=>x.family==='72.retained_execution_fingerprint'&&x.type==='digest-semantics').encoding,'jsonb-array');
  const rows=[['public','zaspXdiscoveryYexecutionZanything','any'],['public','zasp_integration_connections','other'],['public','zasp_integration_connections','zaspXexecutionYcheck'],['foreign','zasp_discovery_execution_q','any'],['public',null,'other']].map(([namespace,relation_name,name],i)=>({kind:'constraint',identity:String(i),namespace,relation_name,name,fact:{definition_pretty:'definition '+i}}));
  assert.deepEqual(projectOrderedFacts([c],rows).map(x=>x.fact.definition_pretty),['definition 0','definition 2']);
});

test('all original definition/ACL substitutions remain explicit rather than raw-body equality rules',()=>{
  const o=lower();
  for(const f of ['70.fingerprint','71.fingerprint','74.outbox65_fingerprint','74.owner66_fingerprint','75.fingerprint','77.domain67_fingerprint','78.predecessor73_fingerprint','78.predecessor76_fingerprint','78.predecessor77_fingerprint','72.retained_precision_fingerprint']){
    assert.ok(!rule(o,f,'function'));const x=obligation(o,f,'function');assert.equal(x.type,'original-transformation');assert.ok(x.selector);assert.ok(o.unsupported.some(u=>u.siteSHA256===x.siteSHA256));
  }
  assert.match(obligation(o,'74.owner66_fingerprint','function').source,/SELECT acl/);
  assert.match(obligation(o,'78.predecessor77_fingerprint','effective-policy-boundary').source,/ordered_writer_definition/);
  assert.match(obligation(o,'78.predecessor77_fingerprint','function').source,/signature LIKE 'zasp_temporal77\.%'/);
  assert.deepEqual(o.obligations.filter(x=>x.family==='77.domain67_fingerprint'&&x.type==='predecessor').map(x=>x.targets[0]),['zasp_ordered_public62.fingerprint()','zasp_temporal65.fingerprint()','zasp_temporal66.fingerprint()']);
});

test('mutated/rehashed selected sources, definition, full frames, absent/duplicate/overload refuse',()=>{
  const selected=id('72.retained_execution_fingerprint');
  const changes=[c=>c.nodes=c.nodes.filter(n=>n.identity!==selected),c=>c.nodes.push({...c.nodes.find(n=>n.identity===selected)}),c=>c.nodes.push({...c.nodes.find(n=>n.identity===selected),identity:selected.replace('()','(text)')}),c=>{const n=c.nodes.find(n=>n.identity===selected);n.source=n.source.replace("LIKE 'zasp_execution_%'","LIKE '%'");n.sourceSHA256=sha(n.source);},c=>{const n=c.nodes.find(n=>n.identity===selected);n.definition+=' ';n.definitionSHA256=sha(n.definition);},...Object.entries({owner:'foreign',acl:null,config:[],security_definer:false,language:'plpgsql',volatility:'v',parallel:'s',strict:true,leakproof:true,cost:1,rows:1,result:'boolean',arguments:'x text'}).map(([k,v])=>c=>{c.nodes.find(n=>n.identity===selected)[k]=v;})];
  for(const change of changes){const c=structuredClone(contract);change(c);assert.throws(()=>lowerOrderedTemporalCatalog(c),/temporal source/);}
  assert.throws(()=>lowerOrderedTemporalCatalog(null),/temporal source/);
});

test('unrelated base67 is untouched; output is deterministic without input mutation',()=>{
  const before=JSON.stringify(contract),a=lower();assert.equal(a.rules.length,92);
  const c=structuredClone(contract);c.nodes.find(n=>n.identity==='zasp_temporal77.base67_fingerprint()').source='unrelated';assert.deepEqual(a,lowerOrderedTemporalCatalog(c));
  assert.deepEqual(a,lowerOrderedTemporalCatalog({...contract,nodes:[...contract.nodes].reverse()}));assert.equal(JSON.stringify(contract),before);
});
