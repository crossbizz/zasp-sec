import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedProductCatalog} from './ordered-current-product-selectors.mjs';
import {projectOrderedFacts} from './ordered-current-catalog.mjs';

const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const bytes=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(bytes),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(bytes);
const id=family=>`public.zasp_production_${family}_live_fingerprint()`;
const lower=()=>lowerOrderedProductCatalog(contract);
const rule=(o,f,b)=>o.rules.find(r=>r.id===`product:${f}:${b}`);

test('nine families lower only their 22 static branches and all outgoing obligations',()=>{
  const o=lower();
  assert.equal(o.rules.length,22);
  assert.deepEqual(o.obligations.filter(x=>x.type==='predecessor').map(x=>[x.family,x.target]),[
    ['approval_notification',id('home_attention')],['home_attention','public.zasp_policy_deployment_execution_live_fingerprint()'],
    ['integration_setup',id('workflow_compatibility')],['integration_webhook',id('integration_setup')],
    ['reconciliation_lane_plan','public.zasp_production_runtime_enrollment_pairing_live_fingerprint()'],
    ['red_team_artifacts',id('red_team_invocation')],['red_team_invocation',id('red_team_safety')],
    ['red_team_safety','public.zasp_production_runtime_queue_replay_live_fingerprint()'],['workflow_compatibility',id('approval_notification')]
  ]);
  assert.equal(o.obligations.filter(x=>x.type==='digest-semantics').length,9);
});

test('approval relation selection includes r/i only and exact public name; routine selection is not a wildcard',()=>{
  const o=lower(),r=rule(o,'approval_notification','table');
  assert.deepEqual(r,{id:'product:approval_notification:table',kind:'relation',namespaces:[],identities:[],
    selector:{all:[{field:'namespace',equals:'public'},{field:'name',equals:'zasp_security_agent_approval_notifications'},{any:[{field:'relation_kind',equals:'r'},{field:'relation_kind',equals:'i'}]}]},
    fields:['name','owner','row_security','forced_row_security','acl_text_or_empty']});
  const fact={name:'zasp_security_agent_approval_notifications',owner:'owner',row_security:true,forced_row_security:true,acl_text_or_empty:''};
  const rows=[['public','r'],['foreign','r'],['public','v'],['public','i']].map(([namespace,relation_kind],i)=>({kind:'relation',identity:'object'+i,namespace,name:fact.name,relation_kind,fact}));
  assert.equal(projectOrderedFacts([r],rows).length,2);
  const h=rule(o,'home_attention','function');
  assert.deepEqual(h.selector,{all:[{field:'namespace',equals:'public'},{any:[{field:'name',equals:'zasp_inventory_home_summary'},{field:'name',equals:'zasp_inventory_home_summary_v29'}]}]});
  const routine={name:'zasp_inventory_home_summary',identity_arguments:'',owner:'owner',security_definer:false,config_text_or_empty:'',acl_text_or_empty:'',definition:'body'};
  assert.equal(projectOrderedFacts([h],[{kind:'routine',identity:'public.good()',namespace:'public',name:routine.name,fact:routine},{kind:'routine',identity:'public.sibling()',namespace:'public',name:routine.name+'_extra',fact:routine}]).length,1);
  assert.ok(o.rules.every(x=>!JSON.stringify(x.selector).includes('startsWith')&&!JSON.stringify(x.selector).includes('"like"')));
});

test('policy encodings remain different, with original command omission and NULL rules',()=>{
  const o=lower();
  assert.deepEqual(rule(o,'approval_notification','policy'),{id:'product:approval_notification:policy',kind:'policy',namespaces:[],identities:[],selector:{field:'relation',equals:'public.zasp_security_agent_approval_notifications'},fields:['name','permissive','roles_csv_public_sorted','using_text_or_empty','check_text_or_empty']});
  assert.deepEqual(rule(o,'integration_webhook','policy')?.fields,['name','command','permissive','roles_named_array_text','using','check']);
  assert.equal(rule(o,'integration_webhook','policy')?.kind,'policy');
  for(const family of ['approval_notification','integration_webhook'])assert.ok(o.unsupported.some(x=>x.family===family&&x.branch==='policy'&&x.source.includes('FROM pg_policy')));
});

test('physical ordinal columns, original deparse modes and exact trigger restriction are not broadened',()=>{
  const o=lower();
  assert.deepEqual(rule(o,'approval_notification','column')?.fields,['relation_name','position','name','type','not_null','default_text_or_empty']);
  assert.equal(rule(o,'approval_notification','column')?.kind,'column');
  assert.deepEqual(rule(o,'integration_webhook','column')?.fields,['position','name','type','not_null','default_text_or_empty']);
  assert.equal(rule(o,'red_team_artifacts','column')?.kind,'column_name');
  assert.deepEqual(rule(o,'red_team_artifacts','column')?.fields,['name','type','not_null']);
  assert.deepEqual(rule(o,'approval_notification','constraint')?.fields,['name','constraint_type','validated','definition_pretty']);
  assert.deepEqual(rule(o,'integration_webhook','constraint')?.fields,['name','definition_pretty']);
  assert.deepEqual(rule(o,'red_team_artifacts','constraint')?.fields,['name','definition','validated']);
  assert.deepEqual(rule(o,'approval_notification','index')?.fields,['name','definition']);
  assert.deepEqual(rule(o,'integration_webhook','index')?.fields,['definition']);
  assert.deepEqual(rule(o,'approval_notification','trigger'),{id:'product:approval_notification:trigger',kind:'trigger',namespaces:[],identities:[],selector:{all:[{field:'relation',equals:'public.zasp_security_agent_approvals'},{field:'name',equals:'zasp_security_agent_enqueue_approval_notification_v30'}]},predicate:'user-triggers',fields:['name','definition_pretty']});
});

test('setup prior remains exact original framed scalar metadata, not a captured constant or collector query',()=>{
  const o=lower(),x=o.obligations.find(x=>x.type==='live-metadata-scalar');
  assert.equal(x?.family,'integration_setup');
  assert.equal(x?.relation,'public.zasp_schema_metadata');
  assert.equal(x?.key,'production_security_agent_attack_path_fingerprint');
  assert.ok(x.source.includes("(SELECT value FROM zasp_schema_metadata WHERE key='production_security_agent_attack_path_fingerprint')"));
  assert.match(x.required,/multiple-row/);
  assert.ok(o.unsupported.some(x=>x.type==='live-metadata-scalar'));
  assert.ok(o.rules.every(x=>!JSON.stringify(x).includes('schema_metadata')));
});

test('all routine addition universes and fixed-regclass error obligations are exact',()=>{
  const o=lower(),names={
    approval_notification:['zasp_security_agent_enqueue_approval_notification','zasp_security_agent_claim_approval_notification','zasp_security_agent_complete_approval_notification','zasp_security_agent_fail_approval_notification','zasp_production_approval_notification_security_ready','zasp_production_approval_notification_readiness','zasp_production_home_attention_readiness'],
    home_attention:['zasp_inventory_home_summary','zasp_inventory_home_summary_v29'],
    integration_setup:['zasp_execution_integration_setup_status','zasp_production_integration_setup_security_ready'],
    integration_webhook:['zasp_integration_webhook_test_public','zasp_integration_webhook_test_reserve','zasp_integration_webhook_test_complete','zasp_integration_webhook_test_status','zasp_production_integration_webhook_security_ready'],
    reconciliation_lane_plan:['zasp_connector_claim_reconciliation','zasp_production_reconciliation_lane_plan_readiness','zasp_production_reconciliation_lane_plan_security_ready'],
    red_team_artifacts:['zasp_production_red_team_artifacts_readiness','zasp_production_red_team_artifacts_security_ready','zasp_red_team_valid_input_artifact','zasp_red_team_finish_run','zasp_red_team_finish_run_v38','zasp_red_team_get_run'],
    red_team_invocation:['zasp_production_red_team_invocation_security_ready'],
    red_team_safety:['zasp_production_red_team_safety_security_ready'],
    workflow_compatibility:['zasp_workflow_mutate','zasp_risk_mutate']
  };
  for(const [f,expected] of Object.entries(names))assert.deepEqual(rule(o,f,'function').selector,{all:[{field:'namespace',equals:'public'},expected.length===1?{field:'name',equals:expected[0]}:{any:expected.map(name=>({field:'name',equals:name}))}]});
  const resolution=o.obligations.filter(x=>x.type==='relation-resolution');
  assert.equal(resolution.length,11);
  for(const x of resolution){assert.match(x.required,/absent relation raises/);assert.ok(o.unsupported.some(u=>u.siteSHA256===x.siteSHA256));}
  assert.deepEqual(rule(o,'integration_webhook','table').selector,{field:'identity',equals:'public.zasp_integration_webhook_tests'});
});

test('sites cover every selected original byte contiguously including prior, compatibility and digest shell',()=>{
  const o=lower(),counts={approval_notification:9,home_attention:3,integration_setup:4,integration_webhook:8,reconciliation_lane_plan:3,red_team_artifacts:5,red_team_invocation:3,red_team_safety:3,workflow_compatibility:3};
  assert.equal(o.sites.length,41);
  for(const [family,count] of Object.entries(counts)){
    const n=contract.nodes.find(x=>x.identity===id(family)),sites=o.sites.filter(x=>x.family===family);assert.equal(sites.length,count);
    let end=0;for(const s of sites){assert.equal(s.start,end);assert.equal(s.text,Buffer.from(n.source).subarray(s.start,s.end).toString());assert.equal(s.sha256,sha(s.text));assert.equal(s.definitionSHA256,n.definitionSHA256);assert.equal(s.owner,'zasp_discovery_authority');assert.deepEqual(s.config,['search_path=pg_catalog, public']);end=s.end;}assert.equal(end,Buffer.byteLength(n.source));
  }
});

test('mutated/rehashed body, definition, frame, omitted/duplicate/overloaded selected source all refuse',()=>{
  const selected=id('approval_notification');
  const mutations=[c=>c.nodes=c.nodes.filter(x=>x.identity!==selected),c=>c.nodes.push({...c.nodes.find(x=>x.identity===selected)}),c=>c.nodes.push({...c.nodes.find(x=>x.identity===selected),identity:selected.replace('()','(text)')}),
    c=>{const n=c.nodes.find(x=>x.identity===selected);n.source=n.source.replace("class.relname='zasp_security_agent_approval_notifications'","class.relname LIKE 'zasp_security_agent_%'");n.sourceSHA256=sha(n.source);},
    c=>{const n=c.nodes.find(x=>x.identity===selected);n.definition+='\n';n.definitionSHA256=sha(n.definition);},
    ...[['owner','foreign'],['acl',null],['security_definer',true],['config',['search_path=public']],['parallel','s'],['strict',true],['leakproof',true],['language','plpgsql'],['volatility','v'],['result','boolean'],['arguments','x text'],['cost',1],['rows',1]].map(([k,v])=>c=>{c.nodes.find(x=>x.identity===selected)[k]=v;})];
  for(const mutate of mutations){const c=structuredClone(contract);mutate(c);assert.throws(()=>lowerOrderedProductCatalog(c),/product source/);}
  assert.throws(()=>lowerOrderedProductCatalog(null),/product source/);
});

test('deterministic family output leaves full input untouched and never absorbs unrelated nodes',()=>{
  const before=JSON.stringify(contract),a=lower();assert.equal(a.rules.length,22);
  assert.deepEqual(a,lowerOrderedProductCatalog({...contract,nodes:[...contract.nodes].reverse()}));
  const c=structuredClone(contract);c.nodes.find(n=>n.identity==='public.zasp_inventory_live_fingerprint()').source='unrelated';assert.deepEqual(a,lowerOrderedProductCatalog(c));assert.equal(JSON.stringify(contract),before);
});
