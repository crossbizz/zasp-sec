import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedRuntimeCatalog} from './ordered-current-runtime-selectors.mjs';

const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const raw=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(raw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(raw);
const signature=n=>`public.zasp_production_runtime_${n}_live_fingerprint()`;
const lower=()=>lowerOrderedRuntimeCatalog(contract);
const rule=(output,name,branch)=>output.rules.find(r=>r.id===`runtime:${name}:${branch}`);

test('reads and search preserve exact relation selectors and distinct predecessor obligations',()=>{
  const out=lower();
  assert.deepEqual(rule(out,'session_reads','table'),{
    id:'runtime:session_reads:table',kind:'relation',namespaces:[],identities:['public.zasp_runtime_session_summaries'],
    fields:['name','owner','row_security','forced_row_security','acl_text_or_empty']
  });
  assert.deepEqual(rule(out,'session_search','table')?.identities,['public.zasp_runtime_session_search_outbox']);
  assert.deepEqual(out.obligations.filter(o=>o.type==='predecessor'&&['session_reads','session_search'].includes(o.family)).map(o=>[o.type,o.target]),[
    ['predecessor','public.zasp_production_runtime_sessions_live_fingerprint()'],
    ['predecessor','public.zasp_production_runtime_session_reads_live_fingerprint()']
  ]);
});

test('source-owned search LIKE retains underscore wildcard semantics rather than a literal prefix',()=>{
  const out=lower();
  assert.deepEqual(rule(out,'session_search','function')?.selector,{
    all:[{field:'namespace',equals:'public'},{any:[
      {field:'name',like:'zasp_runtime_session_search_%'},
      {field:'name',equals:'zasp_production_runtime_session_search_readiness'},
      {field:'name',equals:'zasp_production_runtime_session_search_security_ready'}
    ]}]
  });
  assert.deepEqual(rule(out,'session_search','function')?.fields,['name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition']);
});

test('view policy/index fields preserve source view semantics; trigger filters remain table-specific',()=>{
  const out=lower();
  assert.equal(rule(out,'session_reads','policy')?.kind,'policy_view');
  assert.deepEqual(rule(out,'session_reads','policy')?.fields,['name','roles_text','command','using','check']);
  assert.equal(rule(out,'session_search','index')?.kind,'index_view');
  assert.deepEqual(rule(out,'session_search','index')?.fields,['name','definition']);
  assert.deepEqual(rule(out,'session_search','trigger'),{
    id:'runtime:session_search:trigger',kind:'trigger',namespaces:[],identities:[],
    selector:{field:'relation',equals:'public.zasp_runtime_session_projection_receipts'},
    predicate:'user-triggers',fields:['name','enabled','definition']
  });
});

test('every exact family body is accounted by contiguous byte sites including wrappers and digest shell',()=>{
  const out=lower();
  const expected={acceptance:3,candidate_authority:9,correlation_routing:4,enrollment_pairing:8,precision:1,queue_replay:3,session_evidence:3,session_query:3,session_reads:9,session_search:9,sessions:1};
  assert.deepEqual(Object.fromEntries(Object.entries(expected).map(([family])=>[family,out.sites.filter(s=>s.family===family).length])),expected);
  for(const family of Object.keys(expected)) {
    const node=contract.nodes.find(n=>n.identity===signature(family));
    const sites=out.sites.filter(s=>s.family===family);
    let end=0;
    for(const site of sites){
      assert.equal(site.start,end);assert.equal(site.text,Buffer.from(node.source).subarray(site.start,site.end).toString());
      assert.equal(site.sha256,sha(site.text));assert.equal(site.sourceSHA256,node.sourceSHA256);
      assert.equal(site.owner,'zasp_discovery_authority');assert.deepEqual(site.config,['search_path=pg_catalog, public']);
      end=site.end;
    }
    assert.equal(end,Buffer.byteLength(node.source));
  }
});

test('changed selectors, omitted branches, metadata mismatch, extra overloads and missing identities refuse generation',()=>{
  const identity=signature('session_reads');
  for(const mutate of [
    c=>c.nodes=c.nodes.filter(n=>n.identity!==identity),
    c=>c.nodes.push({...c.nodes.find(n=>n.identity===identity)}),
    c=>c.nodes.push({...c.nodes.find(n=>n.identity===identity),identity:identity.replace('()','(text)')}),
    c=>{const n=c.nodes.find(n=>n.identity===identity);n.source=n.source.replace('zasp_runtime_session_summaries','foreign_table');n.sourceSHA256=sha(n.source);},
    c=>{const n=c.nodes.find(n=>n.identity===identity);n.source=n.source.replace(/\n UNION ALL SELECT[^\n]+pg_indexes[^\n]+/,'');n.sourceSHA256=sha(n.source);},
    c=>{c.nodes.find(n=>n.identity===identity).owner='other';},
    c=>{c.nodes.find(n=>n.identity===identity).definition+='\n';}
  ]) {const copy=structuredClone(contract);mutate(copy);assert.throws(()=>lowerOrderedRuntimeCatalog(copy),/runtime source/);}
});

test('family lowering is deterministic and does not mutate pinned input',()=>{
  const before=JSON.stringify(contract), a=lower();
  assert.equal(a.rules.length>0,true);
  assert.deepEqual(a,lowerOrderedRuntimeCatalog({...contract,nodes:[...contract.nodes].reverse()}));
  assert.equal(JSON.stringify(contract),before);
});

test('global enrollment trigger and scoped correlation trigger do not acquire blanket namespace or internal filters',()=>{
  const out=lower();
  assert.deepEqual(rule(out,'enrollment_pairing','trigger'),{
    id:'runtime:enrollment_pairing:trigger',kind:'trigger',namespaces:[],identities:[],
    selector:{any:[{field:'name',equals:'zasp_runtime_sensor_pairings_immutable'},{field:'name',equals:'zasp_runtime_batch_domains_immutable'},{field:'name',equals:'zasp_runtime_batch_domain_insert'}]},
    predicate:'user-triggers',fields:['name','enabled','definition_pretty']
  });
  assert.deepEqual(rule(out,'correlation_routing','trigger'),{
    id:'runtime:correlation_routing:trigger',kind:'trigger',namespaces:[],identities:[],
    selector:{all:[{field:'relation',equals:'public.zasp_runtime_stage_work'},{field:'name',equals:'zasp_runtime_correlation_claim_version'}]},
    fields:['name','enabled','definition_pretty']
  });
});

test('exact column-name keys and global constraint universe are represented without physical-position substitution',()=>{
  const out=lower();
  assert.deepEqual(rule(out,'session_reads','column'),{
    id:'runtime:session_reads:column',kind:'column_name',namespaces:[],identities:[],
    selector:{field:'relation',equals:'public.zasp_runtime_session_summaries'},fields:['name','type','not_null']
  });
  assert.deepEqual(rule(out,'candidate_authority','column')?.fields,['relation','name','normalized_position','type','not_null','identity','generated','acl_text_or_empty','default_text_or_empty']);
  assert.deepEqual(rule(out,'enrollment_pairing','constraint'),{
    id:'runtime:enrollment_pairing:constraint',kind:'global_constraint',namespaces:[],identities:[],
    selector:{any:[{any:[{field:'relation',equals:'public.zasp_runtime_sensor_pairings'},{field:'relation',equals:'public.zasp_runtime_batch_domains'}]},{any:[{field:'name',equals:'zasp_sensor_kind_identity_v45'},{field:'name',equals:'zasp_runtime_batch_source_identity_v45'}]}]},
    fields:['relation','name','definition_pretty']
  });
});

test('missing reference descriptor and conditional obligations cannot silently become complete',()=>{
  const out=lower();
  assert.deepEqual(out.unsupported.filter(s=>s.branch==='conditional-wrapper').map(s=>s.family),['precision','sessions']);
  for(const [family,branch] of [['candidate_authority','column'],['enrollment_pairing','constraint'],['enrollment_pairing','column'],['session_reads','policy'],['session_search','policy']])assert.ok(out.unsupported.some(s=>s.family===family&&s.branch===branch));
  const precision=out.obligations.find(o=>o.family==='precision');
  assert.deepEqual(precision.targets,['zasp_temporal72.fingerprint()','zasp_temporal72.retained_precision_fingerprint()']);
  assert.ok(precision.source.includes("ELSE NULL END"));
  assert.ok(precision.source.includes("FROM zasp_temporal72.registration WHERE checksum='e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940'"));
});

test('all finite family predecessors and fact branches remain in the declared translation boundary',()=>{
  const out=lower();
  assert.equal(out.rules.length,33);
  assert.deepEqual(out.obligations.filter(o=>o.type==='predecessor').map(o=>[o.family,o.target]),[
    ['acceptance','public.zasp_production_runtime_candidate_authority_live_fingerprint()'],
    ['candidate_authority','public.zasp_production_reconciliation_lane_plan_live_fingerprint()'],
    ['correlation_routing','public.zasp_production_runtime_acceptance_live_fingerprint()'],
    ['enrollment_pairing','public.zasp_production_runtime_session_evidence_live_fingerprint()'],
    ['queue_replay','public.zasp_production_integration_webhook_live_fingerprint()'],
    ['session_evidence','public.zasp_production_runtime_session_query_live_fingerprint()'],
    ['session_query','public.zasp_production_runtime_session_search_live_fingerprint()'],
    ['session_reads','public.zasp_production_runtime_sessions_live_fingerprint()'],
    ['session_search','public.zasp_production_runtime_session_reads_live_fingerprint()']
  ]);
  assert.deepEqual(rule(out,'candidate_authority','table')?.fields,['name','owner','kind','row_security','forced_row_security','acl_text_or_empty','options_text_or_empty']);
  assert.deepEqual(rule(out,'candidate_authority','policy')?.fields,['relation_name','name','roles_text','permissive','command','using','check']);
  assert.deepEqual(rule(out,'enrollment_pairing','column')?.fields,['relation_name','name','data_type','is_nullable','default_text_or_empty']);
  assert.deepEqual(rule(out,'queue_replay','function')?.selector,{all:[{field:'namespace',equals:'public'},{any:[
    {field:'name',equals:'zasp_runtime_claim_delivery'},
    {field:'name',equals:'zasp_runtime_commit_reserved_batch'},
    {field:'name',equals:'zasp_production_runtime_queue_replay_security_ready'}
  ]}]});
});
