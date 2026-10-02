import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedRoleProfileCatalog as lower} from './ordered-current-role-profile.mjs';

const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const raw=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(raw),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(raw);

test('fixed profile retains every row and only original singleton/name fields',()=>{
  const out=lower(contract);
  assert.deepEqual(out.rules.find(r=>r.kind==='fixed_runtime_profile'),{
    id:'role-profile:current-profile',kind:'fixed_runtime_profile',namespaces:['zasp_authorization80'],identities:[],fields:['singleton','name']
  });
  assert.equal(out.obligations.filter(o=>o.type==='profile-aggregate').length,7);
  for(const o of out.obligations.filter(o=>o.type==='profile-aggregate')){
    assert.deepEqual(o.expression,{count:1,boolAnd:{all:[{field:'singleton',equals:true},{field:'name',equals:'canonical61-temporal78-authorization79-80-v1'}]}});
    assert.equal(o.preserveSQLNulls,true);
  }
  assert.ok(out.unsupported.some(o=>o.kind==='fixed_runtime_profile'));
});

test('native roles retain six flags, exact three-name universe, and separate membership obligation',()=>{
  const out=lower(contract);
  assert.deepEqual(out.rules.find(r=>r.kind==='role'),{
    id:'role-profile:native-roles',kind:'role',namespaces:[],identities:[],
    selector:{any:[{field:'name',equals:'zasp_temporal_executor'},{field:'name',equals:'zasp_temporal_compensation'},{field:'name',equals:'zasp_temporal_accounting'}]},
    fields:['login','superuser','create_db','create_role','replication','bypass_rls']
  });
  const obligations=out.obligations.filter(o=>o.type==='native-role-aggregate');
  assert.equal(obligations.length,4);
  for(const o of obligations){
    assert.equal(o.expression.count,3);
    assert.deepEqual(o.expression.boolAnd.notAny,['login','superuser','create_db','create_role','replication','bypass_rls']);
    assert.deepEqual(o.membership,{role:'zasp_temporal_accounting',members:['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'],operation:'not-exists',join:'or',missingRegrole:'error'});
  }
  assert.equal(out.rules.filter(r=>r.kind==='membership').length,0);
});

test('all eleven sites retain exact bytes and original source/frame provenance',()=>{
  const out=lower(contract);
  assert.equal(out.sites.length,11);
  assert.deepEqual(out.sites.map(s=>s.start),[74702,103533,105803,4350,5113,6160,7211,17469,21417,18327,2709]);
  for(const s of out.sites){
    const n=contract.nodes.find(n=>n.identity===s.identity);
    assert.equal(s.text,Buffer.from(n.source).subarray(s.start,s.end).toString());
    assert.equal(s.sha256,sha(s.text));
    assert.equal(s.sourceSHA256,n.sourceSHA256);
    assert.equal(s.definitionSHA256,n.definitionSHA256);
    assert.equal(s.frame.security_definer,n.security_definer);
    assert.equal(s.frame.acl,n.acl);
    assert.deepEqual(s.frame.config,n.config);
  }
});

test('source, definition, frame and annotation drift cannot silently narrow required checks',()=>{
  const mutations=[
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)').source+=' ';},
    c=>{const n=c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)');n.source+=' ';n.sourceSHA256=sha(n.source);},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)').definition+=' ';},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)').security_definer=false;},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal77.base67_fingerprint()').security_definer=true;},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)').acl=null;},
    c=>{c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)').config=['search_path=public'];},
    c=>{c.materializedObligations[0].structuralInvariantSpans.pop();},
    c=>{c.materializedObligations[0].structuralInvariantSpans[0].start++;},
    c=>{c.nodes.push(structuredClone(c.nodes.find(n=>n.identity==='zasp_temporal68.ready(text,text)')));},
    c=>{c.materializedObligations.push(structuredClone(c.materializedObligations[0]));}
  ];
  for(const mutate of mutations){const c=structuredClone(contract);mutate(c);assert.throws(()=>lower(c),/role.profile/);}
});

test('deterministic lowering leaves input intact and unrelated nodes outside the scope',()=>{
  const before=sha(JSON.stringify(contract)),out=lower(contract);
  assert.equal(out.rules.length,2);
  const c=structuredClone(contract);c.nodes.push({identity:'unrelated.f()'});
  assert.deepEqual(lower(c),out);
  assert.deepEqual(lower(contract),out);
  assert.equal(sha(JSON.stringify(contract)),before);
});
