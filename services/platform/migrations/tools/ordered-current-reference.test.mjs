import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import * as reference from './ordered-current-reference.mjs';
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const contractRaw=fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/supplementary-query-contract2.json',import.meta.url));
const contract=JSON.parse(contractRaw);
const key=(rule,identity)=>JSON.stringify([rule,identity]);
// Explicit synthetic boundary fixture, never emitted as reference expectations.
const rows=[{kind:'fixed_runtime_profile',identity:key('role-profile:current-profile',JSON.stringify(['zasp_authorization80.runtime_profile',true])),fact:{singleton:true,name:'canonical61-temporal78-authorization79-80-v1'}},...['executor','compensation','accounting'].map(name=>({kind:'role',identity:key('role-profile:native-roles','zasp_temporal_'+name),fact:{login:false,superuser:false,create_db:false,create_role:false,replication:false,bypass_rls:false}}))];
const sample={format:'ordered-current-supplementary-reference-v1',querySHA256:contract.sqlSHA256,contractSHA256:sha(contractRaw),rulesSHA256:contract.rulesSHA256,sitesSHA256:contract.sitesSHA256,compilerArtifactSHA256:contract.compilerArtifactSHA256,compilerChecksum:contract.compilerChecksum,compiledSourceSHA256:contract.compiledSourceSHA256,catalog1FileSHA256:contract.catalog1FileSHA256,sourceContractSHA256:contract.sourceContractSHA256,variant:'A',sessionUser:'zasp_test',role:'zasp_discovery_authority',searchPath:['pg_catalog'],timeZone:'UTC',postgres:'synthetic PostgreSQL build',serverVersionNum:'180000',pgcrypto:'1.4',readOnly:true,rolledBack:true,frameRestored:true,rows};
const bytes=value=>Buffer.from(JSON.stringify(value)+'\n');
const pins=raw=>({referenceFileSHA256:sha(raw),contractRaw,variant:'A',sessionUser:'zasp_test'});
test('supplement ingestion binds independently approved file and57query provenance',()=>{
  assert.equal(typeof reference.admitOrderedSupplementaryReference,'function');
  const raw=bytes(sample),pinned=pins(raw);
  const accepted=reference.admitOrderedSupplementaryReference(raw,pinned);
  assert.equal(accepted.installable,false);assert.deepEqual(accepted.facts,reference.admitOrderedSupplementaryReference(raw,pinned).facts);
  for(const mutation of [s=>s.rows.pop(),s=>s.rows.push(s.rows[0]),s=>s.role='executor',s=>s.searchPath.push('public'),s=>s.querySHA256='0'.repeat(64),s=>s.rolledBack=false]){
    const changed=structuredClone(sample);mutation(changed);
    assert.throws(()=>reference.admitOrderedSupplementaryReference(bytes(changed),pinned),/reference file/);
  }
});
test('typed rules preserve NULLs and reject unknown fields, duplicate keys and broken fixed aggregates',()=>{
  assert.equal(typeof reference.admitOrderedSupplementaryReference,'function');
  for(const mutation of [s=>s.rows[0].fact.name=null,s=>s.rows[0].fact.extra=true,s=>s.rows.push(s.rows[0]),s=>s.frameRestored=false,s=>s.rows[1].fact.login=true,s=>s.rows[1].identity=key('unknown','role'),s=>s.serverVersionNum=180000,s=>s.rows[0].identity=key('role-profile:current-profile','wrong-table')]){
    const changed=structuredClone(sample);mutation(changed);const raw=bytes(changed);
    assert.throws(()=>reference.admitOrderedSupplementaryReference(raw,pins(raw)));
  }
  const extra=structuredClone(sample),rule=contract.rules.find(r=>r.kind==='policy_view');
  extra.rows.push({kind:rule.kind,identity:key(rule.id,'synthetic-policy'),fact:Object.fromEntries(rule.fields.map(f=>[f,null]))});
  const raw=bytes(extra);assert.ok(reference.admitOrderedSupplementaryReference(raw,pins(raw)).facts.some(r=>r.kind==='policy_view'&&Object.values(r.fact).every(v=>v===null)));
  const duplicate=Buffer.from(JSON.stringify(sample).replace('"variant":"A"','"variant":"A","variant":"A"')+'\n');
  assert.throws(()=>reference.admitOrderedSupplementaryReference(duplicate,pins(duplicate)),/duplicate JSON key/);
});
test('publisher framing accepts maximum JSON payload plus LF and rejects trailing whitespace',()=>{
  const maximumSample=structuredClone(sample);
  maximumSample.postgres+='x'.repeat(16777216-Buffer.byteLength(JSON.stringify(maximumSample)));
  const maximum=bytes(maximumSample);
  assert.equal(maximum.length,16777217);
  assert.doesNotThrow(()=>reference.admitOrderedSupplementaryReference(maximum,pins(maximum)));
  const noNewline=Buffer.from(maximum);noNewline[noNewline.length-1]=32;
  assert.throws(()=>reference.admitOrderedSupplementaryReference(noNewline,pins(noNewline)),/publisher framing/);
  for(const suffix of ['\n\n',' \n']){
    const malformed=Buffer.from(JSON.stringify(sample)+suffix);
    assert.throws(()=>reference.admitOrderedSupplementaryReference(malformed,pins(malformed)),/publisher framing/);
  }
});
