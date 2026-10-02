import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as intake from './ordered-current-consolidated-reference.mjs';

const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const encode=o=>Buffer.from(wire(o)+'\n');
function wire(o){if(Array.isArray(o))return '['+o.map(wire).join(',')+']';if(o&&typeof o==='object')return '{'+Object.keys(o).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k=>wire(k)+':'+wire(o[k])).join(',')+'}';return JSON.stringify(o).replaceAll('\u2028','\\u2028').replaceAll('\u2029','\\u2029');}
const pin='a'.repeat(64);
function fixture(){
 const phases=['demand','keys','original','resolution','witness'].map(id=>({id,searchPath:id==='keys'?'pg_catalog':'pg_catalog, public',timeZone:'UTC',sqlSHA256:pin,ruleIds:id==='original'?['membership']:[]}));
 const contract={format:'ordered-current-complete-capture-contract-v1',status:'REFERENCE-CAPTURE-ONLY',installable:false,captureReady:true,sourceFrameVersion:1,compilerArtifactSHA256:pin,compilerChecksum:pin,compiledSourceSHA256:pin,sourceContractSHA256:pin,closureSHA256:pin,catalog1FileSHA256:pin,requiredPostgres:'PostgreSQL 18.3 test build',requiredServerVersionNum:'180003',pgcrypto:'1.4',variant:'A',sessionUser:'zasp_test',requiredRole:'zasp_discovery_authority',requiredTimeZone:'UTC',maxRows:10000,maxBytes:16777216,phases,rules:{membership:{kind:'membership',section:'rawInputs',phase:'original',fields:['granted_role','member_role','admin_option'],fieldTypes:{granted_role:'text',member_role:'text',admin_option:'boolean'},sourceMaxRows:null,refusalMaxRows:10000,bag:true,rosterRuleId:null,demandRuleId:null}},reusedEvidence:[],sourcePins:{'source.mjs':pin}};
 const contractRaw=encode(contract),manifestRaw=encode({format:1,source:'offline-control',files:{'services/platform/migrations/ordered_current/consolidated-capture-contract.json':sha(contractRaw),'source.mjs':pin}});
 const row={ruleId:'membership',identity:'["worker","authority",false]',multiplicity:2,fact:{granted_role:'worker',member_role:'authority',admin_option:false}};
 const envelope={format:'ordered-current-complete-reference-v1',status:'REFERENCE-CAPTURE-ONLY',installable:false,sourceFrameVersion:1,packetManifestSHA256:sha(manifestRaw),contractSHA256:sha(contractRaw),closureSHA256:pin,compilerArtifactSHA256:pin,compilerChecksum:pin,compiledSourceSHA256:pin,sourceContractSHA256:pin,catalog1FileSHA256:pin,sourcePins:{'source.mjs':pin},variant:'A',sessionUser:'zasp_test',role:'zasp_discovery_authority',timeZone:'UTC',postgres:'PostgreSQL 18.3 test build',serverVersionNum:'180003',pgcrypto:'1.4',readOnly:true,preAdmission:true,postAdmission:true,rolledBack:true,frameRestored:true,phases:phases.map(p=>({id:p.id,searchPath:p.searchPath,timeZone:p.timeZone,sqlSHA256:p.sqlSHA256,rowCount:p.id==='original'?1:0,expandedRows:p.id==='original'?2:0,streamBytes:p.id==='original'?200:0})),counts:{streamRows:1,expandedRows:2,streamBytes:200,demandRows:0,rosterRows:0,ruleRows:{membership:2}},rawInputs:[row],normalizationObservations:[],resolutions:[],witnesses:[],reusedEvidence:[]};
 return {contract,contractRaw,manifestRaw,envelope};
}
function repin(f){f.contractRaw=encode(f.contract);const m=JSON.parse(f.manifestRaw);m.files['services/platform/migrations/ordered_current/consolidated-capture-contract.json']=sha(f.contractRaw);f.manifestRaw=encode(m);f.envelope.contractSHA256=sha(f.contractRaw);f.envelope.packetManifestSHA256=sha(f.manifestRaw);}
function linkedFixture(){
 const f=fixture(),c=f.contract,e=f.envelope;
 c.rules={demand:{kind:'routine',section:'demand',phase:'demand',fields:[],fieldTypes:{},sourceMaxRows:null,refusalMaxRows:10000,bag:false,rosterRuleId:null,demandRuleId:null},keys:{kind:'routine',section:'roster',phase:'keys',fields:[],fieldTypes:{},sourceMaxRows:null,refusalMaxRows:10000,bag:false,rosterRuleId:null,demandRuleId:'demand'},original:{kind:'routine',section:'rawInputs',phase:'original',fields:['definition'],fieldTypes:{definition:'text'},sourceMaxRows:null,refusalMaxRows:10000,bag:false,rosterRuleId:'keys',demandRuleId:null}};
 c.phases.forEach(p=>p.ruleIds=['demand','keys','original'].includes(p.id)?[p.id]:[]);
 e.phases.forEach(p=>{const active=['demand','keys','original'].includes(p.id);p.rowCount=active?1:0;p.expandedRows=active?1:0;p.streamBytes=active?100:0;});
 e.counts={streamRows:3,expandedRows:3,streamBytes:300,demandRows:1,rosterRows:1,ruleRows:{demand:1,keys:1,original:1}};
 e.rawInputs=[{ruleId:'original',identity:'public.fixed()',multiplicity:1,fact:{definition:'SELECT 1'}}];repin(f);return f;
}

// Missing lifecycle evidence or relaxed shape/count checks must break these
// controls. Expected role tuples/counts are handwritten, not derived by intake.
test('validation accepts typed bag evidence without granting file admission',()=>{
 const f=fixture();assert.equal(intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f),undefined);
 assert.throws(()=>intake.admitOrderedConsolidatedReference(encode(f.envelope),f),/not accepted|closed/);
});
test('published demand-key-original evidence retains complete counts but no transient handles',()=>{
 const f=linkedFixture();assert.equal(intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f),undefined);
 for(const mutate of [f=>f.envelope.counts.demandRows=0,f=>f.envelope.counts.ruleRows.keys=0,f=>f.contract.rules.original.rosterRuleId=null,f=>f.contract.rules.keys.demandRuleId=null,f=>f.envelope.rawInputs[0].handle='pg_proc:123:0']){
  const bad=linkedFixture();mutate(bad);repin(bad);assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(bad.envelope),bad));
 }
});
test('validation refuses missing cleanup, provenance, empty phase and type evidence',()=>{
 for(const mutate of [e=>e.rolledBack=false,e=>e.preAdmission=false,e=>e.postAdmission=false,e=>e.frameRestored=false,e=>e.postgres='different',e=>e.sourcePins['source.mjs']='b'.repeat(64),e=>e.phases.pop(),e=>e.phases[3]=e.phases[0],e=>e.phases[1].searchPath='public',e=>e.rawInputs[0].fact.admin_option='false',e=>e.rawInputs[0].fact.extra=1,e=>e.rawInputs[0].handle='pg_proc:123:0',e=>e.counts.ruleRows.membership=1,e=>e.rawInputs[0].multiplicity=0,e=>e.rawInputs.push(structuredClone(e.rawInputs[0]))]){
  const f=fixture();mutate(f.envelope);assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f));
 }
});
test('expanded bag counts and final bytes cannot evade global refusal ceilings',()=>{
 const f=fixture();f.envelope.rawInputs[0].multiplicity=10001;f.envelope.counts.expandedRows=10001;f.envelope.counts.ruleRows.membership=10001;f.envelope.phases[2].expandedRows=10001;
 assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f),/ceiling|bound|count/);
 const g=fixture();g.envelope.rawInputs[0].fact.granted_role='x'.repeat(16777216);assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(g.envelope),g),/byte|bound|ceiling/);
});
test('raw JSON refuses duplicate keys, nonfinite values and malformed Unicode',()=>{
 const f=fixture(),raw=encode(f.envelope).toString();
 for(const value of [raw.replace('"installable":false','"installable":false,"installable":false'),raw.replace('"multiplicity":2','"multiplicity":1e999'),raw.replace('"granted_role":"worker"','"granted_role":"\\ud800"'),Buffer.concat([Buffer.from(raw.slice(0,-2)),Buffer.from([255]),Buffer.from('}\n')])])assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(Buffer.from(value),f));
});
test('witness data cannot masquerade as a structural row even with coherent counts',()=>{
 const f=fixture();f.envelope.witnesses=f.envelope.rawInputs;f.envelope.rawInputs=[];
 assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f),/section/);
});
test('an A contract cannot admit B or a fractional count rounded to a safe integer',()=>{
 const f=fixture();f.envelope.variant='B';f.envelope.sessionUser='zasp_e2e';assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f),/fixture|provenance/);
 const g=fixture();assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(Buffer.from(encode(g.envelope).toString().replace('"multiplicity":2','"multiplicity":2.00000000000000000001')),g),/count|integer/);
});
test('the publisher newline consumes the final byte budget',()=>{
 const f=fixture();const n=16777216-encode(f.envelope).length;f.envelope.rawInputs[0].fact.granted_role='worker'+'x'.repeat(n+1);assert.equal(encode(f.envelope).length,16777217);assert.throws(()=>intake.checkOrderedConsolidatedReferenceEnvelope(encode(f.envelope),f),/byte/);
});
test('shared wire vectors preserve numeric lexemes and UTF8 key order',()=>{
 const vectors=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/complete-capture-wire-vectors.json',import.meta.url)));
 function numericFixture(type){const f=fixture();f.contract.rules.membership.fieldTypes.granted_role=type;f.contractRaw=encode(f.contract);const m=JSON.parse(f.manifestRaw);m.files['services/platform/migrations/ordered_current/consolidated-capture-contract.json']=sha(f.contractRaw);f.manifestRaw=encode(m);f.envelope.contractSHA256=sha(f.contractRaw);f.envelope.packetManifestSHA256=sha(f.manifestRaw);return f;}
 function check(token,type='json'){const f=numericFixture(type);return intake.checkOrderedConsolidatedReferenceEnvelope(Buffer.from(encode(f.envelope).toString().replace('"granted_role":"worker"','"granted_role":'+token)),f);}
 for(const v of vectors.accepted){assert.equal(check(v.wire),undefined,v.name);if(v.input!==v.wire&&v.name.includes('key order'))assert.throws(()=>check(v.input),/order/);}
 for(const token of vectors.integerAccepted)assert.equal(check(token,'integer'),undefined,token);
 for(const token of vectors.integerRejected)assert.throws(()=>check(token,'integer'),/integer|type/,token);
 for(const token of vectors.rejected)assert.throws(()=>check(token));
});
