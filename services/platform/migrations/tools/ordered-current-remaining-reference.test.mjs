import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {admitOrderedRemainingReference, checkOrderedRemainingReferenceEnvelope} from './ordered-current-remaining-reference.mjs';

const p7=new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/',import.meta.url);
const packet='/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-supplement3-qualified-dgdNyg/';
const relative='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
if(!fs.existsSync(packet+relative+'ordered-current-supplementary-query-contract3.json')||!fs.existsSync(packet+'snapshot-manifest.json')){
 test('external supplementary capture unavailable without retained packet inputs',{skip:'supplementary query contract3 capture is not present in this checkout'},()=>{});
}else{
const raw=fs.readFileSync(new URL('ordered-current-remaining-reference1.json',p7));
const inputs={contractRaw:fs.readFileSync(packet+relative+'ordered-current-supplementary-query-contract3.json'),manifestRaw:fs.readFileSync(packet+'snapshot-manifest.json')};
const contract=JSON.parse(inputs.contractRaw), original=JSON.parse(raw);
const encode=x=>Buffer.from(JSON.stringify(x)+'\n');
const changed=change=>{const value=structuredClone(original);change(value);return encode(value);};
const check=value=>checkOrderedRemainingReferenceEnvelope(value,inputs);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');

test('accepted native artifact is immutable and partitions all 2507 rows without promoting 445 raw inputs',()=>{
  assert.equal(sha(raw),'db00d660b9927cc4c5651bcffe3af576881e4d14afbd027e4bfc6abd328022d3');
  const result=admitOrderedRemainingReference(raw,inputs);
  assert.equal(result.installable,false);
  assert.equal(result.staticFacts.length,2062);
  assert.equal(result.rawTransformInputs.length,445);
  const rawIds=new Set(contract.rawInputRuleIds);
  assert.equal(rawIds.size,16);
  assert.ok(result.staticFacts.every(row=>!rawIds.has(JSON.parse(row.identity)[0])));
  assert.ok(result.rawTransformInputs.every(row=>rawIds.has(JSON.parse(row.identity)[0])));
  assert.deepEqual([...result.staticFacts,...result.rawTransformInputs].sort((a,b)=>a.identity.localeCompare(b.identity)),original.rows.slice().sort((a,b)=>a.identity.localeCompare(b.identity)));
  assert.equal(result.referenceFileSHA256,sha(raw));
  assert.equal(result.provenance.packetManifestSHA256,sha(inputs.manifestRaw));
  assert.equal(Object.hasOwn(result,'facts'),false);
});

test('caller cannot repin a changed file, contract, manifest, or add a target-selected principal',()=>{
  const altered=changed(x=>{x.rows[0].fact[Object.keys(x.rows[0].fact)[0]]=null;});
  assert.throws(()=>admitOrderedRemainingReference(altered,inputs),/identity/);
  for(const extra of [{referenceFileSHA256:sha(altered)},{variant:'B'},{sessionUser:'target'},{sourcePins:{}}])assert.throws(()=>admitOrderedRemainingReference(altered,{...inputs,...extra}));
  for(const key of ['contractRaw','manifestRaw'])assert.throws(()=>admitOrderedRemainingReference(raw,{...inputs,[key]:Buffer.concat([inputs[key],Buffer.from(' ')] )}));
});

test('closed provenance, exact build/frame and intermediate disposition are required',()=>{
  const mutations={role:'owner',sessionUser:'other',variant:'B',readOnly:false,rolledBack:false,frameRestored:false,timeZone:'local',searchPath:['public'],postgres:'PostgreSQL other',serverVersionNum:'180004',pgcrypto:'other',status:'INSTALLABLE',rawInputDisposition:'release facts',packetManifestSHA256:'0'.repeat(64),extra:true};
  for(const [field,value] of Object.entries(mutations))assert.throws(()=>check(changed(x=>{x[field]=value;})),undefined,field);
  assert.throws(()=>check(changed(x=>{x.rawInputRuleIds.reverse();})));
  assert.throws(()=>check(changed(x=>{x.rawInputRuleIds.pop();})));
  assert.equal(check(raw),undefined,'shape validation conveys no facts or admission token');
});

test('strict JSON refuses duplicate decoded keys, invalid UTF8, depth, numeric spelling and nonpublisher framing',()=>{
  const small={...original,rows:[]}, valid=encode(small);
  for(const suffix of ['', '\n\n',' '])assert.throws(()=>check(Buffer.from(JSON.stringify(small)+suffix)));
  assert.throws(()=>check(Buffer.from(JSON.stringify(small).replace('"rows":[]','"rows":[],"ro\\u0077s":[]')+'\n')),/duplicate/);
  assert.throws(()=>check(Buffer.concat([Buffer.from([0xff]),valid])));
  assert.throws(()=>check(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),valid])));
  assert.throws(()=>check(Buffer.from('{"x":'+ '['.repeat(34)+'0'+']'.repeat(34)+'}\n')),/depth/);
  for(const number of ['-0','1e0','1e999','9007199254740992'])assert.throws(()=>check(Buffer.from('{"x":'+number+'}\n')),/numeric/);
});

test('all source-selected types remain nullable but wrong types and incomplete fields refuse',()=>{
  const representatives=new Map();
  for(const row of original.rows)for(const field of Object.keys(row.fact)){const type=contract.fieldTypes[row.kind][field];if(!representatives.has(type))representatives.set(type,{row,field});}
  for(const [type,{row,field}] of representatives){
    const value={...original,rows:[structuredClone(row)]};value.rows[0].fact[field]=null;
    assert.equal(check(encode(value)),undefined,type+' nullable');
    value.rows[0].fact[field]=type==='boolean'?'false':type==='string'?false:type==='integer'||type==='number'?'1':{};
    assert.throws(()=>check(encode(value)),/type/,type);
  }
  for(const mutate of [r=>delete r.fact[Object.keys(r.fact)[0]],r=>r.fact.extra=true,r=>r.extra=true,r=>r.kind='unknown',r=>r.identity=JSON.stringify(['unknown','object']),r=>r.identity='[ "x", "y" ]'])assert.throws(()=>check(changed(x=>mutate(x.rows[0]))));
});

test('duplicate identities and each finite per-rule cap refuse, without demanding observed counts',()=>{
  assert.equal(check(encode({...original,rows:[]})),undefined,'maxima are not required positive counts');
  assert.equal(new Set(original.rows.map(r=>JSON.parse(r.identity)[0])).size,62);
  assert.throws(()=>check(changed(x=>x.rows.push(x.rows[0]))),/duplicate/);
  for(const rule of contract.rules){
    const row={kind:rule.kind,identity:'',fact:Object.fromEntries(rule.fields.map(field=>[field,null]))};
    const rows=Array.from({length:contract.ruleMaxRows[rule.id]+1},(_,i)=>({...row,identity:JSON.stringify([rule.id,'object-'+i])}));
    assert.throws(()=>check(encode({...original,rows})),/bound/,rule.id);
  }
  const row=original.rows[0];assert.throws(()=>check(encode({...original,rows:Array.from({length:9624},(_,i)=>({...row,identity:JSON.stringify([JSON.parse(row.identity)[0],String(i)])}))})),/bound/);
  assert.throws(()=>check(Buffer.alloc(16777218,32)),/bound/);
});
}
