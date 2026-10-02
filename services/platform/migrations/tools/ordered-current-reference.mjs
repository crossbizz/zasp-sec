// Immutable independently captured supplement admission; never target learning.
import crypto from 'node:crypto';
import {canonicalOrderedJSON,normalizeOrderedFacts} from './build-ordered-current-integrity.mjs';
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const contractPin='6b8fc25c4d5d0a379735d686fe1d6cde8245663a47d346dbf8cf1c11dd33418f';
function strictJSON(raw){
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let offset=0;
  const whitespace=()=>{while(/[ \r\n\t]/.test(text[offset]??'x'))offset++;};
  const string=()=>{const start=offset++;let escaped=false;for(;offset<text.length;offset++){const c=text[offset];if(c==='"'&&!escaped){offset++;return JSON.parse(text.slice(start,offset));}if(c==='\\'&&!escaped)escaped=true;else escaped=false;}throw Error('unterminated JSON string');};
  const value=(depth=0)=>{
    if(depth>32)throw Error('JSON depth');whitespace();
    if(text[offset]==='"')return string();
    if(text[offset]==='{'){
      offset++;const object={},seen=new Set();whitespace();if(text[offset]==='}'){offset++;return object;}
      while(true){whitespace();if(text[offset]!=='"')throw Error('JSON object key');const key=string();if(seen.has(key))throw Error('duplicate JSON key');seen.add(key);whitespace();if(text[offset++]!==':')throw Error('JSON colon');Object.defineProperty(object,key,{value:value(depth+1),enumerable:true,writable:true,configurable:true});whitespace();const end=text[offset++];if(end==='}')return object;if(end!==',')throw Error('JSON object end');}
    }
    if(text[offset]==='['){offset++;const array=[];whitespace();if(text[offset]===']'){offset++;return array;}while(true){array.push(value(depth+1));whitespace();const end=text[offset++];if(end===']')return array;if(end!==',')throw Error('JSON array end');}}
    const token=text.slice(offset).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0];if(!token)throw Error('JSON value');offset+=token.length;return JSON.parse(token);
  };
  const decoded=value();whitespace();if(offset!==text.length)throw Error('JSON trailing bytes');return decoded;
}
const same=(a,b)=>canonicalOrderedJSON(a)===canonicalOrderedJSON(b);
export function admitOrderedSupplementaryReference(raw,pins){
  if(!Buffer.isBuffer(raw)||raw.length===0||raw.length>16777217||!pins||!/^[a-f0-9]{64}$/.test(pins.referenceFileSHA256)||sha(raw)!==pins.referenceFileSHA256)throw Error('reference file identity changed');
  if(raw.at(-2)!==125||raw.at(-1)!==10||raw.length-1>16777216)throw Error('reference publisher framing');
  if(!Buffer.isBuffer(pins.contractRaw)||sha(pins.contractRaw)!==contractPin)throw Error('query contract identity changed');
  const contract=strictJSON(pins.contractRaw),reference=strictJSON(raw);
  const keys='format querySHA256 contractSHA256 rulesSHA256 sitesSHA256 compilerArtifactSHA256 compilerChecksum compiledSourceSHA256 catalog1FileSHA256 sourceContractSHA256 variant sessionUser role searchPath timeZone postgres serverVersionNum pgcrypto readOnly rolledBack frameRestored rows'.split(' ').sort();
  if(!reference||!same(Object.keys(reference).sort(),keys))throw Error('reference envelope fields');
  const bindings={format:'ordered-current-supplementary-reference-v1',querySHA256:contract.sqlSHA256,contractSHA256:contractPin,rulesSHA256:contract.rulesSHA256,sitesSHA256:contract.sitesSHA256,compilerArtifactSHA256:contract.compilerArtifactSHA256,compilerChecksum:contract.compilerChecksum,compiledSourceSHA256:contract.compiledSourceSHA256,catalog1FileSHA256:contract.catalog1FileSHA256,sourceContractSHA256:contract.sourceContractSHA256,role:contract.requiredRole,searchPath:contract.requiredSearchPath,timeZone:contract.requiredTimeZone,readOnly:true,rolledBack:true,frameRestored:true};
  for(const [field,expected] of Object.entries(bindings))if(!same(reference[field],expected))throw Error('reference provenance '+field);
  if(!['A','B'].includes(pins.variant)||typeof pins.sessionUser!=='string'||!pins.sessionUser||reference.variant!==pins.variant||reference.sessionUser!==pins.sessionUser)throw Error('reference principal provenance');
  if(typeof reference.postgres!=='string'||!reference.postgres||typeof reference.serverVersionNum!=='string'||!/^\d{6}$/.test(reference.serverVersionNum)||typeof reference.pgcrypto!=='string'||!reference.pgcrypto)throw Error('reference build identity');
  if(!Array.isArray(reference.rows)||reference.rows.length>contract.maxRows)throw Error('reference row bound');
  const byRule=new Map(contract.rules.map(r=>[r.id,r])),ruleCounts={},kindCounts={};
  for(const row of reference.rows){
    if(!row||typeof row.identity!=='string')throw Error('reference row identity');
    const key=strictJSON(Buffer.from(row.identity));
    if(!Array.isArray(key)||key.length!==2||key.some(k=>typeof k!=='string')||canonicalOrderedJSON(key)!==row.identity)throw Error('reference key encoding');
    const rule=byRule.get(key[0]);
    if(!rule||row.kind!==rule.kind||!row.fact||!same(Object.keys(row.fact).sort(),rule.fields.slice().sort()))throw Error('reference selected fields');
    ruleCounts[rule.id]=(ruleCounts[rule.id]??0)+1;kindCounts[row.kind]=(kindCounts[row.kind]??0)+1;
    if(ruleCounts[rule.id]>contract.ruleMaxRows[rule.id]||kindCounts[row.kind]>contract.categoryMaxRows[row.kind])throw Error('reference category bound');
  }
  const facts=normalizeOrderedFacts(reference.rows);
  // These exact source aggregates must be TRUE in an accepted reference. This
  // is reference sanity, not replacement of each original runtime call site.
  const profile=facts.filter(r=>r.kind==='fixed_runtime_profile');
  if(profile.length!==1||profile[0].identity!==canonicalOrderedJSON(['role-profile:current-profile',canonicalOrderedJSON(['zasp_authorization80.runtime_profile',true])])||profile[0].fact.singleton!==true||profile[0].fact.name!=='canonical61-temporal78-authorization79-80-v1')throw Error('reference fixed profile aggregate');
  const roles=facts.filter(r=>r.kind==='role'),names=['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'];
  if(roles.length!==3||roles.some(r=>!names.includes(JSON.parse(r.identity)[1])||Object.values(r.fact).some(v=>v!==false)))throw Error('reference fixed role aggregate');
  const {rows,...provenance}=reference;
  return {installable:false,facts,referenceFileSHA256:pins.referenceFileSHA256,contractFileSHA256:contractPin,provenance};
}
