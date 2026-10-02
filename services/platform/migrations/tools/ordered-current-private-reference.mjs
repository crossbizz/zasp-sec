// Build-time intake only. Accepted file and contract pins are fixed here;
// no caller can repin a different file or choose target-derived expectations.
import crypto from 'node:crypto';
import {canonicalOrderedJSON,normalizeOrderedFacts} from './build-ordered-current-integrity.mjs';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const contractPin='59b78441d81c02cedb4e3106c8d573dcf1907c8548bd0e961e0fed464b29ee63';
const referencePin='15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607';
const snapshotPin='367bfda8b37641e79a6dc2284efdf547e28b3ce5e376ed7929ec358387c52208';
const nonroutineIds=['private-namespace','private-relation','private-column','private-constraint','private-index','private-policy','private-trigger','private-view','private-rewrite','private-type'];
const same=(a,b)=>canonicalOrderedJSON(a)===canonicalOrderedJSON(b);
// Keep this closed parser local so the already-reviewed57 intake stays frozen.
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
  };const decoded=value();whitespace();if(offset!==text.length)throw Error('JSON trailing bytes');return decoded;
}
function closed(value,keys,description){if(!value||typeof value!=='object'||Array.isArray(value)||!same(Object.keys(value).sort(),keys.slice().sort()))throw Error(description);}
function validateContent(raw,pins){
  if(!Buffer.isBuffer(raw)||raw.length<3||raw.length>16777217||raw.at(-2)!==125||raw.at(-1)!==10)throw Error('private publisher framing');
  if(!Buffer.isBuffer(pins.contractRaw)||sha(pins.contractRaw)!==contractPin)throw Error('private contract pin');
  const contract=strictJSON(pins.contractRaw),reference=strictJSON(raw);
  if(!Buffer.isBuffer(pins.templateRaw)||sha(pins.templateRaw)!==contract.templateSHA256)throw Error('private declaration template changed');
  const capturedRules=contract.rules.filter(rule=>nonroutineIds.includes(rule.id));
  if(capturedRules.length!==10||!same(pins.currentRules,capturedRules))throw Error('private declaration selectors changed');
  closed(reference,'catalog1FileSHA256 collectorFrame compiledSourceSHA256 compilerArtifactSHA256 compilerChecksum contractSHA256 ddlSHA256 expectedManifestRows format frameRestored namespaceAbsent originalAdmission originalFrame pgcrypto postAdmission postgres querySHA256 readOnly readOnlyPostAdmission readRollback registrationRows rows serverVersionNum sessionUser snapshotSHA256 sourceContractSHA256 supplementaryReferenceFileSHA256 variant writeRollback'.split(' '),'private envelope fields');
  const bindings={format:'ordered-current-private-reference-v1',contractSHA256:contractPin,snapshotSHA256:snapshotPin,ddlSHA256:contract.ddlSHA256,querySHA256:contract.querySHA256,
    compilerChecksum:contract.compilerChecksum,compilerArtifactSHA256:contract.compilerArtifactSHA256,compiledSourceSHA256:contract.compiledSourceSHA256,sourceContractSHA256:contract.sourceContractSHA256,catalog1FileSHA256:contract.catalog1FileSHA256,supplementaryReferenceFileSHA256:contract.supplementaryReferenceFileSHA256,
    postgres:contract.referencePostgres,serverVersionNum:contract.serverVersionNum,pgcrypto:contract.pgcrypto,expectedManifestRows:0,registrationRows:0,readOnly:false,originalAdmission:true,postAdmission:true,readOnlyPostAdmission:true,readRollback:true,writeRollback:true,namespaceAbsent:true,frameRestored:true};
  for(const [field,expected] of Object.entries(bindings))if(!same(reference[field],expected))throw Error('private provenance '+field);
  if(!['A','B'].includes(pins.variant)||typeof pins.sessionUser!=='string'||!pins.sessionUser||reference.variant!==pins.variant||reference.sessionUser!==pins.sessionUser)throw Error('private principal provenance');
  const frameKeys='pgcrypto postgres readOnly role searchPath serverVersionNum sessionUser timeZone'.split(' ');
  for(const name of ['originalFrame','collectorFrame']){
    const frame=reference[name];closed(frame,frameKeys,'private frame fields');
    const common={pgcrypto:contract.pgcrypto,postgres:contract.referencePostgres,serverVersionNum:contract.serverVersionNum,sessionUser:pins.sessionUser,readOnly:false};
    for(const [field,expected] of Object.entries(common))if(!same(frame[field],expected))throw Error('private frame '+field);
    if(name==='collectorFrame'){
      if(frame.role!==contract.requiredRole||frame.searchPath!==contract.requiredSearchPath.join(', ')||frame.timeZone!==contract.requiredTimeZone)throw Error('private collector frame');
    }else if(frame.role!==pins.sessionUser||typeof frame.searchPath!=='string'||!frame.searchPath||typeof frame.timeZone!=='string'||!frame.timeZone)throw Error('private original frame');
  }
  if(!Array.isArray(reference.rows)||reference.rows.length!==contract.maxRows)throw Error('private complete row cardinality');
  const rules=new Map(contract.rules.map(rule=>[rule.id,rule])),categoryCounts={},ruleCounts={};
  for(const row of reference.rows){
    closed(row,['kind','identity','fact'],'private fact envelope');
    if(typeof row.identity!=='string')throw Error('private identity');
    const key=strictJSON(Buffer.from(row.identity));
    if(!Array.isArray(key)||key.length!==2||key.some(value=>typeof value!=='string')||canonicalOrderedJSON(key)!==row.identity)throw Error('private key encoding');
    const rule=rules.get(key[0]);
    if(!rule||row.kind!==rule.kind)throw Error('private selected rule');
    closed(row.fact,rule.fields,'private selected fields');
    categoryCounts[row.kind]=(categoryCounts[row.kind]??0)+1;ruleCounts[rule.id]=(ruleCounts[rule.id]??0)+1;
  }
  for(const [kind,count] of Object.entries(contract.categoryMaxRows))if((categoryCounts[kind]??0)!==count)throw Error('private exact category cardinality');
  for(const [id,count] of Object.entries(contract.ruleMaxRows))if((ruleCounts[id]??0)!==count)throw Error('private exact rule cardinality');
  const rows=normalizeOrderedFacts(reference.rows);
  const routines=rows.filter(row=>JSON.parse(row.identity)[0]==='private-routines');
  if(!same(routines,normalizeOrderedFacts(contract.expectedRoutineFacts)))throw Error('private frozen routine contract');
  // All39 rows were checked above. Import only these declared nonroutine IDs;
  // current generated routine source must be derived afresh by its compiler.
  const facts=rows.filter(row=>nonroutineIds.includes(JSON.parse(row.identity)[0]));
  if(facts.length!==35||facts.some(row=>row.kind==='routine'))throw Error('private nonroutine closure');
  const {rows:ignored,...provenance}=reference;
  return {installable:false,facts,validatedRoutineCount:routines.length,categoryCounts,referenceFileSHA256:pins.referenceFileSHA256,contractFileSHA256:contractPin,provenance};
}
// Diagnostic schema controls receive no facts or admission authority.
export function checkOrderedPrivateReferenceContent(raw,pins){validateContent(raw,pins);return true;}
export function admitOrderedPrivateReference(raw,pins){
  if(!Buffer.isBuffer(raw)||raw.length<3||raw.length>16777217||!pins||pins.referenceFileSHA256!==referencePin||sha(raw)!==referencePin)throw Error('private reference file pin');
  return validateContent(raw,pins);
}
