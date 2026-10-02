// Development reference intake only. No target database, caller pin, or variant
// can authorize another reference. Raw transform inputs are NOT release facts.
import crypto from 'node:crypto';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';

const referencePin='cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797';
const contractPin='2334ebbbad1382db7eafa47f81eec5b59f7721aaafa34b6b0d51311d959538ce';
const manifestPin='338026bf79be5535bf0f57206b679e5846526da676fee6b0adac75186083d7ea';
const queryPin='5efdd0db4f55784ec8fa5a36548668d04ed3cd6cb185af9b154c1e4f48ee3d5c';
const p7='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=(a,b)=>canonicalOrderedJSON(a)===canonicalOrderedJSON(b);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exactKeys=(value,keys)=>object(value)&&same(Object.keys(value).sort(),keys.slice().sort());
const byteOrder=(a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b));

// Bounded JSON parser keeps decoded-key uniqueness and numeric spelling, which
// JSON.parse alone loses. It does not interpret SQL or normalize captured text.
function strictJSON(raw){
  if(raw[0]===0xef&&raw[1]===0xbb&&raw[2]===0xbf)throw Error('JSON BOM');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let offset=0;
  const whitespace=()=>{while(/[ \r\n\t]/.test(text[offset]??'x'))offset++;};
  const string=()=>{
    const start=offset++;let escaped=false;
    for(;offset<text.length;offset++){
      const c=text[offset];
      if(c==='"'&&!escaped){offset++;const result=JSON.parse(text.slice(start,offset));canonicalOrderedJSON(result);return result;}
      if(c==='\\'&&!escaped)escaped=true;else escaped=false;
    }
    throw Error('JSON string');
  };
  const value=(depth=0)=>{
    if(depth>32)throw Error('JSON depth');whitespace();
    if(text[offset]==='"')return string();
    if(text[offset]==='{'){
      offset++;const result={},seen=new Set();whitespace();if(text[offset]==='}'){offset++;return result;}
      while(true){
        whitespace();if(text[offset]!=='"')throw Error('JSON key');const key=string();
        if(seen.has(key))throw Error('duplicate JSON key');seen.add(key);whitespace();
        if(text[offset++]!==':')throw Error('JSON colon');
        Object.defineProperty(result,key,{value:value(depth+1),enumerable:true});
        whitespace();const end=text[offset++];if(end==='}')return result;if(end!==',')throw Error('JSON object end');
      }
    }
    if(text[offset]==='['){
      offset++;const result=[];whitespace();if(text[offset]===']'){offset++;return result;}
      while(true){result.push(value(depth+1));whitespace();const end=text[offset++];if(end===']')return result;if(end!==',')throw Error('JSON array end');}
    }
    const token=text.slice(offset).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0];
    if(!token)throw Error('JSON value');offset+=token.length;const result=JSON.parse(token);
    if(typeof result==='number'&&(/[eE]/.test(token)||Object.is(result,-0)||!Number.isFinite(result)||Math.abs(result)>Number.MAX_SAFE_INTEGER))throw Error('JSON numeric range');
    return result;
  };
  const result=value();whitespace();if(offset!==text.length)throw Error('JSON trailing bytes');return result;
}

function readInputs(inputs){
  if(!exactKeys(inputs,['contractRaw','manifestRaw']))throw Error('reference input fields');
  if(!Buffer.isBuffer(inputs.contractRaw)||sha(inputs.contractRaw)!==contractPin)throw Error('contract identity changed');
  if(!Buffer.isBuffer(inputs.manifestRaw)||sha(inputs.manifestRaw)!==manifestPin)throw Error('manifest identity changed');
  const contract=strictJSON(inputs.contractRaw),manifest=strictJSON(inputs.manifestRaw);
  if(!exactKeys(manifest,['format','source','files'])||manifest.format!==1||Object.keys(manifest.files).length!==19||manifest.files[p7+'ordered-current-supplementary-query-contract3.json']!==contractPin||manifest.files[p7+'ordered-current-supplementary-select3.sql']!==queryPin||contract.sqlSHA256!==queryPin)throw Error('qualified packet binding');
  if(contract.format!=='ordered-current-supplementary-query-v1'||contract.status!=='REFERENCE-CAPTURE-ONLY'||contract.rules.length!==64||contract.rawInputRuleIds.length!==16||contract.maxRows!==9623||contract.maxBytes!==16777216)throw Error('qualified contract shape');
  return contract;
}

function validate(raw,inputs){
  const contract=readInputs(inputs);
  if(!Buffer.isBuffer(raw)||raw.length===0||raw.length>contract.maxBytes+1)throw Error('reference byte bound');
  if(raw.at(-2)!==125||raw.at(-1)!==10)throw Error('reference publisher framing');
  const reference=strictJSON(raw);
  const bindings={
    format:'ordered-current-remaining-reference-v1',status:'REFERENCE-CAPTURE-ONLY',
    querySHA256:queryPin,contractSHA256:contractPin,packetManifestSHA256:manifestPin,
    compilerArtifactSHA256:contract.compilerArtifactSHA256,compilerChecksum:contract.compilerChecksum,
    compiledSourceSHA256:contract.compiledSourceSHA256,catalog1FileSHA256:contract.catalog1FileSHA256,
    sourceContractSHA256:contract.sourceContractSHA256,variant:'A',sessionUser:'zasp_test',
    role:contract.requiredRole,searchPath:contract.requiredSearchPath,timeZone:contract.requiredTimeZone,
    postgres:contract.requiredPostgres,serverVersionNum:contract.requiredServerVersionNum,pgcrypto:'1.4',
    readOnly:true,rolledBack:true,frameRestored:true,
    rawInputRuleIds:contract.rawInputRuleIds,rawInputDisposition:contract.rawInputDisposition
  };
  if(!exactKeys(reference,[...Object.keys(bindings),'rows']))throw Error('reference envelope fields');
  for(const [field,expected] of Object.entries(bindings))if(!same(reference[field],expected))throw Error('reference provenance '+field);
  if(!Array.isArray(reference.rows)||reference.rows.length>contract.maxRows)throw Error('reference row bound');
  const byRule=new Map(contract.rules.map(rule=>[rule.id,rule])),seen=new Set(),ruleCounts=new Map(),kindCounts=new Map();
  for(const row of reference.rows){
    if(!exactKeys(row,['kind','identity','fact'])||typeof row.identity!=='string'||!object(row.fact))throw Error('reference row fields');
    const identity=strictJSON(Buffer.from(row.identity));
    if(!Array.isArray(identity)||identity.length!==2||identity.some(part=>typeof part!=='string'||!part)||canonicalOrderedJSON(identity)!==row.identity)throw Error('reference key encoding');
    const rule=byRule.get(identity[0]);
    if(!rule||row.kind!==rule.kind||!exactKeys(row.fact,rule.fields))throw Error('reference selected fields');
    if(seen.has(row.identity))throw Error('duplicate reference identity');seen.add(row.identity);
    ruleCounts.set(rule.id,(ruleCounts.get(rule.id)??0)+1);kindCounts.set(row.kind,(kindCounts.get(row.kind)??0)+1);
    if(ruleCounts.get(rule.id)>contract.ruleMaxRows[rule.id]||kindCounts.get(row.kind)>contract.categoryMaxRows[row.kind])throw Error('reference category bound');
    for(const [field,value] of Object.entries(row.fact)){
      if(value===null)continue;
      const type=contract.fieldTypes[row.kind][field];
      const valid=type==='acl'?typeof value==='string'||Array.isArray(value)&&value.every(v=>typeof v==='string'):type==='array'?Array.isArray(value)&&value.every(v=>typeof v==='string'):type==='integer'?Number.isSafeInteger(value):['string','boolean','number'].includes(type)&&typeof value===type;
      if(!valid)throw Error('reference fact type');
      canonicalOrderedJSON(value);
    }
  }
  return reference;
}

// Validation-only: deliberately returns no facts, pins, or admission capability.
// Consumers obtaining facts MUST use the fixed-file admission function below.
export function checkOrderedRemainingReferenceEnvelope(raw,inputs){validate(raw,inputs);}

export function admitOrderedRemainingReference(raw,inputs){
  if(!Buffer.isBuffer(raw)||raw.length>16777217||sha(raw)!==referencePin)throw Error('reference file identity changed');
  const reference=validate(raw,inputs),rawRules=new Set(reference.rawInputRuleIds);
  const staticFacts=[],rawTransformInputs=[];
  for(const row of reference.rows)(rawRules.has(JSON.parse(row.identity)[0])?rawTransformInputs:staticFacts).push(JSON.parse(canonicalOrderedJSON(row)));
  for(const rows of [staticFacts,rawTransformInputs])rows.sort((a,b)=>byteOrder(a.kind,b.kind)||byteOrder(a.identity,b.identity));
  const {rows,...provenance}=reference;
  return {installable:false,staticFacts,rawTransformInputs,referenceFileSHA256:referencePin,contractFileSHA256:contractPin,provenance};
}
