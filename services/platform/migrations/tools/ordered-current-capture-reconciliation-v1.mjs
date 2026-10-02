import crypto from 'node:crypto';
import {canonicalOrderedJSON,normalizeOrderedFacts,orderedFactTypes} from './build-ordered-current-integrity.mjs';
import {assertOrderedCurrentPrecisionConflictSettlementV1} from './ordered-current-precision-conflict-settlement-v1.mjs';

const fail=message=>{throw Error(`ordered-current capture reconciliation: ${message}`);};
const plain=value=>value!==null&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype;
const sameKeys=(value,keys)=>plain(value)&&Object.keys(value).sort().join('\0')===[...keys].sort().join('\0');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const key=row=>canonicalOrderedJSON([row.kind,row.identity]);
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};

function declarationMaps(declarations){
 if(!sameKeys(declarations,['direct','missing','private']))fail('declaration collections');
 const result={};
 for(const name of ['direct','missing','private']){
  if(!Array.isArray(declarations[name]))fail(`${name} declarations`);
  const map=new Map();
  for(const declaration of declarations[name]){
   if(!sameKeys(declaration,['fields','id','kind'])||typeof declaration.id!=='string'||!declaration.id||!Object.hasOwn(orderedFactTypes,declaration.kind)||!Array.isArray(declaration.fields)||!declaration.fields.length||new Set(declaration.fields).size!==declaration.fields.length||declaration.fields.some(field=>!Object.hasOwn(orderedFactTypes[declaration.kind],field)))fail(`${name} source declaration`);
   if(map.has(declaration.id))fail(`${name} duplicate source declaration`);
   map.set(declaration.id,declaration);
  }
  result[name]=map;
 }
 return result;
}

function validateIdentity(row,name,declarations){
 if(!sameKeys(row,['fact','identity','kind'])||typeof row.kind!=='string'||typeof row.identity!=='string'||!plain(row.fact))fail(`${name} fact envelope`);
 let identity;try{identity=JSON.parse(row.identity);}catch{fail(`${name} canonical identity`);}
 if(!Array.isArray(identity)||identity.length!==2||identity.some(value=>typeof value!=='string')||canonicalOrderedJSON(identity)!==row.identity)fail(`${name} canonical identity`);
 const declaration=declarations.get(identity[0]);
 if(!declaration||row.kind!==declaration.kind||Object.keys(row.fact).sort().join('\0')!==[...declaration.fields].sort().join('\0'))fail(`${name} source declaration`);
 for(const field of declaration.fields){
  const value=row.fact[field],type=orderedFactTypes[row.kind][field];
  const valid=value===null||type==='string'&&typeof value==='string'||type==='boolean'&&typeof value==='boolean'||type==='number'&&typeof value==='number'&&Number.isFinite(value)||type==='integer'&&Number.isSafeInteger(value)||type==='acl'&&(typeof value==='string'||Array.isArray(value)&&value.every(item=>typeof item==='string'))||type==='array'&&Array.isArray(value)&&value.every(item=>typeof item==='string');
  if(!valid)fail(`${name} source-declared type ${row.kind}.${field}`);
 }
 if(name==='private'&&row.kind==='routine')fail('private routine observations are not importable');
}

export function reconcileOrderedCurrentFactCollectionsV1(input){
 if(!sameKeys(input,['collections','declarations','existingFacts','settlements']))fail('input envelope');
 if(!sameKeys(input.collections,['direct','missing','private']))fail('fact collections');
 const declarations=declarationMaps(input.declarations);
 const existing=normalizeOrderedFacts(input.existingFacts),existingByKey=new Map(existing.map(row=>[key(row),row]));
 if(!Array.isArray(input.settlements))fail('settlements');
 const permitted=new Map();
 for(const row of input.settlements){
  assertOrderedCurrentPrecisionConflictSettlementV1(row);
  const identity=key(row);if(permitted.has(identity))fail('duplicate settlement');permitted.set(identity,row);
 }
 const final=[...existing],seenCapture=new Set(),usedSettlements=new Set(),equalExisting=[],newlySupplied=[],settled=[],collectionCounts={};
 for(const name of ['direct','missing','private']){
  const source=input.collections[name];if(!Array.isArray(source))fail(`${name} facts`);
  const rawKeys=new Set();for(const row of source){validateIdentity(row,name,declarations[name]);const identity=key(row);if(rawKeys.has(identity))fail(`duplicate capture fact ${row.kind} ${row.identity}`);rawKeys.add(identity);}
  let rows;try{rows=normalizeOrderedFacts(source);}catch(error){if(error.message==='duplicate fact key')fail(`duplicate capture fact in ${name}`);throw error;}
  const counts={admitted:rows.length,equalExisting:0,newlySupplied:0,settledConflicts:0,unresolvedConflicts:0};
  for(const row of rows){
   const identity=key(row);if(seenCapture.has(identity))fail(`duplicate capture fact ${row.kind} ${row.identity}`);seenCapture.add(identity);
   const prior=existingByKey.get(identity);
   if(!prior){final.push(row);existingByKey.set(identity,row);newlySupplied.push({collection:name,kind:row.kind,identity:row.identity});counts.newlySupplied++;continue;}
   const existingBytes=canonicalOrderedJSON(prior.fact),incomingBytes=canonicalOrderedJSON(row.fact);
   if(existingBytes===incomingBytes){final[final.findIndex(candidate=>key(candidate)===identity)]=row;existingByKey.set(identity,row);equalExisting.push({collection:name,kind:row.kind,identity:row.identity});counts.equalExisting++;continue;}
   const allowed=permitted.get(identity);
   if(!allowed||allowed.collection!==name||allowed.existingFactSHA256!==sha(existingBytes)||allowed.incomingFactSHA256!==sha(incomingBytes))fail(`conflicting capture fact ${row.kind} ${row.identity}`);
   if(prior.fact.precision_definition!==null||typeof row.fact.precision_definition!=='string'||!row.fact.precision_definition)fail(`settlement incomplete definition ${row.kind} ${row.identity}`);
   const oldRest={...prior.fact},newRest={...row.fact};delete oldRest.precision_definition;delete newRest.precision_definition;
   if(canonicalOrderedJSON(oldRest)!==canonicalOrderedJSON(newRest))fail(`settlement unrelated fields ${row.kind} ${row.identity}`);
   final[final.findIndex(candidate=>key(candidate)===identity)]=row;existingByKey.set(identity,row);
   usedSettlements.add(identity);settled.push(allowed);counts.settledConflicts++;
  }
  collectionCounts[name]=counts;
 }
 if(usedSettlements.size!==permitted.size)fail('unused settlement');
 const counts={admitted:Object.values(collectionCounts).reduce((sum,value)=>sum+value.admitted,0),equalExisting:equalExisting.length,newlySupplied:newlySupplied.length,settledConflicts:settled.length,unresolvedConflicts:0};
 return freeze({facts:normalizeOrderedFacts(final),counts,collections:collectionCounts,equalExisting,newlySupplied,settledConflicts:settled,unresolvedConflicts:[]});
}
