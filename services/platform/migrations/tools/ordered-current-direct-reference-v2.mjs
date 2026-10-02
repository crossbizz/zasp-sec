// Offline projection of the accepted frame-v2 worker/edge observations.
// Canonical descriptor keys and original-frame facts remain deliberately separate.
import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {orderedFactTypes,canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {orderedCurrentPrecisionConflictSettlementsV1,assertOrderedCurrentPrecisionConflictSettlementV1} from './ordered-current-precision-conflict-settlement-v1.mjs';
import {buildOrderedConsolidationNeeds} from './ordered-current-consolidation-needs.mjs';
import {admitOrderedCurrentReferenceIntakeV2} from './ordered-current-reference-intake-v2.mjs';

const fail=message=>{throw Error(`ordered-current direct reference ${message}`);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=isDeepStrictEqual;
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const catalogSHA256='9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df';
const catalogPin='.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/recovery80-effective-catalog.json';
const extraRoutineFields=['config_json','config_raw','config_dims','config_ndims','config_bounds'];
const extraRoutineProjections=['to_jsonb(p.proconfig)','p.proconfig::text','array_dims(p.proconfig)','array_ndims(p.proconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)'];
const inputFields=['aPacketRoot','aRaw','bPacketRoot','bRaw','catalogRaw','compiledReleaseRaw','coverageRaw','sourceContractRaw'];

function exactObject(value,fields){return plain(value)&&same(Object.keys(value).sort(),fields.slice().sort());}
function sameFieldSet(value,fields){return plain(value)&&same(Object.keys(value).sort(),fields.slice().sort());}
function parse(raw,label){try{return JSON.parse(raw);}catch{fail(`${label} JSON`);}}
function identity(value,label){let parsed;try{parsed=JSON.parse(value);}catch{fail(`${label} identity`);}return parsed;}
function one(values,label){if(values.length!==1)fail(`${label} catalog join (${values.length})`);return values[0];}
function scalar(value,label){
 if(typeof value!=='string'||!value)fail(`${label} scalar identity`);
 try{const parsed=JSON.parse(value);if(typeof parsed==='string'&&parsed)return parsed;}catch{return value;}
 fail(`${label} scalar identity`);
}
function tuple(value,length,label){const parsed=identity(value,label);if(!Array.isArray(parsed)||parsed.length!==length||parsed.some(item=>item!==null&&typeof item!=='string'&&typeof item!=='number'))fail(`${label} tuple identity`);return parsed;}
function values(selector,field){
 const out=[];const visit=node=>{if(!plain(node))return;if(node.field===field&&Object.hasOwn(node,'equals'))out.push(node.equals);for(const child of node.all??node.any??[])visit(child);};visit(selector);return [...new Set(out)];
}
function qualifiedParts(value){
 if(typeof value!=='string'||!value)return null;
 const parts=[];let part='',quoted=false;
 for(let index=0;index<value.length;index++){
  const character=value[index];
  if(quoted){if(character==='"'&&value[index+1]==='"'){part+='"';index++;}else if(character==='"')quoted=false;else part+=character;}
  else if(character==='"')quoted=true;else if(character==='.'){parts.push(part);part='';}else part+=character;
 }
 if(quoted)return null;parts.push(part);return parts.length===2&&parts.every(item=>item.length)?parts:null;
}
function fkConstraintCandidates(rule,catalog){
 const namespaces=values(rule.selector,'namespace'),names=values(rule.selector,'relation_name');
 if(namespaces.length!==1)fail(`${rule.id} FK namespace selector`);
 if(names.length)return new Set(names.map(name=>`${namespaces[0]}.${name}`));
 return new Set(catalog.constraints.filter(item=>qualifiedParts(item.relation)?.[0]===namespaces[0]).map(item=>item.relation));
}
function typeValid(type,value){
 if(value===null)return true;
 if(type==='acl')return typeof value==='string'||Array.isArray(value)&&value.every(item=>typeof item==='string');
 if(type==='array')return Array.isArray(value)&&value.every(item=>typeof item==='string');
 if(type==='integer')return Number.isSafeInteger(value);
 return typeof value===type&&(type!=='number'||Number.isFinite(value)&&!Object.is(value,-0));
}
function catalogIdentity(rule,row,catalog){
 const capture=row.identity,fact=row.fact;
 const aliased=aliasIdentity(rule,row,catalog);
 if(aliased!==null)return aliased;
 if(['relation','routine','class_index','index'].includes(rule.kind)){
  const key=scalar(capture,rule.id),collection=rule.kind==='routine'?catalog.functions:rule.kind==='index'?catalog.indexes:catalog.relations;
  one(collection.filter(item=>item.identity===key),`${rule.id} ${rule.kind}`);return key;
 }
 if(rule.kind==='role'){
  const key=scalar(capture,rule.id);one(catalog.roles.filter(item=>item.name===key),`${rule.id} role`);return key;
 }
 if(['column_name','column_all'].includes(rule.kind)){
  const [relation,position,name]=tuple(capture,3,rule.id);
  const item=one(catalog.columns.filter(candidate=>candidate.relation===relation&&candidate.position===position&&candidate.name===name),`${rule.id} column`);
  return JSON.stringify([item.relation,item.name]);
 }
 if(rule.kind==='constraint'){
  const [,relation,,name]=tuple(capture,4,rule.id);
  const item=one(catalog.constraints.filter(candidate=>candidate.relation===relation&&candidate.name===name),`${rule.id} constraint`);
  return JSON.stringify([item.relation,item.name]);
 }
 if(rule.kind==='trigger'){
  const [relation,name]=tuple(capture,2,rule.id);
  const item=one(catalog.triggers.filter(candidate=>candidate.relation===relation&&candidate.name===name),`${rule.id} trigger`);
  return JSON.stringify([item.relation,item.name]);
 }
 if(rule.kind==='policy'){
  const [relation,name]=tuple(capture,2,rule.id);
  const item=one(catalog.policies.filter(candidate=>candidate.relation===relation&&candidate.name===name),`${rule.id} policy`);
  return JSON.stringify([item.relation,item.name]);
 }
 if(rule.kind==='policy_view'){
  const [relation,name]=tuple(capture,2,rule.id);
  const item=one(catalog.policies.filter(candidate=>candidate.relation===relation&&candidate.name===name),`${rule.id} policy view`);
  const namespaces=typeof fact.namespace_name==='string'?[fact.namespace_name]:values(rule.selector,'namespace');
  const tables=typeof fact.table_name==='string'?[fact.table_name]:values(rule.selector,'table_name');
  const keys=[];for(const namespace of namespaces)for(const table of tables)if(`${namespace}.${table}`===item.relation)keys.push([namespace,table,item.name]);
  return JSON.stringify(one(keys,`${rule.id} policy view relation`));
 }
 if(rule.kind==='index_view'){
  const indexIdentity=scalar(capture,rule.id),item=one(catalog.indexes.filter(candidate=>candidate.identity===indexIdentity),`${rule.id} index view`);
  const namespaces=values(rule.selector,'namespace'),tables=values(rule.selector,'table_name'),keys=[];
  for(const namespace of namespaces)for(const table of tables)if(`${namespace}.${table}`===item.relation)keys.push([namespace,table,fact.name]);
  return JSON.stringify(one(keys,`${rule.id} index view relation`));
 }
 if(rule.kind==='foreign_key_trigger'){
  const [triggerRelation,triggerName]=tuple(capture,2,rule.id);
  const trigger=one(catalog.triggers.filter(candidate=>candidate.relation===triggerRelation&&candidate.name===triggerName),`${rule.id} foreign-key trigger`);
  const candidates=fkConstraintCandidates(rule,catalog);
  const constraint=one(catalog.constraints.filter(candidate=>candidate.name===fact.name&&candidates.has(candidate.relation)),`${rule.id} source-proven constraint`);
  if(typeof fact.event_bits!=='number'||!Number.isSafeInteger(fact.event_bits))fail(`${rule.id} event bits`);
  return JSON.stringify([constraint.relation,constraint.name,trigger.relation,trigger.function,fact.event_bits]);
 }
 fail(`${rule.id} unsupported key kind ${rule.kind}`);
}

// Native captures for the development-only missing-reference families used a
// source spelling that predates the qualified descriptor keys.  These joins
// are deliberately limited to the reviewed rule IDs below.  Every candidate
// comes from the pinned catalog; no target row or generated fact participates.
const sourceAliasRules=Object.freeze({
 relation:new Set(['inventory-fields:table','temporal72:table']),
 policy:new Set(['inventory-fields:policy','temporal72:policy']),
 routine:new Set(['inventory-fields:function','temporal72:function']),
 trigger:new Set(['temporal72:trigger']),
 fixed:new Set(['role-profile:current-profile']),
});
const namespaceForRule=rule=>{
 const namespaces=values(rule.selector,'namespace');
 if(namespaces.length!==1)fail(`${rule.id} source alias namespace selector`);
 return namespaces[0];
};
function aliasRelation(rule,captured,catalog){
 let namespace;
 const namespaces=values(rule.selector,'namespace');
 if(namespaces.length===1)namespace=namespaces[0];
 else if(!namespaces.length&&rule.kind==='trigger'&&rule.id.startsWith('worker-edge:')){
  const capturedParts=qualifiedParts(captured),relationRows=[...(catalog.relations??[]),...(catalog.triggers??[]).map(item=>({identity:item?.relation}))],candidateRelations=[...new Map(relationRows.filter(item=>item?.identity).map(item=>[item.identity,item])).values()].filter(item=>{
   const parts=qualifiedParts(item?.identity);if(!parts)return false;
   return capturedParts?item.identity===captured:parts[1]===captured;
  });
  namespace=qualifiedParts(one(candidateRelations,`${rule.id} trigger relation alias` ).identity)[0];
 } else fail(`${rule.id} source alias namespace selector`);
 const name=typeof captured==='string'?captured:null;
 if(!name)fail(`${rule.id} relation alias identity`);
 const capturedParts=qualifiedParts(name),capturedName=capturedParts?capturedParts[1]:name;
 if(capturedParts&&capturedParts[0]!==namespace)fail(`${rule.id} relation alias namespace`);
 const candidates=(catalog.relations??[]).filter(item=>{
  if(typeof item?.identity!=='string')return false;
  const parts=qualifiedParts(item.identity);if(!parts||parts[0]!==namespace)return false;
  const selectorNames=rule.kind==='relation'?[...values(rule.selector,'name'),...values(rule.selector,'relation_name')]:[];
  if(parts[1]!==capturedName)return false;
  return !selectorNames.length||selectorNames.includes(parts[1]);
 });
 return one(candidates,`${rule.id} relation alias` ).identity;
}
function aliasTupleRelation(rule,captured,catalog,label){
 const parsed=tuple(captured,2,rule.id),relation=aliasRelation(rule,parsed[0],catalog);
 const collection=label==='policy'?(catalog.policies??[]):(catalog.triggers??[]);
 return {candidate:one(collection.filter(item=>item?.relation===relation&&item?.name===parsed[1]),`${rule.id} ${label} alias`),relation};
}
function splitSignature(value,label){
 if(typeof value!=='string')fail(`${label} routine alias signature`);
 const match=/^(?:(.+)\.)?([^.(]+)\((.*)\)$/.exec(value);
 if(!match)fail(`${label} routine alias signature`);
 const args=[];let current='',depth=0,quoted=false;
 for(let index=0;index<match[3].length;index++){
  const character=match[3][index];
  if(character==='"'){
   if(quoted&&match[3][index+1]==='"'){current+='""';index++;continue;}
   quoted=!quoted;
  }
  if(!quoted&&character==='(')depth++;
  if(!quoted&&character===')')depth--;
  if(depth<0)fail(`${label} unsupported argument syntax`);
  if(!quoted&&character===','&&depth===0){if(!current.trim())fail(`${label} unsupported argument syntax`);args.push(current.trim());current='';}else current+=character;
 }
 if(quoted||depth!==0||!current.trim()&&args.length)fail(`${label} unsupported argument syntax`);
 if(current.trim())args.push(current.trim());
 return {namespace:match[1]??null,name:match[2],args};
}

// Parse labels separately from complete types. This is a bounded spelling
// grammar, not SQL type equivalence: candidates still supply the exact type.
const argumentIdentifier='(?:[A-Za-z_][A-Za-z0-9_$]*|"(?:[^"]|"")+")';
const argumentType=new RegExp(`^(?:${argumentIdentifier}(?:\\.${argumentIdentifier})*|double precision|timestamp (?:with|without) time zone|time (?:with|without) time zone|character varying|bit varying)(?:\\(\\d+(?:,\\s*\\d+)*\\))?(?:\\[\\])*$`,'i');
const argumentLabel=new RegExp(`^(${argumentIdentifier})\\s+(.+)$`);
function routineArgument(value,label){
 if(typeof value!=='string'||!value.trim())fail(`${label} unsupported argument syntax`);
 const modeMatch=/^(INOUT|IN|OUT|VARIADIC)\s+(.+)$/i.exec(value.trim());
 const mode=modeMatch?modeMatch[1].toUpperCase():'IN',body=modeMatch?modeMatch[2].trim():value.trim();
 if(argumentType.test(body))return {mode,name:null,type:body,body};
 const named=argumentLabel.exec(body);
 if(!named||!argumentType.test(named[2]))fail(`${label} unsupported argument syntax`);
 return {mode,name:named[1],type:named[2],body};
}
const sameArgument=(left,right)=>left.mode===right.mode&&left.type===right.type;
function aliasRoutine(rule,captured,identityArguments,catalog){
 const parsed=splitSignature(captured,rule.id),namespace=namespaceForRule(rule);
 const capturedArguments=parsed.args.map(argument=>routineArgument(argument,rule.id));
 if(identityArguments!==undefined&&typeof identityArguments!=='string')fail(`${rule.id} routine alias fact arguments`);
 const factArguments=identityArguments===undefined?null:splitSignature(`f(${identityArguments})`,rule.id).args.map(argument=>routineArgument(argument,rule.id));
 if(parsed.namespace&&parsed.namespace!==namespace)fail(`${rule.id} routine alias namespace`);
 const candidates=(catalog.functions??[]).filter(item=>{
  if(typeof item?.identity!=='string')return false;
  const candidate=splitSignature(item.identity,rule.id);
  if(candidate.namespace!==namespace||candidate.name!==parsed.name)return false;
  const types=candidate.args.map(argument=>routineArgument(argument,`${rule.id} source type`));
  if(types.some(argument=>argument.name!==null||argument.mode!=='IN'))fail(`${rule.id} unsupported source identity arguments`);
  if(Object.hasOwn(item,'arguments')&&typeof item.arguments!=='string')fail(`${rule.id} unsupported source arguments`);
  const declared=Object.hasOwn(item,'arguments')?splitSignature(`f(${item.arguments})`,rule.id).args.map(argument=>routineArgument(argument,`${rule.id} source arguments`)):types;
  if(declared.length!==types.length)fail(`${rule.id} unsupported source argument arity`);
  if(declared.some((argument,index)=>argument.type!==types[index].type))fail(`${rule.id} source argument vector`);
  return capturedArguments.length===declared.length&&(!factArguments||factArguments.length===declared.length)&&declared.every((argument,index)=>sameArgument(capturedArguments[index],argument)&&(!factArguments||sameArgument(factArguments[index],argument)));
 });
 return one(candidates,`${rule.id} routine alias`).identity;
}
function aliasIdentity(rule,row,catalog){
 const captured=row.identity;
 if(rule.kind==='relation'&&sourceAliasRules.relation.has(rule.id))return aliasRelation(rule,scalar(captured,rule.id),catalog);
 if(rule.kind==='policy'&&sourceAliasRules.policy.has(rule.id))return JSON.stringify([aliasTupleRelation(rule,captured,catalog,'policy').relation,tuple(captured,2,rule.id)[1]]);
 if(rule.kind==='trigger'&&(sourceAliasRules.trigger.has(rule.id)||rule.id.startsWith('worker-edge:'))){
  const {candidate}=aliasTupleRelation(rule,captured,catalog,'trigger');return JSON.stringify([candidate.relation,candidate.name]);
 }
 if(rule.kind==='routine'&&sourceAliasRules.routine.has(rule.id))return aliasRoutine(rule,scalar(captured,rule.id),row.fact?.identity_arguments,catalog);
 if(rule.kind==='fixed_runtime_profile'&&sourceAliasRules.fixed.has(rule.id)){
  const parsed=identity(captured,rule.id);
  const canonical=JSON.stringify(['zasp_authorization80.runtime_profile',true]);
  const valid=JSON.stringify(parsed)===canonical||JSON.stringify(parsed)===JSON.stringify([true,'canonical61-temporal78-authorization79-80-v1']);
  if(!valid||row.fact?.singleton!==true||row.fact?.name!=='canonical61-temporal78-authorization79-80-v1')fail(`${rule.id} fixed profile alias`);
  return canonical;
 }
 return null;
}

// Temporal72 precision capture has one exact 51-row source roster.  Older
// source-bound facts may spell argument names in identity_arguments, while
// PostgreSQL's regprocedure identity is type-only.  This adapter performs the
// one approved source-side join and collapses only byte-identical aliases;
// it never consumes a native/target row or invents a definition.
const precisionRuleId='temporal72:precision-function';
const precisionFields=['namespace_name','name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','precision_definition'];
const precisionRosterSHA256='8274273e43ae89e7ba3928ba1891b17f02814133169e04605cbc69705fa18c90';
function precisionSignatureKey(signature,label){
 return splitSignature(signature,label);
}
function precisionArgumentMatches(argument,declaredArgument,index){
 const source=routineArgument(declaredArgument,'precision source');
 // Preserve the established synthetic wrapper around a source-named argument,
 // but never interpret an arbitrary second label as part of a type.
 const modeMatch=/^(INOUT|IN|OUT|VARIADIC)\s+(.+)$/i.exec(argument);
 const mode=modeMatch?modeMatch[1].toUpperCase():'IN',body=modeMatch?modeMatch[2].trim():argument;
 if(body===`precision_arg_${index} ${source.body}`)return mode===source.mode;
 const candidate=routineArgument(argument,'precision candidate');
 return sameArgument(candidate,source)&&(candidate.name===null||candidate.name===source.name||candidate.name===`precision_arg_${index}`);
}
function precisionSameSignature(left,right,declaredArguments,label){
 const a=precisionSignatureKey(left,label),b=precisionSignatureKey(right,label);
 const sourceArguments=precisionSignatureKey(`f(${declaredArguments})`,label).args;
 return a.namespace===b.namespace&&a.name===b.name&&a.args.length===b.args.length&&sourceArguments.length===b.args.length&&sourceArguments.every((argument,index)=>precisionArgumentMatches(a.args[index],argument,index)&&precisionArgumentMatches(b.args[index],argument,index));
}
export function canonicalizeOrderedCurrentPrecisionFacts(facts,roster){
 if(!Array.isArray(facts)||!Array.isArray(roster))fail('precision fact inputs');
 if(roster.length!==51)fail(`precision roster cardinality (${roster.length})`);
 const rosterRows=[],rosterKeys=new Set();
 for(const row of roster){
  if(!exactObject(row,['kind','identity','fact'])||row.kind!=='routine'||typeof row.identity!=='string'||!sameFieldSet(row.fact,precisionFields)||typeof row.fact.identity_arguments!=='string')fail('precision roster shape');
  const outer=identity(row.identity,'precision roster');
  if(!Array.isArray(outer)||outer.length!==2||outer[0]!==precisionRuleId||typeof outer[1]!=='string')fail('precision roster identity');
  const signature=precisionSignatureKey(outer[1],'precision roster'),declared=precisionSignatureKey(`f(${row.fact.identity_arguments})`,'precision roster').args;
  if(signature.args.length!==declared.length||signature.args.some((argument,index)=>!precisionArgumentMatches(argument,declared[index],index)))fail('precision roster argument vector');
  if(rosterKeys.has(row.identity))fail('precision roster duplicate');
  rosterKeys.add(row.identity);rosterRows.push(row);
 }
 const sortedRoster=rosterRows.slice().sort((a,b)=>Buffer.from(a.identity).compare(Buffer.from(b.identity)));
 if(sha(canonicalOrderedJSON(sortedRoster))!==precisionRosterSHA256)fail('precision roster authority');
 const candidatesBySignature=rosterRows.map(row=>({row,signature:JSON.parse(row.identity)[1]}));
 const exceptions=new Map(orderedCurrentPrecisionConflictSettlementsV1().map(row=>{
  assertOrderedCurrentPrecisionConflictSettlementV1(row);
  return [row.identity,row.existingFactSHA256];
 }));
 const output=[],groups=new Map(),mappings=[],merges=[],seenCapture=new Set();
 for(const row of facts){
  if(!row||typeof row.identity!=='string'){output.push(row);continue;}
  let outer;try{outer=JSON.parse(row.identity);}catch{output.push(row);continue;}
  if(!Array.isArray(outer)||outer[0]!==precisionRuleId){output.push(row);continue;}
  if(outer.length!==2||outer.some(value=>typeof value!=='string'))fail('precision fact identity');
  if(!exactObject(row,['kind','identity','fact'])||row.kind!=='routine'||!sameFieldSet(row.fact,precisionFields)||typeof row.fact.identity_arguments!=='string')fail('precision fact shape');
  if(seenCapture.has(row.identity))fail(`precision duplicate capture identity ${row.identity}`);seenCapture.add(row.identity);
  const matches=candidatesBySignature.filter(candidate=>precisionSameSignature(outer[1],candidate.signature,candidate.row.fact.identity_arguments,'precision candidate'));
  if(matches.length!==1)fail(`precision candidate cardinality (${matches.length}) ${outer[1]}`);
  const source=matches[0].row,sourceFact=source.fact,isCanonical=row.identity===source.identity;
  const sourceArguments=precisionSignatureKey(`f(${sourceFact.identity_arguments})`,'precision source').args;
  const candidateArguments=precisionSignatureKey(outer[1],'precision candidate').args;
  const factArguments=precisionSignatureKey(`f(${row.fact.identity_arguments})`,'precision fact').args;
  if(candidateArguments.length!==sourceArguments.length||factArguments.length!==sourceArguments.length||candidateArguments.some((argument,index)=>!precisionArgumentMatches(argument,sourceArguments[index],index)||!precisionArgumentMatches(factArguments[index],sourceArguments[index],index)))fail(`precision argument vector ${outer[1]}`);
  const canonicalIdentity=source.identity,rowFactSHA256=sha(canonicalOrderedJSON(row.fact));
  const priorHash=exceptions.get(canonicalIdentity);
  const authorizedPrior=isCanonical&&row.fact.precision_definition===null&&rowFactSHA256===priorHash;
  if(!authorizedPrior){
   for(const field of precisionFields){
    if(!isCanonical&&field==='identity_arguments')continue;
    if(canonicalOrderedJSON(row.fact?.[field])!==canonicalOrderedJSON(sourceFact[field]))fail(`precision semantic fact ${outer[1]} ${field}`);
   }
  }
  const canonicalFact=authorizedPrior?row.fact:sourceFact,key=`routine\u0000${canonicalIdentity}`;
  const factSHA256=sha(canonicalOrderedJSON(canonicalFact)),existing=groups.get(key);
  mappings.push({ruleId:precisionRuleId,kind:'routine',captureIdentity:row.identity,canonicalIdentity,factSHA256});
  if(existing){
   if(existing.factSHA256!==factSHA256)fail(`precision canonical identity collision ${canonicalIdentity}`);
   existing.captureIdentities.push(row.identity);
   continue;
  }
  const entry={row:{kind:'routine',identity:canonicalIdentity,fact:structuredClone(canonicalFact)},captureIdentities:[row.identity],factSHA256};
  groups.set(key,entry);output.push(entry.row);
 }
 const expectedKeys=new Set(rosterRows.map(row=>row.identity));
 const actualKeys=new Set([...groups.values()].map(entry=>entry.row.identity));
 if(actualKeys.size!==51||[...expectedKeys].some(identity=>!actualKeys.has(identity)))fail(`precision exact51 closure (${actualKeys.size})`);
 for(const entry of groups.values())if(entry.captureIdentities.length>1)merges.push({ruleId:precisionRuleId,kind:'routine',canonicalIdentity:entry.row.identity,captureIdentities:entry.captureIdentities.slice().sort(),factSHA256:entry.factSHA256,proof:'byte-identical-source-bound-facts'});
 return {facts:output,mappings,merges};
}

export function mergeOrderedCurrentCanonicalCaptureFacts(originalRows,canonicalRows){
 if(!Array.isArray(originalRows)||!Array.isArray(canonicalRows)||originalRows.length!==canonicalRows.length)fail('canonical capture merge cardinality');
 const groups=new Map(),mappings=[],merges=[];
 for(let index=0;index<originalRows.length;index++){
  const original=originalRows[index],canonical=canonicalRows[index];
  if(!original||!canonical||original.kind!==canonical.kind)fail('canonical capture merge kind');
  let outer;try{outer=JSON.parse(canonical.identity);}catch{fail('canonical capture merge identity');}
  if(!Array.isArray(outer)||outer.length!==2||typeof outer[0]!=='string')fail('canonical capture merge rule');
  const key=`${outer[0]}\u0000${canonical.kind}\u0000${canonical.identity}`;
  const factJSON=canonicalOrderedJSON(canonical.fact),existing=groups.get(key);
  mappings.push({ruleId:outer[0],kind:canonical.kind,captureIdentity:original.identity,canonicalIdentity:canonical.identity,factSHA256:sha(factJSON)});
  if(!existing){groups.set(key,{row:{kind:canonical.kind,identity:canonical.identity,fact:canonical.fact},captureIdentities:[original.identity],factSHA256:sha(factJSON)});continue;}
  if(existing.factSHA256!==sha(factJSON)||canonicalOrderedJSON(existing.row.fact)!==factJSON)fail(`${outer[0]} canonical identity collision`);
  existing.captureIdentities.push(original.identity);
 }
 for(const entry of groups.values())if(entry.captureIdentities.length>1)merges.push({ruleId:JSON.parse(entry.row.identity)[0],kind:entry.row.kind,canonicalIdentity:entry.row.identity,captureIdentities:entry.captureIdentities.slice().sort(),factSHA256:entry.factSHA256,proof:'byte-identical-source-bound-facts'});
 return {facts:[...groups.values()].map(entry=>entry.row),mappings,merges};
}

// Resolve the complete FK edge from the same pinned constraint/trigger joins
// used for canonical identity. The referenced relation is accepted only when
// the pinned constraint definition has the standardized FK REFERENCES form
// and names exactly one pinned relation.
export function resolveOrderedCurrentForeignKeyEdge(rule,row,catalog){
 if(rule?.kind!=='foreign_key_trigger'||!row||!catalog)fail(`${rule?.id??'foreign-key'} FK edge inputs`);
 const [triggerRelation,triggerName]=tuple(row.identity,2,rule.id);
 const trigger=one(catalog.triggers.filter(candidate=>candidate.relation===triggerRelation&&candidate.name===triggerName),`${rule.id} foreign-key trigger`);
 const candidates=fkConstraintCandidates(rule,catalog);
 const constraint=one(catalog.constraints.filter(candidate=>candidate.name===row.fact?.name&&candidates.has(candidate.relation)),`${rule.id} source-proven constraint`);
 if(typeof constraint.definition!=='string'||!constraint.definition)fail(`${rule.id} FK definition unavailable`);
 const match=/^FOREIGN KEY \([^)]*\) REFERENCES ([A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?)\s*\(/.exec(constraint.definition);
 if(!match)fail(`${rule.id} FK definition form`);
 const target=match[1],targetCandidates=catalog.relations.filter(candidate=>{
  if(typeof candidate?.identity!=='string')return false;
  const separator=candidate.identity.indexOf('.');
  const unqualified=separator<0?candidate.identity:candidate.identity.slice(separator+1);
  return candidate.identity===target||unqualified===target;
 });
 const referenced=one(targetCandidates,`${rule.id} referenced relation`);
 return Object.freeze({constraintRelation:constraint.relation,triggerRelation:trigger.relation,referencedRelation:referenced.identity,constraintPeerRelation:trigger.relation===constraint.relation?referenced.identity:constraint.relation});
}

// Qualification-only source repair for the native16 deparse drift.  The
// candidate text comes from the pinned catalog row selected by the descriptor
// identity.  A token-by-token proof permits only insertion of a unique
// `public.` relation or routine qualifier; all other lexical differences are
// refused.  This is deliberately not a SQL regexp rewrite and never consumes
// a target/native row.
function qualificationTokens(value,label){
 if(typeof value!=='string'||!value)fail(`${label} qualification text`);
 const out=[];let index=0;
 while(index<value.length){
  const start=index,character=value[index];
  if(/\s/u.test(character)){index++;while(index<value.length&&/\s/u.test(value[index]))index++;out.push({kind:'space',raw:value.slice(start,index),start,end:index});continue;}
  if(value.startsWith('--',index)||value.startsWith('/*',index))fail(`${label} qualification comment`);
  if(character==='"'||character==="'"){
   const quote=character;index++;
   while(index<value.length){
    if(value[index]===quote){if(value[index+1]===quote){index+=2;continue;}index++;break;}
    index++;
   }
   if(value[index-1]!==quote)fail(`${label} qualification unterminated quote`);
   out.push({kind:'quoted',raw:value.slice(start,index),start,end:index});continue;
  }
  if(/[A-Za-z_]/u.test(character)){
   index++;while(index<value.length&&/[A-Za-z0-9_$]/u.test(value[index]))index++;
   out.push({kind:'word',raw:value.slice(start,index),start,end:index});continue;
  }
  if(/[0-9]/u.test(character)){
   index++;while(index<value.length&&/[A-Za-z0-9_.]/u.test(value[index]))index++;
   out.push({kind:'number',raw:value.slice(start,index),start,end:index});continue;
  }
  out.push({kind:'punctuation',raw:character,start,end:index+1});index++;
 }
 return out;
}
function uniqueQualifiedName(catalog,kind,name,label,exactIdentity=null){
 const collection=kind==='relation'?catalog.relations??[]:catalog.functions??[];
 const matches=collection.filter(item=>{
  if(kind==='relation'){const parts=qualifiedParts(item?.identity);return parts&&parts[0]==='public'&&parts[1]===name;}
  try { const parsed=splitSignature(item?.identity,label); return parsed.namespace==='public'&&parsed.name===name; } catch { return false; }
 });
 if(exactIdentity!==null){if(!matches.some(item=>item.identity===exactIdentity))fail(`${label} ${kind} join`);return exactIdentity;}
 if(matches.length!==1)fail(`${label} ${kind} join (${matches.length})`);
 return matches[0].identity;
}
function sourceDefinitionCandidate(rule,row,catalog){
 let identity=row?.identity;
 try { const outer=JSON.parse(identity); if(Array.isArray(outer)&&outer.length===2&&outer[0]===rule.id)identity=outer[1]; } catch { fail(`${rule.id} qualification identity`); }
 let tupleValue;
 try { tupleValue=JSON.parse(identity); } catch { tupleValue=null; }
 const relation=Array.isArray(tupleValue)&&tupleValue.length===4&&typeof tupleValue[1]==='string'?tupleValue[1]:Array.isArray(tupleValue)&&typeof tupleValue[0]==='string'?tupleValue[0]:row.fact?.relation_name??row.fact?.relation;
 const name=Array.isArray(tupleValue)&&tupleValue.length===4&&typeof tupleValue[3]==='string'?tupleValue[3]:Array.isArray(tupleValue)&&typeof tupleValue[1]==='string'?tupleValue[1]:row.fact?.name;
 if(typeof relation!=='string'||typeof name!=='string')fail(`${rule.id} qualification descriptor`);
 const collection=rule.kind==='constraint'?catalog.constraints??[]:catalog.triggers??[];
 return one(collection.filter(item=>item?.relation===relation&&item?.name===name),`${rule.id} qualification descriptor ${relation}/${name}`);
}
function proveQualifiedText(rule,field,expected,candidate,catalog){
 const candidateText=candidate[field]??candidate.definition;
 const left=qualificationTokens(expected,`${rule.id}.${field} expected`),right=qualificationTokens(candidateText,`${rule.id}.${field} source`);
 const significant=tokens=>tokens.filter(token=>token.kind!=='space');
 const grammar=rule.kind==='constraint'?[['REFERENCES','relation']]:[['ON','relation'],['FUNCTION','function']];
 const describe=(tokens,label)=>{
  const sig=significant(tokens),spans=[];
  for(const [keyword,kind] of grammar){
   const indexes=sig.map((token,index)=>token.kind==='word'&&token.raw.toUpperCase()===keyword?index:-1).filter(index=>index>=0);
   if(keyword==='REFERENCES'&&rule.kind==='constraint'&&indexes.length===0)continue;
   if(indexes.length!==1)fail(`${rule.id} ${field} not qualification-only ${keyword} grammar position`);
   const keywordIndex=indexes[0],first=sig[keywordIndex+1];if(!first||first.kind!=='word')fail(`${rule.id} ${field} not qualification-only ${keyword} target`);
   if(keyword==='FUNCTION'&&sig[keywordIndex-1]?.raw.toUpperCase()!=='EXECUTE')fail(`${rule.id} ${field} not qualification-only EXECUTE FUNCTION grammar position`);
   const qualified=sig[keywordIndex+1]?.raw.toLowerCase()==='public'&&sig[keywordIndex+2]?.raw==='.';
   const target=qualified?sig[keywordIndex+3]:first;
   if(!target||target.kind!=='word')fail(`${rule.id} ${field} not qualification-only ${keyword} target`);
   if(qualified&&target.raw.toLowerCase()==='public')fail(`${rule.id} ${field} not qualification-only ${keyword} target`);
   spans.push({grammar:keyword.toLowerCase(),kind,qualified,qualifierStart:qualified?first.start:null,qualifierEnd:qualified?sig[keywordIndex+2].end:null,targetStart:target.start,targetEnd:target.end,targetRaw:target.raw});
  }
  return {tokens,sig,spans,label};
 };
 const expectedInfo=describe(left,'expected'),candidateInfo=describe(right,'source');
 const candidateCheckFunctions=[];
 if(rule.kind==='constraint'&&candidateInfo.sig.some(token=>token.raw.toUpperCase()==='CHECK')){
  for(let index=0;index<candidateInfo.sig.length-3;index++){
   const publicToken=candidateInfo.sig[index],dot=candidateInfo.sig[index+1],name=candidateInfo.sig[index+2],open=candidateInfo.sig[index+3];
   if(publicToken.raw.toLowerCase()!=='public'||dot.raw!=='.'||name.kind!=='word'||open.raw!=='(')continue;
   const authority=uniqueQualifiedName(catalog,'function',name.raw,`${rule.id}.${field}.check-function`);
   const nameOccurrence=candidateInfo.sig.slice(0,index).filter((token,position)=>token.kind==='word'&&token.raw===name.raw&&candidateInfo.sig[position+1]?.raw==='(').length;
   candidateCheckFunctions.push({name:name.raw,occurrence:nameOccurrence,authority,span:{grammar:'check-function',kind:'function',qualified:true,authority,qualifierStart:publicToken.start,qualifierEnd:dot.end,targetStart:name.start,targetEnd:name.end,targetRaw:name.raw}});
  }
 }
 for(const source of candidateCheckFunctions){
  const candidates=expectedInfo.sig.map((token,index)=>({token,index})).filter(({token,index})=>token.kind==='word'&&token.raw===source.name&&expectedInfo.sig[index+1]?.raw==='(');
  const expectedSpan=candidates[source.occurrence];if(!expectedSpan)fail(`${rule.id} ${field} semantic difference`);
  expectedInfo.spans.push({grammar:'check-function',kind:'function',qualified:false,qualifierStart:null,qualifierEnd:null,targetStart:expectedSpan.token.start,targetEnd:expectedSpan.token.end,targetRaw:source.name});
  candidateInfo.spans.push(source.span);
 }
 if(expectedInfo.spans.length!==candidateInfo.spans.length)fail(`${rule.id} ${field} grammar difference`);
 const approved=[];
 for(let index=0;index<candidateInfo.spans.length;index++){
  const sourceSpan=candidateInfo.spans[index],expectedSpan=expectedInfo.spans[index];
  if(sourceSpan.kind!==expectedSpan.kind||sourceSpan.targetRaw!==expectedSpan.targetRaw)fail(`${rule.id} ${field} semantic difference`);
  let authority;
  if(rule.kind==='trigger'&&sourceSpan.kind==='relation')authority=candidate.relation;
  else if(rule.kind==='trigger'&&sourceSpan.kind==='function')authority=candidate.function;
  else authority=sourceSpan.kind==='function'&&sourceSpan.grammar==='check-function'?sourceSpan.authority:`public.${sourceSpan.targetRaw}`;
  const qualifiedPartsAuthority=sourceSpan.kind==='function'?splitSignature(authority,`${rule.id}.${field} function authority`):qualifiedParts(authority);
  if(!qualifiedPartsAuthority||(sourceSpan.kind==='function'?qualifiedPartsAuthority.namespace!=='public':qualifiedPartsAuthority[0]!=='public'))fail(`${rule.id} ${field} ${sourceSpan.kind} authority`);
  const authorityName=sourceSpan.kind==='function'?qualifiedPartsAuthority.name:qualifiedPartsAuthority[1];
  if(authorityName!==sourceSpan.targetRaw)fail(`${rule.id} ${field} ${sourceSpan.kind} target`);
  if(sourceSpan.kind==='function')uniqueQualifiedName(catalog,'function',authorityName,`${rule.id}.${field}`,authority);
  else uniqueQualifiedName(catalog,'relation',authorityName,`${rule.id}.${field}`,`public.${authorityName}`);
  approved.push({grammar:sourceSpan.grammar,kind:sourceSpan.kind,catalogIdentity:authority,expected:[expectedSpan.qualifierStart,expectedSpan.qualifierEnd,expectedSpan.targetStart,expectedSpan.targetEnd],source:[sourceSpan.qualifierStart,sourceSpan.qualifierEnd,sourceSpan.targetStart,sourceSpan.targetEnd],qualified:sourceSpan.qualified});
 }
 const remove=(text,info)=>{let output=text;for(const span of info.spans.filter(item=>item.qualified).sort((a,b)=>b.qualifierStart-a.qualifierStart))output=output.slice(0,span.qualifierStart)+output.slice(span.qualifierEnd);return output;};
 if(remove(expected,expectedInfo)!==remove(candidateText,candidateInfo))fail(`${rule.id} ${field} semantic difference`);
 let output=expected;for(const span of candidateInfo.spans.filter(item=>item.qualified).map((item,index)=>({item,expected:expectedInfo.spans[index]})).filter(item=>!item.expected.qualified).sort((a,b)=>b.expected.targetStart-a.expected.targetStart))output=output.slice(0,span.expected.targetStart)+'public.'+output.slice(span.expected.targetStart);
 return {text:output,spans:approved};
}

const qualificationLedger=(rule,row,candidate,status,details={})=>({version:'native16-qualification-v2',status,ruleId:rule.id,kind:rule.kind,captureIdentity:row.identity,rawFactSHA256:sha(canonicalOrderedJSON(row.fact)),catalogSHA256,catalogRelation:candidate?.relation??null,catalogRegprocedure:candidate?.function??null,...details});
const explicitPrettyDeparseRefusals=new Set(['zasp_recovery_audit_check','zasp_recovery_backups_check','zasp_recovery_fairness_last_organization_id_check','zasp_recovery_request_receipts_check','zasp_recovery_restores_check']);
export function qualificationRefusalOrderedCurrentV2(rule,row,reason){
 return qualificationLedger(rule,row,null,'refused',{refusal:String(reason).replace(/^.*?semantic difference/,'semantic difference')});
}

export function canonicalizeOrderedCurrentSourceQualificationV2(rule,row,catalog){
 if(!rule||!row||!catalog||!['constraint','trigger'].includes(rule.kind))fail(`${rule?.id??'unknown'} qualification inputs`);
 const candidate=sourceDefinitionCandidate(rule,row,catalog),fact=row.fact;
 if(!fact||typeof fact!=='object')fail(`${rule.id} qualification fact`);
 // The pinned non-pretty catalog text for this one policy-sequence trigger
 // has an unexplained WHEN-parenthesis layer; qualification alone cannot
 // prove it, so retain the raw fact and leave the mismatch visible.
 if(rule.id==='worker-edge:ordered_projected28:9'&&candidate.name==='zasp_security_agent_targets_policy_sequence')return {...row,source:{...(row.source??{}),qualificationLedger:qualificationLedger(rule,row,candidate,'refused',{refusal:'unexplained-when-parentheses'})}};
 const next={...row,fact:{...fact},source:{...(row.source??{})}};let changed=false;const fields=[];
 for(const field of ['definition','definition_pretty']){
  if(!Object.hasOwn(fact,field)||typeof fact[field]!=='string')continue;
  if(fact[field]===candidate.definition)continue;
  let proof;try{proof=proveQualifiedText(rule,field,fact[field],candidate,catalog);}catch(error){
   if(/not qualification-only/.test(String(error?.message))||rule.id==='worker-edge:gateway_projected27:7'&&explicitPrettyDeparseRefusals.has(candidate.name)&&/semantic difference/.test(String(error?.message))){
    const refusal=rule.id==='worker-edge:gateway_projected27:7'&&explicitPrettyDeparseRefusals.has(candidate.name)?'non-qualification-parentheses-pretty-deparse-no-authority':String(error.message).replace(/^.*?not qualification-only /,'not qualification-only ');
    return {...row,source:{...(row.source??{}),qualificationLedger:qualificationLedger(rule,row,candidate,'refused',{refusal})}};
   }
   throw error;
  }
  next.fact[field]=proof.text;next.source.qualificationTokenSpans??=[];next.source.qualificationTokenSpans.push({field,spans:proof.spans});changed=true;fields.push(field);
 }
 if(rule.kind==='trigger'){
  // The reviewed trigger descriptor emits relation_name from c.relname::text;
  // it is intentionally raw. Only the explicit relation field is a
  // regclass-derived source branch and may be canonicalized here.
  for(const field of ['relation']){
   if(!Object.hasOwn(fact,field)||typeof fact[field]!=='string')continue;
   const qualified=candidate.relation,parts=qualifiedParts(qualified);
   if(!parts)fail(`${rule.id} ${field} relation authority`);
   if(fact[field]!==qualified&&fact[field]!==parts[1])fail(`${rule.id} ${field} relation qualification`);
   if(fact[field]!==qualified){next.fact[field]=qualified;changed=true;fields.push(field);}
  }
 }
 if(!changed)return row;
 next.source.qualificationProof='pinned-catalog-qualification-only';
 next.source.qualificationFields=fields;
 next.source.qualificationDescriptor={kind:rule.kind,relation:candidate.relation,name:candidate.name};
 const provenCatalogIdentities=next.source.qualificationTokenSpans.flatMap(entry=>entry.spans.map(span=>span.catalogIdentity));
 const provenProcedures=provenCatalogIdentities.filter(identity=>typeof identity==='string'&&identity.includes('('));
 next.source.qualificationLedger=qualificationLedger(rule,row,candidate,'accepted',{fields,tokenSpans:next.source.qualificationTokenSpans,catalogRegprocedure:provenProcedures.length===1?provenProcedures[0]:null,catalogIdentities:[...new Set(provenCatalogIdentities)]});
 return next;
}

// Bounded component-test seam. This proves catalog join behavior only; it does
// not admit a capture or create a source-bound projection.
export function testOnlyOrderedCurrentDirectReferenceCatalogIdentityV2(rule,row,catalog){return catalogIdentity(rule,row,catalog);}

// Authoritative catalog-bound key join for the development capture boundary.
// The caller supplies the accepted rule, captured identity, and pinned
// catalog; no live target rows or generated expectations are consulted.
export function canonicalizeOrderedCurrentDirectReferenceIdentityV2(rule,row,catalog){return catalogIdentity(rule,row,catalog);}

function validateSources(contract,coverage){
 const rules=contract.rules,needs=[...contract.workerNeeds,...contract.edgeNeeds];
 if(rules.length!==50||contract.workerNeeds.length!==11||contract.edgeNeeds.length!==39)fail('current rule coverage');
 const ids=new Set();const result=[];
 for(const rule of rules){
  if(ids.has(rule.id))fail('duplicate current rule');ids.add(rule.id);
  const need=one(needs.filter(item=>item.ruleId===rule.id),`${rule.id} current need`);
  const captured=one(coverage.rawRules.filter(item=>item.id===rule.id),`${rule.id} coverage rule`);
  const expectedFields=rule.kind==='routine'&&rule.id.startsWith('worker-edge:runtime_projected50_binding:')?[...rule.fields,...extraRoutineFields]:rule.fields;
  if(!same(captured.originRule,rule)||!same(captured.fields,expectedFields)||captured.kind!==rule.kind||captured.executionFrameId!=='sourceDiscoveryPublic')fail(`${rule.id} coverage binding`);
  for(const field of ['sourceIdentity','sourceSHA256','definitionSHA256','siteSHA256','start','end','frame'])if(!same(captured.sourceSite[field],need[field]))fail(`${rule.id} source site ${field}`);
  if(need.from!==undefined&&captured.from!==need.from)fail(`${rule.id} source FROM`);
  if(need.projections!==undefined){
   const projections=expectedFields.length===rule.fields.length?need.projections:[...need.projections,...extraRoutineProjections];
   if(!same(captured.projections,projections))fail(`${rule.id} source projections`);
  }
  const fieldTypes=Object.fromEntries(rule.fields.map(field=>[field,orderedFactTypes[rule.kind]?.[field]??fail(`${rule.id} field type ${field}`)]));
  result.push({id:rule.id,family:rule.id.startsWith('worker-edge:')?'edge':'worker',kind:rule.kind,fields:rule.fields,fieldTypes,selector:rule.selector,sourceSite:captured.sourceSite,executionFrameId:captured.executionFrameId,keyFrame:'pg_catalog',captureFrame:'original-source-frame'});
 }
 return result;
}

function projectFrame(envelope,rules,catalog){
 const byId=new Map(rules.map(rule=>[rule.id,rule])),rows=[];
 for(const row of envelope.rawInputs){
  const rule=byId.get(row.ruleId);if(!rule)continue;
  if(!plain(row)||!plain(row.fact)||row.multiplicity!==1||typeof row.identity!=='string')fail(`${row.ruleId} capture row`);
  const expected=rule.kind==='routine'&&rule.id.startsWith('worker-edge:runtime_projected50_binding:')?[...rule.fields,...extraRoutineFields]:rule.fields;
  if(!sameFieldSet(row.fact,expected))fail(`${row.ruleId} selected fields`);
  for(const field of extraRoutineFields)if(expected.includes(field)&&!Object.hasOwn(row.fact,field))fail(`${row.ruleId} config witness`);
  const fact=Object.fromEntries(rule.fields.map(field=>[field,row.fact[field]]));
  for(const [field,type] of Object.entries(rule.fieldTypes))if(!typeValid(type,fact[field]))fail(`${row.ruleId} selected field type ${field}`);
  const descriptorIdentity=catalogIdentity(rule,row,catalog);
  const source={ruleId:rule.id,captureIdentity:row.identity,descriptorIdentity,sourceIdentity:rule.sourceSite.sourceIdentity,sourceSHA256:rule.sourceSite.sourceSHA256,definitionSHA256:rule.sourceSite.definitionSHA256,siteSHA256:rule.sourceSite.siteSHA256,executionFrameId:rule.executionFrameId,keyFrame:'pg_catalog',captureFrame:'original-source-frame'};
  if(expected.length!==rule.fields.length)source.fieldWitnesses=Object.fromEntries(extraRoutineFields.map(field=>[field,row.fact[field]]));
  if(rule.kind==='foreign_key_trigger')source.relationshipProof='pinned-source-k.oid=t.tgconstraint';
  rows.push({kind:rule.kind,identity:JSON.stringify([rule.id,descriptorIdentity]),fact,source});
 }
 rows.sort((a,b)=>Buffer.compare(Buffer.from(a.identity),Buffer.from(b.identity)));
 return rows;
}

function assertExactSelectedFactEquality(a,b,rules){
 const ids=new Set(rules.map(rule=>rule.id));
 const selected=envelope=>envelope.rawInputs.filter(row=>ids.has(row.ruleId)).map(row=>JSON.stringify({ruleId:row.ruleId,multiplicity:row.multiplicity,fact:row.fact})).sort();
 const left=selected(a),right=selected(b);
 if(left.length!==1220||!same(left,right))fail('A/B exact unnormalized selected fact multiset');
}

// Schema/integrity check for an already-produced value. This is not admission;
// only projectOrderedCurrentDirectReferenceV2 invokes the pinned intake.
export function assertOrderedCurrentDirectReferenceV2(value){
 if(!plain(value)||value.status!=='SOURCE-BOUND-DIRECT-EXPECTED-PROJECTION'||value.installable!==false||!Array.isArray(value.descriptorRules)||!Array.isArray(value.expectedRows)||Object.hasOwn(value,'facts')||Object.hasOwn(value,'releaseFacts'))fail('result envelope');
 if(value.descriptorRules.length!==50||value.descriptorRules.filter(rule=>rule.family==='worker').length!==11||value.descriptorRules.filter(rule=>rule.family==='edge').length!==39)fail('descriptor rule coverage');
 const rules=new Map();let total=0;
 for(const rule of value.descriptorRules){
  if(!plain(rule)||typeof rule.id!=='string'||rules.has(rule.id)||!Array.isArray(rule.fields)||!plain(rule.fieldTypes)||!plain(rule.sourceSite)||typeof rule.expectedRows!=='number'||rule.expectedRows<0)fail('descriptor rule');
  if(!sameFieldSet(rule.fieldTypes,rule.fields))fail(`${rule.id} descriptor fields`);rules.set(rule.id,rule);total+=rule.expectedRows;
 }
 if(total!==1220||value.expectedRows.length!==total)fail('row count');
 const keys=new Set(),counts=new Map();
 for(const row of value.expectedRows){
  if(!plain(row)||!plain(row.fact)||!plain(row.source)||typeof row.identity!=='string')fail('row');
  const outer=identity(row.identity,'result');if(!Array.isArray(outer)||outer.length!==2||outer[0]!==row.source.ruleId||outer[1]!==row.source.descriptorIdentity)fail('row key');
  if(keys.has(row.identity))fail('duplicate row key');keys.add(row.identity);
  const rule=rules.get(row.source.ruleId);if(!rule||row.kind!==rule.kind||!sameFieldSet(row.fact,rule.fields))fail('row rule fields');
  for(const [field,type] of Object.entries(rule.fieldTypes))if(!typeValid(type,row.fact[field]))fail('row field type');
  if(row.source.siteSHA256!==rule.sourceSite.siteSHA256||row.source.sourceIdentity!==rule.sourceSite.sourceIdentity||row.source.sourceSHA256!==rule.sourceSite.sourceSHA256||row.source.definitionSHA256!==rule.sourceSite.definitionSHA256||row.source.executionFrameId!==rule.executionFrameId||row.source.keyFrame!=='pg_catalog'||row.source.captureFrame!=='original-source-frame'||typeof row.source.captureIdentity!=='string')fail('row source frame');
  const needsWitnesses=rule.kind==='routine'&&rule.id.startsWith('worker-edge:runtime_projected50_binding:');
  if(needsWitnesses?!sameFieldSet(row.source.fieldWitnesses,extraRoutineFields):Object.hasOwn(row.source,'fieldWitnesses'))fail('row field witnesses');
  if((rule.kind==='foreign_key_trigger')!==(row.source.relationshipProof==='pinned-source-k.oid=t.tgconstraint'))fail('row relationship proof');
  counts.set(rule.id,(counts.get(rule.id)??0)+1);
 }
 for(const rule of value.descriptorRules)if((counts.get(rule.id)??0)!==rule.expectedRows)fail(`${rule.id} row count`);
 return value;
}

export function projectOrderedCurrentDirectReferenceV2(input){
 if(!exactObject(input,inputFields)||!Buffer.isBuffer(input.catalogRaw))fail('input fields');
 if(sha(input.catalogRaw)!==catalogSHA256)fail('catalog identity');
 const intake=admitOrderedCurrentReferenceIntakeV2(Object.fromEntries(inputFields.filter(field=>field!=='catalogRaw').map(field=>[field,input[field]])));
 for(const frame of ['A','B'])if(intake.observations[frame].sourcePins[catalogPin]!==catalogSHA256)fail('catalog source pin');
 const source=parse(input.sourceContractRaw,'source contract'),coverage=parse(input.coverageRaw,'coverage'),catalog=parse(input.catalogRaw,'catalog');
 if(catalog.format!=='zasp-worker-effective-catalog-v2')fail('catalog format');
 const contract=buildOrderedConsolidationNeeds(source,catalog).contract,descriptorRules=validateSources(contract,coverage);
 assertExactSelectedFactEquality(intake.observations.A,intake.observations.B,descriptorRules);
 const aRows=projectFrame(intake.observations.A,descriptorRules,catalog);
 const counts=new Map();for(const row of aRows)counts.set(row.source.ruleId,(counts.get(row.source.ruleId)??0)+1);
 for(const rule of descriptorRules)rule.expectedRows=counts.get(rule.id)??0;
 return assertOrderedCurrentDirectReferenceV2({status:'SOURCE-BOUND-DIRECT-EXPECTED-PROJECTION',installable:false,descriptorRules,expectedRows:aRows,provenance:{catalogSHA256,source:intake.source,comparison:intake.comparison,allowances:intake.allowances,frames:intake.provenance,frameComparison:{mode:'exact-unnormalized-selected-fact-multisets',rules:50,rows:1220,normalizationApplied:false},canonicalKeySource:'admitted-A-pinned-catalog-join',disposition:'original-source-frame-observations-with-separate-canonical-descriptor-keys;not-live-pg_catalog-equivalence'}});
}
