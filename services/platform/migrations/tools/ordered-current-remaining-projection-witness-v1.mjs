// Fixed source-only proof. Original captures, collector semantics and historical
// refusal APIs are never modified. Native-log metadata is not expected authority.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON,orderedFactTypes} from './build-ordered-current-integrity.mjs';
import {parseOrderedCurrentCaptureJSONV1} from './ordered-current-capture-intake-v1.mjs';
const fail=message=>{throw Error('ordered-current remaining projection '+message);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const same=(a,b)=>canonicalOrderedJSON(a)===canonicalOrderedJSON(b);
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const pins=Object.freeze({catalogRaw:'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',contractRaw:'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',directRaw:'c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab',missingRaw:'76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39',remainingRaw:'cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797'});
const byteCaps=Object.freeze({catalogRaw:33554432,contractRaw:16777216,directRaw:16777216,missingRaw:1048576,remainingRaw:16777216});
const referenceRaw=fs.readFileSync(new URL('./ordered-current-remaining-projection-witness-v1-artifacts/reference.json',import.meta.url));
export const remainingProjectionReferenceSHA256='3711750bab518ee5fc8f02e8b08e61a3a8ed6f3497ea109e03e9a42764b57701';
if(referenceRaw.length>65536||sha(referenceRaw)!==remainingProjectionReferenceSHA256)fail('fixed reference authority');
const reference=freeze(parseOrderedCurrentCaptureJSONV1(referenceRaw,{maxBytes:65536}));
const proofs=new WeakSet();
const one=(rows,label)=>{if(rows.length!==1)fail(label+' unique catalog/source join ('+rows.length+')');return rows[0];};
const keys=(value,want)=>value&&typeof value==='object'&&!Array.isArray(value)&&same(Object.keys(value).sort(),[...want].sort());
function fields(fact,kind,want){
 if(!keys(fact,Object.keys(want)))fail('selected field schema');
 for(const field of Object.keys(want)){
  const type=orderedFactTypes[kind]?.[field];
  if(fact[field]===null||!['string','boolean'].includes(type)||typeof fact[field]!==type)fail('selected field type/nullability '+field);
 }
}
function helperProof(contract,witness){
 const helper=witness.helper,node=one(contract.nodes.filter(n=>n.identity===helper.identity),'helper');
 if(node.sourceSHA256!==helper.sourceSHA256||node.definitionSHA256!==helper.definitionSHA256||sha(node.source)!==helper.sourceSHA256||sha(node.definition)!==helper.definitionSHA256||!same(Object.fromEntries(Object.keys(helper.frame).map(k=>[k,node[k]])),helper.frame)||node.owner!=='zasp_discovery_authority'||!same(node.config,['search_path=pg_catalog, public'])||node.security_definer!==(witness.collection==='missing'))fail('helper source/frame');
 const bytes=Buffer.from(node.source),site=helper.site;
 if(!Number.isSafeInteger(site.start)||!Number.isSafeInteger(site.end)||site.start<0||site.end<=site.start||site.end>bytes.length||sha(bytes.subarray(site.start,site.end))!==site.siteSHA256||bytes.subarray(site.start,site.end).toString()!==site.text)fail('source site');
 if(witness.kind==='constraint'&&!site.text.includes('pg_get_constraintdef(constraint_value.oid,true)'))fail('pretty constraint expression');
 if(witness.collection==='direct'&&witness.kind==='trigger'&&!site.text.includes('pg_get_triggerdef(trigger.oid,true)'))fail('pretty trigger expression');
 if(witness.collection==='missing'&&(!site.text.includes("regexp_replace(pg_get_triggerdef(trigger_value.oid,true),E'\\s+',' ','g')")||!site.text.includes('trigger_value.tgfoid::regprocedure::text')||!site.text.includes("n.nspname='public'")||!site.text.includes("trigger_value.tgname LIKE 'zasp_execution_%'")||!site.text.includes('NOT trigger_value.tgisinternal')))fail('temporal original expression/selector');
}
// Tokenize the complete pretty string, retaining offsets. Comments, quoted
// identifiers and unsupported lexemes are refused, not searched through.
function tokens(text){
 if(typeof text!=='string'||text.length>4096)fail('pretty text bound');
 const out=[];let offset=0;
 while(offset<text.length){
  const start=offset,rest=text.slice(offset),space=/^\s+/.exec(rest);if(space){offset+=space[0].length;continue;}
  if(rest.startsWith('--')||rest.startsWith('/*')||rest.startsWith('"'))fail('pretty quoted/comment lookalike');
  const token=/^(?:[A-Za-z_][A-Za-z_0-9$]*|'(?:[^']|'')*'|::|[(),.=])/.exec(rest)?.[0];
  if(!token)fail('pretty unsupported token');offset+=token.length;out.push({text:token,start,end:offset});
 }
 return out;
}
function qualify(text,witness,catalog){
 const lex=tokens(text),spans=[];
 if(witness.kind==='constraint'){
  if(lex[0]?.text!=='CHECK'||lex[1]?.text!=='('||lex.at(-1)?.text!==')')fail('CHECK grammar anchor');
  const fn=one(catalog.functions.filter(f=>f.identity==='public.zasp_valid_product_id(text)'),'CHECK signature');
  for(const [i,t] of lex.entries())if(t.text==='zasp_valid_product_id'){
   if(lex[i+1]?.text!=='('||!['(','AND','OR'].includes(lex[i-1]?.text)||!/^[a-z_]+$/.test(lex[i+2]?.text??'')||lex[i+3]?.text!==')')fail('CHECK call grammar');
   spans.push({start:t.start,targetIdentity:fn.identity,anchor:'CHECK function call'});
  }
 }else{
  if(lex[0]?.text!=='CREATE'||lex[1]?.text!=='TRIGGER')fail('trigger grammar');
  const on=lex.map((t,i)=>t.text==='ON'?i:-1).filter(i=>i>=0),execute=lex.map((t,i)=>t.text==='EXECUTE'?i:-1).filter(i=>i>=0),functions=lex.filter(t=>t.text==='FUNCTION');
  if(on.length!==1||execute.length!==1||functions.length!==1||lex[execute[0]+1]?.text!=='FUNCTION'||on[0]>=execute[0])fail('trigger anchor multiplicity');
  const relation=one(catalog.relations.filter(r=>r.identity===witness.keyProof.relationIdentity),'ON relation');
  const object=one(catalog.triggers.filter(t=>t.relation===relation.identity&&t.name===witness.keyProof.objectName&&t.internal===false),'trigger selector');
  const fn=one(catalog.functions.filter(f=>f.identity===object.function&&f.arguments===''&&f.result==='trigger'),'EXECUTE signature');
  if(witness.collection==='direct'&&(lex[on[0]+1]?.text!==relation.identity.slice(7)||lex[execute[0]+2]?.text!==fn.identity.slice(7,-2)||lex[execute[0]+3]?.text!=='('||lex[execute[0]+4]?.text!==')'))fail('trigger identifier grammar');
  spans.push({start:lex[on[0]].end+1,targetIdentity:relation.identity,anchor:'ON relation'},{start:lex[execute[0]+1].end+1,targetIdentity:fn.identity,anchor:'EXECUTE FUNCTION'});
 }
 if(!same(spans,witness.spans)||!spans.length)fail('fixed grammar-anchored token spans');
 let candidate=text;for(const span of [...spans].reverse())candidate=candidate.slice(0,span.start)+'public.'+candidate.slice(span.start);
 let inverse=candidate;for(let i=spans.length-1;i>=0;i--){const start=spans[i].start+7*i;if(inverse.slice(start,start+7)!=='public.')fail('inverse qualifier');inverse=inverse.slice(0,start)+inverse.slice(start+7);}
 if(inverse!==text)fail('inverse bytes');return candidate;
}
export function proveRemainingProjectionV1(input){
 if(arguments.length!==1||!keys(input,Object.keys(pins)))fail('input authority envelope');
 for(const [name,pin] of Object.entries(pins))if(!Buffer.isBuffer(input[name])||input[name].length>byteCaps[name]||sha(input[name])!==pin)fail(name+' authority');
 const parsed=Object.fromEntries(Object.entries(input).map(([k,v])=>[k,parseOrderedCurrentCaptureJSONV1(v,{maxBytes:byteCaps[k]})]));
 const {catalogRaw:catalog,contractRaw:contract,directRaw:direct,missingRaw:missing,remainingRaw:remaining}=parsed;
 if(reference.records.length!==8||reference.records.filter(r=>r.collection==='direct').length!==6||reference.records.filter(r=>r.collection==='missing').length!==2||!same(reference.inputSHA256,pins))fail('fixed eight-row roster');
 const temporal=one(missing.observations.filter(o=>o.ruleId==='temporal72:trigger'),'temporal observation');
 if(temporal.rows.length!==2||remaining.rows.filter(r=>JSON.parse(r.identity)[0]==='temporal72:trigger').length!==2)fail('temporal multiplicity');
 for(const witness of reference.records){
  helperProof(contract,witness);
  const [ruleId,sourceAlias]=JSON.parse(witness.sourceIdentity),[relation,name]=witness.collection==='missing'?JSON.parse(sourceAlias):JSON.parse(JSON.parse(witness.canonicalIdentity)[1]);
  const relationIdentity=one(catalog.relations.filter(r=>r.identity==='public.'+(witness.collection==='missing'?relation:witness.sourceFact.relation_name)),'public relation').identity;
  const object=one(catalog[witness.kind==='constraint'?'constraints':'triggers'].filter(r=>r.relation===relationIdentity&&r.name===name),'named object');
  const canonicalIdentity=canonicalOrderedJSON([ruleId,canonicalOrderedJSON([object.relation,object.name])]);
  if(canonicalIdentity!==witness.canonicalIdentity)fail('descriptor-derived key');
  let fact;
  if(witness.collection==='direct'){
   const row=one(direct.directFrame.expectedRows.filter(r=>r.kind===witness.kind&&r.identity===canonicalIdentity),'source pretty row');
   const rule=one(direct.directFrame.descriptorRules.filter(r=>r.id===ruleId),'source descriptor');
   if(!same(row.source,witness.sourceProvenance)||row.source.captureIdentity!==sourceAlias||row.source.executionFrameId!=='sourceDiscoveryPublic'||!same(rule.fields.slice().sort(),Object.keys(witness.sourceFact).sort())||rule.sourceSite.siteSHA256!==witness.helper.site.siteSHA256)fail('source helper/site/provenance');
   fact=row.fact;
  }else{
   const row=one(temporal.rows.filter(r=>r.identity===sourceAlias),'temporal source alias');fact=row.fields;
   if(!keys(fact,['relation_name','name','enabled','function','execution_definition'])||fact.relation_name!==relation||fact.name!==name||object.internal!==false||!name.startsWith('zasp_execution_')||object.enabled!==fact.enabled)fail('temporal selected-field selector');
   const fn=one(catalog.functions.filter(f=>f.identity===object.function&&f.arguments===''&&f.result==='trigger'),'temporal regprocedure signature');
   if(fact.function!==fn.identity.slice(7)||witness.canonicalFact.function!==fn.identity)fail('temporal function proof');
   const existing=one(remaining.rows.filter(r=>r.kind==='trigger'&&r.identity===canonicalIdentity),'existing qualified reference');
   if(!same(existing.fact,witness.canonicalFact)||existing.identity!==witness.existingIdentity)fail('complete existing qualified fact');
  }
  fields(fact,witness.kind,witness.sourceFact);
  if(!same(fact,witness.sourceFact)||sha(canonicalOrderedJSON(fact))!==witness.sourceFactSHA256)fail('full selected source fact');
  const field=witness.collection==='direct'?'definition_pretty':'execution_definition',candidate={...fact,[field]:qualify(fact[field],witness,catalog)};
  if(witness.collection==='missing')candidate.function=object.function;
  if(!same(candidate,witness.canonicalFact)||sha(canonicalOrderedJSON(candidate))!==witness.canonicalFactSHA256)fail('fixed complete candidate witness');
 }
 // No caller-visible copy is emitted until every source/field/key proof passes.
 const proof=freeze({...structuredClone(reference),referenceSHA256:remainingProjectionReferenceSHA256});proofs.add(proof);return proof;
}
export function applyRemainingProjectionV1(input){
 if(arguments.length!==1||!keys(input,['proof','directFacts','missingFacts'])||!proofs.has(input.proof))fail('authenticated proof authority');
 const {proof,directFacts,missingFacts}=input;
 for(const [collection,rows,count] of [['direct',directFacts,1600],['missing',missingFacts,204]]){
  if(!Array.isArray(rows)||rows.length!==count||new Set(rows.map(r=>r.identity)).size!==count)fail('application collection multiplicity');
  if(Buffer.byteLength(canonicalOrderedJSON(rows))>16777216)fail('application collection byte bound');
  for(const witness of proof.records.filter(r=>r.collection===collection)){
   const matches=rows.filter(r=>r.identity===witness.sourceIdentity||r.identity===witness.canonicalIdentity);
   const row=one(matches,'application source/canonical row');
   if(rows[witness.sourceIndex]!==row)fail('application original source index');
   if(row.kind!==witness.kind||!same(row.fact,witness.sourceFact))fail('application selected source contract');
  }
 }
 const project=(rows,collection)=>rows.map(row=>{
  const witness=proof.records.find(r=>r.collection===collection&&(r.sourceIdentity===row.identity||r.canonicalIdentity===row.identity));
  if(!witness)return row;
  return {...row,identity:witness.canonicalIdentity,fact:structuredClone(witness.canonicalFact),source:{...row.source,remainingProjection:{version:proof.version,referenceSHA256:proof.referenceSHA256,sourceIdentity:witness.sourceIdentity,canonicalIdentity:witness.canonicalIdentity,disposition:witness.disposition,sourceFactSHA256:witness.sourceFactSHA256,canonicalFactSHA256:witness.canonicalFactSHA256,historicalQualificationDisposition:row.source?.qualificationLedger?.status??'not-applicable'}}};
 });
 return {directFacts:project(directFacts,'direct'),missingFacts:project(missingFacts,'missing')};
}
