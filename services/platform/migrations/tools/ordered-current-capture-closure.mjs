// Source-indexed capture preparation. Refuse incomplete mappings; unsupported
// recipes are diagnostic obligations, never coverage or expected truth.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {buildOrderedConsolidationNeeds} from './ordered-current-consolidation-needs.mjs';
import {lowerOrderedWorkerProjections} from './ordered-current-worker-projections.mjs';
import {lowerOrderedWorkerEdgeProjections} from './ordered-current-worker-edge-projections.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {lowerOrderedTemporal77Transforms} from './ordered-current-temporal77-transforms.mjs';
import {lowerOrderedMixedTransforms} from './ordered-current-mixed-transforms.mjs';
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
import {lowerOrderedProductCatalog} from './ordered-current-product-selectors.mjs';
import {lowerOrderedRuntimeCatalog} from './ordered-current-runtime-selectors.mjs';
import {buildOrderedSpecialCatalogCapture} from './ordered-current-capture-special-catalogs.mjs';
import {buildOrderedWrapperCaptureInputs} from './ordered-current-capture-wrapper-inputs.mjs';
import {buildOrderedRecursiveCaptureInputs} from './ordered-current-capture-recursive-inputs.mjs';
import {lowerOrderedWorkerCatalog} from './ordered-current-worker-selectors.mjs';
import {buildOrderedPriorCaptureInputs} from './ordered-current-capture-prior-inputs.mjs';
import {buildOrderedMaterializedCaptureInputs} from './ordered-current-capture-materialized-inputs.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const base=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const artifactNames=Object.freeze({'ordered-current-effective-contract3.json':'effective-contract3.json','ordered-current-effective-catalog1.json':'effective-catalog1.json','ordered-current-inventory-compiled.json':'inventory-compiled.json','ordered-current-supplementary-reference1.json':'supplementary-reference1.json','ordered-current-remaining-reference1.json':'remaining-reference1.json','ordered-current-private-reference-alias1.json':'private-reference-alias1.json'});
const fixed={
 'ordered-current-effective-contract3.json':'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',
 'ordered-current-effective-catalog1.json':'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',
 'ordered-current-inventory-compiled.json':'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
 'ordered-current-supplementary-reference1.json':'484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b',
 'ordered-current-remaining-reference1.json':'cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797',
 'ordered-current-private-reference-alias1.json':'15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607'
};
const supportPins={
 'services/platform/migrations/sql/0079_production_authorization_projection.up.sql':'8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987',
 'services/platform/migrations/sql/0080_authorization_hierarchy_create.sql':'97482f048fb4ee282bd4f8506f618b83b1252d5afce267ad3b36edcc8a33d46e',
 'services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql':'06ed7d1310bee92bfd80c92698b91c18e3932a573793dcb32344a3fea56831b8',
 'services/platform/migrations/sql/0027_production_recovery.up.sql':'0e4dcbaf987cc3b5f69cf4d415a028d643c2f95bf5160e827e1607e3f60dbc14'
};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function pinned(name){const tracked=artifactNames[name];if(!tracked)throw Error('capture source authority '+name);const raw=fs.readFileSync(new URL(tracked,base));if(sha(raw)!==fixed[name])throw Error('capture source pin '+name);return JSON.parse(raw);}
function admitted(input){
 if(!input||Object.keys(input).sort().join(',')!=='acceptedEvidence,catalog,sourceContract')throw Error('capture source input shape');
 const source=pinned('ordered-current-effective-contract3.json'),catalog=pinned('ordered-current-effective-catalog1.json'),compiled=pinned('ordered-current-inventory-compiled.json');
 if(!same(input.sourceContract,source)||!same(input.catalog,catalog)||sha(compiled.source)!=='233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850')throw Error('capture source identity pin');
 for(const name of Object.keys(fixed).filter(n=>/reference1|alias1|catalog1/.test(n))){const raw=input.acceptedEvidence?.[name];if(!Buffer.isBuffer(raw)||sha(raw)!==fixed[name])throw Error('capture evidence pin '+name);}
 return {source,catalog};
}
function frame(node){return Object.fromEntries(['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'].map(k=>[k,node[k]]));}
function sourceSite(source,identity,start,end){
 const n=source.nodes.find(n=>n.identity===identity);if(!n)throw Error('capture source identity '+identity);
 const body=Buffer.from(n.source),text=body.subarray(start,end).toString('utf8');
 return {identity,sourceSHA256:n.sourceSHA256,definitionSHA256:n.definitionSHA256,start,end,text,sha256:sha(text),frame:frame(n)};
}
function projections(text){
 const start=text.indexOf('concat_ws(');if(start<0)return null;let depth=1,quote=false,begin=start+10;const parts=[];
 for(let i=begin;i<text.length;i++){const c=text[i];if(c==="'"){if(quote&&text[i+1]==="'"){i++;continue;}quote=!quote;continue;}if(quote)continue;if(c==='(')depth++;else if(c===')'&&--depth===0){parts.push(text.slice(begin,i).trim());return {fields:parts.slice(2),from:text.slice(i+1).trim()};}else if(c===','&&depth===1){parts.push(text.slice(begin,i).trim());begin=i+1;}}
 throw Error('capture source expression boundary');
}
function anchor(site){return {sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,start:site.start,end:site.end,frame:structuredClone(site.frame)};}
function firstArgument(expression,name){
 const prefix=name+'(';if(!expression.startsWith(prefix))return null;let depth=0,quote=false;
 for(let i=prefix.length;i<expression.length;i++){const c=expression[i];if(c==="'"){if(quote&&expression[i+1]==="'"){i++;continue;}quote=!quote;continue;}if(quote)continue;if(c==='(')depth++;if(c===')')depth--;if(c===','&&depth===0)return expression.slice(prefix.length,i).trim();}
 throw Error('capture replacement source boundary');
}
function rawExpression(expression){let next;while((next=firstArgument(expression,'replace'))!==null)expression=next;return expression;}
// Locate complete SELECT concat_ws branches in pinned source. Inventory lines
// can split CASE expressions; this scanner only finds lexical boundaries and
// never interprets caller SQL or rewrites a selector.
function sourceMask(text){
 let mask='';for(let i=0;i<text.length;){const start=i,c=text[i];
  if(c==="'"){const escaped=/[eE]/.test(text[i-1]??'')&&!/[a-z_0-9$]/i.test(text[i-2]??'');i++;while(i<text.length){if(text[i]==="'"){if(text[i+1]==="'"){i+=2;continue;}i++;break;}if(escaped&&text[i]==='\\')i+=2;else i++;}mask+=' '.repeat(i-start);continue;}
  if(text.slice(i,i+2)==='--'){const end=text.indexOf('\n',i);i=end<0?text.length:end;mask+=' '.repeat(i-start);continue;}
  if(c==='$'){const tag=text.slice(i).match(/^\$(?:[a-z_][a-z_0-9]*)?\$/i)?.[0];if(tag){const end=text.indexOf(tag,i+tag.length);if(end<0)throw Error('capture source dollar boundary');i=end+tag.length;mask+=' '.repeat(i-start);continue;}}
  mask+=c;i++;
 }
 return mask;
}
function concatBranches(text){
 const mask=sourceMask(text),result=[];for(const match of mask.matchAll(/\bSELECT\s+concat_ws\s*\(/gi)){
  let depth=0,end=text.length;for(let i=match.index;i<mask.length;i++){const c=mask[i];if(c==='(')depth++;else if(c===')'){if(depth===0){end=i;break;}depth--;}else if(depth===0&&/^UNION\b/i.test(mask.slice(i))){end=i;break;}}
  const raw=text.slice(match.index,end).trimEnd();result.push({start:Buffer.byteLength(text.slice(0,match.index)),end:Buffer.byteLength(text.slice(0,match.index+raw.length)),text:raw});
 }return result;
}
function materializedCTEs(text){
 const mask=sourceMask(text),result=[];
 for(const match of mask.matchAll(/\b((?:higher|readiness)_[a-z0-9]+)\s*\(\s*value\s*\)\s+AS\s+(?:MATERIALIZED\s*)?\(/g)){
  const open=match.index+match[0].length-1;let depth=1,end=open+1;
  for(;end<mask.length&&depth;end++){if(mask[end]==='(')depth++;else if(mask[end]===')')depth--;}
  if(depth)throw Error('capture materialized CTE boundary');
  result.push({name:match[1],start:Buffer.byteLength(text.slice(0,open+1)),end:Buffer.byteLength(text.slice(0,end-1)),text:text.slice(open+1,end-1)});
 }return result;
}
// Only locate the top-level FROM of an already source-pinned branch. This is
// not a caller SQL parser: nested ACL/select expressions keep their own FROM.
function branchFrom(text){text=text.replace(/^\s*WITH objects AS\s*\(/,'');let depth=0,quote=false;for(let i=0;i<text.length;i++){
 const c=text[i];if(c==="'"){if(quote&&text[i+1]==="'"){i++;continue;}quote=!quote;continue;}if(quote)continue;
 if(c==='(')depth++;else if(c===')')depth--;else if(depth===0&&/^FROM\b/i.test(text.slice(i))&&(i===0||/\s/.test(text[i-1])))return text.slice(i).trim();
}throw Error('capture top-level FROM boundary');}
function explicitProjection(rule,site){
 if(rule.id==='runtime:candidate_authority:index')return {fields:['indexrelid::regclass::text','indisvalid','indisready','indislive','pg_get_indexdef(indexrelid)'],names:['projected_identity',...rule.fields],from:branchFrom(site.text)};
 const execution=rule.id.startsWith('temporal:72.retained_execution_fingerprint:');
 const inventory=rule.id.startsWith('public:inventory:');if(!execution&&!inventory)return null;
 const a=execution?'a':'attribute',d=execution?'d':'default_value';
 const kind=rule.id.split(':').at(-1),map={
  column:[`format_type(${a}.atttypid,${a}.atttypmod)`,`${a}.attnotnull`,`COALESCE(pg_get_expr(${d}.adbin,${d}.adrelid,true),'')`],
  constraint:['pg_get_constraintdef(constraint_value.oid,true)'],
  index:[execution?'pg_get_indexdef(index_value.indexrelid,0,true)':'pg_get_indexdef(index_value.oid)'],
  trigger:['pg_get_triggerdef(trigger_value.oid,true)']
 };
 return map[kind]?{fields:map[kind],names:rule.fields,from:branchFrom(site.text)}:null;
}
function helperDemand(expression,call){
 expression=expression.trim();if(expression===call)return 'true';if(!expression.includes(call))return 'false';
 if(!/^CASE\b/.test(expression))throw Error('capture helper demand expression');
 const tokens=[];let quote=false,paren=0,nesting=0;
 for(let i=0;i<expression.length;i++){const c=expression[i];if(c==="'"){if(quote&&expression[i+1]==="'"){i++;continue;}quote=!quote;continue;}if(quote)continue;if(c==='('){paren++;continue;}if(c===')'){paren--;continue;}if(paren||i>0&&/[a-z_0-9]/i.test(expression[i-1]))continue;const word=expression.slice(i).match(/^(CASE|WHEN|THEN|ELSE|END)\b/)?.[1];if(!word)continue;if(word==='CASE')nesting++;if(nesting===1&&word!=='CASE')tokens.push({word,start:i,end:i+word.length});if(word==='END')nesting--;i+=word.length-1;}
 let result='CASE';for(let i=0;i<tokens.length;i++){const t=tokens[i];if(t.word==='WHEN'){const then=tokens[++i],next=tokens[i+1];if(then?.word!=='THEN'||!next)throw Error('capture helper CASE correspondence');result+=' WHEN '+expression.slice(t.end,then.start).trim()+' THEN '+helperDemand(expression.slice(then.end,next.start),call);}else if(t.word==='ELSE'){const end=tokens[++i];if(end?.word!=='END')throw Error('capture helper CASE else');result+=' ELSE '+helperDemand(expression.slice(t.end,end.start),call);} }
 return result+' END';
}
const workerFields={
 'worker:projected_domain:trigger':['relation_name','name','enabled','trigger_definition','definition','owner','acl'],
 'worker:projected_temporal_profile:function':['projected_identity','owner','acl','definition'],
 'worker:projected62:function':['name','identity_arguments','owner','acl','definition'],
 'worker:projected68:function':['name','identity_arguments','owner','acl','definition'],
 'worker:projected69:function':['name','identity_arguments','owner','acl','definition'],
 'worker:projected72:function':['name','identity_arguments','owner','acl','definition'],
 'worker:projected72:precision-handoff':['owner','acl','definition'],
 'worker:projected72:bulk-handoff':['projected_identity','owner','acl','definition'],
 'worker:projected78:function':['name','identity_arguments','owner','acl','definition'],
 'worker:projected78:effective-predecessor':['projected_identity','owner','acl','definition'],
 'worker:projected79:function':['name','owner','acl','definition'],
 'worker:projected79:view':['name','definition']
};
function derive(source,catalog){
 for(const [path,pin]of Object.entries(supportPins))if(sha(fs.readFileSync(new URL('../../../../'+path,import.meta.url)))!==pin)throw Error('capture support source pin '+path);
 const prior=buildOrderedConsolidationNeeds(source,catalog).contract;
 const worker=lowerOrderedWorkerProjections(source),edge=lowerOrderedWorkerEdgeProjections(source),temporal=lowerOrderedTemporalCatalog(source),pub=lowerOrderedPublicCatalog(source),product=lowerOrderedProductCatalog(source),runtime=lowerOrderedRuntimeCatalog(source);
 const transforms=[lowerOrderedTemporalTransforms(source),lowerOrderedPublicFunctionTransforms(source),lowerOrderedTemporal77Transforms(source),lowerOrderedMixedTransforms(source)];
 // Older lowerers carry only the frame fields their own recipes inspect.
 // Capture evidence always binds the complete pinned invocation frame.
 for(const component of [worker,edge,temporal,pub,product,runtime,...transforms])for(const site of component.sites)Object.assign(site,sourceSite(source,site.identity,site.start,site.end));
 const entries=[],rawRules=[],unresolved=[],liveWitnesses=[],retainedOpaque=[],runtimeAlgebra=[];
 const byIdentity=new Map(source.nodes.map(n=>[n.identity,n]));
 const missing=(site,field,reason,demandPath)=>unresolved.push({...anchor(site),expressionOrdinal:0,field,sourceExpression:site.text,selector:null,demandPath,reason});
 for(const need of [...prior.workerNeeds,...prior.edgeNeeds]){
  const site=sourceSite(source,need.sourceIdentity,need.start,need.end),p=projections(site.text);
  if(site.sha256!==need.siteSHA256)throw Error('capture source span '+need.ruleId);
  if(!p||p.fields.length!==need.fields.length){missing(site,'field-correspondence','source projection count requires explicit field mapping',[need.ruleId]);continue;}
  const rule=prior.rules.find(r=>r.id===need.ruleId);
  rawRules.push({id:rule.id,kind:rule.kind,fields:[...rule.fields],originRule:structuredClone(rule),sourceSite:anchor(site),sourceMaxRows:need.sourceMaxRows,sourceMaxRowsBasis:need.sourceMaxRowsBasis,refusalMaxRows:10000,projections:p.fields,from:p.from});
  need.fields.forEach((field,expressionOrdinal)=>entries.push({...anchor(site),expressionOrdinal,field,sourceExpression:p.fields[expressionOrdinal],selector:structuredClone(need.selector),demandPath:[need.ruleId],disposition:'capture',evidence:{phase:'original',ruleId:rule.id,field}}));
 }
 const closedSites=new Set(rawRules.map(r=>r.sourceSite.siteSHA256));
 for(const component of [worker,temporal,pub,product,runtime])for(const rule of component.rules){
  if(rawRules.some(r=>r.id===rule.id)||rule.id.startsWith('worker:projected74:'))continue;
  const s=component.sites.find(s=>s.ruleId===rule.id||rule.id===['worker',s.family,s.type].join(':')||rule.id===['temporal',s.family,s.type].join(':')||rule.id===['public',s.family,s.type].join(':')||rule.id===['product',s.family,s.type].join(':')||rule.id===['runtime',s.family,s.type].join(':'));
  if(!s)throw Error('capture source descriptor site absent '+rule.id);
  const p=explicitProjection(rule,s)??projections(s.text),fields=p?.names??rule.fields;if(!p||p.fields.length!==fields.length){missing(s,'field-correspondence','explicit field correspondence required for '+rule.id,[rule.id]);continue;}
  rawRules.push({id:rule.id,kind:rule.kind,fields:[...fields],originRule:structuredClone(rule),sourceSite:anchor(s),sourceMaxRows:null,refusalMaxRows:10000,projections:p.fields,from:p.from});closedSites.add(s.sha256);
  fields.forEach((field,expressionOrdinal)=>entries.push({...anchor(s),expressionOrdinal,field,sourceExpression:p.fields[expressionOrdinal],selector:structuredClone(rule.selector??{namespaces:rule.namespaces,identities:rule.identities}),demandPath:[rule.id],disposition:'capture',evidence:{phase:'original',ruleId:rule.id,field}}));
 }
 for(const o of edge.obligations.filter(o=>o.type==='membership-bag')){
  const s=edge.sites.find(s=>s.sha256===o.siteSHA256),fields=['granted_role','member_role','admin_option'];
  if(o.projections.length!==3)throw Error('membership selected tuple shape');
  rawRules.push({id:o.ruleId,kind:'membership_bag',fields,fieldTypes:{granted_role:'text',member_role:'text',admin_option:'boolean'},sourceSite:anchor(s),sourceMaxRows:null,refusalMaxRows:10000,projections:o.projections,from:o.from,bag:true});closedSites.add(s.sha256);
  fields.forEach((field,expressionOrdinal)=>entries.push({...anchor(s),expressionOrdinal,field,sourceExpression:o.projections[expressionOrdinal],selector:{source:o.from},demandPath:[o.ruleId],disposition:'capture',evidence:{phase:'original',ruleId:o.ruleId,field}}));
 }
 // These tables contain source-selected structural rows, not helper verdicts.
 // Raw bag cardinality remains visible even when a later scalar demands one row.
 const savedBags=[
  ['wrapper:runtime-profile','zasp_authorization80.runtime_audit_ready()','zasp_authorization80.runtime_profile',['singleton','name','audit_mode'],['boolean','text','text'],null],
  ['wrapper:audit-source-acl','public.zasp_audit_export_source_acl_ready()','public.zasp_audit_export_source_acl',['singleton','before_state','after_state','workflow_state'],['boolean','json','json','json'],null],
  ['wrapper:principals','zasp_temporal72.roles_ready()','zasp_temporal72.principals',['principal_name','authority_role'],['text','text'],null],
  ['wrapper:retired-authorities','zasp_temporal68.predecessor_ready(text,text)','zasp_temporal66.retired_authorities',['schema_name','original_fingerprint','retired_fingerprint'],['text','text','text'],"schema_name IN ('zasp_ordered_worker63','zasp_ordered_scheduler64')"]
 ];
 for(const [id,identity,table,fields,types,predicate]of savedBags){const n=byIdentity.get(identity),s=sourceSite(source,identity,0,Buffer.byteLength(n.source));
  const from='FROM '+table+(predicate?' WHERE '+predicate:''),projections=fields.map((f,i)=>f+'::'+(types[i]==='json'?'jsonb':types[i]));
  rawRules.push({id,kind:'saved_bag',fields,fieldTypes:Object.fromEntries(fields.map((f,i)=>[f,types[i]])),sourceSite:anchor(s),sourceMaxRows:null,refusalMaxRows:10000,projections,from,bag:true});
  fields.forEach((field,expressionOrdinal)=>entries.push({...anchor(s),expressionOrdinal,field,sourceExpression:projections[expressionOrdinal],selector:{table,predicate},demandPath:[id],disposition:'capture',evidence:{phase:'original',ruleId:id,field}}));
 }
 // Pure replacement constants remain runtime algebra. Record the demanded raw
 // CASE/scalar input before replacing release checksums; SQL scalar cardinality
 // and NULL semantics remain visible. Application calls remain unresolved.
 const recipes=[...worker.recipes.filter(r=>!r.ruleId.startsWith('worker:projected74:')),...edge.recipes,...transforms.flatMap(x=>x.recipes)];
 const seen=new Set();
 for(const r of recipes){if(seen.has(r.ruleId))throw Error('duplicate source recipe '+r.ruleId);seen.add(r.ruleId);const n=byIdentity.get(r.sourceIdentity??(r.ruleId.startsWith('public:discovery_schedule')?'public.zasp_discovery_schedule_replay_live_fingerprint()':r.ruleId==='public:sa_export:saved'?'public.zasp_sa_export_live_fingerprint()':null));
  const candidates=[...worker.sites,...edge.sites,...transforms.flatMap(x=>x.sites)].filter(s=>s.sha256===r.siteSHA256);const s=candidates[0];if(!s||!n&&r.sourceIdentity)throw Error('capture recipe site '+r.ruleId);
  const site=sourceSite(source,s.identity,s.start,s.end),parsed=projections(site.text);const p=r.projections??parsed?.fields??[site.text];
  if(r.ruleId==='public:sa_export:saved')continue; // Split below into raw bag and live observations.
  if(r.ruleId==='worker:projected72:saved'){
   runtimeAlgebra.push({...anchor(site),ruleId:r.ruleId,disposition:'runtime-algebra-required',children:['signature','definition','owner_name','acl'].map(field=>({ruleId:'saved-input:zasp_temporal72.predecessor_functions',field})),helperRule:'wrapper-algebra:zasp_temporal72.migration_helper_identity(text,text,text)',demand:"signature IN('zasp_valid_product_id(text)','zasp_workflow_replay(text,text,text,text,text,text,jsonb)')",equivalenceGate:'preserve helper NULL/invalid marker and live owner binding; no expected helper verdict'});
   closedSites.add(site.sha256);continue;
  }
  let names=workerFields[r.ruleId]??Object.keys(r.fields??{});
  if(r.ruleId.startsWith('worker-edge:'))names=['name','identity_arguments','owner','security_definer','config_text_or_empty','acl','definition'];
  if(r.ruleId==='public:discovery_schedule_replay:function')names=['namespace_name','name','identity_arguments','owner','security_definer','volatility','parallel','strict','leakproof','config_text_or_empty','acl','definition'];
  const captured=[],expressions=[],types={};
  p.forEach((expression,expressionOrdinal)=>{
   const field=names[expressionOrdinal]??'projection-'+expressionOrdinal;let raw=rawExpression(expression);
   // Four pure public helpers contain only source-pinned pg_get_functiondef
   // and fixed replacements. Their input is the original-frame deparse.
   if(/^public\.zasp_(?:sa_attack_lab|sa_export|sa_multistep|sa_webhook)_function_identity\((\w+)\.oid\)$/.test(raw))raw=raw.replace(/^public\.zasp_[a-z_]+_function_identity/,'pg_get_functiondef');
   const writerMatch=raw.match(/zasp_authorization80_worker\.ordered_writer_definition\(((?:p|procedure)\.oid)\)/),writerCall=writerMatch?.[0];
   if(writerCall){
    const helper=edge.helpers[0],demand=helperDemand(raw,writerCall),helperSite=sourceSite(source,helper.identity,0,Buffer.byteLength(helper.source));
    let body=helper.source.trim().replace(/^SELECT\s+/,'').replace(/\bvalue\b/g,writerMatch[1]);
    body=body.replace(/'((?:[^']|'')*)'::regprocedure/g,(cast,literal)=>{
     const ordinal=rawRules.filter(x=>x.id.startsWith(r.ruleId+':helper-resolution:')).length,id=r.ruleId+':helper-resolution:'+ordinal;
     const gated=`(CASE WHEN ${demand} THEN '${literal}' ELSE NULL END)::regprocedure`;
     const fields=['literal','cast','sourceSite','demandPath','resolvedIdentity'],projections=[`'${literal}'`,`'regprocedure'`,`'${helperSite.sha256}'`,`'${r.ruleId}:ordered-writer'`,gated+'::text'];
     const from=parsed.from+(/\bWHERE\b/.test(parsed.from)?' AND ':' WHERE ')+`(${demand})`;
     rawRules.push({id,kind:'resolution',fields,fieldTypes:Object.fromEntries(fields.map(f=>[f,'text'])),projections,from,bag:true,sqlPhase:'resolution',section:'resolutions',sourceSite:anchor(helperSite),sourceMaxRows:null,refusalMaxRows:10000});
     fields.forEach((field,i)=>entries.push({...anchor(helperSite),expressionOrdinal:i,field,sourceExpression:projections[i],selector:{source:from},demandPath:[r.ruleId,'selected-ordered-writer-arm',literal],disposition:'capture',evidence:{phase:'resolution',ruleId:id,field}}));
     return gated;
    });
    raw=raw.replaceAll(writerCall,'('+body+')');
   }
   if(raw==='public.zasp_discovery_schedule_replay_function_identity(p.oid)'){
    const helper=byIdentity.get('public.zasp_discovery_schedule_replay_function_identity(oid)'),hs=sourceSite(source,helper.identity,0,Buffer.byteLength(helper.source));
    const literals=[...helper.source.matchAll(/'((?:[^']|'')*)'::regprocedure/g)].map(x=>x[1]);
    if(literals.length!==2)throw Error('capture schedule fixed branch literals');
    const casts=literals.map(literal=>`(CASE WHEN p.oid IS NOT NULL THEN '${literal}' ELSE NULL END)::regprocedure`);
    raw=`CASE WHEN p.oid IN(${casts.join(',')}) THEN NULL ELSE pg_get_functiondef(p.oid) END`;
    runtimeAlgebra.push({...anchor(hs),ruleId:r.ruleId+':saved-runtime-demand',disposition:'runtime-demanded-resolution-required',children:[{ruleId:'saved-input:zasp_temporal72.predecessor_functions',field:'signature'},{ruleId:'saved-input:zasp_temporal72.predecessor_functions',field:'definition'},{ruleId:'schedule:guard-registration',field:'checksum'},{ruleId:'schedule:guard-registration',field:'fingerprint'}],guard:'unchanged registration EXISTS AND zasp_temporal72.fingerprint() equality',expression:'to_regprocedure(signature)=value',cardinality:'SQL scalar zero=>NULL; multiple=>error; invalid cast errors only under original guard',observedResolution:false,equivalenceGate:'later evaluator equivalence required before expected admission'});
    literals.forEach((literal,index)=>{const id=r.ruleId+':outer-resolution:'+index,fields=['literal','cast','sourceSite','demandPath','resolvedIdentity'],projections=[`'${literal}'`,"'regprocedure'",`'${hs.sha256}'`,`'${r.ruleId}:outer-case'`,casts[index]+'::text'];
     rawRules.push({id,kind:'resolution',fields,fieldTypes:Object.fromEntries(fields.map(f=>[f,'text'])),projections,from:parsed.from,bag:true,sqlPhase:'resolution',section:'resolutions',sourceSite:anchor(hs),sourceMaxRows:null,refusalMaxRows:10000});
     fields.forEach((field,i)=>entries.push({...anchor(hs),expressionOrdinal:i,field,sourceExpression:projections[i],selector:{source:parsed.from},demandPath:[r.ruleId,'outer-case'],disposition:'capture',evidence:{phase:'resolution',ruleId:id,field}}));
    });
   }
   const executable=raw.replace(/'(?:[^']|'')*'/g,'');
   if(!parsed||names.length!==p.length||/\b(?:public\.zasp_|zasp_[a-z0-9_]+\.)[a-z0-9_]+\s*\(/i.test(executable)){
    unresolved.push({...anchor(site),expressionOrdinal,field,sourceExpression:expression,selector:r.selector??null,demandPath:[r.ruleId],reason:'helper-selected raw input and demand mapping not yet closed'});return;
   }
   captured.push(field);expressions.push(raw);types[field]=['security_definer','strict','leakproof'].includes(field)?'boolean':'text?';
   entries.push({...anchor(site),expressionOrdinal,field,sourceExpression:raw,selector:r.selector??{source:parsed.from},demandPath:[r.ruleId],disposition:'capture',evidence:{phase:'original',ruleId:r.ruleId,field}});
  });
  if(captured.length)rawRules.push({id:r.ruleId,kind:r.kind??(r.ruleId.endsWith(':view')?'view':r.ruleId.endsWith(':trigger')?'trigger_routine':'routine'),fields:captured,fieldTypes:types,sourceSite:anchor(site),sourceMaxRows:null,refusalMaxRows:10000,projections:expressions,from:parsed.from});
  if(captured.length===p.length)closedSites.add(site.sha256);
  runtimeAlgebra.push({...anchor(site),ruleId:r.ruleId,disposition:'runtime-algebra-required',children:captured.map(field=>({ruleId:r.ruleId,field}))});
 }
 // Preserve full saved bags behind both text equality and reg-object matching.
 // Repeated consumers share a raw input query; demand paths remain separate.
 const savedTables=new Map();
 for(const r of recipes){const s=[...worker.sites,...edge.sites,...transforms.flatMap(x=>x.sites)].find(s=>s.sha256===r.siteSHA256);if(!s)continue;for(const match of s.text.matchAll(/\bFROM\s+(zasp_[a-z0-9_]+\.(?:predecessor_functions|predecessor_views|functions))/g)){const table=match[1];if(!savedTables.has(table))savedTables.set(table,[]);savedTables.get(table).push({s,ruleId:r.ruleId});}}
 for(const [table,consumers]of savedTables){
  const columns=catalog.columns.filter(c=>c.relation===table),fields=['signature','definition',...['owner_name','acl'].filter(f=>columns.some(c=>c.name===f))];
  if(!columns.some(c=>c.name==='signature')||!columns.some(c=>c.name==='definition'))throw Error('capture saved table shape '+table);
  const id='saved-input:'+table,projections=fields.map(f=>f+'::text'),s=consumers[0].s;
  rawRules.push({id,kind:'saved_bag',fields,fieldTypes:Object.fromEntries(fields.map(f=>[f,'text?'])),sourceSite:anchor(s),sourceMaxRows:null,refusalMaxRows:10000,projections,from:'FROM '+table,bag:true});
  for(const {s,ruleId}of consumers)fields.forEach((field,expressionOrdinal)=>entries.push({...anchor(s),expressionOrdinal,field:'saved.'+table+'.'+field,sourceExpression:field,selector:{table,predicate:null},demandPath:[ruleId,'saved-table-binding'],disposition:'capture',evidence:{phase:'original',ruleId:id,field}}));
 }
 const addRaw=(s,id,kind,columns,from,extra={})=>{
  const fields=columns.map(x=>x[0]),rule={id,kind,fields,fieldTypes:Object.fromEntries(columns.map(x=>[x[0],x[2]])),projections:columns.map(x=>x[1]),from,sourceSite:anchor(s),sourceMaxRows:null,refusalMaxRows:10000,...extra};
  rawRules.push(rule);closedSites.add(s.sha256);
  columns.forEach(([field,sourceExpression],expressionOrdinal)=>entries.push({...anchor(s),expressionOrdinal,field,sourceExpression,selector:{source:from},demandPath:[id],disposition:rule.sqlPhase==='witness'?'live-witness-only':'capture',evidence:{phase:rule.sqlPhase??'original',ruleId:id,field}}));
  runtimeAlgebra.push({...anchor(s),ruleId:id,disposition:'runtime-algebra-required',children:fields.map(field=>({ruleId:id,field}))});
 };
 const rawACL=(a,field,objectType)=>[
  ['acl_raw',`${a}.${field}::text`,'text?'],
  ['acl_grants',`(SELECT jsonb_agg(jsonb_build_array(CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) ORDER BY CASE WHEN acl.grantee=0 THEN 'PUBLIC' ELSE grantee.rolname END,acl.privilege_type,acl.is_grantable,grantor.rolname) FROM aclexplode(COALESCE(${a}.${field},acldefault('${objectType}',${a}.${field==='proacl'?'proowner':'relowner'}))) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee LEFT JOIN pg_roles grantor ON grantor.oid=acl.grantor)`,'json?']
 ];
 {
  const s=sourceSite(source,'zasp_temporal78.ready(text,text)',22029,22562);
  if(s.sha256!=='c72131918ee70ca2546517b6344f74cedaba7332dd9d66183113b0bf4735f34f')throw Error('capture ready78 saved binding source');
  const exceptions=s.text.match(/s\.signature NOT IN\(([^)]+(?:\)[^']*)?'[^)]*)\)/);
  // Exact pinned literals, including their unqualified spelling, belong to the
  // source CASE. They are not guesses at canonical pg_proc identities.
  const demand="s.signature NOT IN('zasp_production_runtime_precision_live_fingerprint()','zasp_execution_claim_jobs(text,text,integer,integer)','zasp_execution_live_fingerprint()','zasp_discovery_schedule_replay_function_identity(oid)')";
  if(!s.text.includes(demand)||!exceptions)throw Error('capture ready78 exception source');
  addRaw(s,'ready78:saved-current:bindings','saved_current_binding',[
   ['signature','s.signature::text','text'],['present','p.oid IS NOT NULL','boolean'],['resolvedIdentity','p.oid::regprocedure::text','text?'],
   ['definition',`CASE WHEN ${demand} THEN pg_get_functiondef(p.oid) ELSE NULL END`,'text?'],['owner','p.proowner::regrole::text','text?'],['acl',"COALESCE(p.proacl::text,'')",'text']
  ],'FROM zasp_temporal72.predecessor_functions s LEFT JOIN pg_proc p ON p.oid=to_regprocedure(s.signature)',{bag:true});
  addRaw(s,'ready78:saved-current:routines','routine',[['owner','p.proowner::regrole::text','text'],['acl_raw','p.proacl::text','text?']],
   'FROM pg_proc p WHERE p.oid IN(SELECT to_regprocedure(signature) FROM zasp_temporal72.predecessor_functions)');
  runtimeAlgebra.push({...anchor(s),ruleId:'ready78:saved-current:comparison',disposition:'runtime-algebra-required',children:[...['signature','definition','owner_name','acl'].map(field=>({ruleId:'saved-input:zasp_temporal72.predecessor_functions',field})),...['signature','present','resolvedIdentity','definition','owner','acl'].map(field=>({ruleId:'ready78:saved-current:bindings',field}))],sourceExpression:s.text,demand:'original NOT EXISTS inside SQL AND; no evaluation order promise',equivalenceGate:'earlier live guards, original cast errors and SQL Boolean evaluation remain unproved; binding observations are not authorization verdicts'});
 }
 {
  // This guard has two nested catalog recipes. Its old descriptor field lists
  // omit projected identity columns, so bind every original ordinal explicitly.
  const workerCatalog=lowerOrderedWorkerCatalog(source,catalog),node=byIdentity.get(workerCatalog.identity);
  const names={
   4:['owner','acl'],5:['projected_identity','owner','acl','definition'],6:['name','kind','owner','acl','row_security','forced_row_security'],
   7:['relation_name','position','name','type','not_null','acl','default'],8:['relation_name','name','definition','validated'],9:['projected_relation','name','permissive','command','roles','using','check'],10:['projected_relation','name','enabled','definition'],11:['signature','definition','owner_name','acl'],12:['signature','definition'],
   15:['name','owner','acl'],16:['projected_identity','owner','acl','definition'],17:['name','kind','owner','acl','row_security','forced_row_security'],18:['relation_name','position','name','type','not_null','acl','default'],19:['relation_name','name','definition','validated'],20:['relation_name','definition','valid','ready','live'],21:['projected_relation','name','permissive','command','roles','using','check'],22:['projected_relation','name','enabled','definition'],
   23:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl'],24:['projected_identity','kind','owner','acl','row_security','forced_row_security'],25:['position','name','acl'],26:['name','permissive','command','roles','using','check'],27:['signature','definition','owner_name','acl'],31:['singleton','checksum','fingerprint'],32:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl'],33:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl'],34:['projected_identity','owner','acl','definition'],35:['projected_identity','definition'],36:['name','enabled','definition'],37:['projected_relation','name','enabled','definition'],38:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl'],39:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl'],40:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl'],41:['projected_relation','name','enabled','definition','function_definition','function_owner','function_acl']
  };
  const booleanFields=new Set(['row_security','forced_row_security','not_null','validated','permissive','valid','ready','live','singleton']);
  for(const oldSite of workerCatalog.sites){
   const s=sourceSite(source,node.identity,oldSite.start,oldSite.end),id='worker-catalog:line:'+oldSite.line,old=workerCatalog.rules.find(r=>r.id===oldSite.rule);
   if(oldSite.line===2){addRaw(s,id,'registration_bag',[['fingerprint','fingerprint::text','text']],'FROM zasp_authorization80_worker.registration',{bag:true,sqlPhase:'witness',section:'witnesses'});continue;}
   const p=projections(s.text),fields=names[oldSite.line];if(!p||p.fields.length!==fields?.length)throw Error('capture worker catalog ordinal '+oldSite.line);
   addRaw(s,id,old.kind,fields.map((field,i)=>[field,p.fields[i],booleanFields.has(field)?'boolean':field==='position'?'integer':'text?']),p.from,{...(old.kind.startsWith('saved_')||oldSite.line===31?{bag:true}:{}),...(oldSite.line===31?{sqlPhase:'witness',section:'witnesses'}:{})});
  }
  const children=rawRules.filter(r=>r.id.startsWith('worker-catalog:')).flatMap(r=>r.fields.map(field=>({ruleId:r.id,field})));
  runtimeAlgebra.push({...anchor(sourceSite(source,node.identity,0,Buffer.byteLength(node.source))),ruleId:'worker-catalog:nested-source-algebra',disposition:'runtime-algebra-required',children,sourceExpression:node.source,cardinality:'worker registration count(*)=1 and EXISTS fingerprint equality; outer COALESCE false; each sorted nested string_agg retains duplicate and NULL semantics',equivalenceGate:'capture preserves raw source inputs only; no saved catalog_ready verdict'});
 }
 {
  const node=byIdentity.get('zasp_authorization80.fingerprint()');if(node.sourceSHA256!=='7dc72d5920409b1d7e82e81d4e4876c7f955e6506ef62199b4b0a5468687add8')throw Error('capture authorization80 source pin');
  const fields={schema:['owner','acl'], 'runtime-profile':['singleton','name','audit_mode','identity_mode'],'runtime-profile-trigger':['name','enabled','definition'],'runtime-profile-column':['name','type_identity','typmod','not_null','acl','default'],function:['name','owner','acl','definition'],'home-source-function':['name','owner','acl','definition'],relation:['name','kind','owner','acl','row_security','forced_row_security'],constraint:['relation_name','name','definition'],policy:['relation_name','name','roles','using','check'],'risk-relation':['name','owner','acl','row_security','forced_row_security'],'risk-policy':['relation_name','name','permissive','command','roles','using','check'],'data-controls-relation':['name','owner','acl','row_security','forced_row_security'],'data-controls-policy':['name','permissive','command','roles','using','check'],'data-controls-column':['name','type_identity','typmod','not_null','acl','identity','generated','default'],'data-controls-constraint':['name','definition'],'hierarchy-relation':['name','kind','owner','acl','row_security','forced_row_security'],'hierarchy-trigger':['relation_identity','name','enabled','event_bits','internal','deferrable','deferred','constraint_oid','constraint_relation_oid','constraint_index_oid','argument_count','columns','qual_tree','old_table','new_table','routine_identity','arguments','definition'],'hierarchy-column':['relation_identity','name','type_identity','typmod','not_null','acl','identity','generated','default'],'hierarchy-constraint':['relation_identity','name','definition'],'hierarchy-policy':['relation_identity','name','permissive','command','roles','using','check']};
  const bools=new Set(['singleton','not_null','row_security','forced_row_security','permissive','internal','deferrable','deferred']),integers=new Set(['typmod','event_bits','argument_count']);
  for(const b of concatBranches(node.source)){
   const label=b.text.match(/^SELECT concat_ws\('\|','([^']+)'/)[1],names=fields[label],p=projections(b.text),s=sourceSite(source,node.identity,b.start,b.end),id='authorization80:'+label;
   if(!names||names.length!==p.fields.length)throw Error('capture authorization80 ordinal '+label);
   const columns=names.flatMap((f,i)=>{
    if(f==='qual_tree')return [['qual','CASE WHEN t.tgqual IS NULL THEN NULL::text ELSE (t.tgqual IS NULL)::text::integer::text END','text?']];
    const oidFields={constraint_oid:['constraint','t.tgconstraint',"(SELECT jsonb_build_array(k.connamespace::regnamespace::text,CASE WHEN k.conrelid<>0 THEN k.conrelid::regclass::text ELSE NULL END,CASE WHEN k.contypid<>0 THEN k.contypid::regtype::text ELSE NULL END,k.conname)::text FROM pg_constraint k WHERE k.oid=t.tgconstraint)"],constraint_relation_oid:['constraint_relation','t.tgconstrrelid','(SELECT c.oid::regclass::text FROM pg_class c WHERE c.oid=t.tgconstrrelid)'],constraint_index_oid:['constraint_index','t.tgconstrindid','(SELECT c.oid::regclass::text FROM pg_class c WHERE c.oid=t.tgconstrindid)']};
    if(oidFields[f]){const [prefix,oid,semantic]=oidFields[f];return [[prefix+'_present',oid+'<>0','boolean'],[prefix+'_identity',`CASE WHEN ${oid}<>0 THEN ${semantic} ELSE NULL END`,'text?']];}
    return [[f,f==='type_identity'?'a.atttypid::regtype::text':p.fields[i],bools.has(f)?'boolean':integers.has(f)?'integer':'text?']];
   });
   const kind=label==='schema'?'namespace':label==='runtime-profile'?'saved_bag':label.includes('function')?'routine':label.includes('column')?'column':label.includes('constraint')?'constraint':label.includes('trigger')?'trigger':label.includes('policy')?'policy':'relation';
   addRaw(s,id,kind,columns,p.from,{...(label==='runtime-profile'?{bag:true}:{}),selector:{source:p.from,projectionMapping:'source OID inputs use semantic identities; no numeric OID is published',...(label==='hierarchy-trigger'?{nullDomain:{field:'tgqual',required:null,onOther:'abort entire capture through row-dependent failing cast; never filter or serialize pg_node_tree',sourcePins:{...supportPins},nativeRefusalProof:'pending'}}:{})}});
   if(names.includes('type_identity'))addRaw(s,id+':types','type',[['identity','type_row.oid::regtype::text','text']],`FROM pg_type type_row WHERE type_row.oid IN(SELECT a.atttypid ${p.from})`);
  }
 }
 {
  const identity='zasp_authorization80_temporal.triggers_ready(boolean)',node=byIdentity.get(identity),s=sourceSite(source,identity,0,Buffer.byteLength(node.source));if(node.sourceSHA256!=='36cfbf78f948892002d9301a1a53aa924ba4dc291ad8b5c3f115b2b381005897')throw Error('capture temporal trigger guard pin');
  addRaw(s,'authorization-temporal:triggers-ready:triggers','trigger',[
   ['relation_name','c.relname::text','text'],['name','t.tgname::text','text'],['enabled','t.tgenabled::text','text'],['event_bits','t.tgtype','integer'],['internal','t.tgisinternal','boolean'],['deferrable','t.tgdeferrable','boolean'],['deferred','t.tginitdeferred','boolean'],
   ['constraint_is_zero','t.tgconstraint=0','boolean'],['constraint_relation_is_zero','t.tgconstrrelid=0','boolean'],['constraint_index_is_zero','t.tgconstrindid=0','boolean'],['argument_count','t.tgnargs','integer'],['columns','t.tgattr::text','text'],['qual_is_null','t.tgqual IS NULL','boolean'],['old_table','t.tgoldtable::text','text?'],['new_table','t.tgnewtable::text','text?'],['routine_identity','t.tgfoid::regprocedure::text','text'],['arguments',"encode(t.tgargs,'hex')",'text']
  ],"FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND c.relname IN('zasp_integrations','zasp_integration_connections','zasp_discovery_syncs','zasp_inventory_entities') AND t.tgname='zasp_authorization79_capture'");
  addRaw(s,'authorization-temporal:triggers-ready:routine','routine',[['owner','p.proowner::regrole::text','text'],['security_definer','p.prosecdef','boolean'],['config_raw','p.proconfig::text','text?'],['acl_raw','p.proacl::text','text?']],"FROM pg_proc p WHERE p.oid='zasp_authorization79.capture()'::regprocedure");
  const fields=['literal','cast','sourceSite','demandPath','resolvedIdentity'];
  addRaw(s,'authorization-temporal:triggers-ready:resolution','resolution',fields.map((field,i)=>[field,["'zasp_authorization79.capture()'","'regprocedure'",`'${s.sha256}'`,"'authorization-temporal:triggers-ready'","'zasp_authorization79.capture()'::regprocedure::text"][i],'text']),'',{bag:true,sourceMaxRows:1,sqlPhase:'resolution',section:'resolutions'});
  runtimeAlgebra.push({...anchor(s),ruleId:'authorization-temporal:triggers-ready:algebra',disposition:'runtime-algebra-required',children:rawRules.filter(r=>r.id.startsWith('authorization-temporal:triggers-ready:')).flatMap(r=>r.fields.map(field=>({ruleId:r.id,field}))),sourceExpression:s.text,sourceChildren:[],cardinality:'all selected four-relation/name trigger rows; count=4 and bool_and retain missing/extra/NULL; final selects kind versus product_kind expected argument literal',equivalenceGate:'capture only raw trigger/callable inputs; no saved triggers_ready Boolean'});
 }
 for(const component of [pub,product,runtime])for(const obligation of component.obligations){
  if(!['membership-cardinality','live-metadata-scalar'].includes(obligation.type))continue;
  const s=component.sites.find(s=>s.sha256===obligation.siteSHA256);if(!s)throw Error('capture multiset/scalar source site');
  if(obligation.type==='membership-cardinality'){
   const p=projections(s.text);if(p.fields.length!==3)throw Error('capture original public membership tuple');
   addRaw(s,'public:'+s.family+':membership','membership_bag',['granted_role','member_role','admin_option'].map((f,i)=>[f,p.fields[i],i===2?'boolean':'text']),p.from,{bag:true});
  }else{
   const p=projections(s.text);if(p.fields.length!==1)throw Error('capture live metadata scalar projection');
   addRaw(s,'product:'+s.family+':live-metadata','live_metadata_scalar',[['value',p.fields[0],'text?']],'',{bag:true,sqlPhase:'witness',section:'witnesses'});
  }
 }
 {
  const helper=byIdentity.get('public.zasp_discovery_schedule_replay_function_identity(oid)'),s=sourceSite(source,helper.identity,0,Buffer.byteLength(helper.source));
  addRaw(s,'schedule:guard-registration','registration_bag',[['checksum','checksum::text','text'],['fingerprint','fingerprint::text','text']],"FROM zasp_temporal72.registration WHERE checksum='e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940' AND fingerprint='b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e'",{bag:true});
 }
 {
  const recipe=recipes.find(r=>r.ruleId==='public:sa_export:saved'),site=transforms.flatMap(t=>t.sites).find(s=>s.sha256===recipe.siteSHA256),parsed=projections(site.text);
  const node=byIdentity.get(site.identity),prefixStart=node.source.indexOf('WITH saved AS ('),prefixEnd=node.source.indexOf('), identities(value) AS (');
  if(prefixStart<0||prefixEnd<0)throw Error('capture export CTE source');
  const prefix=node.source.slice(prefixStart,prefixEnd+1),prefixSite=pub.sites.find(s=>s.family==='sa_export'&&s.type==='registered-migration-binding');
  addRaw(site,'saved-input:zasp_sa_export_prior.functions','saved_bag',[['signature','signature::text','text'],['definition','definition::text','text?'],['owner_name','owner_name::text','text?'],['acl','acl::text','text?']], 'FROM zasp_sa_export_prior.functions',{bag:true});
  addRaw(site,'public:sa_export:saved-observations','export_observation',[['signature',parsed.fields[0],'text'],['owner',parsed.fields[2],'text?'],['acl',parsed.fields[3],'text?']],parsed.from,{bag:true,sqlPrefix:prefix,sqlPhase:'witness',section:'normalizationObservations'});
  if(!prefixSite)throw Error('capture export binding source site');
  closedSites.add(prefixSite.sha256);runtimeAlgebra.push({...anchor(prefixSite),ruleId:'public:sa_export:binding-algebra',disposition:'runtime-algebra-required',children:[{ruleId:'saved-input:zasp_sa_export_prior.functions',field:'signature'},{ruleId:'saved-input:zasp_sa_export_prior.functions',field:'owner_name'},{ruleId:'saved-input:zasp_sa_export_prior.functions',field:'acl'},{ruleId:'public:sa_export:saved-observations',field:'owner'},{ruleId:'public:sa_export:saved-observations',field:'acl'}],live:'original pg_has_role MEMBER condition, no added LOGIN predicate; false/NULL ELSE and ACL ordinality preserved'});
  const cteSite=sourceSite(source,node.identity,Buffer.byteLength(node.source.slice(0,prefixStart)),Buffer.byteLength(node.source.slice(0,prefixEnd+1)));
  runtimeAlgebra.push({...anchor(cteSite),ruleId:'public:sa_export:saved-cte-algebra',disposition:'runtime-algebra-required',children:runtimeAlgebra.at(-1).children,sourceExpression:prefix,live:'exact WITH saved selector and original MEMBER condition; normalization observation remains witness-only'});
 }
 for(const component of [temporal,pub])for(const s of component.sites){
  const execution=s.family==='72.retained_execution_fingerprint',inventory=s.family==='inventory';if(!execution&&!inventory)continue;
  if(closedSites.has(s.sha256)||!['table','function','policy','trigger','role','rule','restore'].includes(s.type))continue;
  const id=(execution?'temporal:72.retained_execution_fingerprint:':'public:inventory:')+s.type,from=branchFrom(s.text);
  const c=execution?'c':'class',p=execution?'p':'procedure',role=execution?'r':'role';
  if(s.type==='table')addRaw(s,id,'relation', [['owner',`${c}.relowner::regrole::text`,'text'],['row_security',`${c}.relrowsecurity`,'boolean'],['forced_row_security',`${c}.relforcerowsecurity`,'boolean'],...rawACL(c,'relacl','r')],from);
  if(s.type==='function'){
   const body=execution?s.text.match(/regexp_replace\(btrim\((CASE WHEN [\s\S]+? END)\),E/)[1]:`${p}.prosrc`;
   addRaw(s,id,'routine', [['owner',`${p}.proowner::regrole::text`,'text'],['security_definer',`${p}.prosecdef`,'boolean'],['source_body',body,'text?'],['config_json',`to_jsonb(${p}.proconfig)`,'json?'],['config_raw',`${p}.proconfig::text`,'text?'],['config_dims',`array_dims(${p}.proconfig)`,'text?'],['config_ndims',`array_ndims(${p}.proconfig)`,'integer?'],['config_bounds',`(SELECT jsonb_agg(jsonb_build_array(array_lower(${p}.proconfig,d),array_upper(${p}.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(${p}.proconfig)) d)`,'json?'],...rawACL(p,'proacl','f')],from);
   if(inventory)addRaw(s,id+':core-owner','relation',[['owner','relowner::regrole::text','text']],"FROM pg_class WHERE oid='zasp_core_payloads'::regclass");
  }
  if(s.type==='policy')addRaw(s,id,'policy',[['permissive','policy.polpermissive','boolean'],['command','policy.polcmd::text','text'],['roles','(SELECT jsonb_agg(role.rolname ORDER BY role.rolname) FROM unnest(policy.polroles) role_oid JOIN pg_roles role ON role.oid=role_oid)','json?'],['using','pg_get_expr(policy.polqual,policy.polrelid)','text?'],['check','pg_get_expr(policy.polwithcheck,policy.polrelid)','text?']],from);
  if(s.type==='trigger')addRaw(s,id,'trigger',[['definition','pg_get_triggerdef(trigger_value.oid,true)','text'],['enabled','trigger_value.tgenabled::text','text'],['function','trigger_value.tgfoid::regprocedure::text','text']],from);
  if(s.type==='role'){
   addRaw(s,id,'role',[['login','rolcanlogin'],['inherit','rolinherit'],['superuser','rolsuper'],['create_db','rolcreatedb'],['create_role','rolcreaterole'],['replication','rolreplication'],['bypass_rls','rolbypassrls']].map(([f,p])=>[f,role+'.'+p,'boolean']),from);
   const managed=s.text.slice(s.text.indexOf('shobj_description'),s.text.lastIndexOf(')) FROM')+1);
   addRaw(s,id+':managed-marker','managed_marker',[['role',role+'.rolname::text','text'],['managed_here',managed,'boolean?']],from,{bag:true,sqlPhase:'witness',section:'witnesses'});
  }
  if(s.type==='rule')addRaw(s,id,'live_metadata',[['provider','provider::text','text'],['source_kind','source_kind::text','text'],['row','to_jsonb(rule)','json']],from,{bag:true,sqlPhase:'witness',section:'witnesses'});
  if(s.type==='restore')addRaw(s,id,'live_metadata',[['object_kind','object_kind::text','text'],['object_identity','object_identity::text','text'],['definition_digest',"encode(definition_digest,'hex')",'text?']],from,{bag:true,sqlPhase:'witness',section:'witnesses'});
 }
 for(const component of [buildOrderedSpecialCatalogCapture(source,catalog),buildOrderedWrapperCaptureInputs(source,catalog),buildOrderedRecursiveCaptureInputs(source,catalog),buildOrderedPriorCaptureInputs(source,catalog),buildOrderedMaterializedCaptureInputs(source,catalog)]){
  for(const rule of component.rawRules){if(rawRules.some(r=>r.id===rule.id))throw Error('duplicate complete capture rule '+rule.id);rawRules.push(structuredClone(rule));closedSites.add(rule.sourceSite.siteSHA256);}
  entries.push(...component.entries);runtimeAlgebra.push(...component.runtimeAlgebra);unresolved.push(...component.unresolved);
 }
 {
  const identity='zasp_authorization80_worker.ordered_writer_definition(oid)',node=byIdentity.get(identity),site=sourceSite(source,identity,0,Buffer.byteLength(node.source));
  const resolutions=rawRules.filter(r=>r.kind==='resolution'&&r.sourceSite.sourceIdentity===identity);
  const callers=[...new Set(resolutions.map(r=>r.selector?.outerRuleId??r.id.split(':helper-resolution:')[0]))].filter(id=>rawRules.some(r=>r.id===id));
  const selected=rawRules.filter(r=>callers.includes(r.id)||r.id==='saved-input:zasp_authorization80_worker.predecessor_functions');
  runtimeAlgebra.push({...anchor(site),ruleId:'ordered-writer:caller-demand-index',disposition:'selected-helper-source-algebra',children:[...resolutions,...selected].flatMap(r=>r.fields.map(field=>({ruleId:r.id,field}))),sourceChildren:[],sourceExpression:site.text,demandIndex:resolutions.map(r=>({ruleId:r.id,from:r.from,demand:r.selector?.callerDemandPath??r.projections[3],expression:r.projections.at(-1)})),equivalenceGate:'caller-specific original CASE demand, scalar missing/multiple-row behavior and errors remain runtime algebra; this index does not execute the helper or save its result'});
 }
 {
  const identity='public.zasp_security_agent_budgets_function_identity(oid)',node=byIdentity.get(identity),site=sourceSite(source,identity,0,Buffer.byteLength(node.source));
  const fixedLiterals=[...node.source.matchAll(/'((?:[^']|'')*)'::regprocedure/g)].map(m=>m[1]),readiness=[...node.source.matchAll(/to_regprocedure\('((?:[^']|'')*)'\)/g)].map(m=>m[1]),writer=[...byIdentity.get('zasp_authorization80_worker.ordered_writer_definition(oid)').source.matchAll(/'((?:[^']|'')*)'::regprocedure/g)].map(m=>m[1]);
  if(fixedLiterals.length!==3||readiness.length!==1||writer.length!==15)throw Error('capture budget source binding inventory');
  for(const [id,literals]of [['prior:budget:function-identity-fixed-resolution',fixedLiterals],['prior:budget:function-identity-readiness-resolution',readiness],['prior:budget:ordered-writer-resolution',writer]]){
   const rule=rawRules.find(r=>r.id===id);
   if(!rule||!same(rule.selector?.literalBindings,literals.map(literal=>({literal,cast:id.includes('readiness')?'to_regprocedure':'regprocedure'})))||rule.selector?.outerRuleId!=='prior:budget:function'||!rule.projections.at(-1).includes('CASE WHEN '))missing(site,'helper-demand-resolution','missing exact original budget helper literal demand '+id,[id]);
  }
  for(const family of ['compliance','existing','run-context']){const id=`prior:${family}:function-identity-readiness-resolution`,rule=rawRules.find(r=>r.id===id);if(!rule||!rule.from.includes('FROM pg_proc ')||!rule.projections.at(-1).includes('CASE WHEN '))missing(site,'helper-demand-resolution','missing original selected-row helper demand '+id,[id]);}
  const requiredFields=['namespace_name','name'];
  for(const id of ['prior:compliance:function','prior:existing:function','prior:run-context:function','prior:budget:function','prior:audit:function'])for(const field of requiredFields)if(!rawRules.some(r=>r.id===id&&r.fields.includes(field)))missing(site,'original-projection-field','missing exact original routine name '+id+'.'+field,[id,field]);
 }
 for(const family of ['sa_attack_lab','sa_export','sa_multistep','sa_webhook']){
  const identity=`public.zasp_${family}_function_identity(oid)`,node=byIdentity.get(identity),site=sourceSite(source,identity,0,Buffer.byteLength(node.source)),raw=rawRules.find(r=>r.id===`public:${family}:function`);
  const original=rawExpression(node.source.trim().replace(/^SELECT\s+/,''));
  if(original!=='pg_get_functiondef(value)'||!raw||raw.projections[raw.fields.indexOf('definition')]!=='pg_get_functiondef(p.oid)'||node.owner!==raw.sourceSite.frame.owner||!same(node.config,raw.sourceSite.frame.config))throw Error('capture pure helper exact deparse correspondence '+identity);
  runtimeAlgebra.push({...anchor(site),ruleId:`public:${family}:pure-helper-algebra`,disposition:'selected-helper-source-algebra',children:[{ruleId:raw.id,field:'definition'}],sourceChildren:[],sourceExpression:site.text,callerSelector:raw.from,equivalenceGate:'exact raw deparse input under matching original frame; literal replacements and invocation/error behavior remain later evaluator obligations'});
 }
 {
  const guards=[['zasp_authorization80_temporal.fingerprint()','0fde1324803d5cb9b8aff5fb62e56fa3a3faf1adc6bf17f39a07af0c4a14bb8d','zasp_authorization80_worker.projected_temporal_profile()'],['zasp_authorization79.fingerprint()','a3bffc0d55e960fc4b9ba233c8eeba63f367f007df9ba0eb37e34ec6bb042a00','zasp_authorization80_worker.projected79()']];
  for(const [identity,pin,target]of guards){const node=byIdentity.get(identity),s=sourceSite(source,identity,0,Buffer.byteLength(node.source));if(node.sourceSHA256!==pin)throw Error('capture authorization guard pin');
   const children=rawRules.filter(r=>r.id==='recursive:worker-catalog-ready:routine'||r.id==='recursive:worker-catalog-ready:registration'||r.id==='recursive:worker-catalog-ready:literal-resolution').flatMap(r=>r.fields.map(field=>({ruleId:r.id,field})));
   runtimeAlgebra.push({...anchor(s),ruleId:'authorization-guard:'+identity,disposition:'conditional-source-algebra',children,sourceChildren:['zasp_authorization80_worker.catalog_ready()',target],sourceExpression:s.text,equivalenceGate:'original searched CASE and static guard predicates; ready result remains live, never expected'});
  }
  const identity='zasp_authorization79.ready(text)',node=byIdentity.get(identity),s=sourceSite(source,identity,0,Buffer.byteLength(node.source));if(node.sourceSHA256!=='acee85f4bd170221b720fefdbd17968bd684418a4f87ba94382ca43f61daaaa0')throw Error('capture authorization ready pin');
  runtimeAlgebra.push({...anchor(s),ruleId:'authorization-guard:'+identity,disposition:'conditional-source-algebra',children:['checksum','fingerprint'].map(field=>({ruleId:'recursive:authorization79:registration',field})),sourceChildren:['zasp_authorization79.fingerprint()'],sourceExpression:s.text,equivalenceGate:'source checksum argument plus live fingerprint and EXISTS evaluation remains runtime algebra'});
 }
 {
  const s=temporal.sites.find(s=>s.family==='72.retained_precision_fingerprint'&&s.type==='function'),p=projections(s.text);
  const fields=['namespace_name','name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','definition'];
  if(p.fields.length!==fields.length)throw Error('precision raw projection correspondence');
  addRaw(s,'temporal:72.retained_precision_fingerprint:function','routine',fields.map((field,i)=>[field,p.fields[i],field==='security_definer'?'boolean':'text?']),p.from);
 }
 {
  const s=pub.sites.find(s=>s.family==='sa_attack_lab'&&s.type==='saved-table'),id='public:sa_attack_lab:saved-table';
  addRaw(s,id+':relation','relation',[['owner','c.relowner::regrole::text','text'],['acl_raw','c.relacl::text','text?'],['row_security','c.relrowsecurity','boolean'],['forced_row_security','c.relforcerowsecurity','boolean']],"FROM pg_class c WHERE c.oid='zasp_sa_attack_lab_prior.functions'::regclass");
  addRaw(s,id+':column','column',[['position','a.attnum','integer'],['name','a.attname::text','text'],['type','format_type(a.atttypid,a.atttypmod)','text'],['not_null','a.attnotnull','boolean'],['default',"COALESCE(pg_get_expr(d.adbin,d.adrelid),'')",'text']],"FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_sa_attack_lab_prior.functions'::regclass AND a.attnum>0 AND NOT a.attisdropped");
  addRaw(s,id+':constraint','constraint',[['name','k.conname::text','text'],['definition','pg_get_constraintdef(k.oid)','text']],"FROM pg_constraint k WHERE k.conrelid='zasp_sa_attack_lab_prior.functions'::regclass");
 }
 const requiredIndex=[];
 // This branch obligation comes from the pinned source independently of the
 // wrapper output. A whole-body algebra cannot stand in for these reads.
 {
  const site=sourceSite(source,'zasp_authorization80.runtime_audit_ready()',230,461);
  const children=[{ruleId:'wrapper:runtime-profile',field:'singleton'},{ruleId:'wrapper:runtime-profile',field:'audit_mode'},{ruleId:'wrapper:runtime-audit:none-namespace',field:'namespace_identity'},{ruleId:'wrapper:runtime-audit:none-relation-resolution',field:'resolvedIdentity'},{ruleId:'wrapper:runtime-audit:none-trigger-inputs',field:'relation_identity'},{ruleId:'wrapper:runtime-audit:none-trigger-inputs',field:'name'}];
  const branch=runtimeAlgebra.find(a=>a.ruleId==='wrapper:runtime-audit:none-branch'&&a.sourceIdentity===site.identity&&a.start===site.start&&a.end===site.end&&a.siteSHA256===site.sha256);
  const complete=branch&&children.every(ref=>branch.children?.some(c=>c.ruleId===ref.ruleId&&c.field===ref.field)&&rawRules.some(r=>r.id===ref.ruleId&&r.fields.includes(ref.field)));
  requiredIndex.push({...anchor(site),type:'required-conditional-branch',ruleId:'wrapper:runtime-audit:none-branch',disposition:complete?'source-fields':'unresolved',children});
  if(!complete)missing(site,'none-branch-inputs','audit none branch requires exact namespace observation, relation cast and trigger inputs',['wrapper:runtime-audit:none-branch']);
 }
 const components=[worker,edge,temporal,pub,product,runtime,...transforms];
 const directKinds=new Set(['descriptor-reference','original-transformation','original-transformation-or-live-projection','conditional-routine','nested-aggregate','live-metadata','live-metadata-scalar','registered-migration-binding','membership-bag','membership-cardinality','original72-lowering','saved-universe-demand','fresh-registered-identity','acl-array-and-independent-reference','frame-resolution-and-aggregation','helper-frame-and-deparse','typed-reference-integration','saved-membership-and-scalar','selected-helper-frame','helper-demand-frame']);
 const graphKinds=new Set(['original-delegate','delegate','predecessor']);
 const knownKinds=new Set([...directKinds,...graphKinds,'conditional-wrapper','original-reg-object-binding','relation-resolution','digest-semantics','original-aggregate-digest']);
 for(const component of components)for(const o of component.obligations){
  const recipe=component.recipes?.find(r=>r.ruleId===o.ruleId),digest=o.siteSHA256??recipe?.siteSHA256;
  const s=component.sites.find(s=>s.sha256===digest&&(!o.sourceIdentity||s.identity===o.sourceIdentity)&&(!o.family||s.family===o.family));
  if(!s)throw Error('capture obligation exact source site '+o.type+' '+(o.ruleId??o.family));
  const index={...anchor(s),type:o.type,ruleId:o.ruleId??null,disposition:null,children:[]};requiredIndex.push(index);
  if(s.identity==='zasp_authorization80_worker.projected74()'){index.disposition='retained-opaque-P';continue;}
  if(!knownKinds.has(o.type)){index.disposition='unresolved';missing(s,o.type,'unknown lowerer obligation kind refuses',[o.ruleId??o.family]);continue;}
  const children=entries.filter(e=>e.sourceIdentity===s.identity&&e.siteSHA256===s.sha256).map(e=>e.evidence);
  if(graphKinds.has(o.type)){
   const calls=byIdentity.get(s.identity).inventory.calls.filter(c=>c.start>=s.start&&c.end<=s.end);
   const targets=o.targets??calls.map(call=>{const candidates=source.nodes.filter(n=>n.identity.startsWith(call.name+'('));if(candidates.length!==1)throw Error('capture original delegate resolution '+call.name);return candidates[0].identity;});
   index.disposition='source-child-linkage';index.sourceChildren=targets;
   if(!targets.length)missing(s,o.type,'delegate has no exact resolved source child',[o.ruleId??o.family]);
   runtimeAlgebra.push({...anchor(s),ruleId:'source-edge:'+s.identity+':'+s.start,disposition:'runtime-algebra-required',children:[],sourceChildren:targets,sourceExpression:s.text,equivalenceGate:'original invocation frame, conditional demand and NULL/aggregate semantics remain live'});
   continue;
  }
  if(['digest-semantics','original-aggregate-digest'].includes(o.type)){
   index.disposition='runtime-algebra';index.children=entries.filter(e=>e.sourceIdentity===s.identity).map(e=>e.evidence);
   runtimeAlgebra.push({...anchor(s),ruleId:'source-digest:'+s.identity,disposition:'runtime-algebra-required',children:index.children,sourceExpression:s.text,equivalenceGate:'original sorted aggregation, duplicate multiplicity, NULL skipping and digest equivalence not claimed by capture'});continue;
  }
  if(['original-reg-object-binding','relation-resolution'].includes(o.type)){
   const selected=rawRules.filter(r=>r.sourceSite.sourceIdentity===s.identity&&r.sourceSite.siteSHA256===s.sha256);
   if(selected.length){index.disposition='original-query-binding';index.children=children;index.bindings=structuredClone(o.bindings??[{identity:o.relation,cast:'regclass'}]);index.equivalenceGate='query keeps original casts and CASE demand; no inferred qualification or missing-object-as-empty substitution';continue;}
  }
  const mappedAlgebra=runtimeAlgebra.filter(a=>a.sourceIdentity===s.identity&&a.siteSHA256===s.sha256);
  if((closedSites.has(s.sha256)&&children.length)||mappedAlgebra.length){index.disposition=o.type==='conditional-wrapper'?'guard-static-inputs':'source-fields';index.children=[...children,...mappedAlgebra.flatMap(a=>a.children??[])];continue;}
  index.disposition='unresolved';missing(s,o.type,'source obligation lacks exact field/demand evidence',[o.ruleId??o.family+':'+o.branch]);
 }
 for(const n of source.materializedObligations){const node=byIdentity.get(n.identity),s=sourceSite(source,n.identity,0,Buffer.byteLength(node.source)),mapped=runtimeAlgebra.find(a=>a.sourceIdentity===n.identity&&a.disposition==='recursive-source-algebra'&&a.siteSHA256===s.sha256);
  if(!mapped||!same(mapped.recipeSegments,n.recipeSegments))missing(s,'materialized-children','materialized recipe segments and structural child field mapping required',[n.identity]);
  else requiredIndex.push({...anchor(s),type:'materialized-source',ruleId:mapped.ruleId,disposition:'recursive-source-algebra',children:mapped.children,sourceChildren:mapped.sourceChildren});
 }
 const opaque=byIdentity.get('zasp_authorization80_worker.projected74()');retainedOpaque.push({...anchor(sourceSite(source,opaque.identity,0,Buffer.byteLength(opaque.source))),disposition:'retained-opaque-P',demandPath:['accepted-projected74-boundary']});
 for(const n of source.materializedObligations)for(const site of n.inlineLiveSpans??[])liveWitnesses.push({...anchor(sourceSite(source,n.identity,site.start,site.end)),field:site.kind,demandPath:[n.identity,site.kind],disposition:'live-witness-only'});
 for(const rule of rawRules){
  if(/\bFROM selected c\b/.test(rule.from)&&rule.sourceSite.sourceIdentity==='zasp_authorization80_worker.projected_domain()'){
   const body=byIdentity.get(rule.sourceSite.sourceIdentity).source,end=body.indexOf(', identities(value) AS(');if(end<0)throw Error('capture selected CTE source');rule.sqlPrefix=body.slice(body.indexOf('WITH selected AS('),end);
  }
  // The original display projection may coalesce NULL or omit array bounds.
  // Retain the complete raw config representation alongside that projection.
  const joined=rule.projections.join('\n'),config=joined.match(/\b([a-z_]+\.)?(proconfig|rolconfig)\b/);
  if(config&&!rule.fields.includes('config_json')){
   const expr=config[0],extra=[['config_json',`to_jsonb(${expr})`,'json?'],['config_raw',`${expr}::text`,'text?'],['config_dims',`array_dims(${expr})`,'text?'],['config_ndims',`array_ndims(${expr})`,'integer?'],['config_bounds',`(SELECT jsonb_agg(jsonb_build_array(array_lower(${expr},dimension),array_upper(${expr},dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(${expr})) dimension)`,'json?']];
   for(const [field,sourceExpression,type]of extra){if(rule.fields.includes(field))continue;const ordinal=rule.fields.length;rule.fields.push(field);rule.projections.push(sourceExpression);rule.additionalFieldTypes??={};rule.additionalFieldTypes[field]=type;if(rule.fieldTypes)rule.fieldTypes[field]=type;entries.push({...rule.sourceSite,expressionOrdinal:ordinal,field,sourceExpression,selector:{source:rule.from},demandPath:[rule.id,'raw-config-shape'],disposition:'capture',evidence:{phase:rule.sqlPhase??'original',ruleId:rule.id,field}});}
  }
 }
 // Construct this after implicit input expansion. Every algebra field must be
 // a real captured field; an existing parent node is not child closure.
 const materializedIndex=[],materializedIDs=new Set(source.materializedObligations.map(o=>o.identity));
 const candidateBranches=[];
 for(const n of source.nodes.filter(n=>!materializedIDs.has(n.identity))){for(const b of concatBranches(n.source)){
  const refs=entries.filter(e=>e.sourceIdentity===n.identity&&e.start<=b.start&&e.end>=b.end).map(e=>e.evidence);
  if(refs.length)candidateBranches.push({node:n,...b,children:refs});
 }}
 for(const obligation of source.materializedObligations){const node=byIdentity.get(obligation.identity);for(const branch of concatBranches(node.source)){
  const site=sourceSite(source,node.identity,branch.start,branch.end),matches=candidateBranches.filter(c=>c.text===branch.text&&c.node.owner===node.owner&&same(c.node.config,node.config));
  const children=matches.flatMap(m=>m.children);
  const row={...anchor(site),disposition:children.length?'source-exact-copied-fields':'unresolved',children,sourceChildren:[...new Set(matches.map(m=>m.node.identity))],correspondence:matches.map(m=>({sourceIdentity:m.node.identity,start:m.start,end:m.end,siteSHA256:sha(m.text),owner:m.node.owner,config:m.node.config,proof:'identical complete SELECT projection and selector bytes; identical owner and original search_path'}))};
  materializedIndex.push(row);
 }}
 // These five branches inline an already indexed helper or export CTE. Their
 // first projections/selectors are proved separately from the retained live
 // guard. Keep the precise source expression and defer evaluator equivalence.
 const inlined=[
  ['zasp_temporal68.predecessor_ready(text,text)',82109,83635,'1c9c48372de83d191ff9d30cb7c15dcc265ec966e744908c637b2d375947e077','budget'],
  ['zasp_temporal68.predecessor_ready(text,text)',95647,96093,'2dc9319539a982d615d9817c7f9f039fcbe3bef2c80c90ece6e00a45944b1c44','export'],
  ['zasp_temporal68.predecessor_ready(text,text)',104270,106879,'a1c85641da2c8124adbf3696a79b3025e2ad1fd02509dbff2bce734471ee38ae','schedule'],
  ['zasp_temporal77.base67_fingerprint()',70660,72097,'d47c5de3a1b3352ac0d62237e664a71494e446e79c3d2c69579a9c869b9d9063','budget'],
  ['zasp_temporal77.base67_fingerprint()',93510,94944,'abd1b3ea487d73312b25b08f45488305e8e9c0f3e36883e54011b96723823642','schedule']
 ];
 for(const [identity,start,end,pin,kind]of inlined){
  const node=byIdentity.get(identity),site=sourceSite(source,identity,start,end),row=materializedIndex.find(r=>r.sourceIdentity===identity&&r.start===start&&r.end===end);if(!row||site.sha256!==pin)throw Error('capture inlined source pin '+identity+':'+start);
  const id=kind==='budget'?'prior:budget:function':kind==='schedule'?'public:discovery_schedule_replay:function':'public:sa_export:saved-observations',raw=rawRules.find(r=>r.id===id);if(!raw)throw Error('capture inlined raw rule '+id);
  const origin=byIdentity.get(raw.sourceSite.sourceIdentity),original=Buffer.from(origin.source).subarray(raw.sourceSite.start,raw.sourceSite.end).toString(),parsed=projections(site.text),prior=projections(original);
  if(node.owner!==origin.owner||!same(node.config,origin.config))throw Error('capture inlined invocation frame');
  let linked=[raw],targets=[];
  if(kind==='export'){
   const normalize=text=>text.replaceAll('ORDER BY x.n','ORDER BY n').replace(/\s+/g,' ').trim();
   if(normalize(site.text)!==normalize(original.replace(/^\s*UNION ALL\s+/,''))||!node.source.includes(raw.sqlPrefix))throw Error('capture export CTE correspondence');
   linked.push(rawRules.find(r=>r.id==='saved-input:zasp_sa_export_prior.functions'));
  }else{
   if(!same(parsed.fields.slice(0,11),prior.fields.slice(0,11))||parsed.from!==prior.from.replace(/\s+UNION ALL\s*$/,''))throw Error('capture inlined projection/selector correspondence '+id);
   const helper=kind==='budget'?'public.zasp_security_agent_budgets_function_identity(oid)':'public.zasp_discovery_schedule_replay_function_identity(oid)';targets.push(helper);
   linked.push(...rawRules.filter(r=>kind==='budget'?r.id.startsWith('prior:budget:')||r.id==='saved-input:zasp_authorization80_worker.predecessor_functions':r.id.startsWith('public:discovery_schedule_replay:function:')||r.id==='saved-input:zasp_temporal72.predecessor_functions'||r.id==='schedule:guard-registration'));
  }
  if(linked.some(r=>!r))throw Error('capture inlined missing raw input');
  Object.assign(row,{disposition:'source-inlined-inputs',children:linked.flatMap(r=>r.fields.map(field=>({ruleId:r.id,field}))),sourceChildren:targets,sourceExpression:site.text,evaluatorEquivalence:false,correspondence:[{sourceIdentity:origin.identity,start:raw.sourceSite.start,end:raw.sourceSite.end,siteSHA256:raw.sourceSite.siteSHA256,selector:parsed.from,proof:kind==='export'?'identical full saved CTE and projection; x.n explicitly names the sole ordinality n binding':'identical first eleven projections and complete original selector; final helper CASE retained as indexed source algebra',frame:frame(origin)}]});
 }
 // Component-owned copied branches carry their own exact source anchors.
 // Repeated sibling occurrences may share raw reads, but not source coverage.
 for(const row of materializedIndex){if(row.disposition!=='unresolved')continue;
  const mapped=runtimeAlgebra.filter(a=>a.disposition==='materialized-legacy-branch-algebra'&&a.sourceIdentity===row.sourceIdentity&&a.start===row.start&&a.end>=row.end);
  if(mapped.length!==1)continue;
  const a=mapped[0];row.disposition='source-mapped-materialized-fields';row.children=a.children;row.sourceChildren=(a.sourceChildren??[]).map(c=>typeof c==='string'?c:c.sourceIdentity);row.correspondence=[{sourceIdentity:a.sourceIdentity,start:a.start,end:a.end,siteSHA256:a.siteSHA256,proof:'exact component-owned branch projection and selector mapping'}];
 }
 // Source-local concatenation and CTE references carry no independently read
 // catalog row. Bind their exact child spans; never treat an empty field list
 // as proof without a source-local link or an exact application-call edge.
 for(const obligation of source.materializedObligations){const node=byIdentity.get(obligation.identity),ctes=materializedCTEs(node.source),rows=materializedIndex.filter(r=>r.sourceIdentity===node.identity);
  for(const row of rows){if(!['unresolved','source-inlined-inputs'].includes(row.disposition))continue;
   const text=Buffer.from(node.source).subarray(row.start,row.end).toString(),code=sourceMask(text);let depth=0,hasFrom=false;
   for(let i=0;i<code.length;i++){if(code[i]==='(')depth++;else if(code[i]===')')depth--;else if(depth===0&&/^FROM\b/.test(code.slice(i)))hasFrom=true;}if(hasFrom&&row.disposition==='unresolved')continue;
   const nested=rows.filter(r=>r.start>row.start&&r.end<=row.end),bindings=[],callSpans=[row],visited=new Set();
   function bindCTEs(expression){for(const match of sourceMask(expression).matchAll(/\bSELECT\s+value\s+FROM\s+((?:higher|readiness)_[a-z0-9]+)\b/g)){
    if(visited.has(match[1]))continue;visited.add(match[1]);
    const found=ctes.filter(c=>c.name===match[1]);if(found.length!==1)throw Error('capture unique materialized CTE '+match[1]);
    const cte=found[0];bindings.push({name:cte.name,start:cte.start,end:cte.end,sha256:sha(cte.text)});nested.push(...rows.filter(r=>r.start>=cte.start&&r.end<=cte.end));callSpans.push(cte);bindCTEs(cte.text);
   }}bindCTEs(text);
   const calls=node.inventory.calls.filter(c=>callSpans.some(s=>c.start>=s.start&&c.end<=s.end)),targets=[];
   for(const call of calls){const exact=source.nodes.filter(n=>n.identity.startsWith(call.name+'('));if(exact.length===1)targets.push(exact[0].identity);}
   if(nested.length||targets.length){if(row.disposition==='unresolved')row.disposition='source-local-concatenation';row.sourceChildren=[...new Set([...row.sourceChildren,...targets])];row.localChildren=[...new Set(nested.map(r=>r.start))];row.cteBindings=bindings;row.sourceExpression=text;}
  }
  for(const row of rows)if(row.disposition==='unresolved')missing(sourceSite(source,node.identity,row.start,row.end),'materialized-select-inputs','copied SELECT branch has no exact raw field/selector/frame correspondence',[node.identity,'copied-select',String(row.start)]);
 }
 const fieldExists=ref=>rawRules.some(r=>r.id===ref.ruleId&&r.fields.includes(ref.field));
 const childIdentity=child=>typeof child==='string'?child:child.sourceIdentity;
 const sourceIndex=[];
 const indexedIdentities=new Set([...components.flatMap(c=>c.sites.map(s=>s.identity)),...runtimeAlgebra.map(a=>a.sourceIdentity),...runtimeAlgebra.flatMap(a=>(a.sourceChildren??[]).map(childIdentity)),...materializedIndex.flatMap(s=>s.sourceChildren)]);
 for(const algebra of runtimeAlgebra){
  for(const ref of [...algebra.children??[],...(algebra.sourceChildren??[]).flatMap(c=>typeof c==='string'?[]:c.children??[])])if(!fieldExists(ref))missing(sourceSite(source,algebra.sourceIdentity,algebra.start,algebra.end),'algebra-child-field','missing exact capture field '+ref.ruleId+'.'+ref.field,[algebra.ruleId,ref.ruleId,ref.field]);
 }
 for(const identity of indexedIdentities){
  const node=byIdentity.get(identity);if(!node)throw Error('capture source child identity '+identity);
  const algebras=runtimeAlgebra.filter(a=>a.sourceIdentity===identity),sites=new Map();
  for(const site of components.flatMap(c=>c.sites).filter(s=>s.identity===identity))sites.set(site.start+':'+site.end,anchor(site));
  for(const a of algebras)sites.set(a.start+':'+a.end,Object.fromEntries(Object.keys(anchor(sourceSite(source,identity,a.start,a.end))).map(k=>[k,a[k]])));
  for(const s of requiredIndex.filter(s=>s.sourceIdentity===identity))sites.set(s.start+':'+s.end,s);
  for(const s of materializedIndex.filter(s=>s.sourceIdentity===identity))sites.set(s.start+':'+s.end,s);
  const requiredSites=[];
  for(const s of sites.values()){
   const refs=entries.filter(e=>e.sourceIdentity===identity&&e.start===s.start&&e.end===s.end).map(e=>e.evidence);
   const exactText=Buffer.from(node.source).subarray(s.start,s.end).toString().trim();
   const mapped=algebras.filter(a=>a.start===s.start&&a.end===s.end||Buffer.from(node.source).subarray(a.start,a.end).toString().trim()===exactText);
   const obligations=requiredIndex.filter(i=>i.sourceIdentity===identity&&i.start===s.start&&i.end===s.end);
   const children=[...refs,...mapped.flatMap(a=>a.children??[]),...obligations.flatMap(i=>i.children??[]),...s.children??[]];
   const targets=[...new Set([...mapped.flatMap(a=>(a.sourceChildren??[]).map(childIdentity)),...(s.sourceChildren??[]).map(childIdentity)])];
   const opaque=identity==='zasp_authorization80_worker.projected74()';
   const disposition=opaque?'retained-opaque-P':obligations.some(o=>o.disposition==='unresolved')?'unresolved':children.length?'captured-source-inputs':targets.length?'source-child-linkage':s.disposition==='source-local-concatenation'&&s.localChildren?.length?'source-local-concatenation':'unresolved';
   requiredSites.push({...s,disposition,children,sourceChildren:targets});
  }
  const sourceChildren=[...new Set([...algebras.flatMap(a=>(a.sourceChildren??[]).map(childIdentity)),...requiredSites.flatMap(s=>s.sourceChildren)])];
  sourceIndex.push({sourceIdentity:identity,sourceSHA256:node.sourceSHA256,requiredSites,sourceChildren,closed:false});
 }
 const bySource=new Map(sourceIndex.map(n=>[n.sourceIdentity,n])),visiting=new Set();
 function closed(identity){
  if(identity==='zasp_authorization80_worker.projected74()')return true;
  const index=bySource.get(identity);if(!index||!index.requiredSites.length)return false;
  if(visiting.has(identity))return true; // Back-edge only; all local sites still checked.
  visiting.add(identity);
  const value=index.requiredSites.every(s=>s.disposition!=='unresolved')&&!unresolved.some(u=>u.sourceIdentity===identity)&&index.sourceChildren.every(closed);
  visiting.delete(identity);return value;
 }
 for(const index of sourceIndex){index.closed=closed(index.sourceIdentity);if(!index.closed){const node=byIdentity.get(index.sourceIdentity);missing(sourceSite(source,node.identity,0,Buffer.byteLength(node.source)),'source-child-closure','required source site or recursive child is not closed',[node.identity]);}}
 return {entries,rawRules,liveWitnesses,retainedOpaque,unresolved,sourcePins:{...fixed,...supportPins},runtimeAlgebra,requiredIndex,sourceIndex,materializedIndex};
}
export function buildOrderedCaptureClosure(input){const {source,catalog}=admitted(input);return derive(source,catalog);}
export function assertOrderedCaptureClosure(closure){
 if(!closure||!Array.isArray(closure.entries)||!Array.isArray(closure.unresolved))throw Error('capture closure coverage shape');
 const required=derive(pinned('ordered-current-effective-contract3.json'),pinned('ordered-current-effective-catalog1.json'));
 // Re-derive from immutable source, never from the caller's reduced entries.
 for(const key of Object.keys(required))if(!same(closure[key],required[key]))throw Error('capture source/frame coverage mismatch '+key);
 if(required.unresolved.length)throw Error('capture unresolved coverage '+required.unresolved[0].sourceIdentity+' '+required.unresolved[0].field);
}
