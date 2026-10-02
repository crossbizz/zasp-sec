// One source-indexed successor reference proposal. Deliberately not an intake
// authority: missing frames/bounds cannot be repaired with fixture row counts.
import crypto from 'node:crypto';
import fs from 'node:fs';
import {compileOrderedCollector,inspectOrderedReferenceRules,orderedReferenceInput} from './ordered-current-catalog.mjs';
import {lowerOrderedWorkerProjections} from './ordered-current-worker-projections.mjs';
import {lowerOrderedWorkerEdgeProjections} from './ordered-current-worker-edge-projections.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {orderedFactTypes} from './build-ordered-current-integrity.mjs';
import {buildOrderedWorkerSourceClosureV1} from './ordered-current-worker-source-closure-v1.mjs';
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const sourceAuthorityURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url);
const catalogAuthorityURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',import.meta.url);
const sourceFileSHA256='be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6';
const sourceCanonicalSHA256='f705efaa4390c7e73cf9d8a7ac6be9c7795b759da98debdf935e128ffb873cc4';
const catalogFileSHA256='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077';
const catalogCanonicalSHA256='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077';
export const orderedWorkerConsolidationAuthorityV1=Object.freeze({
 source:Object.freeze({url:sourceAuthorityURL,fileSHA256:sourceFileSHA256,canonicalSHA256:sourceCanonicalSHA256}),
 catalog:Object.freeze({url:catalogAuthorityURL,fileSHA256:catalogFileSHA256,canonicalSHA256:catalogCanonicalSHA256}),
});
const captured=new Set(['namespace','relation','column','column_name','constraint','global_constraint','index','policy','trigger','saved_function','saved_constraint','role','routine']);
function finiteDomain(selector,field){
 if(selector?.field===field&&Object.hasOwn(selector,'equals'))return new Set([selector.equals]);
 if(selector?.any){const sets=selector.any.map(s=>finiteDomain(s,field));return sets.every(Boolean)?new Set(sets.flatMap(s=>[...s])):null;}
 if(selector?.all){const sets=selector.all.map(s=>finiteDomain(s,field)).filter(Boolean);return sets.length?new Set([...sets[0]].filter(v=>sets.every(s=>s.has(v)))):null;}
 return null;
}
export function buildOrderedConsolidationNeeds(source,catalog){
 if(sha(JSON.stringify(source))!==sourceCanonicalSHA256)throw Error('consolidation source contract pin');
 if(sha(JSON.stringify(catalog))!==catalogCanonicalSHA256)throw Error('consolidation source catalog pin');
 const workers=lowerOrderedWorkerProjections(source),edge=lowerOrderedWorkerEdgeProjections(source);
 const workerSourceClosure=buildOrderedWorkerSourceClosureV1(source);
 const available=inspectOrderedReferenceRules(workers.rules,orderedReferenceInput(catalog),captured);
 const pendingIds=new Set(available.pending.map(r=>r.id));
 const workerRules=workers.rules.filter(r=>pendingIds.has(r.id)&&!r.id.startsWith('worker:projected74:'));
 if(workerRules.length!==11||edge.rules.length!==39||edge.referenceNeeds.length!==39)throw Error('consolidation source coverage changed');
 const workerNeeds=workerRules.map(rule=>{
  const [,family,branch]=rule.id.split(':');
  const sites=workers.sites.filter(s=>s.family===family&&s.type===branch);
  if(sites.length!==1)throw Error('worker reference source site absent');
  const site=sites[0],names=finiteDomain(rule.selector,'name'),namespaces=finiteDomain(rule.selector,'namespace');
  const sourceMaxRows=rule.kind==='relation'&&names&&namespaces?names.size*namespaces.size:null;
  return {ruleId:rule.id,kind:rule.kind,fields:rule.fields,selector:rule.selector,sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,start:site.start,end:site.end,source:site.text,frame:site.frame,keyFrame:'pg_catalog',captureFrame:'original-source-frame',referenceStatus:'missing-independent-reference',sourceMaxRows,sourceMaxRowsBasis:sourceMaxRows===null?null:'finite namespace/name selector product; pg_class unique name within namespace'};
 });
 const temporal=lowerOrderedTemporalTransforms(source),pub=lowerOrderedPublicFunctionTransforms(source);
 const transformNeeds=[...temporal.recipes,...pub.recipes].map(recipe=>({ruleId:recipe.ruleId,sourceIdentity:recipe.sourceIdentity,sourceSHA256:recipe.sourceSHA256,siteSHA256:recipe.siteSHA256,selector:recipe.selector,fields:Object.keys(recipe.fields),referenceStatus:'missing-independent-original-frame-input',originalFrame:'pg_catalog, public',keyFrame:'pg_catalog',sourceMaxRows:null,
   required:['original-frame definition','original-frame identity_arguments','original-frame projected identity','source-selected scalar/ACL observations',...(recipe.ruleId.startsWith('public:')?['original proconfig::text','array_ndims(proconfig)','array_lower(proconfig,1)','array_upper(proconfig,1)']:[])],
   refusal:'Old pg_catalog raw strings and native5 within-fixture observations are not independent expected truth.'}));
 const rules=[...workerRules,...edge.rules],needs=[...workerNeeds,...edge.referenceNeeds];
 const sql=compileOrderedCollector(rules).sql+'\n';
 const fieldTypes=Object.fromEntries(rules.map(rule=>[rule.id,Object.fromEntries(rule.fields.map(field=>{const type=orderedFactTypes[rule.kind]?.[field];if(!type)throw Error('reference field type absent');return [field,type];}))]));
 const ruleMaxRows=Object.fromEntries(needs.map(n=>[n.ruleId,n.sourceMaxRows??4096]));
 const ruleMaxBytes=Object.fromEntries(needs.map(n=>[n.ruleId,16777216]));
 const ruleCapBasis=Object.fromEntries(needs.map(n=>[n.ruleId,n.sourceMaxRows===null?'fixed source-site refusal ceiling of 4096 rows; never expected target cardinality':n.sourceMaxRowsBasis]));
 const pendingCaps=[];
 const maxRows=Object.values(ruleMaxRows).reduce((sum,value)=>sum+value,0),maxBytes=67108864;
 return {sql,contract:{format:'ordered-current-consolidated-reference-proposal-v1',status:'BLOCKED-NOT-CAPTURE-READY',installable:false,captureReady:false,sqlSHA256:sha(sql),queryUse:'Review-only pg_catalog descriptor proposal. Do not execute as accepted capture: original-frame projections and native observation are unresolved.',requiredRole:'zasp_discovery_authority',canonicalKeyFrame:'pg_catalog',requiredTimeZone:'UTC',maxRows,maxBytes,overflow:'abort-and-publish-nothing',ruleMaxRows,ruleMaxBytes,ruleCapBasis,fieldTypes,pendingCaps,
   workerNeeds,edgeNeeds:edge.referenceNeeds,transformNeeds,rules,
   retainedOpaqueNeeds:available.pending.filter(r=>r.id.startsWith('worker:projected74:')),
   workerSourceClosure,sourceSites:[...workers.sites,...edge.sites],obligations:[...workers.obligations,...edge.obligations,...temporal.obligations,...pub.obligations],
   unresolvedRecipes:[...workers.recipes,...edge.recipes],
   blockers:['Run the fixed worker native observation under the finite publish-nothing row/byte refusal caps; no captured values are admitted yet.','Bind original-frame field projections separately from canonical keys, including all thirteen transformed recipes and actual config dimension witnesses.','Independent fixed regprocedure resolution for runtime50 binding; missing casts retain original errors.','Worker source sites are closed, but their fixed native observation packet has not run; two77 and mixed schedule/export source semantics remain required.'],
   captureProtocol:'One consolidated independent e12 reference after source/cap/frame review; fixed pins, original admission before/after, exact role/frame, rollback/publication and owned cleanup. No per-leaf partial capture or caller-selected repinning.'}};
}
export function admitOrderedWorkerConsolidationNeedsV1(){
 if(arguments.length!==0)throw Error('consolidation caller-selected authority refused');
 const sourceRaw=fs.readFileSync(sourceAuthorityURL),catalogRaw=fs.readFileSync(catalogAuthorityURL);
 if(sha(sourceRaw)!==sourceFileSHA256||sha(catalogRaw)!==catalogFileSHA256)throw Error('consolidation tracked authority pin');
 return buildOrderedConsolidationNeeds(JSON.parse(sourceRaw),JSON.parse(catalogRaw));
}
export function admitOrderedConsolidationCapture(){
 // No approved complete capture contract or independent input exists yet.
 throw Error('consolidation capture contract incomplete');
}
export function assertOrderedConsolidationCaptureBoundsV1(observation,contract){
 if(arguments.length!==2||!contract||contract.format!=='ordered-current-consolidated-reference-proposal-v1'||contract.installable!==false||contract.captureReady!==false||contract.overflow!=='abort-and-publish-nothing'||!Array.isArray(contract.rules)||!Number.isSafeInteger(contract.maxRows)||contract.maxRows<=0||!Number.isSafeInteger(contract.maxBytes)||contract.maxBytes<=0||!Array.isArray(contract.pendingCaps)||contract.pendingCaps.length)throw Error('consolidation capture contract bounds');
 const needs=[...contract.workerNeeds,...contract.edgeNeeds],ids=contract.rules.map(rule=>rule.id);if(needs.length!==ids.length||new Set(ids).size!==ids.length)throw Error('consolidation capture rule coverage');
 let expectedRows=0;for(const need of needs){const rows=need.sourceMaxRows??4096;if(contract.ruleMaxRows?.[need.ruleId]!==rows||contract.ruleMaxBytes?.[need.ruleId]!==16777216||typeof contract.ruleCapBasis?.[need.ruleId]!=='string')throw Error('consolidation capture rule cap');expectedRows+=rows;}
 if(contract.maxRows!==expectedRows||contract.maxBytes!==67108864||Object.keys(contract.ruleMaxRows).length!==ids.length||Object.keys(contract.ruleMaxBytes).length!==ids.length)throw Error('consolidation capture total cap');
 if(!observation||Object.keys(observation).sort().join(',')!=='rules,totalBytes,totalRows,truncated'||observation.truncated!==false||!Array.isArray(observation.rules)||observation.rules.length!==ids.length)throw Error('consolidation capture observation shape');
 const seen=new Set();let rows=0,bytes=0;for(const row of observation.rules){if(!row||Object.keys(row).sort().join(',')!=='bytes,rows,ruleId'||seen.has(row.ruleId)||!ids.includes(row.ruleId)||!Number.isSafeInteger(row.rows)||row.rows<0||!Number.isSafeInteger(row.bytes)||row.bytes<0)throw Error('consolidation capture observation rule');seen.add(row.ruleId);if(row.rows>contract.ruleMaxRows[row.ruleId]||row.bytes>contract.ruleMaxBytes[row.ruleId])throw Error('consolidation capture rule overflow');rows+=row.rows;bytes+=row.bytes;}
 if(rows!==observation.totalRows||bytes!==observation.totalBytes||rows>contract.maxRows||bytes>contract.maxBytes)throw Error('consolidation capture total overflow');
}
export function buildOrderedWorkerSourceClosureNeedsV1(source){
 return buildOrderedWorkerSourceClosureV1(source);
}
