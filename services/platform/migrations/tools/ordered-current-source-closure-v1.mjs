// Fixed build-time source closure. This is not an executable replacement for
// the original predicates, an observation intake, or installation authority.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {workerSourceClosureAuthorityV1} from './ordered-current-worker-source-closure-v1.mjs';
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
import {lowerOrderedPublicCatalog} from './ordered-current-public-selectors.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedTemporal77Transforms} from './ordered-current-temporal77-transforms.mjs';
import {compileOrderedTemporal77Candidate} from './ordered-current-temporal77-candidate.mjs';
import {lowerOrderedMixedTransforms} from './ordered-current-mixed-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {compileOrderedPrivateRoutines,compileOrderedDirectPrivateRoutinesV1,privateObjectRules,withOrderedFrameClosure,withOrderedDirectFrameClosureV1} from './ordered-current-private.mjs';
import {admitOrderedPrivateReference} from './ordered-current-private-reference.mjs';
import {staticDescriptor} from './ordered-current-static-catalog.mjs';
import {compileOrderedPrecisionPrivateRoutinesV1} from './ordered-current-private.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=message=>{throw Error('current source closure '+message);};
const artifact=name=>new URL('./ordered-current-worker-source-closure-v1-artifacts/'+name,import.meta.url);
export const orderedCurrentSourceClosureModulesV1=Object.freeze(['ordered-current-source-closure-v1.mjs','ordered-current-worker-source-closure-v1.mjs','ordered-current-worker-projections.mjs','ordered-current-worker-edge-projections.mjs','ordered-current-reference-needs.mjs','ordered-current-temporal-selectors.mjs','ordered-current-temporal72.mjs','ordered-current-public-selectors.mjs','ordered-current-temporal-transforms.mjs','ordered-current-temporal77-transforms.mjs','ordered-current-temporal77-candidate.mjs','ordered-current-mixed-transforms.mjs','ordered-current-public-function-transforms.mjs','ordered-current-private.mjs','ordered-current-private-reference.mjs','ordered-current-static-catalog.mjs','ordered-current-transform-compiler.mjs','ordered-current-catalog.mjs','ordered-current-deparse-frame.mjs','ordered-current-direct-frame-v1.mjs','ordered-current-precision-resolver-frame-v1.mjs','build-ordered-current-integrity.mjs']);
const frameKeys=['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'];
const frame=node=>Object.fromEntries(frameKeys.map(key=>[key,structuredClone(node[key])]));
const nativeCases={
 temporal77:['like-underscore','membership-null','membership-duplicates','membership-cast-error','saved-zero-null','saved-multiple-error','helper-unselected-no-demand','helper-selected-binding-error','put-source-before-helper','native-first-error','original-frame-deparse','aggregate-null-bag'],
 schedule:['outer-cast-error','unselected-helper-binding','selected-helper-binding','guard-false-null','guard-null-null','saved-zero-null','saved-multiple-error','native-first-error','original-frame-deparse','aggregate-null-bag'],
 export:['owner-not-registered','member-false','member-null','duplicate-bindings-exists','acl-ordinality','acl-tags-cannot-collide','acl-remove-grantee-only','acl-empty-null','acl-scalar-error','raw-else-text','native-first-error','aggregate-null-bag'],
 wrapper:['condition-false-fallback','condition-null-fallback','selected-call-error','unselected-call-no-demand','registration-cardinality','owner-acl-frame-drift','native-first-error'],
 retirement:['schema-absent-row-absent-continue','schema-present-row-absent-false','schema-absent-row-present-false','duplicate-select-into-not-scalar-error','original-fingerprint-null-or-drift','dynamic-fingerprint-error','retired-fingerprint-null-or-drift','worker-execute-true','worker-execute-null','native-first-error'],
};

function nodeFor(contract,identity){
 const nodes=contract.nodes.filter(node=>node.identity===identity);
 if(nodes.length!==1)fail('identity cardinality '+identity);
 const node=nodes[0];
 if(sha(node.source)!==node.sourceSHA256||sha(node.definition)!==node.definitionSHA256)fail('source bytes '+identity);
 return node;
}
function callsFor(contract,site){
 const node=nodeFor(contract,site.sourceIdentity);
 return node.inventory.calls.filter(call=>call.start>=site.start&&call.end<=site.end).map(call=>{
  const targets=contract.nodes.filter(target=>target.identity.startsWith(call.name+'('));
  if(targets.length!==1)fail('unknown or overloaded call '+call.name);
  const target=nodeFor(contract,targets[0].identity);
  return {identity:target.identity,start:call.start,end:call.end,siteSHA256:call.id,source:call.text,targetSourceSHA256:target.sourceSHA256,targetDefinitionSHA256:target.definitionSHA256,targetFrame:frame(target),execution:'original-source-demand-point'};
 });
}
function sourceSite(contract,site,component,lowered){
 const ruleId=component+':'+site.family+':'+site.type;
 const obligations=lowered.obligations.filter(o=>o.siteSHA256===site.sha256);
 const rule=lowered.rules.find(r=>r.id===ruleId);
 const disposition=rule?'source-descriptor-reference':obligations.length?'source-bound-runtime-obligation':'unclassified';
 if(disposition==='unclassified')fail('unclassified site '+ruleId);
 const row={ruleId,family:site.family,branch:site.type,sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,start:site.start,end:site.end,source:site.text,frame:frame(nodeFor(contract,site.identity)),disposition,rule:rule??null,obligations};
 row.calls=callsFor(contract,row);
 return row;
}
function retirement(contract){
 const n=nodeFor(contract,'zasp_temporal68.predecessor_ready(text,text)'),start=118841,end=119679;
 const source=Buffer.from(n.source).subarray(start,end).toString('utf8');
 if(n.sourceSHA256!=='dd0f5fe44a5f0eb1c5853f555adce40e13e43e5fcd70cb3c0f5361a6f4afac4c'||n.definitionSHA256!=='c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6'||sha(source)!=='5b50a6159ba6a8afb26d656ca91273a2c838558d06a14b6d59d0e3230eeb736a')fail('retirement source pin');
 const schemas=['zasp_ordered_worker63','zasp_ordered_scheduler64'];
 for(const schema of schemas){let refused=false;try{staticDescriptor('registration',[schema]);}catch{refused=true;}if(!refused)fail('retirement static registration widening');}
 const catalogFileSHA256='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',catalogRaw=fs.readFileSync(artifact('effective-catalog1.json'));
 if(sha(catalogRaw)!==catalogFileSHA256)fail('retirement static catalog pin');
 const capturedOrderedSchemas=JSON.parse(catalogRaw).registrations.filter(row=>row.schema.startsWith('zasp_ordered_')).map(row=>row.schema);
 if(canonicalOrderedJSON(capturedOrderedSchemas)!=='["zasp_ordered_public62"]')fail('retirement static catalog coverage');
 const kinds=['select-into-nonstrict','namespace-found-distinct','absent-continue','fixed-original-fingerprint','dynamic-fingerprint','retired-fingerprint-or-worker-execute'];
 const lines=source.split('\n').slice(1).filter(line=>line.trim());
 if(lines.length!==kinds.length)fail('retirement statement coverage');
 return {ruleId:'temporal:68.predecessor_ready:retired63-64',family:'68.predecessor_ready',branch:'retired63-64',sourceIdentity:n.identity,sourceSHA256:n.sourceSHA256,definitionSHA256:n.definitionSHA256,siteSHA256:sha(source),start,end,source,frame:frame(n),disposition:'retain-original-live-demand',schemas,
  originalFingerprints:['c81c4cb4cb799894ab9bf69b16815341ac53665e967fd0405b32009898510239','9a8a090c97a4c8b913921dd1503b6ca0925c837adf5da9219c3c8f1e3a6d0419'],
  steps:lines.map((source,index)=>({kind:kinds[index],source,sourceSHA256:sha(source)})),nativeCases:[...nativeCases.retirement],staticRegistration:{catalogFileSHA256,capturedOrderedSchemas,forbiddenSchemas:schemas,capturedFingerprintsAreAuthority:false},
  semantics:'Keep non-STRICT SELECT INTO and its FOUND value, not scalar-subquery cardinality. Namespace existence must agree with FOUND; absent rows CONTINUE. Check fixed original fingerprint before dynamic EXECUTE, then retired fingerprint IS DISTINCT FROM and worker EXECUTE privilege. No static registration or captured dynamic fingerprint substitute.',
  blocker:'Original PL/pgSQL execution, duplicate-row selection, live namespace/privilege and first-error parity remain native gates.'};
}
function privateClosure(){
 const template=fs.readFileSync(new URL('../sql/0080_authorization_worker_ordered_current_integrity.sql',import.meta.url));
 const reference=admitOrderedPrivateReference(fs.readFileSync(artifact('private-reference-alias1.json')),{referenceFileSHA256:'15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607',contractRaw:fs.readFileSync(artifact('private-reference-alias-contract.json')),templateRaw:template,currentRules:privateObjectRules(),variant:'A',sessionUser:'zasp_test'});
 // Standalone admission is source-only. The generator attaches its freshly
 // assembled in-memory SQL below; generated output is never an input.
 const current=withOrderedFrameClosure(template.toString('utf8'));
 const ordinary=compileOrderedPrivateRoutines(current),direct=compileOrderedDirectPrivateRoutinesV1(withOrderedDirectFrameClosureV1(template.toString('utf8')));
 if(reference.facts.length!==35||reference.facts.some(f=>f.kind==='routine')||ordinary.facts.length!==7||direct.facts.length!==22)fail('private authority cardinality');
 return {routineAuthority:'current-compiler-evaluator-only',assemblyAuthority:'source-template-only',compilerInputSHA256:sha(current),routineFactsSHA256:sha(canonicalOrderedJSON(ordinary.facts)),ordinaryFrameRoutineCount:ordinary.facts.length,directFrameRoutineCount:direct.facts.length,ordinaryFrameDeclarations:ordinary.declarations,directFrameDeclarations:direct.declarations,continuityFacts:reference.facts,validatedLegacyRows:39,validatedLegacyRoutines:reference.validatedRoutineCount,importedRoutineObservations:0,blocker:'Compiler declarations are authority, not native evaluator/frame acceptance. Never import observed private routine bodies.'};
}
function secondaryInventory(contract,mixed,two77,publicFunctions){
 const row=(component,site)=>{
  const n=nodeFor(contract,site.identity),start=site.start??0,end=site.end??Buffer.byteLength(n.source),source=Buffer.from(n.source).subarray(start,end).toString('utf8');
  if(site.sourceSHA256!==n.sourceSHA256||site.definitionSHA256!==n.definitionSHA256||(site.sha256&&site.sha256!==sha(source)))fail('secondary site source');
  return {siteId:component+':'+n.identity+':'+start+':'+end,component,sourceIdentity:n.identity,sourceSHA256:n.sourceSHA256,definitionSHA256:n.definitionSHA256,siteSHA256:sha(source),start,end,source,frame:frame(n),disposition:'source-bound-runtime-obligation',semantics:'Preserve exact source and original invocation frame, selected helper demand, NULL/multiplicity/aggregate and binding/error order.',blocker:'No native invocation/frame/first-error parity or independent transformed reference admission is implied.'};
 };
 const sites=[...mixed.sites.map(s=>row('mixed',s)),...publicFunctions.obligations.filter(o=>o.helper).map(o=>row('public-helper',o.helper)),row('temporal77-helper',two77.helper),...mixed.guardInputs.map(s=>row('mixed-guard',s))];
 if(sites.length!==13||new Set(sites.map(s=>s.siteId)).size!==13)fail('secondary site coverage');
 return sites;
}
function derive(contract){
 if(!contract||sha(JSON.stringify(contract))!==workerSourceClosureAuthorityV1.canonicalSHA256)fail('source contract pin');
 const temporal=lowerOrderedTemporalCatalog(contract),publicCatalog=lowerOrderedPublicCatalog(contract);
 const temporalTransforms=lowerOrderedTemporalTransforms(contract),two77=lowerOrderedTemporal77Transforms(contract),mixed=lowerOrderedMixedTransforms(contract),publicFunctions=lowerOrderedPublicFunctionTransforms(contract);
 const sourceSites=[...temporal.sites.map(s=>sourceSite(contract,s,'temporal',temporal)),...publicCatalog.sites.map(s=>sourceSite(contract,s,'public',publicCatalog))];
 const wrappers=sourceSites.filter(s=>s.branch==='conditional-wrapper').map(site=>({...site,disposition:'retain-original-live-demand',fallback:site.source.includes("ELSE ''")?'':null,nativeCases:[...nativeCases.wrapper],blocker:'Original conditional expression including registration cardinality, body/owner/ACL/config checks and outgoing call demand remains live. Do not cache the result, flatten MATERIALIZED demand, or waive NULL/error parity.'}));
 const retired=retirement(contract);sourceSites.push(retired);
 const secondarySites=secondaryInventory(contract,mixed,two77,publicFunctions);
 const completeSites=[...sourceSites.map(s=>({...s,siteId:'primary:'+s.sourceIdentity+':'+s.start+':'+s.end,component:'primary'})),...secondarySites];
 const unclassified=completeSites.filter(s=>!s.disposition||s.disposition==='unclassified').length;
 if(completeSites.length!==246||new Set(completeSites.map(s=>s.siteId)).size!==246||unclassified!==0)fail('complete site coverage');
 const counts={temporalSites:temporal.sites.length,publicSites:publicCatalog.sites.length,retirementSites:1,sourceSites:sourceSites.length,temporalRules:temporal.rules.length,publicRules:publicCatalog.rules.length,temporalWrappers:wrappers.filter(w=>w.sourceIdentity.startsWith('zasp_temporal')).length,publicWrappers:wrappers.filter(w=>w.sourceIdentity.startsWith('public.')).length};
 if(canonicalOrderedJSON(counts)!==canonicalOrderedJSON({temporalSites:137,publicSites:95,retirementSites:1,sourceSites:233,temporalRules:92,publicRules:59,temporalWrappers:12,publicWrappers:4})||new Set(sourceSites.map(s=>s.sourceIdentity+':'+s.start+':'+s.end)).size!==233)fail('site coverage');
 const rules=sourceSites.filter(s=>s.disposition!=='source-descriptor-reference').map(site=>({ruleId:site.ruleId+'@'+site.start+':'+site.end,sourceRuleId:site.ruleId,sourceIdentity:site.sourceIdentity,siteSHA256:site.siteSHA256,maxRows:1024,maxBytes:1048576,capBasis:'fixed source site; conservative refusal cap, not observed capacity',frame:site.frame}));
 if(new Set(rules.map(r=>r.ruleId)).size!==rules.length)fail('native rule identity');
 return {format:'ordered-current-source-closure-v1',status:'SOURCE-CLASSIFIED-NATIVE-PARITY-PENDING',installable:false,nativeVerified:false,captureReady:false,sourceAuthority:{fileSHA256:workerSourceClosureAuthorityV1.fileSHA256,canonicalSHA256:workerSourceClosureAuthorityV1.canonicalSHA256},counts,sourceSites,secondarySites,completeInventory:{sites:completeSites,unclassified},
  temporalTransforms:{recipes:temporalTransforms.recipes,obligations:temporalTransforms.obligations},
  temporal77:{recipes:two77.recipes,helper:{...two77.helper,bindings:two77.helperBindings},candidate:compileOrderedTemporal77Candidate(contract),obligations:two77.obligations,nativeCases:[...nativeCases.temporal77],blockers:two77.unsupported},
  mixed:{schedule:{recipe:mixed.recipes[0],guardInputs:mixed.guardInputs,nativeCases:[...nativeCases.schedule]},export:{recipe:mixed.recipes[1],nativeCases:[...nativeCases.export]},sites:mixed.sites,obligations:mixed.obligations,blockers:mixed.unsupported},
  wrappers,publicFunctions:{...publicFunctions,referencePolicy:'independent-original-frame-raw-fields-only',targetDerivedConfigAllowed:false},retirement:retired,private:privateClosure(),
  nativeObservation:{format:'ordered-current-current-source-native-contract-v1',installable:false,captureReady:false,expectedFactsAllowed:false,rules,limits:{maxRows:rules.length*1024,maxBytes:67108864},protocol:'Reference contract only. No executable capture adapter admitted. Refuse overflow or truncation; do not paginate, sample, resize caps or use target output as expectations.'},
  blockers:['temporal77 selected helper-local demand, binding/planner and first-error native parity','mixed schedule original72 condition and saved universe/helper demand compilation','saved export fresh owner/MEMBER and ordered tagged ACL independent reference/native text parity','higher wrapper live registration/frame/call demand parity','public typed raw original-frame/config dimension reference admission','remaining source descriptors, live metadata, nested aggregates, membership bags and digest parity','retired63/64 original live PL/pgSQL demand and privilege parity','full 379-rule native truth/drift/NULL/forged-entry/frame parity; varied-login/OID and exact production PostgreSQL; connected installed-worker acceptance; full100 capacity; deployment/provider acceptance']};
}

export function buildOrderedCurrentSourceClosureV1(contract){if(arguments.length!==1)fail('caller-selected authority refused');return derive(contract);}
export function admitOrderedCurrentSourceClosureV1(){
 if(arguments.length!==0)fail('caller-selected authority refused');
 const raw=fs.readFileSync(workerSourceClosureAuthorityV1.url);
 if(sha(raw)!==workerSourceClosureAuthorityV1.fileSHA256)fail('tracked authority pin');
 return derive(JSON.parse(raw));
}
export function assertOrderedCurrentSourceClosureV1(packet,contract,assembly){
 if(arguments.length===3)return assertOrderedCurrentAttachedSourceClosureV1(packet,contract,assembly);
 if(arguments.length!==2||canonicalOrderedJSON(packet)!==canonicalOrderedJSON(derive(contract)))fail('packet source/frame/rule/semantic mismatch');
}
function attachedPrivateAuthority(packet,sql,compiled,precision=false){
 let actual;
 try{
  if(typeof sql!=='string')fail('private assembly SQL');
  actual=precision?compileOrderedPrecisionPrivateRoutinesV1(sql):compileOrderedPrivateRoutines(sql);
  if(actual.facts.length!==(precision?8:7)||canonicalOrderedJSON(actual)!==canonicalOrderedJSON(compiled))fail('private in-memory compiler closure');
 }catch{fail('private in-memory compiler closure');}
 return {...structuredClone(packet),private:{...structuredClone(packet.private),assemblyAuthority:precision?'generator-in-memory-precision-resolver-v1':'generator-in-memory',compilerInputSHA256:sha(sql),routineFactsSHA256:sha(canonicalOrderedJSON(actual.facts)),ordinaryFrameDeclarations:actual.declarations,ordinaryFrameRoutineCount:actual.facts.length}};
}
function validateAttached(packet,base,assembly){
 // Assembly is an explicit in-memory witness, never a path, hash override or
 // a source of replacement base facts. Recompile it rather than trust its facts.
 if(!assembly||Object.getPrototypeOf(assembly)!==Object.prototype||Object.keys(assembly).sort().join(',')!=='kind,privateClosure,sql'||!['generator-in-memory','generator-in-memory-precision-resolver-v1'].includes(assembly.kind))fail('private assembly witness shape');
 const required=attachedPrivateAuthority(base,assembly.sql,assembly.privateClosure,assembly.kind==='generator-in-memory-precision-resolver-v1');
 // Compare the entire packet, including the attachment's exact field shape.
 // This preserves every base source, semantic, count, cap and provenance pin.
 if(canonicalOrderedJSON(packet)!==canonicalOrderedJSON(required))fail('attached packet source/private/frame/rule/semantic mismatch');
}
export function assertOrderedCurrentAttachedSourceClosureV1(packet,contract,assembly){
 if(arguments.length!==3)fail('attached packet inputs');
 validateAttached(packet,derive(contract),assembly);
}
export function attachOrderedCurrentPrivateAuthorityV1(packet,sql,compiled){
 if(arguments.length!==3||canonicalOrderedJSON(packet)!==canonicalOrderedJSON(admitOrderedCurrentSourceClosureV1()))fail('private source packet authority');
 return attachedPrivateAuthority(packet,sql,compiled);
}
export function attachOrderedCurrentPrecisionPrivateAuthorityV1(packet,sql,compiled){
 if(arguments.length!==3||canonicalOrderedJSON(packet)!==canonicalOrderedJSON(admitOrderedCurrentSourceClosureV1()))fail('private source packet authority');
 return attachedPrivateAuthority(packet,sql,compiled,true);
}
export function assertOrderedCurrentObservationBoundsV1(observation,packet,assembly){
 if(arguments.length!==2&&arguments.length!==3)fail('observation inputs');
 const required=admitOrderedCurrentSourceClosureV1();
 if(arguments.length===3)validateAttached(packet,required,assembly);
 else if(canonicalOrderedJSON(packet)!==canonicalOrderedJSON(required))fail('observation packet authority');
 const failObservation=()=>fail('observation coverage, counters or refusal cap');
 const exact=(value,keys)=>value&&Object.keys(value).sort().join(',')===keys;
 if(!exact(observation,'rules,totalBytes,totalRows,truncated')||observation.truncated!==false||!Array.isArray(observation.rules)||observation.rules.length!==required.nativeObservation.rules.length)failObservation();
 let rows=0,bytes=0;const seen=new Set(),rules=new Map(required.nativeObservation.rules.map(r=>[r.ruleId,r]));
 for(const row of observation.rules){
  const rule=rules.get(row?.ruleId);
  if(!exact(row,'bytes,rows,ruleId')||!rule||seen.has(row.ruleId)||!Number.isSafeInteger(row.rows)||row.rows<0||row.rows>rule.maxRows||!Number.isSafeInteger(row.bytes)||row.bytes<0||row.bytes>rule.maxBytes)failObservation();
  seen.add(row.ruleId);rows+=row.rows;bytes+=row.bytes;
 }
 if(rows!==observation.totalRows||bytes!==observation.totalBytes||rows>required.nativeObservation.limits.maxRows||bytes>required.nativeObservation.limits.maxBytes)failObservation();
}
