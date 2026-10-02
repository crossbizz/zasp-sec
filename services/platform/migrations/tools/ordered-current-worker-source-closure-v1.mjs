// Source-authorized worker closure only. This module emits no expected facts
// and cannot install an evaluator. Native values and live calls stay explicit.
import crypto from 'node:crypto';
import fs from 'node:fs';
import {lowerOrderedWorkerProjections,orderedWorkerOpaqueBranchesV1,orderedWorkerSourceClosureCountsV1} from './ordered-current-worker-projections.mjs';
import {lowerOrderedWorkerEdgeProjections,orderedWorkerEdgeSourceClosureCountsV1} from './ordered-current-worker-edge-projections.mjs';
import {validateOrderedWorkerSourceRecipeContractV1} from './ordered-current-transform-compiler.mjs';
import {buildOrderedWorkerNativeReferenceContractV1,assertOrderedWorkerNativeObservationBoundsV1 as assertNativeBounds} from './ordered-current-reference-needs.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const sourceContractFileSHA256='be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6';
const canonicalSourceContractSHA256='f705efaa4390c7e73cf9d8a7ac6be9c7795b759da98debdf935e128ffb873cc4';
const authorityURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url);
export const workerSourceClosureAuthorityV1=Object.freeze({url:authorityURL,fileSHA256:sourceContractFileSHA256,canonicalSHA256:canonicalSourceContractSHA256});
const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
const aggregate='UNION ALL bag, bytewise value ordering, newline string_agg, UTF8 SHA256';
const recipeSemantic=Object.freeze({
  branch:'preserve exact source-selected branch and conditional demand',
  frame:'evaluate at the pinned original invocation frame',
  aggregate,
  nulls:'concat_ws skips NULL fields; empty aggregate remains NULL',
  multiplicity:'preserve every source row and duplicate; never DISTINCT',
  errors:'retain original cast, relation, column and scalar-subquery errors',
});
const delegateSemantic=Object.freeze({
  execution:'live invocation at the original source demand point',
  nulls:'preserve concatenation NULL behavior; no empty-result substitution',
  errors:'propagate original invocation and resolution errors',
  aggregate:'retain source UNION ALL multiplicity and outer ordered digest',
});
const conditionalSemantic=Object.freeze({
  branch:'ordered CASE; only the selected value arm is evaluated',
  scalar:'zero rows => NULL; more than one row => SQLSTATE 21000',
  errors:'retain original reg-object resolution and selected helper errors',
  aggregate,
  nulls:'concat_ws skips NULL fields; empty aggregate remains NULL',
  multiplicity:'preserve every source row and duplicate; never DISTINCT',
});

function nodeFor(contract,identity){
  const found=contract.nodes.filter(node=>node.identity===identity);
  if(found.length!==1)throw Error('worker source closure identity coverage '+identity);
  return found[0];
}
function callsFor(contract,site){
  const node=nodeFor(contract,site.identity);
  return node.inventory.calls.filter(call=>call.start>=site.start&&call.end<=site.end).map(call=>{
    const targets=contract.nodes.filter(candidate=>candidate.identity.startsWith(call.name+'('));
    if(targets.length!==1)throw Error('worker source closure unknown call '+call.name);
    return {name:call.name,identity:targets[0].identity,start:call.start,end:call.end,siteSHA256:call.id};
  });
}
function sourceRow(site,ruleId,disposition){
  return {ruleId,sourceIdentity:site.identity,sourceSHA256:site.sourceSHA256,definitionSHA256:site.definitionSHA256,siteSHA256:site.sha256,start:site.start,end:site.end,branch:site.type,frame:structuredClone(site.frame),disposition};
}
function recipeRow(contract,recipe){
  const calls=callsFor(contract,{identity:recipe.sourceIdentity,start:recipe.start??0,end:recipe.end??Number.MAX_SAFE_INTEGER});
  return {ruleId:recipe.ruleId,sourceIdentity:recipe.sourceIdentity,sourceSHA256:recipe.sourceSHA256,definitionSHA256:recipe.definitionSHA256,siteSHA256:recipe.siteSHA256,start:recipe.start??null,end:recipe.end??null,branch:recipe.ruleId.split(':').at(-1),frame:structuredClone(recipe.frame),projectionMode:recipe.projectionMode??'ordered-concat-fields',projections:structuredClone(recipe.projections),source:recipe.source,calls,semantic:{...recipeSemantic},disposition:'source-authorized-native-value-pending'};
}
function delegateRow(contract,obligation,kind){
  const calls=callsFor(contract,{identity:obligation.sourceIdentity,start:obligation.start??0,end:obligation.end??Number.MAX_SAFE_INTEGER});
  if(calls.length!==1)throw Error('worker source closure delegate target '+obligation.ruleId);
  return {ruleId:obligation.ruleId,sourceIdentity:obligation.sourceIdentity,sourceSHA256:obligation.sourceSHA256,definitionSHA256:obligation.definitionSHA256,siteSHA256:obligation.siteSHA256,start:obligation.start??null,end:obligation.end??null,branch:obligation.branch??obligation.ruleId.split(':').at(-1),frame:structuredClone(obligation.frame),target:calls[0].identity,calls,source:obligation.source,semantic:{...delegateSemantic},disposition:kind};
}
function classifySites(worker,edge){
  const rows=[];
  const classify=(site,component)=>{
    if(site.type==='digest')return 'aggregate-runtime-obligation';
    const id=component==='worker'?`worker:${site.family}:${site.type}`:`worker-edge:${site.family}:${site.ordinal}`;
    if((component==='worker'?worker.rules:edge.rules).some(row=>row.id===id))return 'direct-source-reference';
    if((component==='worker'?worker.recipes:edge.recipes).some(row=>row.ruleId===id))return component==='worker'?'worker-source-recipe':'edge-conditional-recipe';
    const obligations=(component==='worker'?worker.obligations:edge.obligations).filter(row=>row.ruleId===id);
    if(obligations.some(row=>row.type==='original-delegate'))return component==='worker'?'unavailable-live-universe':'live-delegate';
    if(obligations.some(row=>row.type==='membership-bag'))return 'membership-bag';
    return 'unclassified';
  };
  for(const [component,lowered]of [['worker',worker],['edge',edge]])for(const site of lowered.sites){
    const disposition=classify(site,component),ruleId=site.type==='digest'?`${component}:${site.family}:aggregate`:component==='worker'?`worker:${site.family}:${site.type}`:`worker-edge:${site.family}:${site.ordinal}`;
    rows.push(sourceRow(site,ruleId,disposition));
  }
  return rows;
}

function derive(contract){
  if(!contract||!Array.isArray(contract.nodes))throw Error('worker source closure source contract');
  if(sha(JSON.stringify(contract))!==canonicalSourceContractSHA256)throw Error('worker source closure source contract pin');
  const worker=lowerOrderedWorkerProjections(contract),edge=lowerOrderedWorkerEdgeProjections(contract);
  const workerSite=row=>{
    const site=worker.sites.find(site=>site.sha256===row.siteSHA256&&site.identity===row.sourceIdentity);
    if(!site)throw Error('worker source closure recipe site '+row.ruleId);
    return {...row,start:site.start,end:site.end};
  };
  const unavailableUniverses=worker.obligations.filter(row=>row.type==='original-delegate').map(row=>delegateRow(contract,workerSite(row),'live-unavailable-worker-universe'));
  const workerRecipes=worker.recipes.map(recipe=>recipeRow(contract,workerSite(recipe)));
  const edgeConditionals=edge.recipes.map(recipe=>{
    const row=recipeRow(contract,recipe);
    return {...row,branch:recipe.branch,type:recipe.type,caseExpressions:recipe.projections.filter(expression=>/\bCASE\b/i.test(expression)),semantic:{...conditionalSemantic},disposition:'source-authorized-conditional-runtime-pending'};
  });
  const membershipBags=edge.obligations.filter(row=>row.type==='membership-bag').map(row=>({
    ruleId:row.ruleId,sourceIdentity:row.sourceIdentity,sourceSHA256:row.sourceSHA256,definitionSHA256:row.definitionSHA256,siteSHA256:row.siteSHA256,start:row.start,end:row.end,branch:row.branch,frame:structuredClone(row.frame),fields:['granted_role','member_role','admin_option'],projections:structuredClone(row.projections),from:row.from,source:row.source,calls:callsFor(contract,{identity:row.sourceIdentity,start:row.start,end:row.end}),bag:true,semantic:{multiplicity:'UNION ALL bag; preserve duplicate membership rows',nulls:'concat_ws skips NULL fields without replacing them',errors:'retain original regrole resolution and relation errors',aggregate},disposition:'source-authorized-native-bag-pending',
  }));
  const delegates=edge.obligations.filter(row=>row.type==='original-delegate').map(row=>delegateRow(contract,row,'live-delegate-runtime-obligation'));
  validateOrderedWorkerSourceRecipeContractV1(workerRecipes,{count:orderedWorkerSourceClosureCountsV1.recipes,prefix:'worker:'});
  validateOrderedWorkerSourceRecipeContractV1(edgeConditionals,{count:orderedWorkerEdgeSourceClosureCountsV1.conditionals,prefix:'worker-edge:'});
  const retainedOpaque=orderedWorkerOpaqueBranchesV1.map(branch=>{
    const ruleId='worker:projected74:'+branch,site=worker.sites.find(row=>row.family==='projected74'&&row.type===branch);
    if(!site||!worker.rules.some(rule=>rule.id===ruleId))throw Error('worker source closure opaque branch '+branch);
    return {...sourceRow(site,ruleId,'retain-original-framed-opaque'),semantic:{frame:'original projected74 SQL frame only',values:'never promote catalog1 or target-derived values',runtime:'compare through the retained opaque fingerprint until later native parity'}};
  });
  const sourceSites=classifySites(worker,edge);
  if(sourceSites.some(row=>row.disposition==='unclassified'))throw Error('worker source closure unclassified source site');
  if(unavailableUniverses.length!==orderedWorkerSourceClosureCountsV1.unavailableUniverses||workerRecipes.length!==orderedWorkerSourceClosureCountsV1.recipes||edgeConditionals.length!==orderedWorkerEdgeSourceClosureCountsV1.conditionals||membershipBags.length!==orderedWorkerEdgeSourceClosureCountsV1.membershipBags||delegates.length!==orderedWorkerEdgeSourceClosureCountsV1.delegates||retainedOpaque.length!==orderedWorkerSourceClosureCountsV1.retainedOpaque||sourceSites.length!==orderedWorkerSourceClosureCountsV1.branches+orderedWorkerSourceClosureCountsV1.digestTails+orderedWorkerEdgeSourceClosureCountsV1.branches+orderedWorkerEdgeSourceClosureCountsV1.digestTails)throw Error('worker source closure coverage counts');
  const nativeObservation=buildOrderedWorkerNativeReferenceContractV1({workerRecipes,edgeConditionals,membershipBags});
  const runtimeObligations=[...unavailableUniverses,...workerRecipes,...edgeConditionals,...delegates].map(row=>({ruleId:row.ruleId,sourceIdentity:row.sourceIdentity,siteSHA256:row.siteSHA256,disposition:row.disposition}));
  const packet={format:'ordered-current-worker-source-closure-v1',status:'SOURCE-CLOSED-NATIVE-VALUES-PENDING',installable:false,captureReady:false,sourceContractFileSHA256,canonicalSourceContractSHA256,sourceSites,unavailableUniverses,workerRecipes,edgeConditionals,membershipBags,delegates,retainedOpaque,nativeObservation,runtimeObligations};
  return packet;
}

export function buildOrderedWorkerSourceClosureV1(contract){
  if(arguments.length!==1)throw Error('worker source closure caller-selected paths/hashes refused');
  return derive(contract);
}

export function admitOrderedWorkerSourceClosureV1(){
  if(arguments.length!==0)throw Error('worker source closure caller-selected authority refused');
  const raw=fs.readFileSync(authorityURL);if(sha(raw)!==sourceContractFileSHA256)throw Error('worker source closure tracked authority pin');
  return derive(JSON.parse(raw));
}

export function assertOrderedWorkerNativeObservationBoundsV1(observation,packet){
  if(arguments.length!==2||!packet?.nativeObservation)throw Error('worker native observation packet');
  return assertNativeBounds(observation,packet.nativeObservation);
}

export function assertOrderedWorkerSourceClosureV1(packet,contract){
  if(arguments.length!==2)throw Error('worker source closure assertion inputs');
  const required=derive(contract);
  if(!same(packet,required))throw Error('worker source closure source/frame/rule coverage mismatch');
}
