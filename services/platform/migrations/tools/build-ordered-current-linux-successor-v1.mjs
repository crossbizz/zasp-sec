// Complete declared-source contract for a dormant NON-INSTALLABLE evaluator.
// Source accounting is not executable replacement or native parity acceptance.
// No target connection, target-derived expectations, or SQL execution exists.
import fs from 'node:fs';
import {readOrderedCurrentLinuxProvenanceV1,linuxProvenanceInputSHA256} from './ordered-current-linux-provenance-v1.mjs';
import {admitOrderedCurrentNative379PacketV2} from './ordered-current-native379-packet-v2.mjs';
import crypto from 'node:crypto';
import {buildManifest,canonicalOrderedJSON,classifyOrderedAuth80Live,compileOrderedCollector,projectOrderedFacts,orderedFactTypes} from './build-ordered-current-integrity.mjs';
import {orderedReferenceInput,inspectOrderedReferenceRules,canonicalizeOrderedCurrentDevelopmentFacts} from './ordered-current-catalog.mjs';
import {compileOrderedPrecisionResolverCollectorV1} from './ordered-current-catalog.mjs';
import {mergeOrderedCurrentCanonicalCaptureFacts,canonicalizeOrderedCurrentPrecisionFacts} from './ordered-current-direct-reference-v2.mjs';
import {lowerOrderedWorkerCatalog,buildOrderedWorkerTest74StopEvidenceSource,native18WorkerClosure,assertNative18WorkerClosure} from './ordered-current-worker-selectors.mjs';
import {lowerOrderedWorkerProjections} from './ordered-current-worker-projections.mjs';
import {compileOrderedPrecisionPrivateRoutinesV1,privateObjectRules,withOrderedPrecisionResolverClosureV1} from './ordered-current-private.mjs';
import {admitOrderedSupplementaryReference} from './ordered-current-reference.mjs';
import {buildOrderedReferenceNeeds} from './ordered-current-reference-needs.mjs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
import {definitionFrame,definitionAdmissionSQL,admitFramedTransformSource} from './ordered-current-deparse-frame.mjs';
import {precisionResolverAdmissionSQLV1,inspectOrderedPrecisionResolverSourceV1} from './ordered-current-precision-resolver-frame-v1.mjs';
import {compileOrderedTransforms,projectOrderedTransforms} from './ordered-current-transform-compiler.mjs';
import {admitOrderedPrivateReference} from './ordered-current-private-reference.mjs';
import {admitOrderedRemainingReference} from './ordered-current-remaining-reference.mjs';
import {buildOrderedConsolidationNeeds} from './ordered-current-consolidation-needs.mjs';
import {lowerOrderedWorkerEdgeProjections} from './ordered-current-worker-edge-projections.mjs';
import {admitOrderedCurrentCaptureBundleV1,assertOrderedCurrentCaptureBundleV1} from './ordered-current-capture-intake-v1.mjs';
import {reconcileOrderedCurrentFactCollectionsV1} from './ordered-current-capture-reconciliation-v1.mjs';
import {orderedCurrentPrecisionConflictSettlementsV1} from './ordered-current-precision-conflict-settlement-v1.mjs';
import {admitOrderedCurrentSourceClosureV1,attachOrderedCurrentPrecisionPrivateAuthorityV1,assertOrderedCurrentAttachedSourceClosureV1,orderedCurrentSourceClosureModulesV1} from './ordered-current-source-closure-v1.mjs';
import {assertOrderedWorkerSourceClosureV1} from './ordered-current-worker-source-closure-v1.mjs';
import {native19WorkerSourceReplay} from './ordered-current-worker-source-replay-v1.mjs';
import {issueWorkerHigherIntegrationContextV1,applyWorkerHigherSuccessorV1} from './ordered-current-worker-higher-integration-v1.mjs';
import {proveRemainingProjectionV1,applyRemainingProjectionV1,remainingProjectionReferenceSHA256} from './ordered-current-remaining-projection-witness-v1.mjs';
import {readOrderedCurrentBuildSourceInventoryV1} from './ordered-current-build-source-inventory-v1.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
export function propagateNative21WorkerTailFacts(facts,replay){
 const identities=['zasp_authorization80_worker.test74_effect_source(text,jsonb)','zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)'];
 const accepted=(replay?.accepted??[]).filter(row=>row.category?.startsWith('worker-tail-'));
 if(accepted.length!==identities.length||new Set(accepted.map(row=>row.identity)).size!==identities.length||accepted.some(row=>!identities.includes(row.identity)||typeof row.replacementDefinition!=='string'||!/^f[0-9a-f]{63}$/.test(row.replacementFactSHA256)))throw Error('native21 worker-tail replay propagation authority');
 const before=new Map(facts.filter(row=>row.kind==='routine'&&JSON.parse(row.identity)[0]==='worker-line-5').map(row=>[JSON.parse(row.identity)[1],canonicalOrderedJSON(row.fact)]));
 const replacements=new Map();
 for(const replayRow of accepted){
  const matches=facts.filter(row=>row.kind==='routine'&&row.identity===JSON.stringify(['worker-line-5',replayRow.identity]));
  if(matches.length!==1)throw Error('native21 worker-tail fact cardinality '+replayRow.identity);
  const replacement={...matches[0].fact,definition:replayRow.replacementDefinition};
  if(sha(canonicalOrderedJSON(replacement))!==replayRow.replacementFactSHA256)throw Error('native21 worker-tail replacement hash '+replayRow.identity);
  replacements.set(matches[0].identity,replacement);
 }
 const projected=facts.map(row=>replacements.has(row.identity)?{...row,fact:replacements.get(row.identity)}:row);
 const changed=projected.filter(row=>row.kind==='routine'&&JSON.parse(row.identity)[0]==='worker-line-5'&&before.get(JSON.parse(row.identity)[1])!==canonicalOrderedJSON(row.fact));
 if(changed.length!==identities.length||!identities.every(identity=>changed.some(row=>row.identity===JSON.stringify(['worker-line-5',identity]))))throw Error('native21 worker-tail propagation cardinality');
 return projected;
}
export function applyOrderedCurrentRemainingProjectionV1(sourceInputs,directFacts,missingFacts){
 const proof=proveRemainingProjectionV1(sourceInputs);
 const projected=applyRemainingProjectionV1({proof,directFacts,missingFacts});
 return {...projected,proof};
}
const migrations=new URL('../',import.meta.url);
const artifactRoot=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const artifactNames=Object.freeze({'ordered-current-effective-contract3.json':'effective-contract3.json','ordered-current-effective-catalog1.json':'effective-catalog1.json','ordered-current-inventory-compiled.json':'inventory-compiled.json','ordered-current-supplementary-query-contract2.json':'supplementary-query-contract2.json','ordered-current-supplementary-reference1.json':'supplementary-reference1.json','ordered-current-private-reference-alias1.json':'private-reference-alias1.json','ordered-current-private-reference-alias-contract.json':'private-reference-alias-contract.json','ordered-current-remaining-reference1.json':'remaining-reference1.json','ordered-current-supplementary-query-contract3.json':'supplementary-query-contract3.json','ordered-current-remaining-reference-packet-manifest.json':'remaining-reference-packet-manifest.json'});
const artifactRaw=name=>{const tracked=artifactNames[name];if(!tracked)throw Error('untracked build authority '+name);return fs.readFileSync(new URL(tracked,artifactRoot));};
const readPinned=(name,pin)=>{const raw=artifactRaw(name);if(sha(raw)!==pin)throw Error('reference identity changed: '+name);return JSON.parse(raw);};
const contractPin='be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6';
const referencePin='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077';
const contract=readPinned('ordered-current-effective-contract3.json',contractPin);
const catalog=readPinned('ordered-current-effective-catalog1.json',referencePin);
const compiled=readPinned('ordered-current-inventory-compiled.json','4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425');
const supplementContractName='ordered-current-supplementary-query-contract2.json';
const supplementContractPin='6b8fc25c4d5d0a379735d686fe1d6cde8245663a47d346dbf8cf1c11dd33418f';
const supplementReferenceName='ordered-current-supplementary-reference1.json';
const supplementReferencePin='484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b';
const supplementContract=readPinned(supplementContractName,supplementContractPin);
const supplement=admitOrderedSupplementaryReference(artifactRaw(supplementReferenceName),{
  referenceFileSHA256:supplementReferencePin,contractRaw:artifactRaw(supplementContractName),variant:'A',sessionUser:'zasp_test'});
// The captured rule projections remain byte-identical to the reviewed query.
if(sha(compileOrderedCollector(supplementContract.rules).sql+'\n')!==supplementContract.sqlSHA256)throw Error('supplementary projection SQL changed');
if(sha(compiled.source)!=='233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850')throw Error('compiler source identity changed');
const auth80=classifyOrderedAuth80Live(contract);
const retainedSites=identity=>auth80.sites.filter(s=>s.identity===identity);
const successor={...contract,format:'ordered-current-effective-contract-v2',
  auth80RetainedObligations:auth80,
  partition:contract.partition.map(row=>({...row,retainedAuth80Comparisons:retainedSites(row.identity),
    ...(row.identity===auth80.primitive.identity?{disposition:'retain-original-framed-auth80-primitive',obligation:auth80.obligation}:{})})),
  materializedObligations:contract.materializedObligations.map(row=>({...row,retainedAuth80Comparisons:retainedSites(row.identity)})),
  higherRegions:contract.higherRegions.map(row=>({...row,predicateObligations:{...row.predicateObligations,retainedAuth80Comparisons:retainedSites(row.identity)}}))};
const successorText=JSON.stringify(successor,null,2)+'\n';
const workerLowering=lowerOrderedWorkerCatalog(contract,catalog);
const input=orderedReferenceInput(catalog);
const sourceBuiltTest74=buildOrderedWorkerTest74StopEvidenceSource(catalog);
const workerRules=workerLowering.rules.map(rule=>rule.id==='worker-line-5'&&sourceBuiltTest74
  ? {...rule,identities:[...rule.identities,sourceBuiltTest74.identity]}
  : rule);
if(sourceBuiltTest74)input.push({kind:'routine',identity:sourceBuiltTest74.identity,namespace:'zasp_authorization80_worker',fact:{definition:sourceBuiltTest74.definition,owner:sourceBuiltTest74.owner,acl:sourceBuiltTest74.acl},sourceClosure:sourceBuiltTest74.sourceClosure});
const workerProjectionModulePin='0bcd29c17c316416b38f978b22b4cb2ce561e0655d85b0cdd2f87439e85f65a8';
if(sha(fs.readFileSync(new URL('./ordered-current-worker-projections.mjs',import.meta.url)))!==workerProjectionModulePin)throw Error('reviewed worker projection module changed');
const workerProjections=lowerOrderedWorkerProjections(contract);
const workerReference=inspectOrderedReferenceRules(workerProjections.rules,input,new Set(['namespace','relation','column','column_name','constraint','global_constraint','index','policy','trigger','saved_function','saved_constraint','role','routine']));
// The original P source stays framed opaque. Available catalog1 fields do not
// authorize freezing its owner/policy/saved-ACL facets as direct expectations.
const retainedOpaqueRules=workerReference.resolved.filter(rule=>rule.id.startsWith('worker:projected74:'));
const workerProjectionRules=workerReference.resolved.filter(rule=>!rule.id.startsWith('worker:projected74:'));
if(workerReference.resolved.length!==60||workerReference.pending.length!==13||retainedOpaqueRules.length!==8||workerProjectionRules.length!==52||
  contract.partition.find(row=>row.identity==='zasp_authorization80_worker.projected74()')?.disposition!=='retain-original-framed-opaque')throw Error('worker projection reference/disposition boundary changed');
const workerProjectionFacts=projectOrderedFacts(workerProjectionRules,input);
const edgeProjections=lowerOrderedWorkerEdgeProjections(contract);
const missingReference=buildOrderedConsolidationNeeds(contract,catalog);
const captureBundle=admitOrderedCurrentCaptureBundleV1();
assertOrderedCurrentCaptureBundleV1(captureBundle);
const consolidationModules=['ordered-current-consolidation-needs.mjs','ordered-current-worker-source-closure-v1.mjs','ordered-current-worker-edge-projections.mjs','ordered-current-worker-projections.mjs','ordered-current-deparse-frame.mjs','ordered-current-transform-compiler.mjs','ordered-current-catalog.mjs','build-ordered-current-integrity.mjs'];
Object.assign(missingReference.contract,{sourceContractSHA256:contractPin,catalog1FileSHA256:referencePin,modules:Object.fromEntries(consolidationModules.map(name=>[name,sha(fs.readFileSync(new URL(name,import.meta.url)))]))});
const missingReferenceText=JSON.stringify(missingReference.contract,null,2)+'\n';
const templatePath=new URL('sql/0080_authorization_worker_ordered_current_integrity.sql',migrations);
const template=fs.readFileSync(templatePath,'utf8');
const privateReferenceName='ordered-current-private-reference-alias1.json';
const privateReferencePin='15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607';
const privateContractName='ordered-current-private-reference-alias-contract.json';
const privateContractPin='59b78441d81c02cedb4e3106c8d573dcf1907c8548bd0e961e0fed464b29ee63';
const privateReference=admitOrderedPrivateReference(artifactRaw(privateReferenceName),{
  referenceFileSHA256:privateReferencePin,contractRaw:artifactRaw(privateContractName),templateRaw:Buffer.from(template),currentRules:privateObjectRules(),variant:'A',sessionUser:'zasp_test'});
const framedTemplate=withOrderedPrecisionResolverClosureV1(template);
const privateDeclarations=compileOrderedPrecisionPrivateRoutinesV1(framedTemplate);
const baseRules=[...workerRules,...privateDeclarations.rules,...privateObjectRules()];
baseRules.push({id:'native-memberships',kind:'membership',namespaces:[],identities:[],fields:['admin'],predicate:'fixed-native-negative-universe'});
const referenceNeeds=buildOrderedReferenceNeeds(contract,catalog);
const remainingReferenceName='ordered-current-remaining-reference1.json';
const remainingReferencePin='cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797';
const remainingContractName='ordered-current-supplementary-query-contract3.json';
const remainingContractPin='2334ebbbad1382db7eafa47f81eec5b59f7721aaafa34b6b0d51311d959538ce';
const remainingManifestName='ordered-current-remaining-reference-packet-manifest.json';
const remainingManifestPin='338026bf79be5535bf0f57206b679e5846526da676fee6b0adac75186083d7ea';
const remaining=admitOrderedRemainingReference(artifactRaw(remainingReferenceName),{
  contractRaw:artifactRaw(remainingContractName),manifestRaw:artifactRaw(remainingManifestName)});
if(sha(compileOrderedCollector(referenceNeeds.rules).sql+'\n')!==remaining.provenance.querySHA256)throw Error('remaining reference projection SQL changed');
const transformLowering=lowerOrderedTemporalTransforms(contract);
const publicTransforms=lowerOrderedPublicFunctionTransforms(contract);
const transformRecipes=[...transformLowering.recipes,...publicTransforms.recipes];
const transformCollector=compileOrderedTransforms(transformRecipes,{definitionFrame});
const transformEnvironment={identities:new Set(catalog.functions.map(row=>row.identity)),savedTables:{}};
for(const schema of ['zasp_temporal74','zasp_temporal77','zasp_temporal78','zasp_authorization80_worker']){
  const relation=schema+'.predecessor_functions';
  if(catalog.relations.filter(row=>row.identity===relation).length!==1)throw Error('captured transform saved relation absent');
  transformEnvironment.savedTables[schema]={columns:catalog.columns.filter(row=>row.relation===relation).map(row=>row.name),rows:catalog.saved_functions.filter(row=>row.schema===schema)};
}
// Retain the historical derivation only as a deferred-identity ledger. These
// old pg_catalog inputs cannot prove the corrected original-frame values.
const deferredTransformFacts=projectOrderedTransforms(transformLowering.recipes,remaining.rawTransformInputs,transformEnvironment);
const transformedFacts=[];
const unresolvedRaw=remaining.rawTransformInputs;
const resolvedRules=referenceNeeds.resolvedRules;
const pendingRules=referenceNeeds.rules.filter(rule=>!rule.id.startsWith('raw-transform:'));
const rules=[...baseRules,...supplementContract.rules,...resolvedRules,...pendingRules,...workerProjectionRules,...missingReference.contract.rules.filter(rule=>rule.id.startsWith('worker:')),...edgeProjections.rules];
// The temporal72 trigger aliases exist only in the missing-reference capture;
// keep the independently captured direct rows in their original collection so
// reconciliation can compare their distinct fact projections without a
// cross-collection identity collision.
const directCanonicalRules=rules.map(rule=>rule.id==='temporal72:trigger'?{...rule,id:'direct:temporal72:trigger'}:rule);
let canonicalDirectRaw=canonicalizeOrderedCurrentDevelopmentFacts(captureBundle.directFacts,directCanonicalRules,catalog);
let canonicalMissingRaw=canonicalizeOrderedCurrentDevelopmentFacts(captureBundle.missingFacts,rules,catalog);
const remainingProjection=applyOrderedCurrentRemainingProjectionV1({catalogRaw:artifactRaw('ordered-current-effective-catalog1.json'),contractRaw:artifactRaw('ordered-current-effective-contract3.json'),directRaw:fs.readFileSync(new URL('./ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json',import.meta.url)),missingRaw:fs.readFileSync(new URL('./ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json',import.meta.url)),remainingRaw:artifactRaw(remainingReferenceName)},canonicalDirectRaw,canonicalMissingRaw);
canonicalDirectRaw=remainingProjection.directFacts;
canonicalMissingRaw=remainingProjection.missingFacts;
const canonicalDirectMerge=mergeOrderedCurrentCanonicalCaptureFacts(captureBundle.directFacts,canonicalDirectRaw);
const canonicalMissingMerge=mergeOrderedCurrentCanonicalCaptureFacts(captureBundle.missingFacts,canonicalMissingRaw);
const canonicalDirectFacts=canonicalDirectMerge.facts;
const canonicalMissingFacts=canonicalMissingMerge.facts;
const canonicalizedCaptureIdentities=[...canonicalDirectMerge.mappings,...canonicalMissingMerge.mappings].filter(row=>row.captureIdentity!==row.canonicalIdentity);
const changedCaptureFacts=(original,canonical)=>original.flatMap((row,index)=>canonicalOrderedJSON(row.fact)===canonicalOrderedJSON(canonical[index].fact)?[]:[{kind:row.kind,captureIdentity:row.identity,descriptorIdentity:canonical[index].identity,fields:Object.keys(row.fact).filter(field=>canonicalOrderedJSON(row.fact[field])!==canonicalOrderedJSON(canonical[index].fact[field])).sort()}]);
const canonicalizedCaptureFacts=[...changedCaptureFacts(captureBundle.directFacts,canonicalDirectRaw),...changedCaptureFacts(captureBundle.missingFacts,canonicalMissingRaw)];
const qualificationLedger=[...canonicalDirectRaw,...canonicalMissingRaw].map(row=>row.source?.qualificationLedger).filter(Boolean);
const qualificationLedgerKeys=new Set();
const boundedQualificationLedger=qualificationLedger.filter(row=>{const key=`${row.ruleId}\u0000${row.captureIdentity}\u0000${row.rawFactSHA256}`;if(qualificationLedgerKeys.has(key))return false;qualificationLedgerKeys.add(key);return true;});
if(boundedQualificationLedger.length>200||Buffer.byteLength(JSON.stringify(boundedQualificationLedger))>262144)throw Error('qualification ledger bounds');
const ordinaryCollector=compileOrderedPrecisionResolverCollectorV1(rules);
const collectorSQL='SELECT kind,identity,fact FROM (\n'+ordinaryCollector.sql+'\n) direct_catalog\nUNION ALL\nSELECT kind,identity,fact FROM (\n'+transformCollector.sql+'\n) transformed_catalog';
admitFramedTransformSource(inspectOrderedPrecisionResolverSourceV1(collectorSQL));
const collector={sql:collectorSQL,sourceSHA256:sha(collectorSQL)};
const start='  -- ordered-current:direct-collector-begin';
const end='  -- ordered-current:direct-collector-end';
if(template.split(start).length!==2||template.split(end).length!==2||template.split('-- ordered-current:embedded-expectations').length!==2)throw Error('template anchors changed');
const sql=framedTemplate.slice(0,framedTemplate.indexOf(start))+start+'\n'+collector.sql+'\n'+framedTemplate.slice(framedTemplate.indexOf(end));
const privateClosure=compileOrderedPrecisionPrivateRoutinesV1(sql);
const currentSourceClosurePacket=attachOrderedCurrentPrecisionPrivateAuthorityV1(admitOrderedCurrentSourceClosureV1(),sql,privateClosure);
assertOrderedCurrentAttachedSourceClosureV1(currentSourceClosurePacket,contract,{kind:'generator-in-memory-precision-resolver-v1',sql,privateClosure});
const currentSourceClosure={packet:currentSourceClosurePacket,packetSHA256:sha(canonicalOrderedJSON(currentSourceClosurePacket)),modules:Object.fromEntries(orderedCurrentSourceClosureModulesV1.map(name=>[name,sha(fs.readFileSync(new URL(name,import.meta.url)))]))};
const resolvedFacts=projectOrderedFacts(resolvedRules,input);
let legacyFacts=[...projectOrderedFacts(baseRules,input),...privateClosure.facts,...privateReference.facts,...supplement.facts,...resolvedFacts,...remaining.staticFacts,...transformedFacts,...workerProjectionFacts];
const precisionSourceRoster=canonicalMissingRaw.filter(row=>row.kind==='routine'&&JSON.parse(row.identity)[0]==='temporal72:precision-function');
const precisionIdentityCanonicalization=canonicalizeOrderedCurrentPrecisionFacts(legacyFacts,precisionSourceRoster);
legacyFacts=precisionIdentityCanonicalization.facts;
const missingCaptureRuleIds=new Set(captureBundle.missingFacts.map(row=>JSON.parse(row.identity)[0]));
const missingCaptureDeclarations=[
 {id:'role-profile:current-profile',kind:'fixed_runtime_profile',fields:['singleton','name']},
 {id:'role-profile:native-roles',kind:'role',fields:['login','superuser','create_db','create_role','replication','bypass_rls']},
 ...referenceNeeds.rules.filter(rule=>missingCaptureRuleIds.has(rule.id)).map(rule=>({id:rule.id,kind:rule.kind,fields:rule.fields})),
];
const captureDeclarations={
 direct:[...missingReference.contract.rules.map(rule=>({id:rule.id,kind:rule.kind,fields:rule.fields})),...transformRecipes.map(recipe=>({id:recipe.ruleId,kind:recipe.kind,fields:Object.keys(recipe.fields)}))],
 missing:missingCaptureDeclarations,
 private:privateObjectRules().map(rule=>({id:rule.id,kind:rule.kind,fields:rule.fields})),
};
const precisionConflictSettlements=orderedCurrentPrecisionConflictSettlementsV1();
const captureReconciliation=reconcileOrderedCurrentFactCollectionsV1({existingFacts:legacyFacts,collections:{direct:canonicalDirectFacts,missing:canonicalMissingFacts,private:captureBundle.privateFacts},declarations:captureDeclarations,settlements:precisionConflictSettlements});
const remainingTemporalKeys=remainingProjection.proof.records.filter(row=>row.collection==='missing').map(row=>row.canonicalIdentity);
if(captureReconciliation.equalExisting.filter(row=>row.collection==='missing'&&remainingTemporalKeys.includes(row.identity)).length!==2||captureReconciliation.newlySupplied.some(row=>row.collection==='missing'&&JSON.parse(row.identity)[0]==='temporal72:trigger'))throw Error('remaining projection exact-two equalExisting reconciliation');
let facts=captureReconciliation.facts;
assertNative18WorkerClosure(sourceBuiltTest74.sourceClosure);
const native19WorkerReplay=native19WorkerSourceReplay();
facts=propagateNative21WorkerTailFacts(facts,native19WorkerReplay);
const workerHigherIntegration=issueWorkerHigherIntegrationContextV1();
const workerHigherProof=workerHigherIntegration.proof;
const workerRefusalIdentities=[
  'zasp_authorization79.fingerprint()','zasp_authorization80_temporal.fingerprint()','zasp_authorization80_temporal.projected68()',
  'zasp_authorization80_temporal.projected72()','zasp_authorization80_temporal.projected_domain()','zasp_ordered_public62.fingerprint()',
  'zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal69.fingerprint()',
  'zasp_temporal76.executor74_fingerprint()','zasp_temporal77.base67_fingerprint()','zasp_temporal78.fingerprint()',
  'zasp_temporal78.ready(text,text)','zasp_authorization80_worker.fingerprint()','zasp_authorization80_worker.catalog_ready()'];
workerRefusalIdentities.push('zasp_authorization80_worker.test74_effect_source(text,jsonb)','zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)');
const workerFactForIdentity=identity=>facts.find(row=>row.kind==='routine'&&JSON.parse(row.identity)[0]==='worker-line-5'&&JSON.parse(row.identity)[1]===identity);
const workerRefusalEntries=workerRefusalIdentities.map(identity=>{
  const row=workerFactForIdentity(identity); if(!row)throw Error('native18 worker refusal identity missing: '+identity);
  const replay=native19WorkerReplay.refused.find(entry=>entry.identity===identity)??native19WorkerReplay.accepted.find(entry=>entry.identity===identity); if(!replay)throw Error('native19 worker replay identity missing: '+identity);
  return {...replay,ruleId:'worker-line-5',rawFactSHA256:sha(canonicalOrderedJSON(row.fact)),evidence:{closureVersion:native18WorkerClosure.version,sourceReplayVersion:native19WorkerReplay.version,profileChecksum:native19WorkerReplay.profileChecksum,sourceArtifactSHA256:native19WorkerReplay.sourceArtifactSHA256}};
});
const registrationIdentity='["worker-line-2","[\\"zasp_authorization80_worker.registration\\",true]"]';
const registrationFact=facts.find(row=>row.kind==='worker_registration'&&row.identity===registrationIdentity); if(!registrationFact)throw Error('native18 worker registration refusal identity missing');
const workerRefusalLedger={version:'native19-worker-definition-replay-v1',accepted:native19WorkerReplay.accepted.length,refused:native19WorkerReplay.refused.length,sourceReplay:{version:native19WorkerReplay.version,accepted:native19WorkerReplay.accepted.length,refused:native19WorkerReplay.refused.length,builder:native19WorkerReplay.builder,sourceArtifactSHA256:native19WorkerReplay.sourceArtifactSHA256},entries:workerRefusalEntries,registration:{...native19WorkerReplay.registration,identity:registrationIdentity,rawFactSHA256:sha(canonicalOrderedJSON(registrationFact.fact)),fingerprintEvidence:{expectedFingerprint:registrationFact.fact.fingerprint,profileChecksum:native19WorkerReplay.registration.profileChecksum}}};
if(workerRefusalLedger.entries.length!==17||new Set(workerRefusalLedger.entries.map(row=>row.identity)).size!==17)throw Error('native20 worker replay ledger cardinality');
const workerHigherSuccessor=applyWorkerHigherSuccessorV1({facts,proof:workerHigherProof,historicalLedger:workerRefusalLedger,canonicalJSON:canonicalOrderedJSON,
 context:workerHigherIntegration.context});
facts=workerHigherSuccessor.facts;
const capturedTransformRuleIds=new Set(transformRecipes.map(recipe=>recipe.ruleId));
const capturedEdgeRuleIds=new Set(edgeProjections.rules.map(rule=>rule.id));
const capturedWorkerRuleIds=new Set(missingReference.contract.workerNeeds.map(need=>need.ruleId));
const capturedTransformFacts=canonicalDirectFacts.filter(row=>capturedTransformRuleIds.has(JSON.parse(row.identity)[0]));
const capturedEdgeFacts=canonicalDirectFacts.filter(row=>capturedEdgeRuleIds.has(JSON.parse(row.identity)[0]));
const capturedWorkerFacts=canonicalDirectFacts.filter(row=>capturedWorkerRuleIds.has(JSON.parse(row.identity)[0]));
if(capturedTransformFacts.length!==380||capturedEdgeFacts.length!==799||capturedWorkerFacts.length!==421)throw Error('capture collection source partition changed');
const remainingBlockers=[
 'full 379-rule native truth/drift/NULL/forged-entry/frame parity',
 'varied-login/OID and exact production PostgreSQL',
 'connected installed-worker acceptance',
 'full100 capacity under unchanged limits',
 'deployment/provider acceptance',
];
function buildDormantEvaluator(){
 const fail=message=>{throw Error('dormant evaluator '+message);};
 const workerPacket=missingReference.contract.workerSourceClosure;
 assertOrderedWorkerSourceClosureV1(workerPacket,contract);
 assertOrderedCurrentAttachedSourceClosureV1(currentSourceClosurePacket,contract,{kind:'generator-in-memory-precision-resolver-v1',sql,privateClosure});
 const frameKeys=['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'];
 const siteRow=(component,site,identity,disposition)=>{
  const node=contract.nodes.find(n=>n.identity===identity);
  const start=site.start,end=site.end,siteSHA256=site.siteSHA256??site.sha256;
  if(!node||!Number.isInteger(start)||!Number.isInteger(end)||start<0||end<=start||end>Buffer.byteLength(node.source)||sha(Buffer.from(node.source).subarray(start,end))!==siteSHA256||!disposition||disposition==='unclassified')fail('source site '+identity);
  return {siteId:component+':'+(site.siteId??identity+':'+start+':'+end),component,sourceIdentity:identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,start,end,siteSHA256,frame:Object.fromEntries(frameKeys.map(key=>[key,structuredClone(node[key])])),disposition};
 };
 const supplementarySites=supplementContract.sites.map(site=>{
  const matched=supplementContract.rules.filter(r=>['runtime','product'].some(prefix=>r.id===prefix+':'+site.family+':'+site.type));
  const obligations=supplementContract.unresolvedObligations.filter(o=>o.siteSHA256===site.sha256);
  return siteRow('supplementary',site,site.identity,matched.length===1?'source-descriptor-reference':obligations.length?'source-bound-runtime-obligation':'unclassified');
 });
 const sites=[
  ...workerLowering.sites.map(s=>siteRow('workerCatalog',s,workerLowering.identity,'source-descriptor-reference')),
  ...workerPacket.sourceSites.map(s=>siteRow('workerClosure',s,s.sourceIdentity,s.disposition)),
  ...currentSourceClosurePacket.completeInventory.sites.map(s=>siteRow('currentClosure',s,s.sourceIdentity,s.disposition)),
  ...supplementarySites,...auth80.sites.map(s=>siteRow('auth80',s,s.identity,s.disposition)),
 ];
 const counts=Object.fromEntries(['workerCatalog','workerClosure','currentClosure','supplementary','auth80'].map(key=>[key,sites.filter(s=>s.component===key).length]));
 if(canonicalOrderedJSON(counts)!==canonicalOrderedJSON({workerCatalog:34,workerClosure:172,currentClosure:246,supplementary:105,auth80:8})||new Set(sites.map(s=>s.siteId)).size!==565)fail('source inventory cardinality');
 const factCounts=new Map();
 for(const fact of facts){const id=JSON.parse(fact.identity)[0];factCounts.set(id,(factCounts.get(id)??0)+1);}
 const inventory=[...rules.map(rule=>({id:rule.id,kind:rule.kind,fields:rule.fields,collector:'direct',declarationSHA256:sha(canonicalOrderedJSON(rule)),expectedFacts:factCounts.get(rule.id)??0})),...transformRecipes.map(recipe=>({id:recipe.ruleId,kind:recipe.kind,fields:Object.keys(recipe.fields),collector:'transform',declarationSHA256:sha(canonicalOrderedJSON(recipe)),expectedFacts:factCounts.get(recipe.ruleId)??0}))];
 const inventoryFacts=inventory.reduce((sum,r)=>sum+r.expectedFacts,0);
 // Two incoming temporal aliases now prove equality to existing qualified rows.
 // Their source rows remain in both index-aligned arrays; only generic equality
 // reconciliation avoids supplying a second fact under an unqualified alias.
 // Original 10052 source facts minus two proven equalExisting aliases, plus
 // the newly declared private8 resolver. No target observation sets this cap.
 if(rules.length!==366||transformRecipes.length!==13||inventory.length!==379||new Set(inventory.map(r=>r.id)).size!==379||facts.length!==10051||inventoryFacts!==facts.length)fail('rule/fact inventory cardinality '+JSON.stringify({rules:rules.length,transforms:transformRecipes.length,inventory:inventory.length,unique:new Set(inventory.map(r=>r.id)).size,facts:facts.length,inventoryFacts}));
 if(captureReconciliation.counts.settledConflicts!==7||captureReconciliation.counts.unresolvedConflicts!==0)fail('precision closure');
 return {format:'ordered-current-dormant-evaluator-v1',status:'SOURCE-CONTRACT-COMPLETE-NATIVE-PARITY-PENDING',installable:false,nativeVerified:false,executableReplacementVerified:false,ledgerStatus:'component-only',facts:facts.length+1,
  collectorSHA256:collector.sourceSHA256,compilerInputSHA256:sha(sql),rules:inventory,
  sourceInventory:{scope:'Declared contract role-sites; roles may share source bytes. Zero unclassified does not establish executable operator completion or native parity.',counts,sites,unclassified:0},
  sourceContracts:{worker:{packetSHA256:sha(canonicalOrderedJSON(workerPacket)),nativeRules:workerPacket.nativeObservation.rules.length,limits:workerPacket.nativeObservation.limits,legacyReplay:workerRefusalLedger,higherSuccessor:workerHigherSuccessor.currentSuccessor},current:{packetSHA256:currentSourceClosure.packetSHA256,nativeRules:currentSourceClosurePacket.nativeObservation.rules.length,limits:currentSourceClosurePacket.nativeObservation.limits},precision:{packetSHA256:sha(canonicalOrderedJSON(precisionConflictSettlements)),rosterRows:precisionSourceRoster.length,rosterSHA256:'8274273e43ae89e7ba3928ba1891b17f02814133169e04605cbc69705fa18c90',identityAliases:precisionIdentityCanonicalization.merges.length,settlements:captureReconciliation.counts.settledConflicts,unresolvedConflicts:captureReconciliation.counts.unresolvedConflicts},supplementary:{contractSHA256:supplementContractPin},effective:{contractSHA256:contractPin},private:{routineFactsSHA256:sha(canonicalOrderedJSON(privateClosure.facts)),compilerDerivedRoutines:privateClosure.facts.length,continuityFacts:35,importedRoutineObservations:0}},
  // Retain every approved source obligation; the five next gates group them,
  // they do not waive missing demand operators, references or live semantics.
  runtimeObligations:{worker:workerPacket.runtimeObligations,workerOpaque:workerPacket.retainedOpaque,workerMemberships:workerPacket.membershipBags,current:currentSourceClosurePacket.blockers,workerCatalog:workerLowering.obligations,supplementary:supplementContract.unresolvedObligations,supplementaryReference:supplementContract.referenceGaps,auth80:auth80.obligation},nextGates:[...remainingBlockers]};
}
const dormantEvaluator=buildDormantEvaluator();
// No generated output, caller path, hash override or target value is authority.
export function admitOrderedCurrentDormantEvaluatorV1(){
 if(arguments.length!==0)throw Error('dormant evaluator caller-selected authority refused');
 return structuredClone(dormantEvaluator);
}
export function assertOrderedCurrentDormantEvaluatorV1(value){
 if(arguments.length!==1||canonicalOrderedJSON(value)!==canonicalOrderedJSON(dormantEvaluator))throw Error('dormant evaluator source/rule/site/gate mismatch');
}
assertOrderedCurrentDormantEvaluatorV1(dormantEvaluator);
function withCurrentBuildSourceInventory(modulePins){
 const inventory=readOrderedCurrentBuildSourceInventoryV1();
 if(Object.keys(inventory).sort().join(',')!=='executable,format,inputs,installable,native,status'||inventory.format!=='ordered-current-build-source-inventory-v1'||inventory.status!=='SOURCE-PROVENANCE-ONLY'||inventory.installable!==false||inventory.native!==false||inventory.executable!==false||Object.keys(inventory.inputs).length!==53)throw Error('current build source inventory shape/status/flags');
 const {inputs}=inventory;
 for(const [relative,digest]of Object.entries(inputs)){
  if(Object.hasOwn(modulePins,relative)&&modulePins[relative]!==digest)throw Error('current build source inventory conflicting duplicate '+relative);
  modulePins[relative]=digest;
 }
 return modulePins;
}
const linuxProvenance=readOrderedCurrentLinuxProvenanceV1();
const historicalGenerator=fs.readFileSync(new URL('./build-ordered-current-development.mjs',import.meta.url));
if(sha(historicalGenerator)!=='11381b173903472e492067c17c605b0f61ebc752b318c6b75b74c1fbffd5a600')throw Error('Linux successor historical generator source drift');
const sourceRelease={format:1,purpose:'development-only',expectedFromTarget:false,
  profileChecksum:compiled.checksum,compiledSourceSHA256:sha(compiled.source),contractSHA256:sha(successorText),referenceFileSHA256:referencePin,
  postgres:linuxProvenance.identity.version,pgcrypto:linuxProvenance.identity.pgcrypto,
  generatorSHA256:sha(fs.readFileSync(new URL(import.meta.url))),moduleSHA256:withCurrentBuildSourceInventory({
    'ordered-current-linux-provenance-v1.json':linuxProvenanceInputSHA256,
    'ordered-current-linux-provenance-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-linux-provenance-v1.mjs',import.meta.url))),
    'ordered-current-remaining-projection-witness-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-remaining-projection-witness-v1.mjs',import.meta.url))),
    'ordered-current-remaining-projection-witness-v1.reference':remainingProjectionReferenceSHA256,
    'ordered-current-dormant-evaluator-v1.packet':sha(canonicalOrderedJSON(dormantEvaluator)),
    'ordered-current-source-closure-v1.packet':currentSourceClosure.packetSHA256,...currentSourceClosure.modules,
    'integrity-template.sql':sha(template),'direct-collector.sql':collector.sourceSHA256,
    'build-ordered-current-integrity.mjs':sha(fs.readFileSync(new URL('./build-ordered-current-integrity.mjs',import.meta.url))),
    'ordered-current-catalog.mjs':sha(fs.readFileSync(new URL('./ordered-current-catalog.mjs',import.meta.url))),
    'ordered-current-static-catalog.mjs':sha(fs.readFileSync(new URL('./ordered-current-static-catalog.mjs',import.meta.url))),
    'ordered-current-private.mjs':sha(fs.readFileSync(new URL('./ordered-current-private.mjs',import.meta.url))),
    'ordered-current-capture-intake-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-capture-intake-v1.mjs',import.meta.url))),
    'ordered-current-capture-reconciliation-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-capture-reconciliation-v1.mjs',import.meta.url))),
    'ordered-current-precision-conflict-settlement-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-precision-conflict-settlement-v1.mjs',import.meta.url))),
    'ordered-current-reference.mjs':sha(fs.readFileSync(new URL('./ordered-current-reference.mjs',import.meta.url))),
    'ordered-current-private-reference.mjs':sha(fs.readFileSync(new URL('./ordered-current-private-reference.mjs',import.meta.url))),
    [privateReferenceName]:privateReferencePin,[privateContractName]:privateContractPin,
    'ordered-current-remaining-reference.mjs':sha(fs.readFileSync(new URL('./ordered-current-remaining-reference.mjs',import.meta.url))),
    [remainingReferenceName]:remainingReferencePin,[remainingContractName]:remainingContractPin,[remainingManifestName]:remainingManifestPin,
    ...Object.fromEntries(['ordered-current-reference-needs.mjs','ordered-current-temporal-selectors.mjs','ordered-current-public-selectors.mjs','ordered-current-temporal72.mjs','ordered-current-temporal-transforms.mjs','ordered-current-public-function-transforms.mjs','ordered-current-transform-compiler.mjs','ordered-current-deparse-frame.mjs','ordered-current-precision-resolver-frame-v1.mjs'].map(name=>[name,sha(fs.readFileSync(new URL(name,import.meta.url)))])),
    [supplementContractName]:supplementContractPin,[supplementReferenceName]:supplementReferencePin,
    'ordered-current-worker-selectors.mjs':sha(fs.readFileSync(new URL('./ordered-current-worker-selectors.mjs',import.meta.url))),
    'ordered-current-worker-projections.mjs':workerProjectionModulePin,
    'ordered-current-worker-higher-source-replay-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-worker-higher-source-replay-v1.mjs',import.meta.url))),
    'ordered-current-worker-higher-integration-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-worker-higher-integration-v1.mjs',import.meta.url))),
    'worker-higher-successor.packet':sha(canonicalOrderedJSON(workerHigherSuccessor.currentSuccessor)),
    ...workerHigherSuccessor.currentSuccessor.sourceInventory,
    'consolidated-reference-contract.json':sha(missingReferenceText),...missingReference.contract.modules}),facts,entries:[]};
const baselineModules=Object.fromEntries(Object.entries(sourceRelease.moduleSHA256).filter(([name])=>!['ordered-current-linux-provenance-v1.json','ordered-current-linux-provenance-v1.mjs'].includes(name)));
const baselineBuilt=buildManifest({...sourceRelease,postgres:supplement.provenance.postgres,pgcrypto:supplement.provenance.pgcrypto,generatorSHA256:sha(historicalGenerator),moduleSHA256:baselineModules});
const built=buildManifest(sourceRelease);
const literal=value=>"'"+value.replaceAll("'","''")+"'";
const expectedSQL=built.facts.map(r=>'('+[literal(r.kind),literal(r.identity),literal(canonicalOrderedJSON(r.fact))+'::jsonb'].join(',')+')').join(',\n');
const assembled=sql.replace('-- ordered-current:embedded-expectations',()=>
  'INSERT INTO zasp_authorization80_ordered_current.registration(singleton,format_version,profile_checksum,manifest_sha256) VALUES(true,1,'+literal(compiled.checksum)+','+literal(built.payloadSHA256)+');\n'+
  'INSERT INTO zasp_authorization80_ordered_current.expected(kind,identity,fact) VALUES\n'+expectedSQL+';');
const admissionSQL="SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('kind',kind,'identity',identity,'fact',fact) ORDER BY identity COLLATE \"C\"),'[]'::jsonb) FROM (\n"+compileOrderedCollector(privateDeclarations.rules).sql+"\n) private_admission WHERE current_user='zasp_discovery_authority' AND pg_catalog.current_setting('search_path')='pg_catalog' AND ("+definitionAdmissionSQL+") IS TRUE AND ("+precisionResolverAdmissionSQLV1+") IS TRUE;\n";
const privateDDL=sql.replace('-- ordered-current:embedded-expectations','-- Reference-only: both private tables remain empty.');
const privateRules=[...privateDeclarations.rules,...privateObjectRules()];
const privateQuery=compileOrderedCollector(privateRules).sql+'\n';
// Source-declared finite bounds for PG18: two tables and two PK indexes;
// seven table columns plus three index attributes; seven NOT NULL, five CHECK
// and two PRIMARY KEY constraints; two composite types and their two arrays.
// These are refusal caps only. No native definition or expected value is made up.
const privateCaps={routine:privateClosure.facts.length,namespace:1,relation:4,column:10,constraint:14,index:2,policy:0,trigger:0,view:0,rewrite:0,type:4};
const privateContract={format:'ordered-current-private-reference-query-v1',status:'REFERENCE-CAPTURE-ONLY',
  namespace:'zasp_authorization80_ordered_current',ddlSHA256:sha(privateDDL),querySHA256:sha(privateQuery),
  templateSHA256:sha(template),generatorSHA256:sha(fs.readFileSync(new URL(import.meta.url))),moduleFileSHA256:sha(assembled),
  compilerChecksum:compiled.checksum,compiledSourceSHA256:sha(compiled.source),compilerArtifactSHA256:'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
  sourceContractSHA256:contractPin,catalog1FileSHA256:referencePin,supplementaryReferenceFileSHA256:supplementReferencePin,
  referencePostgres:supplement.provenance.postgres,serverVersionNum:supplement.provenance.serverVersionNum,pgcrypto:supplement.provenance.pgcrypto,
  requiredRole:'zasp_discovery_authority',requiredSearchPath:['pg_catalog'],requiredTimeZone:'UTC',
  maxRows:Object.values(privateCaps).reduce((a,b)=>a+b,0),maxBytes:16777216,categoryMaxRows:privateCaps,
  ruleMaxRows:Object.fromEntries(privateRules.map(rule=>[rule.id,privateCaps[rule.kind]])),rules:privateRules,
  fieldTypes:Object.fromEntries(privateRules.map(rule=>[rule.kind,Object.fromEntries(rule.fields.map(field=>[field,orderedFactTypes[rule.kind][field]]))])),
  expectedRoutineFacts:privateClosure.facts,expectedManifestRows:0,registrationRows:0,
  sourceModules:Object.fromEntries(['build-ordered-current-integrity.mjs','ordered-current-catalog.mjs','ordered-current-static-catalog.mjs','ordered-current-private.mjs','ordered-current-deparse-frame.mjs','ordered-current-precision-resolver-frame-v1.mjs','ordered-current-reference.mjs','ordered-current-worker-selectors.mjs'].map(name=>[name,sha(fs.readFileSync(new URL(name,import.meta.url)))])),
  captureProtocol:'Independent accepted e12 fixture only; original admission before DDL; absent private namespace; fixed DDL in rollback-only transaction; own-namespace SELECT under discovery/pg_catalog/UTC; exact source-derived eight-routine successor comparison; empty private data tables; rollback; original admission after rollback and frame/namespace restoration. Root must review adapter before native execution.',
  deferredGates:['Native complete evaluator truth/drift/frame controls','Full original recipe lowering and live relationships','Independent varied-login/OID build','Production-platform exact version reference']};
const connectedWorkerCaptureRules=missingReference.contract.rules.filter(rule=>capturedWorkerRuleIds.has(rule.id));
const remainingWorkerReferenceRules=workerReference.pending.filter(rule=>!capturedWorkerRuleIds.has(rule.id));
const canonicalReconciliationLedger=rows=>[...rows].sort((left,right)=>Buffer.compare(Buffer.from(canonicalOrderedJSON(left)),Buffer.from(canonicalOrderedJSON(right))));
const captureCoverage={captureStatus:captureBundle.captureStatus,installable:false,manifestSHA256:captureBundle.provenance.manifestSHA256,
 remainingProjection:{version:remainingProjection.proof.version,referenceSHA256:remainingProjection.proof.referenceSHA256,installable:false,nativeVerified:false,executableReplacementVerified:false,records:remainingProjection.proof.records.map(({sourceFact,canonicalFact,...record})=>record),historicalQualificationLedger:'Unchanged native16 refusals; new source proof disposition is recorded separately.',temporalEqualExisting:2,temporalNewlySupplied:0},
 bundleHashes:{manifest:captureBundle.provenance.manifestSHA256,directPacket:captureBundle.provenance.packets.directSHA256,missingPacket:captureBundle.provenance.packets.missingSHA256,missingCapture:captureBundle.provenance.captures.missingSHA256,privatePacket:captureBundle.provenance.packets.privateSHA256,privateCapture:captureBundle.provenance.captures.privateSHA256,compositionLog:captureBundle.provenance.compositionLogSHA256},
 counts:captureReconciliation.counts,collections:captureReconciliation.collections,validatedPrivateRoutineRows:captureBundle.provenance.private.validatedRoutineRows,importedPrivateRoutineRows:0,
 equalExisting:canonicalReconciliationLedger(captureReconciliation.equalExisting),newlySupplied:canonicalReconciliationLedger(captureReconciliation.newlySupplied),
 exactBundleEqualOverlaps:captureBundle.provenance.equalOverlaps,qualificationLedger:{version:'native16-qualification-v2',catalogSHA256:'9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df',transformVersion:'native16-qualification-v2',accepted:boundedQualificationLedger.filter(row=>row.status==='accepted'),refused:boundedQualificationLedger.filter(row=>row.status==='refused'),counts:{accepted:boundedQualificationLedger.filter(row=>row.status==='accepted').length,refused:boundedQualificationLedger.filter(row=>row.status==='refused').length,total:boundedQualificationLedger.length}},identityCanonicalization:{families:['column_name','column_all','constraint','foreign_key_trigger','index_view','policy','policy_view','relation','routine','trigger','fixed_runtime_profile'],rows:canonicalizedCaptureIdentities,factRows:canonicalizedCaptureFacts,mappings:[...canonicalDirectMerge.mappings,...canonicalMissingMerge.mappings],merges:[...canonicalDirectMerge.merges,...canonicalMissingMerge.merges]},precisionIdentityCanonicalization:{version:'native22-precision-v1',rosterRows:precisionSourceRoster.length,rosterSHA256:'8274273e43ae89e7ba3928ba1891b17f02814133169e04605cbc69705fa18c90',mappings:precisionIdentityCanonicalization.mappings,merges:precisionIdentityCanonicalization.merges},settledConflicts:canonicalReconciliationLedger(captureReconciliation.settledConflicts),unresolvedConflicts:canonicalReconciliationLedger(captureReconciliation.unresolvedConflicts),
 provenanceModules:['ordered-current-capture-intake-v1.mjs','ordered-current-capture-reconciliation-v1.mjs','ordered-current-direct-reference-v2.mjs','ordered-current-precision-conflict-settlement-v1.mjs'],remainingBlockers};
const checkpoint={status:'IN_PROGRESS-NOT-INSTALLABLE',contractFileSHA256:sha(successorText),payloadSHA256:built.payloadSHA256,manifestFileSHA256:built.fileSHA256,
  dormantEvaluator,
  moduleFileSHA256:sha(assembled),collectorSHA256:collector.sourceSHA256,facts:built.facts.length,rules:rules.length+transformRecipes.length,
  consolidation:{nativeSemanticEvidence:{file:'ordered-current-transform-acceptance-native5.json',sha256:'02b23f15d03b661d66c1399dd2521810a96686d223f683341c50290217eafbfe',use:'Historical source-semantics evidence only. The separate Task1 fixed capture bundle is the accepted authority for380 transform facts.'},frameVersion:2,compiledTransformSHA256:transformCollector.sourceSHA256,
    deferredFactIdentities:deferredTransformFacts.map(row=>({kind:row.kind,identity:row.identity})),deferredFacts:deferredTransformFacts.length,
    replacementRequirement:'The accepted Task1 direct capture supplies the thirteen original-frame expectations. Old raw observations remain excluded. Seven precision-function definitions are separately settled only by the exact source-authorized typed settlement ledger.',pendingRecipes:[],factDelta:{prior:8651,deferred:204,newPrivateRoutines:privateClosure.facts.length-4,captureSupplied:captureReconciliation.counts.newlySupplied,settledCaptureConflicts:captureReconciliation.counts.settledConflicts,unresolvedCaptureConflicts:captureReconciliation.counts.unresolvedConflicts,current:built.facts.length}},
  sourceCoverage:{worker:{identity:workerLowering.identity,sourceSHA256:workerLowering.sourceSHA256,factBranches:33,registrationBoundary:1,sites:workerLowering.sites,obligations:workerLowering.obligations,
    sourceBuiltStopEvidence:sourceBuiltTest74?{...sourceBuiltTest74.sourceClosure,identity:sourceBuiltTest74.identity,owner:sourceBuiltTest74.owner,acl:sourceBuiltTest74.acl,definition:sourceBuiltTest74.definition}:null,
    refusalLedger:workerRefusalLedger,higherSuccessor:workerHigherSuccessor.currentSuccessor},
    currentSourceClosure,
    captureBundle:captureCoverage,
    workerEdge:{rules:edgeProjections.rules,connectedRules:edgeProjections.rules,connectedFacts:capturedEdgeFacts.length,referenceNeeds:edgeProjections.referenceNeeds,sites:edgeProjections.sites,recipes:edgeProjections.recipes,obligations:edgeProjections.obligations,unsupported:edgeProjections.unsupported,helpers:edgeProjections.helpers,scope:'All39 source-declared direct projections are connected to the accepted Task1 capture. Membership bags, saved/helper demand, delegates, portability and full evaluator parity remain required.'},
    missingReference:{contractSHA256:sha(missingReferenceText),sqlSHA256:missingReference.contract.sqlSHA256,status:missingReference.contract.status,workerUniverses:missingReference.contract.workerNeeds.length,edgeRules:missingReference.contract.edgeNeeds.length,pendingCaps:missingReference.contract.pendingCaps,transformNeeds:missingReference.contract.transformNeeds,blockers:missingReference.contract.blockers},
    workerProjections:{sourceContractSHA256:contractPin,referenceFileSHA256:referencePin,moduleSHA256:workerProjectionModulePin,
      availableRules:workerReference.resolved.length,connectedRules:[...workerProjectionRules,...connectedWorkerCaptureRules],connectedFacts:workerProjectionFacts.length+capturedWorkerFacts.length,
      retainedOpaqueRules,pendingReferenceRules:remainingWorkerReferenceRules,uncompiledRecipes:workerProjections.recipes,
      sites:workerProjections.sites,obligations:workerProjections.obligations,
      scope:'Development-only63 direct projections:52 pinned catalog1 rules plus11 accepted Task1 capture rules. Eight projected74 projections remain source/provenance evidence, not expected facts; its original framed opaque P obligation remains outside the direct collector. Two unavailable reference universes and28 transformed/live recipes now have exact source closure but no admitted native values. Original aggregation, NULL, registration, helper demand/frame, portability and full native parity remain required.'},
    legacyPrivateContinuity:{validatedFacts:39,equalSuccessorFacts:captureReconciliation.collections.private.equalExisting,validatedFrozenRoutines:privateReference.validatedRoutineCount,categoryCounts:privateReference.categoryCounts,
      referenceFileSHA256:privateReferencePin,contractFileSHA256:privateContractPin,provenance:{...privateReference.provenance,authority:'historical-non-authoritative',usedForExpectedTruth:false},
      scope:'The superseded predecessor is retained only as a continuity comparator. Its35 nonroutine bytes equal the accepted successor bundle and are replaced by the successor rows; no predecessor routine observation is imported. Eight current successor routine facts derive from current assembled source. Full candidate native parity remains required.'},
    supplementary:{rules:supplementContract.rules.length,facts:supplement.facts.length,sites:supplementContract.sites,sourcePins:supplementContract.sourcePins,obligations:supplementContract.unresolvedObligations,referenceGaps:supplementContract.referenceGaps,referenceFileSHA256:supplementReferencePin,queryContractFileSHA256:supplementContractPin,provenance:supplement.provenance},
    remainingReference:{capturedRows:remaining.staticFacts.length+remaining.rawTransformInputs.length,staticFacts:remaining.staticFacts.length,rawTransformInputs:remaining.rawTransformInputs.length,
      transformedFacts:capturedTransformFacts.length,unresolvedRawRows:unresolvedRaw.length,unresolvedRawRuleIds:[...new Set(unresolvedRaw.map(row=>JSON.parse(row.identity)[0]))],
      referenceFileSHA256:remainingReferencePin,contractFileSHA256:remainingContractPin,packetManifestSHA256:remainingManifestPin,provenance:remaining.provenance,
      scope:'Static facts remain compared. All445 raw inputs are excluded from expectations, including204 old-frame temporal projections now explicitly deferred. Native5 proves source semantics only, not reference independence.'},
    temporalPublic:{staticRules:resolvedRules.length+referenceNeeds.pending.length,resolvedStaticRules:resolvedRules.length,resolvedStaticFacts:resolvedFacts.length,pendingStaticRules:[],capturedStaticRules:referenceNeeds.pending.length,
      specialFieldRules:pendingRules.length-referenceNeeds.pending.length,transformedRecipes:transformRecipes.length,pendingTransformedReferences:[],connectedTransformedReferences:transformRecipes.map(r=>r.ruleId),transformedFacts:capturedTransformFacts.length,
      unresolvedTransforms:transformLowering.unsupported,sites:referenceNeeds.sites,transformSites:transformLowering.sites,obligations:[...referenceNeeds.obligations,...transformLowering.obligations],
      transformCollectorSHA256:transformCollector.sourceSHA256,pendingExpectedRuleIds:[],
      referenceStatus:'Accepted static facts and all13 Task1 original-frame recipe expectations are connected. Prior raw observations are not promoted; local capture does not discharge full-product execution, portability, frame or deployment obligations.'}},
  privateRoutineDeclarations:privateClosure.declarations,
  missingRequiredLowering:remainingBlockers,
  nativeVerified:false};
checkpoint.linuxSuccessor={format:'ordered-current-linux-successor-v1',status:'SOURCE-PROVENANCE-ONLY',installable:false,nativeVerified:false,expectedFromTarget:false,descriptorSHA256:linuxProvenanceInputSHA256,identitySHA256:linuxProvenance.evidence.identitySHA256,observedVersion:linuxProvenance.identity.version,historicalReferenceVersion:supplement.provenance.postgres};
const outputs=[
 [new URL('ordered_current/linux-successor-v1/effective-contract4.json',migrations),successorText],
 [new URL('ordered_current/linux-successor-v1/development-manifest.json',migrations),built.file],
 [new URL('ordered_current/linux-successor-v1/development-collector.sql',migrations),collector.sql+'\n'],
 [new URL('ordered_current/linux-successor-v1/development-admission.sql',migrations),admissionSQL],
 [new URL('ordered_current/linux-successor-v1/development-module.sql',migrations),assembled],
 [new URL('ordered_current/linux-successor-v1/development-checkpoint.json',migrations),JSON.stringify(checkpoint,null,2)+'\n']
 ,[new URL('ordered_current/linux-successor-v1/consolidated-reference-contract.json',migrations),missingReferenceText]
 ,[new URL('ordered_current/linux-successor-v1/consolidated-reference-select.sql',migrations),missingReference.sql]
];
void [
 [new URL('ordered_current/private-reference-ddl.sql',migrations),privateDDL]
 ,[new URL('ordered_current/private-reference-select.sql',migrations),privateQuery]
 ,[new URL('ordered_current/private-reference-contract.json',migrations),JSON.stringify(privateContract,null,2)+'\n']
];
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(new URL(import.meta.url))){
if(process.argv.length!==3||!['--write','--check'].includes(process.argv[2]))throw Error('use --write/--check, or an explicit private-reference operation');
for(const [url,text] of outputs) {
  if(process.argv[2].startsWith('--check')){if(fs.readFileSync(url,'utf8')!==text)throw Error('generated output differs: '+url.pathname);}
  else {fs.mkdirSync(new URL('./',url),{recursive:true});fs.writeFileSync(url,text);}
}
console.log(JSON.stringify({...checkpoint,sourceCoverage:{worker:{identity:workerLowering.identity,factBranches:33,registrationBoundary:1}},privateRoutineDeclarations:privateClosure.declarations.length}));
}

// These APIs return source-only proposals. They never admit a runtime packet.
export function buildOrderedCurrentLinuxSuccessorV1(){
 if(arguments.length!==0)throw Error('Linux successor caller authority refused');
 readOrderedCurrentLinuxProvenanceV1();
 return structuredClone({format:'ordered-current-linux-successor-v1',installable:false,nativeVerified:false,expectedFromTarget:false,manifest:built,facts:built.facts,outputs:Object.fromEntries(outputs.map(([url,value])=>[url.pathname.split('/').at(-1),value]))});
}
let fullDelta;
export function analyzeOrderedCurrentLinuxSuccessorV1(){
 if(arguments.length!==0)throw Error('Linux successor borrowed baseline refused');
 readOrderedCurrentLinuxProvenanceV1();
 if(fullDelta)return structuredClone(fullDelta);
 const oldFacts=new Map(baselineBuilt.facts.map(f=>[canonicalOrderedJSON([f.kind,f.identity]),f]));
 const newFacts=new Map(built.facts.map(f=>[canonicalOrderedJSON([f.kind,f.identity]),f]));
 const changed=[],added=[],removed=[];
 for(const [key,next]of newFacts){const before=oldFacts.get(key);if(!before)added.push(next);else if(canonicalOrderedJSON(before)!==canonicalOrderedJSON(next))changed.push({kind:next.kind,identity:next.identity,beforeSHA256:sha(canonicalOrderedJSON(before)),afterSHA256:sha(canonicalOrderedJSON(next)),before:before.fact,after:next.fact});}
 for(const [key,before]of oldFacts)if(!newFacts.has(key))removed.push(before);
 const expected=(value)=>value.facts.map(r=>'('+[literal(r.kind),literal(r.identity),literal(canonicalOrderedJSON(r.fact))+'::jsonb'].join(',')+')').join(',\n');
 const assemble=(value)=>sql.replace('-- ordered-current:embedded-expectations',()=> 'INSERT INTO zasp_authorization80_ordered_current.registration(singleton,format_version,profile_checksum,manifest_sha256) VALUES(true,1,'+literal(compiled.checksum)+','+literal(value.payloadSHA256)+');\n'+'INSERT INTO zasp_authorization80_ordered_current.expected(kind,identity,fact) VALUES\n'+expected(value)+';');
 const baselineModule=assemble(baselineBuilt),nextModule=assemble(built);
 // The v2 packet is independently source-regenerated under its original pins.
 // We enumerate all original programs and literal impacts, not a v3 admission.
 const packet=admitOrderedCurrentNative379PacketV2();
 if(packet.controls.length!==589||packet.controls.reduce((n,c)=>n+c.program.steps.length,0)!==6348||canonicalOrderedJSON(packet.expectedFacts)!==canonicalOrderedJSON(baselineBuilt.facts))throw Error('Linux successor complete baseline packet mismatch');
 const generatedIdentitiesRaw=fs.readFileSync(new URL('./ordered-current-native379-packet-v2-artifacts/generated-identities.json',import.meta.url));
 if(sha(generatedIdentitiesRaw)!=='9d1053e9310e27128404e45c2eeedce1dc6b42eaff004ecf0e0760c903b59f99')throw Error('Linux successor historical output identity drift');
 const beforeOutputPins=JSON.parse(generatedIdentitiesRaw).outputPins;
 if(baselineBuilt.fileSHA256!==beforeOutputPins['development-manifest.json']||sha(baselineModule)!==beforeOutputPins['development-module.sql'])throw Error('Linux successor baseline assembly differs from reviewed old source');
 const substitutions=[{kind:'manifest-payload',before:baselineBuilt.payloadSHA256,after:built.payloadSHA256}];
 const programs=packet.controls.map(c=>({id:c.id,phase:c.phase,stepCount:c.program.steps.length,programSHA256:sha(canonicalOrderedJSON(c.program)),steps:c.program.steps.map((step,index)=>{
  let proposed=step.sql;const spans=[];
  for(const sub of substitutions){let at=0;while((at=step.sql.indexOf(sub.before,at))>=0){spans.push({kind:sub.kind,start:at,end:at+sub.before.length,beforeSHA256:sha(sub.before),afterSHA256:sha(sub.after)});at+=sub.before.length;}proposed=proposed.replaceAll(sub.before,sub.after);}
  return {index,id:step.id,role:step.role,expectedSHA256:sha(canonicalOrderedJSON(step.expected)),beforeSQLSHA256:sha(step.sql),proposedSQLSHA256:sha(proposed),literalSpans:spans};
 })}));
 const guard="IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version() THEN RETURN false; END IF;";
 if(!baselineModule.includes(guard)||!nextModule.includes(guard))throw Error('Linux successor exact guard changed');
 fullDelta={format:'ordered-current-linux-successor-delta-v1',observations:'source-derived-delta-only; no SQL execution or runtime packet admission',baselineFacts:baselineBuilt.facts.length,successorFacts:built.facts.length,added,removed,changed,functionalFactsEqual:added.length===0&&removed.length===0&&changed.every(f=>f.kind==='build'&&f.identity==='provenance'),baselineManifestSHA256:baselineBuilt.fileSHA256,successorManifestSHA256:built.fileSHA256,baselineModuleSHA256:sha(baselineModule),successorModuleSHA256:sha(nextModule),guardSameBytes:true,guardSHA256:sha(guard),privateRoutineDefinitions:privateClosure.facts.filter(f=>f.kind==='routine').map(f=>({identity:f.identity,beforeSHA256:sha(canonicalOrderedJSON(f)),afterSHA256:sha(canonicalOrderedJSON(f)),sameBytes:true})),rules:packet.rules.length,sites:packet.sourceInventory.sites.length,controlCount:programs.length,stepCount:programs.reduce((n,c)=>n+c.stepCount,0),programs,programMeaning:'Complete original source-derived589/6348; only enumerated manifest literal substitution proposals, not complete successor runtime control compilation. Every expectation/role/program identity retained. Later versioned packet must independently recompile all dependent metadata/preimages and compare full control structures.',limits:structuredClone(packet.limits),phases:structuredClone(packet.phases),outputs:outputs.map(([url,value])=>({name:url.pathname.split('/').at(-1),beforeSHA256:beforeOutputPins[url.pathname.split('/').at(-1)],sha256:sha(value),changed:beforeOutputPins[url.pathname.split('/').at(-1)]!==sha(value),bytes:Buffer.byteLength(value)}))};
 return structuredClone(fullDelta);
}

export function assertOrderedCurrentLinuxSuccessorDeltaV1(value){
 if(arguments.length!==1||canonicalOrderedJSON(value)!==canonicalOrderedJSON(analyzeOrderedCurrentLinuxSuccessorV1()))throw Error('Linux successor delta source/preimage/budget mismatch');
 return true;
}
