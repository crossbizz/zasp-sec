// Executes the actual builder's bounded, exported seam from source, without
// executing its full authority generator or bypassing private-capture intake.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {canonicalOrderedJSON} from './build-ordered-current-integrity.mjs';
import {canonicalizeOrderedCurrentDevelopmentFacts} from './ordered-current-catalog.mjs';
import {mergeOrderedCurrentCanonicalCaptureFacts} from './ordered-current-direct-reference-v2.mjs';
import {reconcileOrderedCurrentFactCollectionsV1} from './ordered-current-capture-reconciliation-v1.mjs';
import * as witness from './ordered-current-remaining-projection-witness-v1.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url));
const inputs=()=>({catalogRaw:read('ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json'),contractRaw:read('ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json'),directRaw:read('ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json'),missingRaw:read('ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json'),remainingRaw:read('ordered-current-worker-source-closure-v1-artifacts/remaining-reference1.json')});
function actualBuilderSeam(){
 const text=read('build-ordered-current-development.mjs').toString(),name='applyOrderedCurrentRemainingProjectionV1',start=text.indexOf('export function '+name+'(');
 assert.notEqual(start,-1,'active builder source has no remaining-reference seam');
 const end=text.indexOf('\n}',start);assert.ok(end>start);
 const declaration=text.slice(start,end+2).replace('export ','');
 return Function('proveRemainingProjectionV1','applyRemainingProjectionV1',declaration+';return '+name)(witness.proveRemainingProjectionV1,witness.applyRemainingProjectionV1);
}
// A missing call, source index shift, old refusal promotion, or dropped incoming
// temporal pair makes these real application/merge/reconciliation checks fail.
test('active builder seam proves then applies exact source rows before canonical merges',()=>{
 const seam=actualBuilderSeam(),raw=inputs();witness.proveRemainingProjectionV1(raw);
 const direct=JSON.parse(raw.directRaw),missing=JSON.parse(raw.missingRaw),catalog=JSON.parse(raw.catalogRaw);
 const originals=[...direct.directFrame.expectedRows,...direct.transform.expectedRows].map(r=>({kind:r.kind,identity:canonicalOrderedJSON([JSON.parse(r.identity)[0],r.source.captureIdentity]),fact:r.fact}));
 const rules=direct.directFrame.descriptorRules;
 const ordinary=canonicalizeOrderedCurrentDevelopmentFacts(originals,rules,catalog);
 const aliases=missing.observations.flatMap(o=>o.rows.map(r=>({kind:o.ruleId==='temporal72:trigger'?'trigger':'source-unselected',identity:canonicalOrderedJSON([o.ruleId,r.identity]),fact:r.fields})));
 const before=structuredClone({ordinary,aliases});
 const result=seam(raw,ordinary,aliases);
 assert.deepEqual({ordinary,aliases},before);assert.equal(result.proof.records.length,8);
 assert.equal(result.directFacts.length,1600);assert.equal(result.missingFacts.length,204);
 const directMerge=mergeOrderedCurrentCanonicalCaptureFacts(originals,result.directFacts);
 const missingMerge=mergeOrderedCurrentCanonicalCaptureFacts(aliases,result.missingFacts);
 assert.equal(directMerge.mappings.length,1600);assert.equal(missingMerge.mappings.length,204);
 for(const r of result.proof.records){const original=r.collection==='direct'?originals:aliases,canonical=r.collection==='direct'?result.directFacts:result.missingFacts,mappings=r.collection==='direct'?directMerge.mappings:missingMerge.mappings,index=original.findIndex(o=>o.identity===r.sourceIdentity);assert.ok(index>=0);assert.equal(canonical[index].identity,r.canonicalIdentity);assert.equal(mappings[index].captureIdentity,r.sourceIdentity);assert.equal(mappings[index].canonicalIdentity,r.canonicalIdentity);assert.equal(canonical[index].source.remainingProjection.sourceIdentity,r.sourceIdentity);}
 const oldRefusals=ordinary.filter(r=>result.proof.records.some(p=>p.collection==='direct'&&p.canonicalIdentity===r.identity));
 assert.equal(oldRefusals.length,6);assert.ok(oldRefusals.every(r=>r.source.qualificationLedger.status==='refused'));
 assert.ok(result.directFacts.filter(r=>r.source?.remainingProjection).every(r=>r.source.qualificationLedger.status==='refused'&&r.source.remainingProjection.disposition==='source-pretty-qualified'));
 const temporal=result.missingFacts.filter(r=>JSON.parse(r.identity)[0]==='temporal72:trigger').map(({kind,identity,fact})=>({kind,identity,fact}));
 const existing=JSON.parse(raw.remainingRaw).rows.filter(r=>JSON.parse(r.identity)[0]==='temporal72:trigger');
 const reconciled=reconcileOrderedCurrentFactCollectionsV1({existingFacts:existing,collections:{direct:[],missing:temporal,private:[]},declarations:{direct:[],missing:[{id:'temporal72:trigger',kind:'trigger',fields:['name','enabled','function','relation_name','execution_definition']}],private:[]},settlements:[]});
 assert.equal(reconciled.counts.equalExisting,2);assert.equal(reconciled.counts.newlySupplied,0);assert.equal(reconciled.facts.length,2);
});
test('active builder seam refuses a changed witness after source assembly',()=>{
 const seam=actualBuilderSeam(),raw=inputs();
 const direct=JSON.parse(raw.directRaw),missing=JSON.parse(raw.missingRaw);
 const rows=[...direct.directFrame.expectedRows,...direct.transform.expectedRows].map(r=>({kind:r.kind,identity:canonicalOrderedJSON([JSON.parse(r.identity)[0],r.source.captureIdentity]),fact:r.fact}));
 const aliases=missing.observations.flatMap(o=>o.rows.map(r=>({kind:o.ruleId==='temporal72:trigger'?'trigger':'source-unselected',identity:canonicalOrderedJSON([o.ruleId,r.identity]),fact:r.fields})));
 rows.find(r=>r.fact.name==='zasp_recovery_backups_check'&&JSON.parse(r.identity)[0]==='worker-edge:gateway_projected27:7').fact.definition_pretty+=' ';
 assert.throws(()=>seam(raw,rows,aliases),/remaining projection.*source contract/);
});
