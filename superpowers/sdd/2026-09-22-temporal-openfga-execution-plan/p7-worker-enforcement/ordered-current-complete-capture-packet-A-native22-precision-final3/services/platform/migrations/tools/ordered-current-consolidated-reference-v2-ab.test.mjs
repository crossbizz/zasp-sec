import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  admitFixedOrderedConsolidatedReferencePairV2,
  compareAdmittedOrderedConsolidatedReferencePairV2,
} from './ordered-current-consolidated-reference-v2-ab.mjs';

const carrier='/private/tmp/zasp-recovery80-native-composition-carrier.L06LsF';
const aRoot='/private/tmp/zasp-recovery80-native-composition-A.86UE9x/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-complete-capture-packet-A-recovery80-frame-v2-global-limits';
const bRoot='/private/tmp/zasp-recovery80-native-composition-B.tImwZI/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-complete-capture-packet-B-recovery80-frame-v2-global-limits';
const aPath=path.join(carrier,'a-evidence/ordered-current-complete-reference-v2.json'),bPath=path.join(carrier,'b-evidence/ordered-current-complete-reference-v2.json');
const artifactOptIn=process.env.ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED==='1';
function packetAvailable(root){
 const contractPath=path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json'),required=[path.join(root,'snapshot-manifest.json'),contractPath,path.join(root,'services/platform/migrations/ordered_current/consolidated-capture-coverage-v2.json')];
 if(!required.every(file=>fs.existsSync(file)))return false;
 try{return JSON.parse(fs.readFileSync(contractPath)).phases.flatMap(phase=>phase.batches).every(batch=>fs.existsSync(path.join(root,batch.file)));}catch{return false;}
}
const artifactsAvailable=artifactOptIn&&[aPath,bPath].every(file=>fs.existsSync(file))&&packetAvailable(aRoot)&&packetAvailable(bRoot);
const aRaw=artifactsAvailable?fs.readFileSync(aPath):null;
const bRaw=artifactsAvailable?fs.readFileSync(bPath):null;
const artifactSkip=artifactOptIn?'fixed private frame-v2 artifact prerequisites unavailable':'set ZASP_ORDERED_CURRENT_FRAME_V2_ACCEPTED=1 to run fixed private evidence tests';
const artifactTest=(name,fn)=>test(name,{skip:artifactsAvailable?false:artifactSkip},fn);

const admitted=()=>({a:JSON.parse(aRaw),b:JSON.parse(bRaw)});
const locate=(envelope,section,ruleId)=>envelope[section].filter(row=>row.ruleId===ruleId);
const wire=value=>Array.isArray(value)?`[${value.map(wire).join(',')}]`:value&&typeof value==='object'?`{${Object.keys(value).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(key=>`${wire(key)}:${wire(value[key])}`).join(',')}}`:JSON.stringify(value).replaceAll('\u2028','\\u2028').replaceAll('\u2029','\\u2029');

test('fixed comparator refuses absent capture bytes before packet access',()=>{
 assert.throws(()=>admitFixedOrderedConsolidatedReferencePairV2({aRaw:null,bRaw:null,aPacketRoot:'missing',bPacketRoot:'missing'}),/fixed A capture/);
});

artifactTest('fixed A and B captures admit only after strict packet and source-bound typed comparison',()=>{
 const result=admitFixedOrderedConsolidatedReferencePairV2({aRaw,bRaw,aPacketRoot:aRoot,bPacketRoot:bRoot});
 assert.deepEqual(result,{status:'APPLICATION-FACT-EQUIVALENT',rules:1862,physicalRows:39090,expandedRows:52764,principalLeaves:350,physicalIdentityRows:408,conditionalDerivedFields:1});
});

artifactTest('fixed admission rejects A-vs-A and self-consistent repinned bytes',t=>{
 assert.throws(()=>admitFixedOrderedConsolidatedReferencePairV2({aRaw,bRaw:aRaw,aPacketRoot:aRoot,bPacketRoot:aRoot}),/fixed B capture/);
 const changed=Buffer.from(bRaw);changed[changed.indexOf(Buffer.from('zasp_e2e'))]=0x5a;
 assert.throws(()=>admitFixedOrderedConsolidatedReferencePairV2({aRaw,bRaw:changed,aPacketRoot:aRoot,bPacketRoot:bRoot}),/fixed B capture/);
 const repinned=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-ab-repinned-'));t.after(()=>fs.rmSync(repinned,{recursive:true,force:true}));fs.cpSync(bRoot,repinned,{recursive:true});
 const contractPath=path.join(repinned,'services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json'),manifestPath=path.join(repinned,'snapshot-manifest.json'),contract=JSON.parse(fs.readFileSync(contractPath)),manifest=JSON.parse(fs.readFileSync(manifestPath));contract.closureSHA256='0'.repeat(64);const contractRaw=Buffer.from(wire(contract)+'\n');fs.writeFileSync(contractPath,contractRaw);manifest.files['services/platform/migrations/ordered_current/consolidated-capture-contract-v2.json']=crypto.createHash('sha256').update(contractRaw).digest('hex');fs.writeFileSync(manifestPath,wire(manifest)+'\n');
 assert.throws(()=>admitFixedOrderedConsolidatedReferencePairV2({aRaw,bRaw,aPacketRoot:aRoot,bPacketRoot:repinned}),/fixed B packet/);
});

artifactTest('undeclared facts, multiplicity and privilege bits remain exact',()=>{
 for(const mutate of [
  ({a})=>{locate(a,'rawInputs','authorization80:function')[0].fact.security_definer=!locate(a,'rawInputs','authorization80:function')[0].fact.security_definer;},
  ({a})=>{locate(a,'rawInputs','authorization80:function')[0].multiplicity++;},
  ({a})=>{const row=locate(a,'rawInputs','public:inventory:function')[0];row.fact.acl_grants[0][2]=!row.fact.acl_grants[0][2];},
 ]){const pair=admitted();mutate(pair);assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(pair),/A\/B fact equivalence/);}
});

artifactTest('declared role paths reject substring and undeclared-role substitutions',()=>{
 const pair=admitted(),row=locate(pair.a,'rawInputs','authorization80:data-controls-relation')[0];
 row.fact.owner='prefix_zasp_test';
 assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(pair),/principal syntax/);
});

artifactTest('only eleven source-justified physical identities ignore generated trigger names',()=>{
 const pass=admitted();
 assert.doesNotThrow(()=>compareAdmittedOrderedConsolidatedReferencePairV2(pass));
 const drift=admitted(),row=locate(drift.a,'rawInputs','worker:projected_domain:foreign-key-trigger')[0];
 row.fact.event_bits++;
 assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(drift),/physical identity fact multiset/);
});

artifactTest('registration fingerprint is last and requires checksum plus leaf closure equality',()=>{
 const checksum=admitted();locate(checksum.a,'witnesses','recursive:authorization80:registration')[0].fact.checksum='0'.repeat(64);
 assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(checksum),/registration checksum/);
 const leaf=admitted();locate(leaf.a,'rawInputs','authorization80:function')[0].fact.security_definer=!locate(leaf.a,'rawInputs','authorization80:function')[0].fact.security_definer;
 assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(leaf),/A\/B fact equivalence/);
});

artifactTest('B-only envelope fields and wrong frame principals refuse before normalization',()=>{
 const extra=admitted();extra.b.unknownComparatorField={unexpected:true};assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(extra),/envelope fields/);
 const mutations=[
  pair=>{pair.b.entryFrame.sessionUser='wrong_principal';},
  pair=>{pair.b.phases[0].batches[0].beforeFrame.sessionUser='wrong_principal';},
  pair=>{pair.b.phases[0].batches[0].afterFrame.sessionUser='wrong_principal';},
  pair=>{pair.b.phases[0].batches[0].restoredFrame.sessionUser='wrong_principal';},
 ];
 for(const mutate of mutations){const pair=admitted();mutate(pair);assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(pair),/frame session user/);}
});

artifactTest('policy and trigger SQL normalization rejects identifiers and comments',()=>{
 const policy=admitted(),aPolicy=locate(policy.a,'rawInputs','authorization80:data-controls-policy')[0],bPolicy=locate(policy.b,'rawInputs','authorization80:data-controls-policy')[0];aPolicy.fact.using='(foo.zasp_test = true)';bPolicy.fact.using='(foo.zasp_e2e = true)';assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(policy),/policy role syntax/);
 const trigger=admitted(),aTrigger=locate(trigger.a,'rawInputs','authorization80:hierarchy-trigger')[0],bTrigger=locate(trigger.b,'rawInputs','authorization80:hierarchy-trigger')[0];aTrigger.fact.definition='CREATE TRIGGER t EXECUTE FUNCTION foo.zasp_test()';bTrigger.fact.definition='CREATE TRIGGER t EXECUTE FUNCTION foo.zasp_e2e()';assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(trigger),/trigger SQL role syntax/);
 const comment=admitted(),aComment=locate(comment.a,'rawInputs','authorization80:hierarchy-trigger')[0],bComment=locate(comment.b,'rawInputs','authorization80:hierarchy-trigger')[0];aComment.fact.definition='CREATE TRIGGER t EXECUTE FUNCTION public.f() /* zasp_test */';bComment.fact.definition='CREATE TRIGGER t EXECUTE FUNCTION public.f() /* zasp_e2e */';assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(comment),/trigger SQL role syntax/);
});

artifactTest('trigger argument normalization preserves nonprincipal bytes exactly',()=>{
 const pair=admitted(),aRow=locate(pair.a,'rawInputs','authorization80:hierarchy-trigger')[0],bRow=locate(pair.b,'rawInputs','authorization80:hierarchy-trigger')[0];
 aRow.fact.arguments=Buffer.concat([Buffer.from('zasp_test\0'),Buffer.from([0xff])]).toString('hex');bRow.fact.arguments=Buffer.concat([Buffer.from('zasp_e2e\0'),Buffer.from([0xef,0xbf,0xbd])]).toString('hex');
 assert.throws(()=>compareAdmittedOrderedConsolidatedReferencePairV2(pair),/hierarchy-trigger/);
});
