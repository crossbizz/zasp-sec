import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  admitOrderedCurrentCaptureBundleV1,
  assertOrderedCurrentCaptureBundleV1,
  compareOrderedCurrentCaptureFactSetsV1,
  materializeOrderedCurrentCaptureEvidenceV1,
  parseOrderedCurrentCaptureJSONV1,
  validateOrderedCurrentCaptureArtifactsV1,
} from './ordered-current-capture-intake-v1.mjs';

const artifacts=new URL('./ordered-current-capture-intake-v1-artifacts/',import.meta.url);
const artifact=name=>new URL(name,artifacts);
const inputs=()=>({
  directRaw:fs.readFileSync(artifact('direct-frame-acceptance.json')),
  missingPacketRaw:fs.readFileSync(artifact('missing-reference-native-packet.json')),
  missingCaptureRaw:fs.readFileSync(artifact('missing-reference-capture.json')),
  privatePacketRaw:fs.readFileSync(artifact('private-successor-packet.json')),
  privateCaptureRaw:fs.readFileSync(artifact('private-successor-reference.json')),
});
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
const mutateJSON=(raw,mutate)=>{const value=JSON.parse(raw);mutate(value);return Buffer.from(JSON.stringify(value)+'\n');};

test('admits only the fixed native composition as three frozen, separately provenanced fact sets',()=>{
  const value=admitOrderedCurrentCaptureBundleV1();
  assert.deepEqual(Object.keys(value).sort(),['captureStatus','directFacts','installable','missingFacts','privateFacts','provenance']);
  assert.equal(value.installable,false);
  assert.equal(value.captureStatus,'LOCAL-NATIVE-VERIFIED-UNBOUND');
  assert.equal(value.directFacts.length,1600);
  assert.equal(value.missingFacts.length,204);
  assert.equal(value.privateFacts.length,35);
  assert.equal(value.provenance.private.validatedRoutineRows,22);
  assert.equal(value.provenance.compositionLogSHA256,'2a875ddd77d36971fa5f66921d45b69ae3f8f9165be95c070fc159327948100a');
  assert.equal(Object.isFrozen(value),true);
  assert.equal(Object.isFrozen(value.directFacts),true);
  assert.equal(Object.isFrozen(value.provenance),true);
  assert.equal(assertOrderedCurrentCaptureBundleV1(value),true);
  assert.ok([...value.directFacts,...value.missingFacts,...value.privateFacts].every(row=>JSON.stringify(Object.keys(row).sort())===JSON.stringify(['fact','identity','kind'])));
  assert.ok(value.missingFacts.every(row=>JSON.parse(row.identity).length===2));
  const directPacket=JSON.parse(inputs().directRaw);
  assert.deepEqual(value.directFacts.map(row=>row.identity),[...directPacket.directFrame.expectedRows,...directPacket.transform.expectedRows].map(row=>JSON.stringify([row.source.ruleId,row.source.captureIdentity])));
  assert.equal(new Set(value.missingFacts.map(row=>row.identity)).size,204);
  assert.equal(new Set(value.directFacts.map(row=>`${row.kind}\u0000${row.identity}`)).size,1600);
  assert.equal(new Set(value.privateFacts.map(row=>`${row.kind}\u0000${row.identity}`)).size,35);
  assert.throws(()=>admitOrderedCurrentCaptureBundleV1({path:'/tmp/not-allowed'}),/caller input/i);
  assert.throws(()=>admitOrderedCurrentCaptureBundleV1({sha256:'0'.repeat(64)}),/caller input/i);
  const changed=structuredClone(value);changed.installable=true;
  assert.throws(()=>assertOrderedCurrentCaptureBundleV1(changed),/installable|bundle/i);
  const altered=structuredClone(value);altered.directFacts[0].fact.name='not-admitted';
  const refreeze=item=>{if(item&&typeof item==='object'){for(const child of Object.values(item))refreeze(child);Object.freeze(item);}return item;};
  assert.throws(()=>assertOrderedCurrentCaptureBundleV1(refreeze(altered)),/bundle direct schema/);
});

test('refuses altered reviewed bytes, source pins, malformed JSON, and unsafe capture controls',()=>{
  const baseline=inputs();
  assert.equal(validateOrderedCurrentCaptureArtifactsV1(baseline).directFacts.length,1600);
  const changes=[
    {...baseline,missingCaptureRaw:Buffer.concat([baseline.missingCaptureRaw,Buffer.from(' ')])},
    {...baseline,privateCaptureRaw:mutateJSON(baseline.privateCaptureRaw,value=>{value.packetSHA256='0'.repeat(64);})},
    {...baseline,directRaw:mutateJSON(baseline.directRaw,value=>{value.counts.totalRows=1599;})},
    {...baseline,missingPacketRaw:mutateJSON(baseline.missingPacketRaw,value=>{value.sourcePins.contractJSONSHA256='0'.repeat(64);})},
    {...baseline,missingCaptureRaw:mutateJSON(baseline.missingCaptureRaw,value=>{value.observations.pop();})},
    {...baseline,missingCaptureRaw:mutateJSON(baseline.missingCaptureRaw,value=>{value.observations.push(structuredClone(value.observations[0]));})},
    {...baseline,missingCaptureRaw:mutateJSON(baseline.missingCaptureRaw,value=>{value.canonicalIdentities[0].identities.push(value.canonicalIdentities[0].identities[0]);})},
    {...baseline,privateCaptureRaw:mutateJSON(baseline.privateCaptureRaw,value=>{value.frameRestored=false;})},
    {...baseline,privateCaptureRaw:mutateJSON(baseline.privateCaptureRaw,value=>{value.publication.mode='0644';})},
  ];
  for(const changed of changes)assert.throws(()=>validateOrderedCurrentCaptureArtifactsV1(changed),/ordered-current capture intake/i);
  assert.throws(()=>parseOrderedCurrentCaptureJSONV1(Buffer.from('{"a":1,"a":2}')),/duplicate key/i);
  assert.throws(()=>parseOrderedCurrentCaptureJSONV1(Buffer.from('{"a":9007199254740992}')),/unsafe integer/i);
  assert.throws(()=>parseOrderedCurrentCaptureJSONV1(Buffer.from('{"a":1} trailing')),/trailing bytes/i);
  assert.throws(()=>parseOrderedCurrentCaptureJSONV1(Buffer.alloc(32),{maxBytes:16}),/byte bound/i);
  const equal=compareOrderedCurrentCaptureFactSetsV1({direct:[{kind:'fixture',identity:'one',fact:{a:1,b:2}}],missing:[{kind:'fixture',identity:'one',fact:{b:2,a:1}}],private:[]});
  assert.deepEqual(equal,[{key:'fixture\u0000one',sets:['direct','missing']}]);
  assert.throws(()=>compareOrderedCurrentCaptureFactSetsV1({direct:[{kind:'fixture',identity:'one',fact:{a:1}}],missing:[{kind:'fixture',identity:'one',fact:{a:2}}],private:[]}),/conflicting duplicate/);
  assert.equal(digest(baseline.missingCaptureRaw),'76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39');
});

test('materializes owner-only capture evidence idempotently and refuses predecessor bytes',()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-ordered-current-evidence-'));
  const first=materializeOrderedCurrentCaptureEvidenceV1(directory);
  const second=materializeOrderedCurrentCaptureEvidenceV1(directory);
  assert.deepEqual(second,first);
  for(const item of Object.values(first))assert.equal(fs.statSync(item.path).mode&0o777,0o600);
  fs.writeFileSync(first.privateCapture.path,Buffer.from('{"format":"old-private-predecessor-capture-v1"}\n'));
  assert.throws(()=>materializeOrderedCurrentCaptureEvidenceV1(directory),/refuses mismatch|predecessor/i);
  assert.throws(()=>validateOrderedCurrentCaptureArtifactsV1({...inputs(),privateCaptureRaw:Buffer.from('{"format":"old-private-predecessor-capture-v1"}\n')}),/privateCapture authority/i);
 const raw=fs.readFileSync(artifact('private-successor-reference.json')),tamperDirectory=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-ordered-current-tamper-'));
 try{
  fs.writeFileSync(artifact('private-successor-reference.json'),Buffer.concat([raw,Buffer.from(' ')]));
  assert.throws(()=>materializeOrderedCurrentCaptureEvidenceV1(tamperDirectory),/privateCapture authority/i);
  assert.equal(fs.existsSync(path.join(tamperDirectory,'ordered-current-private-successor-reference-v1.json')),false);
 }finally{fs.writeFileSync(artifact('private-successor-reference.json'),raw);}
});
