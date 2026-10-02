import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
const {lowerOrderedTemporalCatalog}=await import(process.env.ZASP_ORDERED_CURRENT_TEMPORAL_SELECTOR_MODULE??'./ordered-current-temporal-selectors.mjs');
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const oldBytes=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-complete-capture-packet-A-fix1/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(oldBytes),'5fed1f43b6475087e16ba4f1ab1db6d6827f508bf9160b13c05e6ef8f6a975e8');
const oldContract=JSON.parse(oldBytes);
const oldChecksum='e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960';
const successorChecksum='f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214';
const successorChanges=[
  ['zasp_authorization79.fingerprint()',1,'3a79b64e0e2334c932c34a2f7dd6d336d75f742940fd797d0d3f99c4d356e838','9a2c9e31958670871eddb2f5ff8fa9129cb64c7978fd62eba98e14c6b7df13bb'],
  ['zasp_authorization80_temporal.fingerprint()',1,'16b74f451df693e50ff322da26d79f0ece23cbf726b4f2e5aeccdaad7c790ed2','50b4f766dc5af01391c72336aeae267e54e8122ad7f162012a37f31f17ff6785'],
  ['zasp_authorization80_temporal.projected_domain()',1,'492d5e22145be03e0318e9b571a17a9dff8ab7e13c39c287acdfa21041468a6d','b1ad55fc48899482555112017674c8e2ac552a68660fa07978a585cd7dd9a218'],
  ['zasp_authorization80_temporal.projected68()',1,'05abc0b37017f8138f865ae39d38e47b5c4b6c81ba8406fbabd88cf9591da7de','48ba3787d20509fb6394941269545076353f0ed1e656162a254c7c8bc7837640'],
  ['zasp_authorization80_temporal.projected72()',1,'7da584d308abe44f1ff998146385562d16362801271ade7732c4a6d8b86260bb','308f3042c2105e37b2e00dd8e040ed05b1f47fb6429b69f362d05d263fc00c90'],
  ['zasp_ordered_public62.fingerprint()',1,'b297fbeaec112b38c3e2b30a887d8eb1d9e5712fc8036aecb1daaa22db8d7f9c','795ace2f9ee868e7e89633c7540c670578b5c3c2ba307d8271fa53fc9504c6d7'],
  ['zasp_temporal68.predecessor_ready(text,text)',9,'6b20a1fe34c7dcf1cdc0fda30ca8133a9afe35b32c3deec096aed4286283d76c','4e317014c1dcdc36267bca7a768516e2c225763790794781ac60fdf22ed00ebb'],
  ['zasp_temporal68.ready(text,text)',5,'0bc29e8e2f5209a33e5a92aecada14dc5609aa1e916aedc20a4257ad3751fe63','1612fcd9c1481cea3cd900e8d30e8557213ea3c8add4f357f8791c370bc9bf6a'],
  ['zasp_temporal69.fingerprint()',1,'d36361132bc266195f79ba68ca924a3a563aa267383d02235dac6fe74041a9d5','90a11d27e52a03931ab685d81130023461805cd3c0e7be3d8481e60568c967de'],
  ['zasp_temporal76.executor74_fingerprint()',1,'76bcb5eee587b2e10dd6700dcb11a6fef45e21f8275e2fe4bc54398ad9b41882','f8bd2b66facd1ad63bb5c9e61ce36889bf79ee0555834af89d7d521cf9a10e7f'],
  ['zasp_temporal77.base67_fingerprint()',4,'3a69fa3bf45249bf28eb3b365b3fca68fe9985c04e815335df7215772d7ef169','0aa3b07e9f238cd654b2b2c8e9f230e0a3f293df4e6ae66603c95e02213206ff'],
  ['zasp_temporal78.fingerprint()',1,'00d67a26c3ce62d1ab2cd8468c148620d31f69a5abf4410c4451212eea659fb2','47e83201f6c26f2e3a2160d535c68d9cd35b38b6d741d76b6ec0d372421948fd'],
  ['zasp_temporal78.ready(text,text)',9,'1463c4a87d8fd6134a020eb5b72188fbe2bc0d0e66fe7e49244fefe619e3ddb9','e67e4f1fb6b1bf199ca8f6727cc5232f39d8b5d483325d583e627a0007187dd0'],
];
const selectedSuccessorIdentities=[
  'zasp_temporal69.fingerprint()',
  'zasp_temporal76.executor74_fingerprint()',
  'zasp_temporal78.fingerprint()',
];
const selectedTemporalIdentities=[
  '65.fingerprint','66.fingerprint','67.base_fingerprint','67.fingerprint','68.fingerprint','69.fingerprint','70.fingerprint','71.fingerprint','72.fingerprint','72.retained_execution_fingerprint','72.retained_precision_fingerprint','73.fingerprint','74.fingerprint','74.outbox65_fingerprint','74.owner66_fingerprint','75.fingerprint','76.executor74_fingerprint','76.fingerprint','77.domain67_fingerprint','77.fingerprint','78.fingerprint','78.predecessor73_fingerprint','78.predecessor76_fingerprint','78.predecessor77_fingerprint',
].map(family=>'zasp_temporal'+family+'()');
const occurrences=(text,value)=>text.split(value).length-1;

function successorContract() {
  const contract=structuredClone(oldContract);
  for(const [identity,count,sourceSHA256,definitionSHA256] of successorChanges){
    const node=contract.nodes.find(node=>node.identity===identity);
    assert.ok(node,identity);
    assert.equal(occurrences(node.source,oldChecksum),count,identity+' source predecessor checksum count');
    assert.equal(occurrences(node.definition,oldChecksum),count,identity+' definition predecessor checksum count');
    node.source=node.source.split(oldChecksum).join(successorChecksum);
    node.definition=node.definition.split(oldChecksum).join(successorChecksum);
    assert.equal(sha(node.source),sourceSHA256,identity+' reviewed source pin');
    assert.equal(sha(node.definition),definitionSHA256,identity+' reviewed definition pin');
    node.sourceSHA256=sourceSHA256;
    node.definitionSHA256=definitionSHA256;
  }
  return contract;
}

test('reviewed successor lowers all 24 families and all 137 source sites with newer provenance',()=>{
  const contract=successorContract();
  const lowered=lowerOrderedTemporalCatalog(contract);
  assert.equal(new Set(lowered.sites.map(site=>site.identity)).size,24);
  assert.equal(lowered.sites.length,137);
  assert.equal(lowered.rules.length,92);
  assert.equal(lowered.obligations.filter(item=>item.type==='conditional-wrapper'||item.type==='delegate').length,13);
  for(const site of lowered.sites){
    const node=contract.nodes.find(node=>node.identity===site.identity);
    assert.equal(site.sourceSHA256,node.sourceSHA256,site.identity+' source provenance');
    assert.equal(site.definitionSHA256,node.definitionSHA256,site.identity+' definition provenance');
    assert.equal(site.text,Buffer.from(node.source).subarray(site.start,site.end).toString(),site.identity+' site bytes');
    assert.equal(site.sha256,sha(site.text),site.identity+' site pin');
  }
});

test('successor keeps all nine recipe ASTs and unsupported predecessor77 obligations unchanged',()=>{
  const before=lowerOrderedTemporalTransforms(oldContract);
  const after=lowerOrderedTemporalTransforms(successorContract());
  assert.deepEqual(after.recipes,before.recipes);
  assert.deepEqual(after.unsupported,before.unsupported);
  assert.equal(after.recipes.length,9);
  assert.deepEqual(after.unsupported.map(item=>item.ruleId),[
    'temporal:78.predecessor77_fingerprint:function',
    'temporal:78.predecessor77_fingerprint:effective-policy-boundary',
  ]);
});

test('closed profiles reject every old/new hybrid and arbitrary selected source changes',()=>{
  const successor=successorContract();
  for(const identity of selectedSuccessorIdentities){
    const hybrid=structuredClone(successor);
    const oldNode=oldContract.nodes.find(node=>node.identity===identity);
    Object.assign(hybrid.nodes.find(node=>node.identity===identity),structuredClone(oldNode));
    assert.throws(()=>lowerOrderedTemporalCatalog(hybrid),/temporal source pin or frame mismatch/,identity+' hybrid');
  }
  const edited=structuredClone(successor);
  const editedNode=edited.nodes.find(node=>node.identity==='zasp_temporal69.fingerprint()');
  editedNode.source+=' ';
  editedNode.sourceSHA256=sha(editedNode.source);
  assert.throws(()=>lowerOrderedTemporalCatalog(edited),/temporal source pin or frame mismatch/);
  const arbitrary=structuredClone(successor);
  const arbitraryNode=arbitrary.nodes.find(node=>node.identity==='zasp_temporal78.fingerprint()');
  const unknownChecksum='0'.repeat(64);
  arbitraryNode.source=arbitraryNode.source.split(successorChecksum).join(unknownChecksum);
  arbitraryNode.definition=arbitraryNode.definition.split(successorChecksum).join(unknownChecksum);
  arbitraryNode.sourceSHA256=sha(arbitraryNode.source);
  arbitraryNode.definitionSHA256=sha(arbitraryNode.definition);
  assert.throws(()=>lowerOrderedTemporalCatalog(arbitrary),/temporal source pin or frame mismatch/);
});

test('historical accepted profile keeps overload and frame-edit refusals independent of successor admission',()=>{
  const overload=structuredClone(oldContract);
  overload.nodes.push({...structuredClone(overload.nodes.find(node=>node.identity==='zasp_temporal68.fingerprint()')),identity:'zasp_temporal68.fingerprint(text)'});
  assert.throws(()=>lowerOrderedTemporalCatalog(overload),/temporal source/);
  for(const [field,value] of [['owner','foreign_owner'],['acl',null],['config',[]]]){
    const changed=structuredClone(oldContract);
    changed.nodes.find(node=>node.identity==='zasp_temporal76.executor74_fingerprint()')[field]=value;
    assert.throws(()=>lowerOrderedTemporalCatalog(changed),/temporal source pin or frame mismatch/,field);
  }
});

test('historical accepted profile rejects caller-provided pin overrides at the dedicated boundary',()=>{
  assert.throws(()=>lowerOrderedTemporalCatalog(oldContract,{pins:{}}),/caller-provided temporal profile/);
});

const artifactPath=process.env.ZASP_ORDERED_CURRENT_SUCCESSOR_CONTRACT;
if(artifactPath){
  test('opt-in accepted packet is the exact reviewed successor fixture',()=>{
    const bytes=fs.readFileSync(artifactPath);
    assert.equal(sha(bytes),'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb');
    const actual=JSON.parse(bytes),expected=successorContract();
    const fields=['identity','source','sourceSHA256','definition','definitionSHA256','owner','acl','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','result','arguments','config'];
    for(const identity of selectedTemporalIdentities){
      const actualNode=actual.nodes.find(node=>node.identity===identity),expectedNode=expected.nodes.find(node=>node.identity===identity);
      assert.deepEqual(Object.fromEntries(fields.map(field=>[field,actualNode[field]])),Object.fromEntries(fields.map(field=>[field,expectedNode[field]])),identity);
    }
    assert.equal(lowerOrderedTemporalCatalog(actual).sites.length,137);
  });
}
